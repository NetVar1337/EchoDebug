//! EchoDebug relay: routes `/client` and MCP requests to Echo's native memory server (`/agent`)
//! and the AngelScript agent (`/ext`). See PROTOCOL.md at the repo root.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Map, Value};
use tokio::sync::{broadcast, mpsc, oneshot};

pub mod local;

pub const DEFAULT_PORT: u16 = 47110;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

const NATIVE_VERBS: &[&str] = &[
    "ping",
    "read",
    "read_batch",
    "modules",
    "sig_scan",
    "sig_scan_ida",
    "string_scan",
    "resolve_relative",
    "rtti_resolve",
    "rtti_resolve_batch",
    "enumerate_functions",
    "disassemble",
];

/// Verbs served by the connected desktop UI (its name/comment/patch stores), not by Echo.
const UI_VERBS: &[&str] = &[
    "list_names",
    "set_name",
    "list_comments",
    "set_comment",
    "list_patches",
    "revert_patch",
    "list_signatures",
];
const UI_TIMEOUT: Duration = Duration::from_secs(10);

static TOOLS: LazyLock<Vec<Value>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../src/lib/tools.json"))
        .expect("src/lib/tools.json is a JSON array")
});

/// MCP prompts: canned RE workflows an MCP client can hand to its model.
static PROMPTS: LazyLock<Vec<Value>> = LazyLock::new(|| {
    serde_json::from_str(r#"[
      { "name": "explain_function", "description": "Explain what the function at an address does: disassemble it, enumerate functions in the module, follow direct calls, note xrefs.",
        "arguments": [{ "name": "address", "description": "0x-prefixed hex address inside a loaded module", "required": true }] },
      { "name": "find_pattern", "description": "Find an IDA-style AoB pattern in a module and list the hits with disassembly around them.",
        "arguments": [{ "name": "pattern", "description": "IDA pattern, e.g. '48 8B ?? ?? ?? ?? ?? E8'", "required": true }, { "name": "module", "description": "Module name; default main executable" }] },
      { "name": "find_string", "description": "Locate a string in a module and disassemble the code that references it.",
        "arguments": [{ "name": "text", "description": "Substring to search for", "required": true }, { "name": "module", "description": "Module name; default main executable" }] },
      { "name": "pointer_path", "description": "Find static pointer chains that reach a target address, then verify one with the chain resolver.",
        "arguments": [{ "name": "target", "description": "0x-prefixed hex address to reach", "required": true }, { "name": "max_depth", "description": "Pointer depth 1-5, default 3" }] },
      { "name": "scan_value", "description": "Walk a Cheat-Engine-style value scan: first scan, then narrow with changed/increased/decreased until few candidates remain.",
        "arguments": [{ "name": "value_type", "description": "u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 bytes string wstring", "required": true }, { "name": "value", "description": "Value to search for on the first scan", "required": true }] },
      { "name": "triage_module", "description": "Read a module's PE headers, sections (with entropy) and imports from live memory, run anti-debug and crypto-constant scans, and flag what deserves a second look.",
        "arguments": [{ "name": "module", "description": "Module name", "required": true }] },
      { "name": "find_value_references", "description": "Locate a value in memory with the value scanner, then find what points at it: static pointer paths, absolute pointers and the code around them.",
        "arguments": [{ "name": "value_type", "description": "u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 bytes string wstring", "required": true }, { "name": "value", "description": "Current value to search for", "required": true }] },
      { "name": "rebuild_class", "description": "Rebuild a C++ class sketch from a live object: RTTI name and bases, vtable slots, field offsets used by the virtual functions and typed reads of the object.",
        "arguments": [{ "name": "address", "description": "0x-prefixed address of a live object (its first qword is the vtable)", "required": true }, { "name": "size", "description": "Bytes of the object to inspect, default 0x200" }] },
      { "name": "update_signatures_after_patch", "description": "Re-scan the user's saved signatures after a game update, report which still match, moved or broke, and propose replacements for the broken ones.",
        "arguments": [{ "name": "module", "description": "Module to scan; default each signature's own module" }] }
    ]"#).expect("prompts")
});

/// MCP resources: read-only snapshots of relay state.
static RESOURCES: LazyLock<Vec<Value>> = LazyLock::new(|| {
    serde_json::from_str(r#"[
      { "uri": "echodebug://status", "name": "Relay status", "description": "Connection state, app/agent versions and attached target", "mimeType": "application/json" },
      { "uri": "echodebug://tools", "name": "Tool catalog", "description": "Every MCP tool with its input schema", "mimeType": "application/json" },
      { "uri": "echodebug://mcp/log", "name": "MCP call log", "description": "Recent tools/call requests seen by the relay", "mimeType": "application/json" },
      { "uri": "echodebug://target/modules", "name": "Target modules", "description": "Loaded modules of the attached process", "mimeType": "application/json" }
    ]"#).expect("resources")
});

const MCP_LOG_CAP: usize = 200;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Agent,
    Ext,
}

struct Upstream {
    conn: u64,
    tx: mpsc::UnboundedSender<String>,
}

struct Pending {
    kind: Kind,
    conn: u64,
    orig: Value,
    reply: oneshot::Sender<Value>,
}

#[derive(Default)]
struct Shared {
    agent: Option<Upstream>,
    ext: Option<Upstream>,
    pending: HashMap<u64, Pending>,
    /// the `/client` socket that registered as the desktop UI (`ui_register`); last one wins
    ui: Option<Upstream>,
    /// relay -> UI calls awaiting a `ui_reply`, keyed by `call_id`, with the UI conn they went to
    ui_pending: HashMap<u64, (u64, oneshot::Sender<Value>)>,
    ext_version: String,
    target: Value,
}

impl Shared {
    fn slot(&mut self, kind: Kind) -> &mut Option<Upstream> {
        match kind {
            Kind::Agent => &mut self.agent,
            Kind::Ext => &mut self.ext,
        }
    }
}

struct Inner {
    app_version: String,
    timeout: Duration,
    next_id: AtomicU64,
    shared: Mutex<Shared>,
    events: broadcast::Sender<String>,
    mcp_log: Mutex<VecDeque<Value>>,
    /// serve verbs from /proc when no Echo upstream is connected (Linux default; tests turn it off)
    local_backend: AtomicBool,
    /// bearer token required on `/mcp` and `/client`; `None` disables the check
    token: Mutex<Option<String>>,
}

/// Shared relay state. Cheap to clone.
#[derive(Clone)]
pub struct Relay(Arc<Inner>);

fn error(id: Value, code: u32, message: &str) -> Value {
    json!({ "type": "error", "id": id, "code": code, "message": message })
}

impl Relay {
    pub fn new(app_version: impl Into<String>, timeout: Duration) -> Self {
        Relay(Arc::new(Inner {
            app_version: app_version.into(),
            timeout,
            next_id: AtomicU64::new(1),
            shared: Mutex::new(Shared::default()),
            events: broadcast::channel(1024).0,
            mcp_log: Mutex::new(VecDeque::new()),
            local_backend: AtomicBool::new(local::available()),
            token: Mutex::new(None),
        }))
    }

    /// Builder: require `token` on `/mcp` (`Authorization: Bearer`) and `/client` (header or `?token=`).
    pub fn with_token(self, token: Option<String>) -> Self {
        self.set_token(token);
        self
    }

    /// Replaces the token at runtime (token regeneration). Open sockets stay connected.
    pub fn set_token(&self, token: Option<String>) {
        *self.0.token.lock().unwrap_or_else(|e| e.into_inner()) = token;
    }

    fn token_ok(&self, headers: &HeaderMap, query: Option<&str>) -> bool {
        let guard = self.0.token.lock().unwrap_or_else(|e| e.into_inner());
        let Some(want) = guard.as_deref() else {
            return true;
        };
        let bearer = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        [bearer, query].into_iter().flatten().any(|got| {
            // constant-time compare: no early exit on the first differing byte
            got.len() == want.len()
                && got.bytes().zip(want.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        })
    }

    /// Builder: enable/disable the local /proc backend (default: on for Linux, off elsewhere).
    pub fn with_local_backend(self, on: bool) -> Self {
        self.0.local_backend.store(on, Ordering::Relaxed);
        self
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.0.shared.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn next_id(&self) -> u64 {
        self.0.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn status(&self, ty: &str) -> Map<String, Value> {
        let s = self.lock();
        let backend = if s.agent.is_some() {
            "echo"
        } else if local::attached_pid().is_some() {
            "local"
        } else {
            "none"
        };
        let v = json!({
            "type": ty,
            "agent": s.agent.is_some(),
            "ext": s.ext.is_some(),
            "ext_version": s.ext_version,
            "app_version": self.0.app_version,
            "target": s.target,
            "backend": backend,
            "local": backend == "local",
        });
        let Value::Object(m) = v else { unreachable!() };
        m
    }

    pub(crate) fn broadcast_status(&self) {
        let _ = self
            .0
            .events
            .send(Value::Object(self.status("status")).to_string());
    }

    /// Handles one request exactly as if it came from a `/client` socket and returns the reply
    /// (original `id` restored).
    pub async fn request(&self, req: Value) -> Value {
        let Value::Object(mut req) = req else {
            return error(json!(0), 2000, "request must be a JSON object");
        };
        let orig = req.remove("id").unwrap_or(json!(0));
        let verb = req
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let kind = match verb.as_str() {
            "" => return error(orig, 2000, "missing type"),
            "status" => {
                let mut m = self.status("status_result");
                m.insert("id".into(), orig);
                m.insert("success".into(), true.into());
                return Value::Object(m);
            }
            "processes" => {
                let processes = tokio::task::spawn_blocking(processes)
                    .await
                    .unwrap_or_default();
                return json!({ "type": "processes_result", "id": orig, "success": true, "processes": processes });
            }
            // Local introspection verbs for the app's MCP panel.
            "mcp_log" => {
                let entries: Vec<Value> = self.0.mcp_log.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect();
                return json!({ "type": "mcp_log_result", "id": orig, "success": true, "entries": entries });
            }
            "mcp_meta" => {
                return json!({
                    "type": "mcp_meta_result", "id": orig, "success": true,
                    "serverInfo": { "name": "echodebug", "version": self.0.app_version },
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {}, "prompts": {}, "resources": {} },
                    "prompts": *PROMPTS,
                    "resources": *RESOURCES,
                    "tools": TOOLS.len(),
                });
            }
            v if UI_VERBS.contains(&v) => return self.ui_call(&verb, req, orig).await,
            v if NATIVE_VERBS.contains(&v) => Kind::Agent,
            _ => Kind::Ext,
        };

        let id = self.next_id();
        req.insert("id".into(), id.into());
        let (tx, mut rx) = oneshot::channel();
        // Grab the upstream sender in a short lock scope so no guard is held across an await.
        let upstream = {
            let mut s = self.lock();
            s.slot(kind).as_ref().map(|up| (up.conn, up.tx.clone()))
        };
        let Some((conn, up_tx)) = upstream else {
            // No Echo upstream: on Linux the relay serves the verbs itself from /proc.
            if self.0.local_backend.load(Ordering::Relaxed) && local::available() {
                return match kind {
                    Kind::Agent => local::handle_native(self, req, &orig).await
                        .unwrap_or_else(|| error(orig.clone(), 2001, "echo memory server not connected")),
                    Kind::Ext => local::handle_ext(self, req, &orig).await
                        .unwrap_or_else(|| error(orig.clone(), 2002, "EchoDebug agent not connected")),
                };
            }
            return match kind {
                Kind::Agent => error(orig, 2001, "echo memory server not connected"),
                Kind::Ext => error(orig, 2002, "EchoDebug agent not connected"),
            };
        };
        let sent = up_tx.send(Value::Object(req).to_string());
        drop(up_tx); // a cloned sender held across the await would keep the old upstream alive
        if sent.is_err() {
            return error(orig, 2004, "upstream disconnected");
        }
        self.lock().pending.insert(
            id,
            Pending {
                kind,
                conn,
                orig: orig.clone(),
                reply: tx,
            },
        );

        match tokio::time::timeout(self.0.timeout, &mut rx).await {
            Ok(Ok(reply)) => reply,
            // Pending entry dropped: its upstream went away.
            Ok(Err(_)) => error(orig, 2004, "upstream disconnected"),
            Err(_) => {
                self.lock().pending.remove(&id);
                rx.try_recv()
                    .unwrap_or_else(|_| error(orig, 2003, "timed out"))
            }
        }
    }

    /// Forwards a UI verb to the registered desktop UI as
    /// `{ "type":"ui_call", "call_id", "verb", "args" }` and waits for its `ui_reply`.
    async fn ui_call(&self, verb: &str, mut args: Map<String, Value>, orig: Value) -> Value {
        args.remove("type");
        args.remove("id");
        let call_id = self.next_id();
        let (tx, rx) = oneshot::channel();
        {
            let mut s = self.lock();
            let Some(ui) = s.ui.as_ref() else {
                return error(orig, 2005, "EchoDebug UI not connected: open the desktop app (or the browser dev UI) and retry");
            };
            let frame = json!({ "type": "ui_call", "call_id": call_id, "verb": verb, "args": args });
            if ui.tx.send(frame.to_string()).is_err() {
                return error(orig, 2005, "EchoDebug UI not connected");
            }
            let conn = ui.conn;
            s.ui_pending.insert(call_id, (conn, tx));
        }
        let reply = match tokio::time::timeout(self.0.timeout.min(UI_TIMEOUT), rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => return error(orig, 2004, "UI disconnected"),
            Err(_) => {
                self.lock().ui_pending.remove(&call_id);
                return error(orig, 2003, "timed out waiting for the UI");
            }
        };
        if let Some(msg) = reply.get("error").and_then(Value::as_str) {
            return error(orig, 2006, msg);
        }
        let mut out = match reply.get("result") {
            Some(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        };
        out.insert("type".into(), format!("{verb}_result").into());
        out.insert("id".into(), orig);
        out.insert("success".into(), true.into());
        Value::Object(out)
    }

    /// Sends a one-shot request to the ext agent; the reply (if any) is dropped. Used for
    /// housekeeping pokes like `reopen_socket` that no client is waiting on.
    fn poke_ext(&self, verb: &str) {
        let id = self.next_id();
        let (tx, _rx) = oneshot::channel();
        let mut s = self.lock();
        let Some(conn) = s.ext.as_ref().map(|up| up.conn) else {
            return;
        };
        if s.ext.as_ref().unwrap().tx.send(json!({ "type": verb, "id": id }).to_string()).is_ok() {
            s.pending.insert(
                id,
                Pending {
                    kind: Kind::Ext,
                    conn,
                    orig: Value::Null,
                    reply: tx,
                },
            );
        }
    }

    fn on_upstream_frame(&self, kind: Kind, text: &str) {
        let Ok(Value::Object(mut msg)) = serde_json::from_str::<Value>(text) else {
            return;
        };
        let id = msg.get("id").filter(|v| !v.is_null()).map(|v| v.as_u64());
        match id {
            None => {
                if kind != Kind::Ext {
                    return;
                }
                let event = msg.get("event").and_then(Value::as_str);
                let (status_changed, reopen_socket) = if event == Some("hello") {
                    let mut s = self.lock();
                    s.ext_version = msg
                        .get("version")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let attached = msg.get("attached") == Some(&Value::Bool(true));
                    s.target = if attached {
                        json!({
                            "pid": msg.get("pid"),
                            "base": msg.get("base"),
                            "peb": msg.get("peb"),
                            "name": msg.get("name"),
                        })
                    } else {
                        Value::Null
                    };
                    // Attached per the agent, but no native memory server connected: after an app
                    // restart Echo's old process::open_socket connection is dead. Ask the agent to
                    // re-open it (one-shot, fire-and-forget).
                    let reopen = attached && s.agent.is_none();
                    (true, reopen)
                } else if event == Some("detached") {
                    self.lock().target = Value::Null;
                    (true, false)
                } else {
                    (false, false)
                };
                let _ = self.0.events.send(text.to_owned());
                if status_changed {
                    self.broadcast_status();
                }
                if reopen_socket {
                    self.poke_ext("reopen_socket");
                }
            }
            Some(Some(id)) => {
                let Some(p) = self.lock().pending.remove(&id) else {
                    return;
                };
                msg.insert("id".into(), p.orig);
                let ty = msg.get("type").and_then(Value::as_str).unwrap_or_default();
                if ty == "attach_result" || ty == "detach_result" {
                    let mut target = msg.clone();
                    target.remove("type");
                    target.remove("id");
                    self.lock().target = if ty == "attach_result" {
                        Value::Object(target)
                    } else {
                        Value::Null
                    };
                    self.broadcast_status();
                }
                let _ = p.reply.send(Value::Object(msg));
            }
            Some(None) => {} // non-integer id: not one of ours
        }
    }

    async fn upstream(self, kind: Kind, mut socket: WebSocket) {
        let conn = self.next_id();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        {
            let mut s = self.lock();
            // Dropping the old sender makes the old connection's loop close it and fail its requests.
            *s.slot(kind) = Some(Upstream { conn, tx });
            if kind == Kind::Ext {
                s.ext_version.clear();
            }
        }
        self.broadcast_status();

        loop {
            tokio::select! {
                out = rx.recv() => match out {
                    Some(text) => if socket.send(Message::Text(text.into())).await.is_err() { break },
                    None => { let _ = socket.send(Message::Close(None)).await; break }
                },
                inc = socket.recv() => match inc {
                    Some(Ok(Message::Text(t))) => self.on_upstream_frame(kind, t.as_str()),
                    Some(Ok(Message::Binary(b))) => if let Ok(t) = std::str::from_utf8(&b) { self.on_upstream_frame(kind, t) },
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
            }
        }

        let was_current = {
            let mut s = self.lock();
            s.pending.retain(|_, p| !(p.kind == kind && p.conn == conn));
            let current = s.slot(kind).as_ref().is_some_and(|u| u.conn == conn);
            if current {
                *s.slot(kind) = None;
                if kind == Kind::Ext {
                    s.ext_version.clear();
                    s.target = Value::Null;
                }
            }
            current
        };
        if was_current {
            self.broadcast_status();
        }
    }

    async fn client(self, socket: WebSocket) {
        let conn = self.next_id();
        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let mut events = self.0.events.subscribe();
        let _ = tx.send(Value::Object(self.status("status")).to_string());

        let writer = tokio::spawn(async move {
            loop {
                let text = tokio::select! {
                    m = rx.recv() => match m { Some(t) => t, None => break },
                    e = events.recv() => match e {
                        Ok(t) => t,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                };
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
        });

        while let Some(Ok(msg)) = stream.next().await {
            let text = match msg {
                Message::Text(t) => t.as_str().to_owned(),
                Message::Close(_) => break,
                _ => continue,
            };
            let req = serde_json::from_str(&text).unwrap_or(Value::Null);
            match req["type"].as_str() {
                // This socket is the desktop UI: route UI verbs (names, comments, patches) to it.
                Some("ui_register") => {
                    self.lock().ui = Some(Upstream { conn, tx: tx.clone() });
                    let _ = tx.send(json!({ "type": "ui_register_result", "id": req["id"], "success": true }).to_string());
                }
                Some("ui_reply") => {
                    let waiter = req["call_id"].as_u64().and_then(|id| self.lock().ui_pending.remove(&id));
                    if let Some((_, reply)) = waiter {
                        let _ = reply.send(req);
                    }
                }
                _ => {
                    let (relay, tx) = (self.clone(), tx.clone());
                    tokio::spawn(async move {
                        let _ = tx.send(relay.request(req).await.to_string());
                    });
                }
            }
        }
        writer.abort();
        let mut s = self.lock();
        if s.ui.as_ref().is_some_and(|u| u.conn == conn) {
            s.ui = None;
        }
        // dropping the senders fails this UI's in-flight calls with "UI disconnected"
        s.ui_pending.retain(|_, (c, _)| *c != conn);
    }

    /// Handles one JSON-RPC message; `None` for notifications and client responses.
    async fn rpc(&self, msg: Value) -> Option<Value> {
        let id = msg.get("id").cloned();
        let Some(method) = msg.get("method").and_then(Value::as_str) else {
            if msg.get("result").is_some() || msg.get("error").is_some() {
                return None;
            }
            return Some(rpc_error(
                id.unwrap_or(Value::Null),
                -32600,
                "invalid request".into(),
            ));
        };
        let id = id?;
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": params["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                "capabilities": { "tools": {}, "prompts": {}, "resources": {} },
                "serverInfo": { "name": "echodebug", "version": self.0.app_version },
                "instructions": "Reverse-engineering tools over Echo's hypervisor-backed memory API. Attach with the attach tool before reading/writing memory. Addresses are 0x-prefixed hex strings; byte payloads are lowercase hex. See prompts/list for canned workflows and resources/read for live status.",
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": TOOLS.iter().map(|t| json!({
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["input_schema"],
            })).collect::<Vec<_>>() })),
            "tools/call" => self.call_tool(&params).await,
            "prompts/list" => Ok(json!({ "prompts": *PROMPTS })),
            "prompts/get" => {
                let Some(name) = params["name"].as_str() else {
                    return Some(rpc_error(id, -32602, "missing prompt name".to_owned()));
                };
                let Some(p) = PROMPTS.iter().find(|p| p["name"] == name) else {
                    return Some(rpc_error(id, -32602, format!("unknown prompt: {name}")));
                };
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);
                Ok(prompt_messages(p, &args))
            }
            "resources/list" => Ok(json!({ "resources": *RESOURCES })),
            "resources/read" => {
                let Some(uri) = params["uri"].as_str() else {
                    return Some(rpc_error(id, -32602, "missing resource uri".to_owned()));
                };
                self.read_resource(uri).await
            }
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => rpc_error(id, code, message),
        })
    }

    async fn call_tool(&self, params: &Value) -> Result<Value, (i32, String)> {
        let name = params["name"]
            .as_str()
            .ok_or((-32602, "missing tool name".to_owned()))?;
        let tool = TOOLS
            .iter()
            .find(|t| t["name"] == name)
            .ok_or_else(|| (-32602, format!("unknown tool: {name}")))?;
        let mut req = match &params["arguments"] {
            Value::Object(m) => m.clone(),
            Value::Null => Map::new(),
            _ => return Err((-32602, "arguments must be an object".to_owned())),
        };
        req.remove("id");
        req.insert("type".into(), tool["verb"].clone());
        let t0 = SystemTime::now();
        let args_str = serde_json::to_string(&req).unwrap_or_default();
        let verb = tool["verb"].clone();
        let mut reply = self.request(Value::Object(req)).await;
        let is_error = reply["type"] == "error";
        // Ring-buffer the call for the app's MCP panel and the echodebug://mcp/log resource.
        let entry = json!({
            "ts": SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0),
            "tool": name,
            "verb": verb,
            "args": truncate_str(&args_str, 400),
            "ok": !is_error,
            "ms": t0.elapsed().map(|d| d.as_millis()).unwrap_or(0),
        });
        {
            let mut log = self.0.mcp_log.lock().unwrap_or_else(|e| e.into_inner());
            if log.len() >= MCP_LOG_CAP {
                log.pop_front();
            }
            log.push_back(entry);
        }
        if let Some(m) = reply.as_object_mut() {
            m.remove("type");
            m.remove("id");
        }
        let text = serde_json::to_string_pretty(&reply).unwrap_or_default();
        Ok(json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }))
    }

    async fn read_resource(&self, uri: &str) -> Result<Value, (i32, String)> {
        let body = match uri {
            "echodebug://status" => Value::Object(self.status("status")),
            "echodebug://tools" => json!({ "tools": TOOLS.iter().map(|t| json!({
                "name": t["name"], "verb": t["verb"], "description": t["description"], "inputSchema": t["input_schema"],
            })).collect::<Vec<_>>() }),
            "echodebug://mcp/log" => {
                let entries: Vec<Value> = self.0.mcp_log.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect();
                json!({ "entries": entries })
            }
            "echodebug://target/modules" => {
                if self.lock().agent.is_none() {
                    return Err((-32000, "echo memory server not connected".to_owned()));
                }
                let mut req = Map::new();
                req.insert("type".into(), json!("modules"));
                self.request(Value::Object(req)).await
            }
            other => return Err((-32602, format!("unknown resource: {other}"))),
        };
        Ok(json!({ "contents": [{ "uri": uri, "mimeType": "application/json", "text": serde_json::to_string_pretty(&body).unwrap_or_default() }] }))
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}…", &s[..max])
    }
}

/// Renders a prompt's `messages` with the caller's arguments substituted.
fn prompt_messages(prompt: &Value, args: &Value) -> Value {
    // Substitutes every declared argument; ones the caller left out read "(not given)".
    let text = |_: &str, tmpl: &str| -> Value {
        let mut t = tmpl.to_owned();
        for a in prompt["arguments"].as_array().into_iter().flatten() {
            let name = a["name"].as_str().unwrap_or_default();
            let value = args.get(name).and_then(Value::as_str).unwrap_or("(not given)");
            t = t.replace(&format!("{{{{{name}}}}}"), value);
        }
        json!({ "role": "user", "content": { "type": "text", "text": t } })
    };
    let name = prompt["name"].as_str().unwrap_or_default();
    let msgs = match name {
        "explain_function" => vec![text("address",
            "Explain the function at {{address}}. Steps: disassemble 512 bytes there, list module functions to find its bounds, read the strings it references, and check which functions call it. Summarize its purpose, arguments and side effects, citing addresses as module+0xRVA.")],
        "find_pattern" => vec![text("pattern",
            "Find every occurrence of the IDA pattern {{pattern}} (module: {{module}}) with signature scanning, then disassemble 64 bytes around each hit and report what each site does.")],
        "find_string" => vec![text("text",
            "Find the string \"{{text}}\" (module: {{module}}) with string scanning, then find code references to each hit (scan for the little-endian address bytes) and disassemble those sites. Report what reads the string.")],
        "pointer_path" => vec![text("target",
            "Find static pointer chains that reach {{target}}: run a pointer scan with max_depth {{max_depth}} (default 3), take the first module-rooted result, verify it with the chain resolver, and report module+offset and the offsets array.")],
        "scan_value" => vec![text("value",
            "Run a value scan of type {{value_type}} for {{value}}: first scan with compare 'exact' (or 'unknown' if the value is not known yet), then narrow with changed/increased/decreased/unchanged scans until under 50 candidates remain. Report the surviving addresses and their current values.")],
        // Tool names are in backticks; a unit test checks each one exists in tools.json.
        "triage_module" => vec![text("module",
            "Triage the module {{module}}. 1) `list_modules` for its base and size. 2) `read_memory` 0x1000 bytes at the base and parse the DOS/NT headers, section table and data directories; follow the import and export directories with more `read_memory` calls. 3) For each section, `read_memory` its bytes (in chunks up to 1 MiB) and compute Shannon entropy; flag sections above 7.2 (packed/encrypted) and writable+executable sections (`query_region` on each). 4) Suspicious imports (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, NtProtectVirtualMemory, IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess): find their IAT slots, then call sites with `signature_scan` for 'FF 15 ?? ?? ?? ??' and `resolve_relative` (offset 2, inst_size 6) to see which hits target those slots. 5) Anti-debug: `signature_scan` with find_all for 'CD 2D' (INT 2D), '0F 01 C1' (VMCALL), '65 48 8B 04 25 60 00 00 00' (PEB via gs:[60]), '0F 31' (RDTSC); `string_scan` for debugger names (x64dbg, ollydbg, ida, cheat engine). 6) Crypto: `signature_scan` for '63 7C 77 7B F2 6B 6F C5' (AES S-box), '98 2F 8A 42 91 44 37 71' (SHA-256 K), '67 E6 09 6A 85 AE 67 BB' (SHA-256 H), '78 A4 6A D7 56 B7 C7 E8' (MD5 T), '96 30 07 77 2C 61 0E EE' (CRC-32 table), and `string_scan` for 'expand 32-byte k' (ChaCha/Salsa). `disassemble` around interesting hits. Summarize per category with module+0xRVA addresses and label the key sites with `set_name`.")],
        "find_value_references" => vec![text("value",
            "Find what references the {{value_type}} value {{value}}. 1) `value_scan_first` with compare 'exact'; while more than ~20 candidates remain, ask the user to change the value in the target and narrow with `value_scan_next` (exact/changed/increased/decreased), reading the survivors with `value_scan_results`. 2) For each surviving address: `query_region` to see where it lives, then `pointer_scan` with it as target and verify the best module-rooted results with `pointer_chain`. 3) Find absolute pointers to it: `signature_scan` with find_all for its 8 little-endian address bytes, and for each hit `disassemble` 64 bytes before it if it lies in code. 4) Report the stable pointer paths as module+offset plus offsets, the code sites that touch the value, and name the confirmed address with `set_name` (check `list_names` first so existing user names are reused). Call `value_scan_clear` when done.")],
        "rebuild_class" => vec![text("address",
            "Rebuild the C++ class of the object at {{address}} (inspect {{size}} bytes; default 0x200). 1) `rtti_resolve` on {{address}} for the class name, base classes and vtable; if it fails, `read_memory` 8 bytes for the vtable pointer. 2) `read_memory` the vtable (8 bytes per slot) until a slot leaves the module's executable range (`query_region`); `list_names` to reuse names the user gave those functions. 3) `disassemble` 0x100 bytes of each virtual function and collect the [rcx+offset] accesses with their operand sizes and the call targets (`enumerate_functions` for function bounds). 4) `read_memory` the object and decode candidate fields with `read_typed` (pointers, floats, ints, strings); `rtti_resolve_batch` the qwords that look like pointers to identify member objects. 5) Output a C++ class sketch: inheritance from RTTI, a commented vtable listing slot index, address and inferred purpose, and fields with offset comments, type and a guessed name. Offer to store the names with `set_name` and notes with `set_comment`.")],
        "update_signatures_after_patch" => vec![text("module",
            "Update the user's saved signatures after a patch (module override: {{module}}). 1) `list_signatures` for the catalog (name, module, IDA pattern, original address, previous hit count). 2) `list_modules` to get each module's new base. 3) For each signature, `signature_scan` its IDA pattern with find_all in its module. Classify: OK (exactly one hit, same RVA), MOVED (one hit at a new RVA; give old and new RVA), AMBIGUOUS (several hits), BROKEN (no hit). 4) For each BROKEN or AMBIGUOUS one: `disassemble` around its old address and around candidates found by scanning a shorter prefix of the pattern, decide where the function went, then build a new signature like the sigmaker does: take the instruction bytes from `read_memory`, wildcard rel32/disp32 operands and immediates that look like addresses, and grow it one instruction at a time until `signature_scan` reports exactly one hit. 5) Report a table: name, status, old RVA, new RVA, old pattern, proposed pattern. Do not modify the catalog yourself; the user re-saves the proposals from the Signatures view.")],
        _ => vec![json!({ "role": "user", "content": { "type": "text", "text": format!("Run the {name} workflow.") } })],
    };
    json!({ "description": prompt["description"], "messages": msgs })
}

fn rpc_error(id: Value, code: i32, message: String) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn processes() -> Vec<Value> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_memory()
            .with_exe(UpdateKind::OnlyIfNotSet),
    );
    let mut list: Vec<(String, Value)> = sys
        .processes()
        .values()
        .map(|p| {
            let name = p.name().to_string_lossy().into_owned();
            let path = p.exe().map(|e| e.display().to_string()).unwrap_or_default();
            let v = json!({ "pid": p.pid().as_u32(), "name": name, "path": path, "memory": p.memory() });
            (name.to_lowercase(), v)
        })
        .collect();
    list.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1["pid"].as_u64().cmp(&b.1["pid"].as_u64()))
    });
    list.into_iter().map(|(_, v)| v).collect()
}

/// Browser pages may only reach `/client` and `/mcp` from the app itself or a local dev server;
/// native tools send no Origin.
fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    if matches!(
        origin,
        "tauri://localhost" | "http://tauri.localhost" | "https://tauri.localhost"
    ) {
        return true;
    }
    ["http://localhost", "http://127.0.0.1"].iter().any(|base| {
        origin.strip_prefix(base).is_some_and(|rest| {
            rest.is_empty()
                || rest.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                })
        })
    })
}

async fn health(State(relay): State<Relay>) -> Json<Value> {
    Json(json!({ "ok": true, "version": relay.0.app_version }))
}

async fn client_ws(
    State(relay): State<Relay>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Response {
    if !origin_allowed(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Browsers cannot set headers on a WebSocket, so the UI passes the token as `?token=`.
    if !relay.token_ok(&headers, query.get("token").map(String::as_str)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    ws.on_upgrade(move |s| relay.client(s))
}

fn upstream_ws(relay: Relay, kind: Kind, headers: &HeaderMap, ws: WebSocketUpgrade) -> Response {
    // Echo connects without an Origin; anything with one is a browser page. No token here: Echo's
    // `process::open_socket(url)` and the agent's `ws::connect` dial a fixed URL baked into the agent
    // script, and upstreams only answer requests the relay sends them (they cannot drive tools).
    if headers.contains_key(header::ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    ws.on_upgrade(move |s| relay.upstream(kind, s))
}

async fn agent_ws(
    State(relay): State<Relay>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    upstream_ws(relay, Kind::Agent, &headers, ws)
}

async fn ext_ws(State(relay): State<Relay>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    upstream_ws(relay, Kind::Ext, &headers, ws)
}

async fn mcp(State(relay): State<Relay>, headers: HeaderMap, body: Bytes) -> Response {
    if !origin_allowed(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !relay.token_ok(&headers, None) {
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")]).into_response();
    }
    let Ok(msg) = serde_json::from_slice::<Value>(&body) else {
        return Json(rpc_error(Value::Null, -32700, "parse error".into())).into_response();
    };
    let reply = match msg {
        Value::Array(batch) if batch.is_empty() => {
            Some(rpc_error(Value::Null, -32600, "empty batch".into()))
        }
        Value::Array(batch) => {
            let replies: Vec<Value> =
                futures_util::future::join_all(batch.into_iter().map(|m| relay.rpc(m)))
                    .await
                    .into_iter()
                    .flatten()
                    .collect();
            (!replies.is_empty()).then_some(Value::Array(replies))
        }
        msg => relay.rpc(msg).await,
    };
    match reply {
        Some(r) => Json(r).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

pub fn router(relay: Relay) -> Router {
    Router::new()
        .route("/agent", get(agent_ws))
        .route("/ext", get(ext_ws))
        .route("/client", get(client_ws))
        .route("/health", get(health))
        .route("/mcp", post(mcp))
        .with_state(relay)
}

/// Binds `127.0.0.1:port` synchronously so callers learn about a busy port immediately.
/// Port 0 picks a free port; read it back with `local_addr()`.
pub fn bind(port: u16) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Serves the relay on an already-bound listener (must be called inside a tokio runtime).
pub async fn run(listener: TcpListener, relay: Relay) -> std::io::Result<()> {
    axum::serve(tokio::net::TcpListener::from_std(listener)?, router(relay)).await
}

pub async fn serve(port: u16, app_version: String, token: Option<String>) -> std::io::Result<()> {
    run(bind(port)?, Relay::new(app_version, DEFAULT_TIMEOUT).with_token(token)).await
}

/// A fresh random bearer token: 32 bytes from the OS RNG as 64 lowercase hex chars.
pub fn generate_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("OS random number generator");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_reference_only_known_tools() {
        for p in PROMPTS.iter() {
            let msgs = prompt_messages(p, &json!({}));
            let text = msgs["messages"][0]["content"]["text"].as_str().unwrap();
            assert!(!text.contains("{{"), "{text}");
            // backticked words are tool names: odd-indexed pieces of a split on '`'
            for name in text.split('`').skip(1).step_by(2) {
                assert!(TOOLS.iter().any(|t| t["name"] == name), "prompt {} names unknown tool `{name}`", p["name"]);
            }
        }
    }

    #[test]
    fn generated_tokens_are_random_hex() {
        let (a, b) = (generate_token(), generate_token());
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn origins() {
        let check = |o: Option<&str>| {
            let mut h = HeaderMap::new();
            if let Some(o) = o {
                h.insert(header::ORIGIN, o.parse().unwrap());
            }
            origin_allowed(&h)
        };
        for ok in [
            None,
            Some("http://localhost"),
            Some("http://localhost:1420"),
            Some("http://127.0.0.1:5173"),
            Some("tauri://localhost"),
            Some("http://tauri.localhost"),
            Some("https://tauri.localhost"),
        ] {
            assert!(check(ok), "{ok:?}");
        }
        for bad in [
            "https://evil.com",
            "http://localhost.evil.com",
            "http://localhost:",
            "http://localhost:80x",
            "http://127.0.0.1.evil.com",
            "null",
            "https://localhost",
        ] {
            assert!(!check(Some(bad)), "{bad}");
        }
    }
}
