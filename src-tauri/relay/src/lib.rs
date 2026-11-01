//! EchoDebug relay: routes `/client` and MCP requests to Echo's native memory server (`/agent`)
//! and the AngelScript agent (`/ext`). See PROTOCOL.md at the repo root.

use std::collections::HashMap;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Map, Value};
use tokio::sync::{broadcast, mpsc, oneshot};

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

static TOOLS: LazyLock<Vec<Value>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../../../src/lib/tools.json"))
        .expect("src/lib/tools.json is a JSON array")
});

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
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
        }))
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.0.shared.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn next_id(&self) -> u64 {
        self.0.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn status(&self, ty: &str) -> Map<String, Value> {
        let s = self.lock();
        let v = json!({
            "type": ty,
            "agent": s.agent.is_some(),
            "ext": s.ext.is_some(),
            "ext_version": s.ext_version,
            "app_version": self.0.app_version,
            "target": s.target,
        });
        let Value::Object(m) = v else { unreachable!() };
        m
    }

    fn broadcast_status(&self) {
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
            v if NATIVE_VERBS.contains(&v) => Kind::Agent,
            _ => Kind::Ext,
        };

        let id = self.next_id();
        req.insert("id".into(), id.into());
        let (tx, mut rx) = oneshot::channel();
        {
            let mut s = self.lock();
            let Some(up) = s.slot(kind) else {
                return match kind {
                    Kind::Agent => error(orig, 2001, "echo memory server not connected"),
                    Kind::Ext => error(orig, 2002, "EchoDebug agent not connected"),
                };
            };
            let conn = up.conn;
            if up.tx.send(Value::Object(req).to_string()).is_err() {
                return error(orig, 2004, "upstream disconnected");
            }
            s.pending.insert(
                id,
                Pending {
                    kind,
                    conn,
                    orig: orig.clone(),
                    reply: tx,
                },
            );
        }

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
            let (relay, tx) = (self.clone(), tx.clone());
            tokio::spawn(async move {
                let req = serde_json::from_str(&text).unwrap_or(Value::Null);
                let _ = tx.send(relay.request(req).await.to_string());
            });
        }
        writer.abort();
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
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "echodebug", "version": self.0.app_version },
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": TOOLS.iter().map(|t| json!({
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["input_schema"],
            })).collect::<Vec<_>>() })),
            "tools/call" => self.call_tool(&params).await,
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
        let mut reply = self.request(Value::Object(req)).await;
        let is_error = reply["type"] == "error";
        if let Some(m) = reply.as_object_mut() {
            m.remove("type");
            m.remove("id");
        }
        let text = serde_json::to_string_pretty(&reply).unwrap_or_default();
        Ok(json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }))
    }
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
    ws: WebSocketUpgrade,
) -> Response {
    if !origin_allowed(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    ws.on_upgrade(move |s| relay.client(s))
}

fn upstream_ws(relay: Relay, kind: Kind, headers: &HeaderMap, ws: WebSocketUpgrade) -> Response {
    // Echo connects without an Origin; anything with one is a browser page.
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

pub async fn serve(port: u16, app_version: String) -> std::io::Result<()> {
    run(bind(port)?, Relay::new(app_version, DEFAULT_TIMEOUT)).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
