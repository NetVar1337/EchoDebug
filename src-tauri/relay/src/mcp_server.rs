//! The MCP server: protocol versions, sessions, the Streamable HTTP endpoint (`/mcp`) and stdio.
//!
//! Dual-era (see PROTOCOL.md "MCP surface"):
//! - **2026-07-28** (stateless): every request carries `_meta` with
//!   `io.modelcontextprotocol/protocolVersion` and `clientCapabilities`; `server/discover`,
//!   `subscriptions/listen` for change notifications, per-request `logLevel`, multi round-trip
//!   requests (an `input_required` result) for elicitation, `resultType` and cache hints on results,
//!   and the `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` headers on HTTP.
//! - **2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05** (initialize-based): an `initialize`
//!   handshake creates a session (`Mcp-Session-Id` on HTTP), `GET /mcp` streams the session's
//!   notifications, `logging/setLevel`, `resources/subscribe`, server-initiated
//!   `elicitation/create` on the request's stream. Older revisions get older result shapes (no
//!   `title`, `outputSchema`, `structuredContent` or `resource_link` before 2025-06-18).
//!
//! The tool calls themselves go through [`Relay::request`] after the call policy
//! (`mcp::decide`): allow, deny, or ask (an elicitation in the client when it supports one and the
//! policy allows it, else the Allow/Deny dialog in the app window).

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::{auth, mcp, Relay, PROMPTS, PROVIDER_PREFIX, RESOURCES, TOOLS};

// ---- protocol versions ----------------------------------------------------------------------------

/// A protocol revision this server speaks, oldest first (so `>=` reads "at least").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ver {
    V20241105,
    V20250326,
    V20250618,
    V20251125,
    V20260728,
}

impl Ver {
    /// Newest first: the order `supportedVersions` lists them in.
    pub const ALL: [Ver; 5] = [Ver::V20260728, Ver::V20251125, Ver::V20250618, Ver::V20250326, Ver::V20241105];

    pub fn parse(s: &str) -> Option<Ver> {
        Ver::ALL.into_iter().find(|v| v.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Ver::V20241105 => "2024-11-05",
            Ver::V20250326 => "2025-03-26",
            Ver::V20250618 => "2025-06-18",
            Ver::V20251125 => "2025-11-25",
            Ver::V20260728 => "2026-07-28",
        }
    }

    /// Per-request metadata instead of an initialize handshake (2026-07-28 and later).
    pub fn modern(self) -> bool {
        self >= Ver::V20260728
    }

    /// `title`, `outputSchema`, `structuredContent`, `resource_link`, elicitation (2025-06-18+).
    pub fn rich(self) -> bool {
        self >= Ver::V20250618
    }
}

/// The latest stable revision (modelcontextprotocol.io/specification/versioning).
pub const LATEST: Ver = Ver::V20260728;
/// What an `initialize` gets when it asks for a version this server does not speak.
pub const LATEST_LEGACY: Ver = Ver::V20251125;

pub fn supported_versions() -> Vec<&'static str> {
    Ver::ALL.iter().map(|v| v.as_str()).collect()
}

/// The version an `initialize` request ends up with: the requested one when it is an
/// initialize-based revision this server speaks, else the latest of those.
pub fn negotiate(requested: Option<&str>) -> Ver {
    match requested.and_then(Ver::parse) {
        Some(v) if !v.modern() => v,
        _ => LATEST_LEGACY,
    }
}

// ---- JSON-RPC errors --------------------------------------------------------------------------------

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;
/// Resource not found before 2026-07-28 (that revision uses -32602).
pub const RESOURCE_NOT_FOUND_LEGACY: i32 = -32002;
pub const HEADER_MISMATCH: i32 = -32020;
pub const MISSING_CLIENT_CAPABILITY: i32 = -32021;
pub const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;
/// Application codes (outside the JSON-RPC reserved range) on HTTP-level refusals.
pub const UNAUTHORIZED: i32 = 401;
pub const SESSION_NOT_FOUND: i32 = 404;

#[derive(Debug, Clone)]
pub(crate) struct RpcErr {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcErr {
    fn new(code: i32, message: impl Into<String>) -> Self {
        RpcErr { code, message: message.into(), data: None }
    }
    fn params(message: impl Into<String>) -> Self {
        RpcErr::new(INVALID_PARAMS, message)
    }
    fn data(mut self, d: Value) -> Self {
        self.data = Some(d);
        self
    }
    pub fn response(&self, id: Value) -> Value {
        let mut e = json!({ "code": self.code, "message": self.message });
        if let Some(d) = &self.data {
            e["data"] = d.clone();
        }
        json!({ "jsonrpc": "2.0", "id": id, "error": e })
    }
}

pub(crate) fn rpc_error(id: Value, code: i32, message: impl Into<String>) -> Value {
    RpcErr::new(code, message).response(id)
}

fn unsupported_version(requested: &str) -> RpcErr {
    RpcErr::new(UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version")
        .data(json!({ "supported": supported_versions(), "requested": requested }))
}

// ---- logging ----------------------------------------------------------------------------------------

pub const LEVELS: [&str; 8] = ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"];

pub fn level_index(s: &str) -> Option<usize> {
    LEVELS.iter().position(|l| *l == s)
}

/// The MCP level of a relay `event` frame.
fn frame_level(frame: &Value) -> &'static str {
    match frame["level"].as_str() {
        Some("error") => "error",
        Some("warn") | Some("warning") => "warning",
        Some("debug") => "debug",
        _ => "info",
    }
}

// ---- state --------------------------------------------------------------------------------------------

/// Events of the MCP layer itself (relay frames arrive on the relay's own channel).
#[derive(Clone, Debug)]
pub(crate) enum McpEvent {
    ToolsChanged,
}

/// One MCP client: an initialize-based session, or a 2026-07-28 client keyed by its clientInfo.
pub(crate) struct Session {
    pub id: String,
    pub transport: String,
    pub ver: Ver,
    pub client: Value,
    pub caps: Value,
    /// minimum level for notifications/message (legacy `logging/setLevel`)
    pub level: Option<usize>,
    /// resources/subscribe URIs (legacy)
    pub subs: HashSet<String>,
    pub created: u64,
    pub last_seen: u64,
    pub calls: u64,
    pub last_call: Value,
    /// every open stream of this session holds a receiver; dropping the sender closes them
    close: watch::Sender<bool>,
}

/// An `input_required` approval waiting for the client's retry (2026-07-28 elicitation).
struct Mrtr {
    tool: String,
    args: String,
    expires: Instant,
}

pub(crate) struct McpState {
    sessions: Mutex<HashMap<String, Session>>,
    /// server-initiated requests (legacy elicitation/create) waiting for the client's response
    elicit: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    mrtr: Mutex<HashMap<String, Mrtr>>,
    /// in-flight requests by (connection key, JSON-RPC id), for notifications/cancelled
    inflight: Mutex<HashMap<(String, String), Inflight>>,
    fingerprint: Mutex<String>,
    pub(crate) events: broadcast::Sender<McpEvent>,
    next: AtomicU64,
    page_size: AtomicUsize,
}

struct Inflight {
    abort: tokio::task::AbortHandle,
    /// a backend job runs for it: send `cancel` when it is cancelled
    poke: bool,
}

/// Items per page of tools/list, prompts/list, resources/list and resources/templates/list. Large
/// enough that every list fits one page, so clients that ignore `nextCursor` still see every tool.
pub const DEFAULT_PAGE_SIZE: usize = 500;
/// Sessions kept (idle ones beyond this are dropped, oldest first).
const MAX_SESSIONS: usize = 64;
const MRTR_TTL: Duration = Duration::from_secs(300);
const ELICIT_TIMEOUT: Duration = Duration::from_secs(100);
/// Resources whose `notifications/resources/updated` the server sends.
pub const SUBSCRIBABLE: &[&str] = &["echodebug://status", "echodebug://target/modules"];
const APPROVE_KEY: &str = "echodebug_approval";

impl Default for McpState {
    fn default() -> Self {
        McpState {
            sessions: Mutex::new(HashMap::new()),
            elicit: Mutex::new(HashMap::new()),
            mrtr: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashMap::new()),
            fingerprint: Mutex::new(String::new()),
            events: broadcast::channel(64).0,
            next: AtomicU64::new(1),
            page_size: AtomicUsize::new(DEFAULT_PAGE_SIZE),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    if getrandom::fill(&mut b).is_err() {
        // never expected; fall back to something unique per process
        let n = now_ms() ^ (std::process::id() as u64) << 32;
        return format!("{n:016x}");
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Per-request context: the protocol version and what the client declared.
#[derive(Clone)]
pub(crate) struct Ctx {
    pub ver: Ver,
    /// key into the session table (legacy session id, or a modern client's key)
    pub session: Option<String>,
    pub caps: Value,
    /// minimum level of request-scoped notifications/message (None: send none)
    pub level: Option<usize>,
    /// the request's own stream (SSE response or stdio): progress, logs, elicitation requests
    pub out: Option<mpsc::UnboundedSender<Value>>,
    pub transport: &'static str,
    pub client: Value,
}

impl Ctx {
    pub fn new(ver: Ver, transport: &'static str) -> Ctx {
        Ctx { ver, session: None, caps: json!({}), level: None, out: None, transport, client: Value::Null }
    }

    fn log(&self, level: &str, logger: &str, data: Value) {
        let (Some(min), Some(out), Some(l)) = (self.level, &self.out, level_index(level)) else { return };
        if l >= min {
            let _ = out.send(json!({ "jsonrpc": "2.0", "method": "notifications/message", "params": { "level": level, "logger": logger, "data": data } }));
        }
    }
}

/// Whether the client can show a form elicitation (2025-06-18: `elicitation: {}`; 2025-11-25 and
/// later: `{}` or `{ form: {} }`).
pub fn elicit_form_supported(caps: &Value) -> bool {
    match caps.get("elicitation") {
        Some(Value::Object(m)) => m.is_empty() || m.contains_key("form") || !m.contains_key("url"),
        _ => false,
    }
}

// ---- small codecs -------------------------------------------------------------------------------------

fn hex_encode(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<String> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..s.len() / 2).map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()).collect();
    String::from_utf8(bytes?).ok()
}

pub(crate) fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::new();
    for c in s.chunks(4) {
        let mut n = 0u32;
        for (i, b) in c.iter().enumerate() {
            n |= val(*b)? << (18 - 6 * i);
        }
        match c.len() {
            4 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]),
            3 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]),
            2 => out.push((n >> 16) as u8),
            _ => return None,
        }
    }
    Some(out)
}

/// A header value as the client meant it: `=?base64?…?=` decoded, plain values as they are.
pub fn header_text(v: &str) -> Option<String> {
    match v.strip_prefix("=?base64?").and_then(|r| r.strip_suffix("?=")) {
        Some(b) => String::from_utf8(base64_decode(b)?).ok(),
        None => Some(v.to_owned()),
    }
}

/// How a client puts `s` into a header (`Mcp-Name`): plain when it is safe ASCII, else base64.
pub fn header_encode(s: &str) -> String {
    let safe = !s.is_empty()
        && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
        && !s.starts_with(' ')
        && !s.ends_with(' ')
        && !(s.starts_with("=?base64?") && s.ends_with("?="));
    if safe {
        s.to_owned()
    } else {
        format!("=?base64?{}?=", base64_encode(s.as_bytes()))
    }
}

/// The 2026-07-28 request headers: `MCP-Protocol-Version` equal to the `_meta` version,
/// `Mcp-Method` equal to the method, and `Mcp-Name` equal to `params.name` / `params.uri` on
/// tools/call, resources/read and prompts/get. Err: the HeaderMismatch message.
pub fn check_modern_headers(headers: &HeaderMap, method: &str, params: &Value, version: &str) -> Result<(), String> {
    let get = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(str::trim);
    match get("mcp-protocol-version") {
        None => return Err("missing MCP-Protocol-Version header".into()),
        Some(h) if h != version => return Err(format!("MCP-Protocol-Version header '{h}' does not match _meta protocolVersion '{version}'")),
        _ => {}
    }
    match get("mcp-method") {
        None => return Err("missing Mcp-Method header".into()),
        Some(h) if h != method => return Err(format!("Mcp-Method header '{h}' does not match body method '{method}'")),
        _ => {}
    }
    let named = match method {
        "tools/call" | "prompts/get" => params["name"].as_str(),
        "resources/read" => params["uri"].as_str(),
        _ => return Ok(()),
    };
    let Some(body) = named else { return Ok(()) };
    match get("mcp-name").map(header_text) {
        None => Err("missing Mcp-Name header".into()),
        Some(None) => Err("Mcp-Name header is not valid base64".into()),
        Some(Some(h)) if h != body => Err(format!("Mcp-Name header '{h}' does not match body value '{body}'")),
        _ => Ok(()),
    }
}

/// Methods each era knows (used for the 404 of an unknown 2026-07-28 method).
fn known_method(method: &str, modern: bool) -> bool {
    let common = ["ping", "server/discover", "tools/list", "tools/call", "prompts/list", "prompts/get", "resources/list", "resources/templates/list", "resources/read", "completion/complete"];
    common.contains(&method)
        || if modern {
            method == "subscriptions/listen"
        } else {
            matches!(method, "initialize" | "resources/subscribe" | "resources/unsubscribe" | "logging/setLevel")
        }
}

// ---- tool catalog ----------------------------------------------------------------------------------------

/// "read_memory" → "Read memory".
pub fn tool_title(name: &str) -> String {
    let mut t = name.replace('_', " ");
    if let Some(f) = t.get(0..1) {
        let up = f.to_uppercase();
        t.replace_range(0..1, &up);
    }
    t
}

/// One tools/list entry for `ver`: schema, annotations from the verb, title and outputSchema on
/// 2025-06-18 and later.
pub fn tool_entry(t: &Value, ver: Ver) -> Value {
    let verb = t["verb"].as_str().unwrap_or_default();
    let name = t["name"].as_str().unwrap_or_default();
    let title = tool_title(name);
    let mut e = json!({
        "name": name,
        "description": t["description"],
        "inputSchema": t["input_schema"],
        "annotations": mcp::annotations(verb, &title),
    });
    if ver.rich() {
        e["title"] = json!(title);
        e["outputSchema"] = mcp::output_schema(verb);
    }
    e
}

fn prompt_entry(p: &Value, ver: Ver) -> Value {
    let mut p = p.clone();
    if ver.rich() {
        p["title"] = json!(tool_title(p["name"].as_str().unwrap_or_default()));
    }
    p
}

fn resource_entry(r: &Value, ver: Ver) -> Value {
    let mut r = r.clone();
    if ver.rich() {
        r["title"] = r["name"].clone();
    }
    r
}

pub(crate) const INSTRUCTIONS: &str = "EchoDebug: reverse-engineering and memory-debugging tools for a live process (Echo's hypervisor-backed memory API on Windows, a local ptrace//proc backend on Linux). Call `status` first, then `attach` to a process (see `list_processes`) before reading or writing memory. Addresses are 0x-prefixed hex strings or module+0xRVA; byte payloads are lowercase hex. Tools whose annotations say readOnlyHint=false change EchoDebug's state or the target; writes may need the user's approval. `ui_*`-backed tools run in the EchoDebug app window and are listed only while it is open. See prompts/list for canned workflows and the echodebug:// resources for live status.";

fn capabilities() -> Value {
    json!({
        "tools": { "listChanged": true },
        "prompts": { "listChanged": false },
        "resources": { "subscribe": true, "listChanged": false },
        "logging": {},
        "completions": {},
    })
}

/// Maps one relay broadcast onto the MCP notifications it implies.
pub(crate) fn notifications_for(frame: &Value) -> Vec<Value> {
    let note = |method: &str, params: Value| json!({ "jsonrpc": "2.0", "method": method, "params": params });
    match (frame["type"].as_str(), frame["event"].as_str()) {
        (Some("status"), _) => vec![
            note("notifications/resources/updated", json!({ "uri": "echodebug://status" })),
            note("notifications/resources/updated", json!({ "uri": "echodebug://target/modules" })),
        ],
        (Some("event"), Some("progress")) => vec![],
        (Some("event"), Some(ev @ ("module_loaded" | "module_unloaded"))) => vec![
            note("notifications/resources/updated", json!({ "uri": "echodebug://target/modules" })),
            note("notifications/message", json!({ "level": "info", "logger": ev, "data": frame })),
        ],
        (Some("event"), Some(ev)) => vec![note("notifications/message", json!({ "level": frame_level(frame), "logger": ev, "data": frame }))],
        _ => vec![],
    }
}

fn tools_changed_note() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" })
}

// ---- the relay's MCP side ----------------------------------------------------------------------------------

enum Approval {
    Yes(&'static str),
    No(String),
    /// a 2026-07-28 `input_required` result to return as is
    Input(Value),
}

impl Relay {
    /// Builder: items per page on the list methods (tests use small pages to exercise cursors).
    pub fn with_mcp_page_size(self, n: usize) -> Self {
        self.0.mcp.page_size.store(n.max(1), Ordering::Relaxed);
        self
    }

    fn mcp_state(&self) -> &McpState {
        &self.0.mcp
    }

    fn server_info(&self, ver: Ver) -> Value {
        let mut i = json!({ "name": "echodebug", "version": self.0.app_version });
        if ver.rich() {
            i["title"] = json!("EchoDebug");
        }
        i
    }

    /// The tools a client can use right now: `ui_*` tools only while the app window is open, the
    /// thread tools not under the Echo backend, and nothing the policy always refuses.
    pub(crate) fn visible_tools(&self) -> Vec<&'static Value> {
        let policy = self.policy();
        let (provider, ext) = {
            let s = self.lock();
            (s.provider.is_some(), s.ext.is_some())
        };
        let tools: &'static [Value] = &TOOLS;
        tools
            .iter()
            .filter(|t| {
                let verb = t["verb"].as_str().unwrap_or_default();
                let name = t["name"].as_str().unwrap_or_default();
                if verb.starts_with(PROVIDER_PREFIX) && !provider {
                    return false;
                }
                if ext && matches!(verb, "threads" | "stack" | "handles") {
                    return false;
                }
                !matches!(mcp::decide(&policy, name, verb), mcp::Decision::Deny(_))
            })
            .collect()
    }

    /// Sends `notifications/tools/list_changed` when the visible tool set changed (app window,
    /// backend or policy).
    pub(crate) fn check_tools_changed(&self) {
        let names: Vec<&str> = self.visible_tools().iter().filter_map(|t| t["name"].as_str()).collect();
        let fp = names.join(",");
        let mut cur = lock(&self.mcp_state().fingerprint);
        if *cur != fp {
            let first = cur.is_empty();
            *cur = fp;
            drop(cur);
            if !first {
                let _ = self.mcp_state().events.send(McpEvent::ToolsChanged);
            }
        }
    }

    // ---- sessions ----

    fn new_session(&self, id: String, transport: &str, ver: Ver, client: Value, caps: Value) {
        let mut s = lock(&self.mcp_state().sessions);
        if s.len() >= MAX_SESSIONS {
            // drop the longest-idle sessions without an open stream
            let mut idle: Vec<(u64, String)> = s.values().filter(|x| x.close.receiver_count() == 0).map(|x| (x.last_seen, x.id.clone())).collect();
            idle.sort();
            for (_, k) in idle.into_iter().take(s.len() + 1 - MAX_SESSIONS) {
                s.remove(&k);
            }
        }
        let t = now_ms();
        s.insert(
            id.clone(),
            Session { id, transport: transport.to_owned(), ver, client, caps, level: None, subs: HashSet::new(), created: t, last_seen: t, calls: 0, last_call: Value::Null, close: watch::channel(false).0 },
        );
    }

    /// A legacy `initialize`: creates the session, returns its id and the result.
    pub(crate) fn initialize(&self, params: &Value, transport: &str) -> (String, Value) {
        let ver = negotiate(params["protocolVersion"].as_str());
        let id = random_hex(16);
        self.new_session(id.clone(), transport, ver, params["clientInfo"].clone(), params["capabilities"].clone());
        let result = json!({
            "protocolVersion": ver.as_str(),
            "capabilities": capabilities(),
            "serverInfo": self.server_info(ver),
            "instructions": INSTRUCTIONS,
        });
        (id, result)
    }

    /// The table entry of a 2026-07-28 client (created on its first request).
    pub(crate) fn touch_modern(&self, transport: &str, bridge: Option<&str>, meta: &Value, ver: Ver) -> String {
        let client = meta["io.modelcontextprotocol/clientInfo"].clone();
        let key = format!(
            "{}:{}:{}/{}",
            transport,
            bridge.unwrap_or("-"),
            client["name"].as_str().unwrap_or("client"),
            client["version"].as_str().unwrap_or("")
        );
        let caps = meta["io.modelcontextprotocol/clientCapabilities"].clone();
        let exists = {
            let mut s = lock(&self.mcp_state().sessions);
            match s.get_mut(&key) {
                Some(x) => {
                    x.last_seen = now_ms();
                    x.caps = caps.clone();
                    x.ver = ver;
                    true
                }
                None => false,
            }
        };
        if !exists {
            self.new_session(key.clone(), transport, ver, client, caps);
        }
        key
    }

    /// Context of a legacy request on session `id` (None: unknown or disconnected session).
    pub(crate) fn session_ctx(&self, id: &str, transport: &'static str) -> Option<Ctx> {
        let mut s = lock(&self.mcp_state().sessions);
        let x = s.get_mut(id)?;
        x.last_seen = now_ms();
        Some(Ctx { ver: x.ver, session: Some(id.to_owned()), caps: x.caps.clone(), level: None, out: None, transport, client: x.client.clone() })
    }

    fn session_close_rx(&self, id: &str) -> Option<watch::Receiver<bool>> {
        lock(&self.mcp_state().sessions).get(id).map(|x| x.close.subscribe())
    }

    fn record_call(&self, session: Option<&str>, tool: &str, outcome: &str) {
        let Some(id) = session else { return };
        if let Some(x) = lock(&self.mcp_state().sessions).get_mut(id) {
            x.calls += 1;
            x.last_seen = now_ms();
            x.last_call = json!({ "tool": tool, "ts": now_ms(), "outcome": outcome });
        }
    }

    /// The panel's connection list.
    pub(crate) fn sessions_json(&self) -> Value {
        let s = lock(&self.mcp_state().sessions);
        let mut list: Vec<Value> = s
            .values()
            .map(|x| {
                json!({
                    "id": x.id,
                    "transport": x.transport,
                    "era": if x.ver.modern() { "stateless" } else { "session" },
                    "protocolVersion": x.ver.as_str(),
                    "client": x.client,
                    "elicitation": elicit_form_supported(&x.caps),
                    "created": x.created,
                    "last_seen": x.last_seen,
                    "calls": x.calls,
                    "last_call": x.last_call,
                    "streams": x.close.receiver_count(),
                    "log_level": x.level.map(|l| LEVELS[l]),
                })
            })
            .collect();
        list.sort_by(|a, b| b["last_seen"].as_u64().cmp(&a["last_seen"].as_u64()));
        json!(list)
    }

    /// Ends a session: its streams close, its in-flight requests stop and a legacy session id
    /// gets 404 afterwards (the client must initialize again).
    pub(crate) fn disconnect(&self, id: &str) -> bool {
        let gone = lock(&self.mcp_state().sessions).remove(id);
        let Some(x) = gone else { return false };
        let _ = x.close.send(true);
        let mut inflight = lock(&self.mcp_state().inflight);
        inflight.retain(|(k, _), f| {
            if k == id {
                f.abort.abort();
                false
            } else {
                true
            }
        });
        true
    }

    fn set_session_level(&self, id: Option<&str>, level: usize) {
        if let Some(id) = id {
            if let Some(x) = lock(&self.mcp_state().sessions).get_mut(id) {
                x.level = Some(level);
            }
        }
    }

    fn set_subscription(&self, id: Option<&str>, uri: &str, on: bool) {
        let Some(id) = id else { return };
        if let Some(x) = lock(&self.mcp_state().sessions).get_mut(id) {
            if on {
                x.subs.insert(uri.to_owned());
            } else {
                x.subs.remove(uri);
            }
        }
    }

    // ---- in-flight requests ----

    fn track(&self, key: &str, id: &Value, abort: tokio::task::AbortHandle, poke: bool) {
        lock(&self.mcp_state().inflight).insert((key.to_owned(), id.to_string()), Inflight { abort, poke });
    }

    fn untrack(&self, key: &str, id: &Value) {
        lock(&self.mcp_state().inflight).remove(&(key.to_owned(), id.to_string()));
    }

    /// `notifications/cancelled` from connection `key`.
    pub(crate) fn cancel_request(&self, key: &str, request_id: &Value) -> bool {
        let f = lock(&self.mcp_state().inflight).remove(&(key.to_owned(), request_id.to_string()));
        match f {
            Some(f) => {
                f.abort.abort();
                if f.poke {
                    self.poke_cancel();
                }
                true
            }
            None => false,
        }
    }

    /// Stops the backend's running job (scans, pointer scans, emulation) after a cancelled call.
    fn poke_cancel(&self) {
        let relay = self.clone();
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(async move {
                let mut r = Map::new();
                r.insert("type".into(), json!("cancel"));
                let _ = relay.request(Value::Object(r)).await;
            });
        }
    }

    /// A client's response to one of our requests (legacy elicitation/create).
    pub(crate) fn resolve_client_response(&self, msg: &Value) -> bool {
        let Some(id) = msg["id"].as_str() else { return false };
        match lock(&self.mcp_state().elicit).remove(id) {
            Some(tx) => tx.send(msg.clone()).is_ok(),
            None => false,
        }
    }

    // ---- dispatch ----

    /// Handles one JSON-RPC request (`initialize` and `subscriptions/listen` are the transports'
    /// business). `None` when `msg` is not a request.
    pub(crate) async fn dispatch(&self, msg: &Value, ctx: &Ctx) -> Option<Value> {
        let id = msg.get("id").filter(|i| !i.is_null())?.clone();
        let method = msg["method"].as_str().unwrap_or_default();
        let params = match msg.get("params") {
            None | Some(Value::Null) => json!({}),
            Some(p @ Value::Object(_)) => p.clone(),
            Some(_) => return Some(rpc_error(id, INVALID_PARAMS, "params must be an object")),
        };
        Some(match self.method(method, &params, ctx).await {
            Ok(mut v) => {
                if ctx.ver.modern() {
                    if v.get("resultType").is_none() {
                        v["resultType"] = json!("complete");
                    }
                    v["_meta"]["io.modelcontextprotocol/serverInfo"] = self.server_info(ctx.ver);
                }
                json!({ "jsonrpc": "2.0", "id": id, "result": v })
            }
            Err(e) => e.response(id),
        })
    }

    async fn method(&self, method: &str, params: &Value, ctx: &Ctx) -> Result<Value, RpcErr> {
        let modern = ctx.ver.modern();
        let cache = |mut v: Value, ttl: u64, scope: &str| {
            if modern {
                v["ttlMs"] = json!(ttl);
                v["cacheScope"] = json!(scope);
            }
            v
        };
        match method {
            "ping" => Ok(json!({})),
            "server/discover" => Ok(json!({
                "resultType": "complete",
                "supportedVersions": supported_versions(),
                "capabilities": capabilities(),
                "instructions": INSTRUCTIONS,
                "_meta": { "io.modelcontextprotocol/serverInfo": self.server_info(LATEST) },
                "ttlMs": 60_000,
                "cacheScope": "private",
            })),
            "tools/list" => {
                let all: Vec<Value> = self.visible_tools().iter().map(|t| tool_entry(t, ctx.ver)).collect();
                let (items, next) = self.page("tools", all, params)?;
                Ok(cache(with_cursor(json!({ "tools": items }), next), 0, "private"))
            }
            "tools/call" => self.call_tool(params, ctx).await,
            "prompts/list" => {
                let all: Vec<Value> = PROMPTS.iter().map(|p| prompt_entry(p, ctx.ver)).collect();
                let (items, next) = self.page("prompts", all, params)?;
                Ok(cache(with_cursor(json!({ "prompts": items }), next), 3_600_000, "public"))
            }
            "prompts/get" => {
                let name = params["name"].as_str().ok_or_else(|| RpcErr::params("missing prompt name"))?;
                let p = PROMPTS.iter().find(|p| p["name"] == name).ok_or_else(|| RpcErr::params(format!("unknown prompt: {name}")))?;
                for a in p["arguments"].as_array().into_iter().flatten() {
                    let an = a["name"].as_str().unwrap_or_default();
                    if a["required"] == true && params["arguments"][an].as_str().is_none_or(str::is_empty) {
                        return Err(RpcErr::params(format!("prompt '{name}' needs the argument '{an}'")));
                    }
                }
                Ok(crate::prompt_messages(p, &params["arguments"]))
            }
            "resources/list" => {
                let all: Vec<Value> = RESOURCES.iter().map(|r| resource_entry(r, ctx.ver)).collect();
                let (items, next) = self.page("resources", all, params)?;
                Ok(cache(with_cursor(json!({ "resources": items }), next), 3_600_000, "public"))
            }
            "resources/templates/list" => {
                let all: Vec<Value> = mcp::templates().as_array().cloned().unwrap_or_default().iter().map(|r| resource_entry(r, ctx.ver)).collect();
                let (items, next) = self.page("templates", all, params)?;
                Ok(cache(with_cursor(json!({ "resourceTemplates": items }), next), 3_600_000, "public"))
            }
            "resources/read" => {
                let uri = params["uri"].as_str().ok_or_else(|| RpcErr::params("missing resource uri"))?;
                Ok(cache(self.read_resource(uri, ctx).await?, 0, "private"))
            }
            "completion/complete" => self.complete(params).await,
            "resources/subscribe" | "resources/unsubscribe" if !modern => {
                let uri = params["uri"].as_str().ok_or_else(|| RpcErr::params("missing resource uri"))?;
                self.set_subscription(ctx.session.as_deref(), uri, method == "resources/subscribe");
                Ok(json!({}))
            }
            "logging/setLevel" if !modern => {
                let level = params["level"].as_str().unwrap_or_default();
                let l = level_index(level).ok_or_else(|| RpcErr::params(format!("unknown log level '{level}' (one of {})", LEVELS.join(", "))))?;
                self.set_session_level(ctx.session.as_deref(), l);
                Ok(json!({}))
            }
            "subscriptions/listen" if modern => Err(RpcErr::new(INVALID_REQUEST, "subscriptions/listen needs a streaming response: send Accept: text/event-stream")),
            "initialize" if !modern => Err(RpcErr::new(INVALID_REQUEST, "initialize must not be batched")),
            _ => Err(RpcErr::new(METHOD_NOT_FOUND, format!("method not found: {method}"))),
        }
    }

    /// One page of a list (cursor: an opaque token naming the list and the offset).
    fn page(&self, list: &str, all: Vec<Value>, params: &Value) -> Result<(Vec<Value>, Option<String>), RpcErr> {
        let size = self.mcp_state().page_size.load(Ordering::Relaxed);
        let start = match params.get("cursor").filter(|c| !c.is_null()) {
            None => 0,
            Some(c) => {
                let bad = || RpcErr::params("invalid cursor");
                let s = hex_decode(c.as_str().ok_or_else(bad)?).ok_or_else(bad)?;
                let (l, off) = s.split_once(':').ok_or_else(bad)?;
                let off: usize = off.parse().map_err(|_| bad())?;
                if l != list || off > all.len() {
                    return Err(bad());
                }
                off
            }
        };
        let end = (start + size).min(all.len());
        let next = (end < all.len()).then(|| hex_encode(&format!("{list}:{end}")));
        Ok((all[start..end].to_vec(), next))
    }

    // ---- tools/call ----

    async fn call_tool(&self, params: &Value, ctx: &Ctx) -> Result<Value, RpcErr> {
        let name = params["name"].as_str().ok_or_else(|| RpcErr::params("missing tool name"))?;
        let tool = TOOLS.iter().find(|t| t["name"] == name).ok_or_else(|| RpcErr::params(format!("unknown tool: {name}")))?;
        let args = match params.get("arguments") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => return Err(RpcErr::params("arguments must be an object")),
        };
        let verb = tool["verb"].as_str().unwrap_or_default();
        let progress = params["_meta"]["progressToken"].clone();
        let t0 = Instant::now();
        let policy = self.policy();
        let missing: Vec<&str> = tool["input_schema"]["required"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|k| args.get(*k).is_none_or(Value::is_null))
            .collect();
        let mut outcome = "ok";
        let mut via = None;
        let reply = if !missing.is_empty() {
            outcome = "error";
            crate::error(Value::Null, 3002, &format!("missing required argument(s) for {name}: {}", missing.join(", ")))
        } else {
            match mcp::decide(&policy, name, verb) {
                mcp::Decision::Allow => self.run_tool(verb, &args, ctx, &progress).await,
                mcp::Decision::Deny(why) => {
                    outcome = "denied";
                    crate::error(Value::Null, 4003, &why)
                }
                mcp::Decision::Ask => match self.approve(name, verb, &args, params, ctx, &policy).await? {
                    Approval::Yes(how) => {
                        via = Some(how);
                        ctx.log("info", "policy", json!(format!("{name} approved in the {how}")));
                        self.run_tool(verb, &args, ctx, &progress).await
                    }
                    Approval::No(why) => {
                        outcome = "denied";
                        crate::error(Value::Null, 4003, &why)
                    }
                    Approval::Input(r) => return Ok(r),
                },
            }
        };
        let is_error = reply["type"] == "error";
        if is_error && outcome == "ok" {
            outcome = "error";
        }
        let entry = json!({
            "ts": now_ms(),
            "tool": name,
            "verb": verb,
            "args": crate::truncate_str(&serde_json::to_string(&args).unwrap_or_default(), 400),
            "ok": !is_error,
            "outcome": outcome,
            "ms": t0.elapsed().as_millis() as u64,
            "client": ctx.client["name"],
            "session": ctx.session,
            "transport": ctx.transport,
            "approved_via": via,
        });
        self.record_call(ctx.session.as_deref(), name, outcome);
        if policy.audit {
            let e = entry.clone();
            tokio::task::spawn_blocking(move || mcp::append_audit(&e));
        }
        {
            let mut log = lock(&self.0.mcp_log);
            if log.len() >= crate::MCP_LOG_CAP {
                log.pop_front();
            }
            log.push_back(entry);
        }
        Ok(tool_result(reply, verb, &args, ctx.ver))
    }

    /// Runs a verb for a tool call; while it runs, backend progress and events go to the call's
    /// stream when the client asked for them (progressToken, log level).
    async fn run_tool(&self, verb: &str, args: &Map<String, Value>, ctx: &Ctx, progress: &Value) -> Value {
        let mut req = args.clone();
        req.remove("id");
        req.insert("type".into(), json!(verb));
        let fwd = match &ctx.out {
            Some(out) if !progress.is_null() || ctx.level.is_some() => {
                let (out, token, level) = (out.clone(), progress.clone(), ctx.level);
                let mut events = self.0.events.subscribe();
                Some(tokio::spawn(async move {
                    let mut last = f64::MIN;
                    loop {
                        let text = match events.recv().await {
                            Ok(t) => t,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(_) => break,
                        };
                        let Ok(f) = serde_json::from_str::<Value>(&text) else { continue };
                        if f["type"] != "event" {
                            continue;
                        }
                        let n = if f["event"] == "progress" {
                            let done = f["done"].as_f64().unwrap_or(0.0);
                            if token.is_null() || done <= last {
                                continue;
                            }
                            last = done;
                            let mut p = json!({ "progressToken": token, "progress": done, "message": f["job"] });
                            if let Some(t) = f["total"].as_f64() {
                                p["total"] = json!(t);
                            }
                            json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": p })
                        } else {
                            let (Some(min), Some(l)) = (level, level_index(frame_level(&f))) else { continue };
                            if l < min {
                                continue;
                            }
                            json!({ "jsonrpc": "2.0", "method": "notifications/message", "params": { "level": frame_level(&f), "logger": f["event"], "data": f } })
                        };
                        if out.send(n).is_err() {
                            break;
                        }
                    }
                }))
            }
            _ => None,
        };
        ctx.log("debug", "echodebug", json!(format!("{verb}: request sent")));
        let r = self.request(Value::Object(req)).await;
        if let Some(f) = fwd {
            f.abort();
        }
        if r["type"] == "error" {
            ctx.log("warning", "echodebug", json!(format!("{verb}: {}", r["message"].as_str().unwrap_or("failed"))));
        }
        r
    }

    /// The "ask" policy for one call: an elicitation in the client (2026-07-28: an
    /// `input_required` result; earlier: an `elicitation/create` request on the call's stream) when
    /// the client supports form elicitation and the policy allows it, else the app window's dialog.
    async fn approve(&self, name: &str, verb: &str, args: &Map<String, Value>, params: &Value, ctx: &Ctx, policy: &mcp::Policy) -> Result<Approval, RpcErr> {
        let can_elicit = policy.elicit && ctx.ver.rich() && elicit_form_supported(&ctx.caps);
        let args_text = serde_json::to_string(args).unwrap_or_default();
        if can_elicit && ctx.ver.modern() {
            if let Some(state) = params.get("requestState").and_then(Value::as_str) {
                self.take_mrtr(state, name, &args_text)?;
                let resp = &params["inputResponses"][APPROVE_KEY];
                if resp.is_null() {
                    return Ok(Approval::Input(self.mrtr_request(name, verb, &args_text)));
                }
                return Ok(if accepted(resp) { Approval::Yes("MCP client (elicitation)") } else { Approval::No(format!("the user declined '{name}' in the MCP client")) });
            }
            return Ok(Approval::Input(self.mrtr_request(name, verb, &args_text)));
        }
        if can_elicit {
            if let Some(out) = &ctx.out {
                let id = format!("echodebug-elicit-{}", self.mcp_state().next.fetch_add(1, Ordering::Relaxed));
                let (tx, rx) = oneshot::channel();
                lock(&self.mcp_state().elicit).insert(id.clone(), tx);
                let mut p = elicit_params(name, verb, &args_text);
                if ctx.ver < Ver::V20251125 {
                    p.as_object_mut().map(|m| m.remove("mode"));
                }
                if out.send(json!({ "jsonrpc": "2.0", "id": id, "method": "elicitation/create", "params": p })).is_ok() {
                    let r = tokio::time::timeout(ELICIT_TIMEOUT, rx).await;
                    lock(&self.mcp_state().elicit).remove(&id);
                    return Ok(match r {
                        Ok(Ok(m)) if accepted(&m["result"]) => Approval::Yes("MCP client (elicitation)"),
                        Ok(Ok(m)) if m.get("error").is_some() => Approval::No(format!("'{name}' needs approval and the MCP client's elicitation failed: {}", m["error"]["message"].as_str().unwrap_or("error"))),
                        Ok(Ok(_)) => Approval::No(format!("the user declined '{name}' in the MCP client")),
                        _ => Approval::No(format!("'{name}' needs approval and the MCP client did not answer the elicitation in time")),
                    });
                }
                lock(&self.mcp_state().elicit).remove(&id);
            }
        }
        // the app window shows an approve/deny dialog; no window → refuse
        let mut ask = Map::new();
        ask.insert("type".into(), json!("ui_approve"));
        ask.insert("tool".into(), json!(name));
        ask.insert("verb".into(), json!(verb));
        ask.insert("arguments".into(), Value::Object(args.clone()));
        let r = self.request(Value::Object(ask)).await;
        Ok(if r["approved"] == true {
            Approval::Yes("EchoDebug window")
        } else if r["type"] == "error" {
            Approval::No(format!(
                "'{name}' needs approval in the EchoDebug window (policy: ask), which did not answer: {}. Open the EchoDebug app, or use a client that supports elicitation",
                r["message"].as_str().unwrap_or("no window")
            ))
        } else {
            Approval::No(format!("the user denied '{name}' in the EchoDebug window"))
        })
    }

    fn mrtr_request(&self, name: &str, verb: &str, args_text: &str) -> Value {
        let state = random_hex(16);
        let mut m = lock(&self.mcp_state().mrtr);
        m.retain(|_, x| x.expires > Instant::now());
        m.insert(state.clone(), Mrtr { tool: name.to_owned(), args: args_text.to_owned(), expires: Instant::now() + MRTR_TTL });
        json!({
            "resultType": "input_required",
            "inputRequests": { APPROVE_KEY: { "method": "elicitation/create", "params": elicit_params(name, verb, args_text) } },
            "requestState": state,
        })
    }

    /// Consumes a requestState: it must be one we issued, unexpired, for the same tool and arguments.
    fn take_mrtr(&self, state: &str, name: &str, args_text: &str) -> Result<(), RpcErr> {
        let x = lock(&self.mcp_state().mrtr).remove(state);
        match x {
            Some(x) if x.expires > Instant::now() && x.tool == name && x.args == args_text => Ok(()),
            Some(_) => Err(RpcErr::params("requestState does not match this call (tool or arguments changed, or it expired); call the tool again")),
            None => Err(RpcErr::params("unknown or already used requestState; call the tool again")),
        }
    }

    // ---- resources, completion ----

    async fn read_resource(&self, uri: &str, ctx: &Ctx) -> Result<Value, RpcErr> {
        let not_found = || {
            let code = if ctx.ver.modern() { INVALID_PARAMS } else { RESOURCE_NOT_FOUND_LEGACY };
            RpcErr::new(code, format!("unknown resource: {uri}")).data(json!({ "uri": uri }))
        };
        let body = match uri {
            "echodebug://status" => Value::Object(self.status("status")),
            "echodebug://tools" => json!({ "tools": TOOLS.iter().map(|t| json!({
                "name": t["name"], "verb": t["verb"], "description": t["description"], "inputSchema": t["input_schema"],
            })).collect::<Vec<_>>() }),
            "echodebug://mcp/log" => {
                let entries: Vec<Value> = lock(&self.0.mcp_log).iter().cloned().collect();
                json!({ "entries": entries })
            }
            other => {
                let req = if other == "echodebug://target/modules" {
                    let mut m = Map::new();
                    m.insert("type".into(), json!("modules"));
                    m
                } else {
                    mcp::template_request(other).ok_or_else(not_found)?
                };
                let mut r = self.request(Value::Object(req)).await;
                if r["type"] == "error" {
                    return Err(RpcErr::new(INTERNAL_ERROR, format!("{uri}: {}", r["message"].as_str().unwrap_or("request failed"))).data(json!({ "uri": uri, "code": r["code"] })));
                }
                if let Some(m) = r.as_object_mut() {
                    m.remove("type");
                    m.remove("id");
                }
                r
            }
        };
        Ok(json!({ "contents": [{ "uri": uri, "mimeType": "application/json", "text": serde_json::to_string_pretty(&body).unwrap_or_default() }] }))
    }

    /// completion/complete for prompt and resource-template arguments.
    async fn complete(&self, params: &Value) -> Result<Value, RpcErr> {
        if !params["ref"].is_object() || !params["argument"].is_object() {
            return Err(RpcErr::params("completion/complete needs 'ref' and 'argument'"));
        }
        let arg = params["argument"]["name"].as_str().unwrap_or_default();
        let prefix = params["argument"]["value"].as_str().unwrap_or_default();
        let strings = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let values: Vec<String> = match mcp::completion_kind(arg) {
            Some("value_type") => strings(mcp::VALUE_TYPES),
            Some("format") => strings(&["cpp", "c", "ida", "ghidra", "binja", "reclass"]),
            Some("module") => self.module_names().await,
            Some("address") => {
                // named addresses from the app window, then module names (module+0x… is accepted everywhere)
                let mut out = Vec::new();
                let mut req = Map::new();
                req.insert("type".into(), json!("ui_names"));
                let r = self.request(Value::Object(req)).await;
                if let Some(list) = r["names"].as_array() {
                    out.extend(list.iter().filter_map(|n| n["name"].as_str().map(str::to_owned)));
                }
                out.extend(self.module_names().await.into_iter().map(|m| format!("{m}+0x")));
                out
            }
            _ => Vec::new(),
        };
        Ok(mcp::rank(values, prefix))
    }

    async fn module_names(&self) -> Vec<String> {
        let mut req = Map::new();
        req.insert("type".into(), json!("modules"));
        let r = self.request(Value::Object(req)).await;
        r["modules"].as_array().map(|a| a.iter().filter_map(|m| m["name"].as_str().map(str::to_owned)).collect()).unwrap_or_default()
    }

    /// The MCP panel's "test this tool": the same call an MCP client makes (policy, approval,
    /// result shape of the latest revision), logged as the panel.
    pub(crate) async fn test_call(&self, name: &str, args: &Value) -> Value {
        let mut ctx = Ctx::new(LATEST, "panel");
        ctx.client = json!({ "name": "EchoDebug MCP panel" });
        let t0 = Instant::now();
        let params = json!({ "name": name, "arguments": args });
        match self.call_tool(&params, &ctx).await {
            Ok(r) => json!({ "type": "mcp_test_call_result", "success": true, "result": r, "ms": t0.elapsed().as_millis() as u64 }),
            Err(e) => crate::error(Value::Null, 2000, &e.message),
        }
    }

    // ---- notification streams ----

    /// A legacy `GET /mcp` stream (or a legacy stdio session): resource updates, tool list changes
    /// and log messages, filtered by the session's subscriptions and log level.
    /// (Subscribes before it returns, so nothing between the call and the first poll is lost.)
    pub(crate) fn legacy_events(self, session: Option<String>, out: mpsc::UnboundedSender<Value>) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut frames = self.0.events.subscribe();
        let mut mcp_ev = self.mcp_state().events.subscribe();
        let close = session.as_deref().map(|id| self.session_close_rx(id));
        async move {
        let mut close = match close {
            Some(Some(rx)) => Some(rx),
            Some(None) => return,
            None => None,
        };
        loop {
            let note = tokio::select! {
                f = frames.recv() => match f {
                    Ok(text) => serde_json::from_str::<Value>(&text).map(|f| notifications_for(&f)).unwrap_or_default(),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                },
                e = mcp_ev.recv() => match e {
                    Ok(McpEvent::ToolsChanged) => vec![tools_changed_note()],
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                },
                _ = closed(&mut close) => return,
                _ = out.closed() => return,
            };
            for n in note {
                if self.legacy_wants(session.as_deref(), &n) && out.send(n).is_err() {
                    return;
                }
            }
        }
        }
    }

    fn legacy_wants(&self, session: Option<&str>, n: &Value) -> bool {
        let Some(id) = session else { return true };
        let s = lock(&self.mcp_state().sessions);
        let Some(x) = s.get(id) else { return false };
        match n["method"].as_str() {
            Some("notifications/resources/updated") => x.subs.contains(n["params"]["uri"].as_str().unwrap_or_default()),
            Some("notifications/message") => level_index(n["params"]["level"].as_str().unwrap_or("info")).unwrap_or(1) >= x.level.unwrap_or(1),
            _ => true,
        }
    }

    /// A 2026-07-28 `subscriptions/listen`: the acknowledgement, then the notifications the
    /// filter asked for, each tagged with the subscription id, until the client goes away or the
    /// session is disconnected (then a graceful closing result).
    pub(crate) fn listen(self, id: Value, filter: Value, session: Option<String>, out: mpsc::UnboundedSender<Value>) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut frames = self.0.events.subscribe();
        let mut mcp_ev = self.mcp_state().events.subscribe();
        let mut close = session.as_deref().and_then(|s| self.session_close_rx(s));
        async move {
        let tools = filter["toolsListChanged"] == true;
        let subs: Vec<String> = filter["resourceSubscriptions"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|u| SUBSCRIBABLE.contains(u)).map(str::to_owned).collect();
        let mut agreed = Map::new();
        if tools {
            agreed.insert("toolsListChanged".into(), json!(true));
        }
        if filter.get("resourceSubscriptions").is_some() {
            agreed.insert("resourceSubscriptions".into(), json!(subs));
        }
        let meta = json!({ "io.modelcontextprotocol/subscriptionId": id });
        let _ = out.send(json!({ "jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged", "params": { "_meta": meta, "notifications": agreed } }));
        loop {
            let notes = tokio::select! {
                f = frames.recv() => match f {
                    Ok(text) => serde_json::from_str::<Value>(&text).map(|f| notifications_for(&f)).unwrap_or_default(),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                },
                e = mcp_ev.recv() => match e {
                    Ok(McpEvent::ToolsChanged) if tools => vec![tools_changed_note()],
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                },
                _ = closed(&mut close) => {
                    let _ = out.send(json!({ "jsonrpc": "2.0", "id": id, "result": { "resultType": "complete", "_meta": { "io.modelcontextprotocol/subscriptionId": id, "io.modelcontextprotocol/serverInfo": self.server_info(LATEST) } } }));
                    return;
                }
                _ = out.closed() => return,
            };
            for mut n in notes {
                let keep = match n["method"].as_str() {
                    Some("notifications/resources/updated") => subs.iter().any(|u| n["params"]["uri"] == *u.as_str()),
                    Some("notifications/tools/list_changed") => true,
                    _ => false, // log messages belong to requests, never to the listen stream
                };
                if !keep {
                    continue;
                }
                n["params"]["_meta"] = meta.clone();
                if out.send(n).is_err() {
                    return;
                }
            }
        }
        }
    }
}

/// Resolves when the session's close channel fires or its sender is dropped; never without one.
async fn closed(rx: &mut Option<watch::Receiver<bool>>) {
    match rx {
        Some(rx) => loop {
            if *rx.borrow() || rx.changed().await.is_err() {
                return;
            }
        },
        None => std::future::pending().await,
    }
}

fn with_cursor(mut v: Value, next: Option<String>) -> Value {
    if let Some(n) = next {
        v["nextCursor"] = json!(n);
    }
    v
}

fn accepted(r: &Value) -> bool {
    r["action"] == "accept" && r["content"]["allow"] == true
}

fn elicit_params(name: &str, verb: &str, args_text: &str) -> Value {
    json!({
        "mode": "form",
        "message": format!(
            "EchoDebug: allow '{name}' ({verb})? It changes the target process or writes a file. Arguments: {}",
            crate::truncate_str(args_text, 600)
        ),
        "requestedSchema": {
            "type": "object",
            "properties": {
                "allow": { "type": "boolean", "title": "Allow this call", "description": format!("Run {name} now (the MCP policy is set to ask)"), "default": false }
            },
            "required": ["allow"]
        }
    })
}

/// A CallToolResult: the reply as JSON text, plus `structuredContent` and resource links on
/// 2025-06-18 and later.
pub(crate) fn tool_result(mut reply: Value, verb: &str, args: &Map<String, Value>, ver: Ver) -> Value {
    let is_error = reply["type"] == "error";
    if let Some(m) = reply.as_object_mut() {
        m.remove("type");
        m.remove("id");
    }
    let text = serde_json::to_string_pretty(&reply).unwrap_or_default();
    let mut content = vec![json!({ "type": "text", "text": text })];
    let mut out = json!({ "isError": is_error });
    if ver.rich() {
        if !is_error {
            content.extend(mcp::resource_links(verb, args, &reply));
        }
        out["structuredContent"] = reply;
    }
    out["content"] = json!(content);
    out
}

// ---- HTTP -----------------------------------------------------------------------------------------------------

fn wants_sse(headers: &HeaderMap) -> bool {
    headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("text/event-stream"))
}

fn hget<'a>(headers: &'a HeaderMap, k: &str) -> Option<&'a str> {
    headers.get(k).and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty())
}

fn json_status(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

/// Origin and token checks for every `/mcp` request, with errors that say what to fix.
fn guard(relay: &Relay, headers: &HeaderMap, query: Option<&str>) -> Option<Response> {
    if !crate::origin_allowed(headers) {
        let body = json!({ "jsonrpc": "2.0", "error": { "code": INVALID_REQUEST, "message": "requests from web pages are refused (Origin is not the EchoDebug app or localhost)" } });
        return Some(json_status(StatusCode::FORBIDDEN, body));
    }
    let want = relay.token();
    if auth::authorized(want.as_deref(), headers, query) {
        return None;
    }
    let message = match auth::presented(headers, query) {
        None => "EchoDebug needs its relay token: send 'Authorization: Bearer <token>'. Copy it (or a ready-made client config) from EchoDebug → MCP Server → Connect a client. stdio clients (echodebug-relay --stdio) need no token.",
        Some(_) => "The relay token is wrong or was regenerated. Copy the current one from EchoDebug → MCP Server → Connect a client and update this client's configuration.",
    };
    let body = json!({ "jsonrpc": "2.0", "error": { "code": UNAUTHORIZED, "message": message } });
    let mut r = json_status(StatusCode::UNAUTHORIZED, body);
    let challenge = if auth::presented(headers, query).is_some() { r#"Bearer realm="EchoDebug", error="invalid_token""# } else { r#"Bearer realm="EchoDebug""# };
    r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
    Some(r)
}

/// Connection key for cancellation: the legacy session, else the stdio bridge's id.
fn conn_key(headers: &HeaderMap) -> Option<String> {
    hget(headers, "mcp-session-id").map(|s| format!("s:{s}")).or_else(|| hget(headers, "x-echodebug-bridge").map(|b| format!("b:{b}")))
}

fn http_transport(headers: &HeaderMap) -> &'static str {
    if hget(headers, "x-echodebug-transport") == Some("stdio") {
        "stdio (bridged)"
    } else {
        "http"
    }
}

/// Aborts the request's task when its response stream is dropped (the client closed it: a
/// cancellation in 2026-07-28), and stops the backend job behind it.
struct AbortOnDrop {
    handle: tokio::task::AbortHandle,
    poke: Option<Relay>,
    done: Arc<AtomicBool>,
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if !self.done.load(Ordering::Relaxed) {
            self.handle.abort();
            if let Some(r) = &self.poke {
                r.poke_cancel();
            }
        }
    }
}

fn sse_response(rx: mpsc::UnboundedReceiver<Value>, guard: Option<AbortOnDrop>) -> Response {
    let stream = futures_util::stream::unfold((rx, guard), |(mut rx, guard)| async move {
        let v = rx.recv().await?;
        let ev: Result<Event, Infallible> = Ok(Event::default().event("message").data(v.to_string()));
        Some((ev, (rx, guard)))
    });
    let mut r = Sse::new(stream).keep_alive(KeepAlive::default()).into_response();
    r.headers_mut().insert("x-accel-buffering", HeaderValue::from_static("no"));
    r
}

fn is_backend_call(msg: &Value) -> bool {
    msg["method"] == "tools/call"
        && TOOLS.iter().find(|t| t["name"] == msg["params"]["name"]).and_then(|t| t["verb"].as_str()).is_some_and(|v| !v.starts_with(PROVIDER_PREFIX))
}

/// Whether a legacy tools/call may need an elicitation (so it must answer as a stream).
fn may_elicit(relay: &Relay, msg: &Value, ctx: &Ctx) -> bool {
    // 2026-07-28 elicits with an input_required result instead
    if msg["method"] != "tools/call" || !ctx.ver.rich() || ctx.ver.modern() || !elicit_form_supported(&ctx.caps) {
        return false;
    }
    let policy = relay.policy();
    let name = msg["params"]["name"].as_str().unwrap_or_default();
    let Some(verb) = TOOLS.iter().find(|t| t["name"] == name).and_then(|t| t["verb"].as_str()) else { return false };
    policy.elicit && mcp::decide(&policy, name, verb) == mcp::Decision::Ask
}

enum Shape {
    Request,
    Notification,
    Response,
    Invalid(&'static str),
}

fn shape(msg: &Value) -> Shape {
    let Some(m) = msg.as_object() else { return Shape::Invalid("a JSON-RPC message must be an object") };
    if m.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Shape::Invalid("missing \"jsonrpc\": \"2.0\"");
    }
    match (m.get("method"), m.get("id")) {
        (Some(Value::String(_)), None) => Shape::Notification,
        (Some(Value::String(_)), Some(Value::String(_) | Value::Number(_))) => Shape::Request,
        (Some(Value::String(_)), Some(_)) => Shape::Invalid("request id must be a string or an integer"),
        (Some(_), _) => Shape::Invalid("method must be a string"),
        (None, Some(_)) if m.contains_key("result") || m.contains_key("error") => Shape::Response,
        _ => Shape::Invalid("not a request, notification or response"),
    }
}

impl Relay {
    /// A notification from a client on connection `key`.
    pub(crate) fn on_notification(&self, msg: &Value, key: Option<&str>, session: Option<&str>) {
        match msg["method"].as_str() {
            Some("notifications/cancelled") => {
                if let Some(k) = key {
                    self.cancel_request(k, &msg["params"]["requestId"]);
                }
            }
            Some("notifications/initialized") => {
                if let Some(s) = session {
                    if let Some(x) = lock(&self.mcp_state().sessions).get_mut(s) {
                        x.last_seen = now_ms();
                    }
                }
            }
            _ => {}
        }
    }
}

/// `POST /mcp`.
pub(crate) async fn post(State(relay): State<Relay>, headers: HeaderMap, RawQuery(query): RawQuery, body: Bytes) -> Response {
    if let Some(r) = guard(&relay, &headers, query.as_deref()) {
        return r;
    }
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return json_status(StatusCode::BAD_REQUEST, rpc_error(Value::Null, PARSE_ERROR, format!("parse error: {e}"))),
    };
    let transport = http_transport(&headers);
    let key = conn_key(&headers);
    let session_hdr = hget(&headers, "mcp-session-id").map(str::to_owned);
    if let Value::Array(batch) = msg {
        return post_batch(relay, &headers, batch, session_hdr, key, transport).await;
    }
    match shape(&msg) {
        Shape::Invalid(why) => return json_status(StatusCode::BAD_REQUEST, rpc_error(msg.get("id").cloned().unwrap_or(Value::Null), INVALID_REQUEST, why)),
        Shape::Response => {
            relay.resolve_client_response(&msg);
            return StatusCode::ACCEPTED.into_response();
        }
        Shape::Notification => {
            relay.on_notification(&msg, key.as_deref(), session_hdr.as_deref());
            return StatusCode::ACCEPTED.into_response();
        }
        Shape::Request => {}
    }
    let id = msg["id"].clone();
    let method = msg["method"].as_str().unwrap_or_default().to_owned();
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let meta = &params["_meta"];
    let ctx = if let Some(v) = meta.get("io.modelcontextprotocol/protocolVersion") {
        // 2026-07-28: stateless, everything is in the request
        let vs = v.as_str().unwrap_or_default();
        let Some(ver) = Ver::parse(vs).filter(|v| v.modern()) else {
            return json_status(StatusCode::BAD_REQUEST, unsupported_version(vs).response(id));
        };
        if let Err(why) = check_modern_headers(&headers, &method, &params, vs) {
            return json_status(StatusCode::BAD_REQUEST, rpc_error(id, HEADER_MISMATCH, format!("Header mismatch: {why}")));
        }
        if !meta["io.modelcontextprotocol/clientCapabilities"].is_object() {
            return json_status(StatusCode::BAD_REQUEST, rpc_error(id, INVALID_PARAMS, "missing _meta io.modelcontextprotocol/clientCapabilities"));
        }
        if !known_method(&method, true) {
            return json_status(StatusCode::NOT_FOUND, rpc_error(id, METHOD_NOT_FOUND, format!("method not found: {method}")));
        }
        let level = meta["io.modelcontextprotocol/logLevel"].as_str().map(|l| level_index(l).ok_or(l));
        let level = match level {
            Some(Err(l)) => return json_status(StatusCode::BAD_REQUEST, rpc_error(id, INVALID_PARAMS, format!("unknown log level '{l}'"))),
            Some(Ok(l)) => Some(l),
            None => None,
        };
        let session = relay.touch_modern(transport, hget(&headers, "x-echodebug-bridge"), meta, ver);
        Ctx {
            ver,
            session: Some(session),
            caps: meta["io.modelcontextprotocol/clientCapabilities"].clone(),
            level,
            out: None,
            transport,
            client: meta["io.modelcontextprotocol/clientInfo"].clone(),
        }
    } else if method == "initialize" {
        let (sid, result) = relay.initialize(&params, transport);
        let mut r = Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response();
        if let Ok(v) = HeaderValue::from_str(&sid) {
            r.headers_mut().insert("mcp-session-id", v);
        }
        return r;
    } else {
        let hdr_ver = hget(&headers, "mcp-protocol-version");
        if let Some(h) = hdr_ver {
            match Ver::parse(h) {
                Some(v) if v.modern() => return json_status(StatusCode::BAD_REQUEST, rpc_error(id, INVALID_PARAMS, "protocol 2026-07-28 requests must carry _meta io.modelcontextprotocol/protocolVersion")),
                Some(_) => {}
                None if method == "server/discover" => {}
                None => return json_status(StatusCode::BAD_REQUEST, unsupported_version(h).response(id)),
            }
        }
        match &session_hdr {
            Some(sid) => match relay.session_ctx(sid, transport) {
                Some(c) => c,
                None => return json_status(StatusCode::NOT_FOUND, rpc_error(id, SESSION_NOT_FOUND, "session not found (it ended or was disconnected in EchoDebug); initialize again")),
            },
            // sessionless: the header's version, else 2025-03-26 (the spec's default for no header)
            None => Ctx::new(hdr_ver.and_then(Ver::parse).filter(|v| !v.modern()).unwrap_or(Ver::V20250326), transport),
        }
    };
    let sse = wants_sse(&headers);
    if method == "subscriptions/listen" {
        if !sse {
            return json_status(StatusCode::BAD_REQUEST, rpc_error(id, INVALID_REQUEST, "subscriptions/listen needs Accept: text/event-stream"));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(relay.clone().listen(id.clone(), params["notifications"].clone(), ctx.session.clone(), tx));
        let done = Arc::new(AtomicBool::new(false));
        if let Some(k) = &key {
            relay.track(k, &id, task.abort_handle(), false);
        }
        return sse_response(rx, Some(AbortOnDrop { handle: task.abort_handle(), poke: None, done }));
    }
    let progress = !params["_meta"]["progressToken"].is_null();
    let stream = sse && (progress || may_elicit(&relay, &msg, &ctx) || (ctx.ver.modern() && ctx.level.is_some() && method == "tools/call"));
    let poke = is_backend_call(&msg);
    if stream {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut ctx = ctx;
        ctx.out = Some(tx.clone());
        let done = Arc::new(AtomicBool::new(false));
        let (relay2, done2, key2, id2) = (relay.clone(), done.clone(), key.clone(), id.clone());
        let task = tokio::spawn(async move {
            let reply = relay2.dispatch(&msg, &ctx).await;
            done2.store(true, Ordering::Relaxed);
            if let Some(k) = &key2 {
                relay2.untrack(k, &id2);
            }
            drop(ctx);
            if let Some(r) = reply {
                let _ = tx.send(r);
            }
        });
        if let Some(k) = &key {
            relay.track(k, &id, task.abort_handle(), poke);
        }
        let guard = AbortOnDrop { handle: task.abort_handle(), poke: poke.then(|| relay.clone()), done };
        return sse_response(rx, Some(guard));
    }
    // a plain JSON answer; still cancellable with notifications/cancelled
    let relay2 = relay.clone();
    let task = tokio::spawn(async move { relay2.dispatch(&msg, &ctx).await });
    if let Some(k) = &key {
        relay.track(k, &id, task.abort_handle(), poke);
    }
    let done = Arc::new(AtomicBool::new(false));
    let _guard = AbortOnDrop { handle: task.abort_handle(), poke: poke.then(|| relay.clone()), done: done.clone() };
    let reply = task.await;
    done.store(true, Ordering::Relaxed);
    if let Some(k) = &key {
        relay.untrack(k, &id);
    }
    match reply {
        Ok(Some(r)) => Json(r).into_response(),
        Ok(None) => StatusCode::ACCEPTED.into_response(),
        // cancelled by the client: nobody reads this
        Err(_) => StatusCode::NO_CONTENT.into_response(),
    }
}

/// A JSON-RPC batch (2025-03-26 and earlier; later revisions send single messages).
async fn post_batch(relay: Relay, headers: &HeaderMap, batch: Vec<Value>, session_hdr: Option<String>, key: Option<String>, transport: &'static str) -> Response {
    if batch.is_empty() {
        return json_status(StatusCode::BAD_REQUEST, rpc_error(Value::Null, INVALID_REQUEST, "empty batch"));
    }
    let ctx = match &session_hdr {
        Some(sid) => match relay.session_ctx(sid, transport) {
            Some(c) => c,
            None => return json_status(StatusCode::NOT_FOUND, rpc_error(Value::Null, SESSION_NOT_FOUND, "session not found; initialize again")),
        },
        None => Ctx::new(hget(headers, "mcp-protocol-version").and_then(Ver::parse).filter(|v| !v.modern()).unwrap_or(Ver::V20250326), transport),
    };
    let mut replies = Vec::new();
    let mut calls = Vec::new();
    for m in batch {
        match shape(&m) {
            Shape::Invalid(why) => replies.push(rpc_error(m.get("id").cloned().unwrap_or(Value::Null), INVALID_REQUEST, why)),
            Shape::Response => {
                relay.resolve_client_response(&m);
            }
            Shape::Notification => relay.on_notification(&m, key.as_deref(), session_hdr.as_deref()),
            Shape::Request if m["params"]["_meta"].get("io.modelcontextprotocol/protocolVersion").is_some() => {
                replies.push(rpc_error(m["id"].clone(), INVALID_REQUEST, "batches are not part of protocol 2026-07-28; send one message per request"))
            }
            Shape::Request => calls.push(m),
        }
    }
    let done = futures_util::future::join_all(calls.iter().map(|m| relay.dispatch(m, &ctx))).await;
    replies.extend(done.into_iter().flatten());
    if replies.is_empty() {
        StatusCode::ACCEPTED.into_response()
    } else {
        Json(Value::Array(replies)).into_response()
    }
}

/// `GET /mcp`: the legacy event stream (`Accept: text/event-stream`), for a session when the
/// request names one.
pub(crate) async fn get(State(relay): State<Relay>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    if let Some(r) = guard(&relay, &headers, query.as_deref()) {
        return r;
    }
    if !wants_sse(&headers) {
        let mut r = json_status(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({ "error": "GET /mcp is the notification stream of initialize-based sessions (send Accept: text/event-stream). JSON-RPC goes to POST /mcp; a health probe is GET /mcp/health." }),
        );
        r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, POST, DELETE"));
        return r;
    }
    let session = hget(&headers, "mcp-session-id").map(str::to_owned);
    if let Some(s) = &session {
        if relay.session_ctx(s, "http").is_none() {
            return json_status(StatusCode::NOT_FOUND, rpc_error(Value::Null, SESSION_NOT_FOUND, "session not found; initialize again"));
        }
    }
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(relay.clone().legacy_events(session, tx));
    sse_response(rx, Some(AbortOnDrop { handle: task.abort_handle(), poke: None, done: Arc::new(AtomicBool::new(false)) }))
}

/// `DELETE /mcp` with `Mcp-Session-Id`: the client ends its session.
pub(crate) async fn delete(State(relay): State<Relay>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    if let Some(r) = guard(&relay, &headers, query.as_deref()) {
        return r;
    }
    match hget(&headers, "mcp-session-id") {
        Some(s) if relay.disconnect(s) => StatusCode::NO_CONTENT.into_response(),
        Some(_) => StatusCode::NOT_FOUND.into_response(),
        None => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// `GET /mcp/health`: for clients and scripts that probe before connecting. No token needed; it
/// says whether a presented token is right.
pub(crate) async fn health(State(relay): State<Relay>, headers: HeaderMap, RawQuery(query): RawQuery) -> Response {
    if !crate::origin_allowed(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let want = relay.token();
    let authorized = match (&want, auth::presented(&headers, query.as_deref())) {
        (None, _) => json!(true),
        (Some(_), None) => Value::Null,
        (Some(w), Some(p)) => json!(auth::eq(&p, w)),
    };
    let st = relay.status("status");
    Json(json!({
        "ok": true,
        "server": "echodebug",
        "version": relay.0.app_version,
        "endpoint": "/mcp",
        "protocolVersions": supported_versions(),
        "latest": LATEST.as_str(),
        "transports": ["streamable-http", "stdio"],
        "auth": if want.is_some() { "bearer" } else { "none" },
        "authorized": authorized,
        "appWindow": st["provider"],
        "backend": st["backend"],
        "tools": relay.visible_tools().len(),
    }))
    .into_response()
}

// ---- stdio ------------------------------------------------------------------------------------------------------

/// One stdio connection served by this process (embedded relay).
struct StdioConn {
    relay: Relay,
    out: mpsc::UnboundedSender<Value>,
    session: Mutex<Option<String>>,
    inflight: Mutex<HashMap<String, (tokio::task::AbortHandle, bool)>>,
}

impl StdioConn {
    fn send(&self, v: Value) {
        let _ = self.out.send(v);
    }

    async fn handle(self: &Arc<Self>, msg: Value) {
        if let Value::Array(batch) = msg {
            let mut replies = Vec::new();
            for m in batch {
                if let Some(r) = Box::pin(self.one(m, false)).await {
                    replies.push(r);
                }
            }
            if !replies.is_empty() {
                self.send(Value::Array(replies));
            }
            return;
        }
        if let Some(r) = self.one(msg, true).await {
            self.send(r);
        }
    }

    /// Handles one message. `spawn`: run requests as their own task (cancellable, replies written
    /// when done); otherwise answer inline (batches).
    async fn one(self: &Arc<Self>, msg: Value, spawn: bool) -> Option<Value> {
        match shape(&msg) {
            Shape::Invalid(why) => return Some(rpc_error(msg.get("id").cloned().unwrap_or(Value::Null), INVALID_REQUEST, why)),
            Shape::Response => {
                self.relay.resolve_client_response(&msg);
                return None;
            }
            Shape::Notification => {
                if msg["method"] == "notifications/cancelled" {
                    let rid = msg["params"]["requestId"].to_string();
                    if let Some((h, poke)) = lock(&self.inflight).remove(&rid) {
                        h.abort();
                        if poke {
                            self.relay.poke_cancel();
                        }
                    }
                }
                return None;
            }
            Shape::Request => {}
        }
        let id = msg["id"].clone();
        let method = msg["method"].as_str().unwrap_or_default().to_owned();
        let params = msg.get("params").cloned().unwrap_or(json!({}));
        let meta = &params["_meta"];
        let mut ctx = if let Some(v) = meta.get("io.modelcontextprotocol/protocolVersion") {
            let vs = v.as_str().unwrap_or_default();
            let Some(ver) = Ver::parse(vs).filter(|v| v.modern()) else { return Some(unsupported_version(vs).response(id)) };
            if !meta["io.modelcontextprotocol/clientCapabilities"].is_object() {
                return Some(rpc_error(id, INVALID_PARAMS, "missing _meta io.modelcontextprotocol/clientCapabilities"));
            }
            let level = meta["io.modelcontextprotocol/logLevel"].as_str().and_then(level_index);
            let session = self.relay.touch_modern("stdio", None, meta, ver);
            Ctx { ver, session: Some(session), caps: meta["io.modelcontextprotocol/clientCapabilities"].clone(), level, out: None, transport: "stdio", client: meta["io.modelcontextprotocol/clientInfo"].clone() }
        } else if method == "initialize" {
            let (sid, result) = self.relay.initialize(&params, "stdio");
            let old = lock(&self.session).replace(sid.clone());
            if let Some(o) = old {
                self.relay.disconnect(&o);
            }
            // a legacy stdio session gets resource, tool-list and log notifications on stdout
            tokio::spawn(self.relay.clone().legacy_events(Some(sid), self.out.clone()));
            return Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }));
        } else {
            let sid = lock(&self.session).clone();
            match sid.and_then(|s| self.relay.session_ctx(&s, "stdio")) {
                Some(c) => c,
                None => Ctx::new(Ver::V20250326, "stdio"),
            }
        };
        if method == "subscriptions/listen" && ctx.ver.modern() {
            let task = tokio::spawn(self.relay.clone().listen(id.clone(), params["notifications"].clone(), ctx.session.clone(), self.out.clone()));
            lock(&self.inflight).insert(id.to_string(), (task.abort_handle(), false));
            return None;
        }
        ctx.out = Some(self.out.clone());
        if !spawn {
            return self.relay.dispatch(&msg, &ctx).await;
        }
        let poke = is_backend_call(&msg);
        let me = self.clone();
        let key = id.to_string();
        let key2 = key.clone();
        let task = tokio::spawn(async move {
            let r = me.relay.dispatch(&msg, &ctx).await;
            lock(&me.inflight).remove(&key2);
            if let Some(r) = r {
                me.send(r);
            }
        });
        lock(&self.inflight).insert(key, (task.abort_handle(), poke));
        None
    }
}

/// MCP over stdio (`echodebug-relay --stdio`): newline-delimited JSON-RPC on stdin/stdout, for
/// clients that launch servers as subprocesses. stdio is local by nature, so it needs no token:
/// when a relay is already listening on `port` (the desktop app, or a headless relay) this process
/// bridges to its `/mcp` with the token from the config directory; otherwise it becomes the relay
/// on `port` itself (Echo and the app connect to it as usual).
pub async fn serve_stdio(port: u16, app_version: String) -> std::io::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(v) = out_rx.recv().await {
            let line = v.to_string();
            if stdout.write_all(line.as_bytes()).await.is_err() || stdout.write_all(b"\n").await.is_err() {
                break;
            }
            let _ = stdout.flush().await;
        }
    });
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    match crate::bind(port) {
        Ok(listener) => {
            let token = auth::default_token()?;
            let relay = Relay::new(app_version, crate::DEFAULT_TIMEOUT).with_token(token);
            eprintln!("echodebug: stdio MCP with its own relay on ws://127.0.0.1:{port} (start the EchoDebug app first to use its window's tools)");
            tokio::spawn(crate::run(listener, relay.clone()));
            let conn = Arc::new(StdioConn { relay, out: out_tx.clone(), session: Mutex::new(None), inflight: Mutex::new(HashMap::new()) });
            while let Some(line) = lines.next_line().await? {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(&line) {
                    Ok(msg) => conn.handle(msg).await,
                    Err(e) => conn.send(rpc_error(Value::Null, PARSE_ERROR, format!("parse error: {e}"))),
                }
            }
            // stdin closed: the client is gone
            let sid = lock(&conn.session).take();
            if let Some(s) = sid {
                conn.relay.disconnect(&s);
            }
        }
        Err(_) => {
            eprintln!("echodebug: stdio MCP bridged to the relay on http://127.0.0.1:{port}/mcp");
            let bridge = Arc::new(crate::mcp_bridge::Bridge::new(port, out_tx.clone()));
            while let Some(line) = lines.next_line().await? {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(&line) {
                    Ok(msg) => {
                        let b = bridge.clone();
                        tokio::task::spawn_blocking(move || b.forward(msg));
                    }
                    Err(e) => {
                        let _ = out_tx.send(rpc_error(Value::Null, PARSE_ERROR, format!("parse error: {e}")));
                    }
                }
            }
            bridge.close();
        }
    }
    drop(out_tx);
    // in-flight tasks hold senders; give their last lines a moment, then exit
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_negotiation() {
        assert_eq!(supported_versions(), ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]);
        assert_eq!(negotiate(Some("2025-03-26")), Ver::V20250326);
        assert_eq!(negotiate(Some("2025-06-18")), Ver::V20250618);
        assert_eq!(negotiate(Some("1999-01-01")), LATEST_LEGACY);
        assert_eq!(negotiate(Some("2026-07-28")), LATEST_LEGACY, "2026-07-28 has no initialize");
        assert_eq!(negotiate(None), LATEST_LEGACY);
        assert!(LATEST.modern() && !LATEST_LEGACY.modern());
        assert!(Ver::V20250618.rich() && !Ver::V20250326.rich());
    }

    #[test]
    fn codecs_and_headers() {
        for s in ["", "a", "ab", "abc", "Hello, 世界", "line1\nline2"] {
            assert_eq!(base64_decode(&base64_encode(s.as_bytes())).unwrap(), s.as_bytes());
        }
        assert_eq!(base64_encode("Hello, 世界".as_bytes()), "SGVsbG8sIOS4lueVjA==");
        assert_eq!(header_encode("read_memory"), "read_memory");
        assert_eq!(header_encode(" padded "), "=?base64?IHBhZGRlZCA=?=");
        assert_eq!(header_text("=?base64?SGVsbG8sIOS4lueVjA==?=").unwrap(), "Hello, 世界");
        assert_eq!(hex_decode(&hex_encode("tools:5")).unwrap(), "tools:5");
        let mut h = HeaderMap::new();
        let p = json!({ "name": "read_memory" });
        assert!(check_modern_headers(&h, "tools/call", &p, "2026-07-28").unwrap_err().contains("MCP-Protocol-Version"));
        h.insert("mcp-protocol-version", "2026-07-28".parse().unwrap());
        assert!(check_modern_headers(&h, "tools/call", &p, "2026-07-28").unwrap_err().contains("Mcp-Method"));
        h.insert("mcp-method", "tools/list".parse().unwrap());
        assert!(check_modern_headers(&h, "tools/call", &p, "2026-07-28").unwrap_err().contains("does not match"));
        h.insert("mcp-method", "tools/call".parse().unwrap());
        assert!(check_modern_headers(&h, "tools/call", &p, "2026-07-28").unwrap_err().contains("Mcp-Name"));
        h.insert("mcp-name", "=?base64?cmVhZF9tZW1vcnk=?=".parse().unwrap());
        assert!(check_modern_headers(&h, "tools/call", &p, "2026-07-28").is_ok());
        h.insert("mcp-name", "write_memory".parse().unwrap());
        assert!(check_modern_headers(&h, "tools/call", &p, "2026-07-28").is_err());
        assert!(check_modern_headers(&h, "tools/call", &p, "2025-11-25").is_err(), "header must equal _meta version");
    }

    #[test]
    fn message_shapes() {
        assert!(matches!(shape(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })), Shape::Request));
        assert!(matches!(shape(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })), Shape::Notification));
        assert!(matches!(shape(&json!({ "jsonrpc": "2.0", "id": "e1", "result": {} })), Shape::Response));
        assert!(matches!(shape(&json!({ "id": 1, "method": "ping" })), Shape::Invalid(_)));
        assert!(matches!(shape(&json!({ "jsonrpc": "2.0", "id": null, "method": "ping" })), Shape::Invalid(_)));
        assert!(matches!(shape(&json!([1])), Shape::Invalid(_)));
        assert!(known_method("subscriptions/listen", true) && !known_method("subscriptions/listen", false));
        assert!(known_method("logging/setLevel", false) && !known_method("logging/setLevel", true));
    }

    #[test]
    fn elicitation_capability_and_titles() {
        assert!(elicit_form_supported(&json!({ "elicitation": {} })));
        assert!(elicit_form_supported(&json!({ "elicitation": { "form": {} } })));
        assert!(!elicit_form_supported(&json!({ "elicitation": { "url": {} } })));
        assert!(!elicit_form_supported(&json!({})));
        assert_eq!(tool_title("read_memory"), "Read memory");
        let t = TOOLS.iter().find(|t| t["name"] == "read_memory").unwrap();
        assert!(tool_entry(t, Ver::V20250326).get("title").is_none());
        assert!(tool_entry(t, Ver::V20250326).get("outputSchema").is_none());
        assert_eq!(tool_entry(t, Ver::V20250618)["title"], "Read memory");
        assert_eq!(tool_entry(t, Ver::V20250618)["outputSchema"]["type"], "object");
    }

    #[test]
    fn tool_results_by_version() {
        let args: Map<String, Value> = serde_json::from_value(json!({ "address": "game.exe+0x10", "size": 16 })).unwrap();
        let r = tool_result(json!({ "type": "read_result", "id": 3, "success": true, "data": "00" }), "read", &args, Ver::V20250618);
        assert_eq!(r["isError"], false);
        assert_eq!(r["structuredContent"]["data"], "00");
        assert!(r["structuredContent"].get("type").is_none());
        let link = &r["content"][1];
        assert_eq!(link["type"], "resource_link");
        assert_eq!(link["uri"], "echodebug://memory/game.exe%2B0x10/16");
        let old = tool_result(json!({ "type": "read_result", "success": true, "data": "00" }), "read", &args, Ver::V20250326);
        assert!(old.get("structuredContent").is_none() && old["content"].as_array().unwrap().len() == 1);
        let err = tool_result(json!({ "type": "error", "code": 1005, "message": "memory read failed" }), "read", &args, Ver::V20260728);
        assert_eq!(err["isError"], true);
        assert_eq!(err["content"].as_array().unwrap().len(), 1, "no links on errors");
    }
}
