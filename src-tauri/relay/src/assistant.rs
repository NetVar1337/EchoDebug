//! The in-app assistant's link to the Anthropic Messages API.
//!
//! The desktop app (not the web view, and not the relay's sockets) owns the user's API key: the
//! React UI builds a request body, the app's `assistant_send` command checks it with
//! [`prepare_body`], adds the key from [`load_key`] and streams the response with [`stream`].
//! The key only ever goes to `api.anthropic.com`; it is never logged, never returned to the UI and
//! never written anywhere but [`key_path`].
//!
//! Key storage: on Windows the key is encrypted with DPAPI (`CryptProtectData`, bound to the
//! user's login); elsewhere it is a plain file readable only by the current user (mode 0600) in
//! the app's config directory, which [`KeyInfo::note`] tells the user.

use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

pub const API_URL: &str = "https://api.anthropic.com/v1/messages";
pub const API_VERSION: &str = "2026-10-21";
/// `fallbacks: "default"` (server-side retry of a refused request on Anthropic's recommended model).
pub const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";

/// Tools the assistant handles inside the app without touching the target (they only fill the
/// review lists the user accepts from).
pub const LOCAL_TOOLS: &[&str] = &["submit_name_suggestions", "submit_struct_fields"];

/// Read-only by the MCP annotations, but still not for the assistant: they run code (emulation),
/// change the agent's state or go to the network.
pub const ASSISTANT_DENY: &[&str] = &[
    "emulate", "lift_trace", "devirt", "ui_find_oep", "ui_batch_decrypt", "ui_rebuild_imports",
    "ui_load_symbols", "alert_add", "alert_remove", "ui_flirt_pat", "ui_binary_diff",
];

/// Whether the assistant may call the tool behind `verb`: read-only by the MCP annotations
/// (`mcp::is_read_only`, which excludes every write, freeze, dump and state change) and not on
/// [`ASSISTANT_DENY`]. Execution-control verbs (`dbg_*`, `emu_*`) are refused by prefix too.
pub fn assistant_tool_allowed(verb: &str) -> bool {
    crate::mcp::is_read_only(verb)
        && !ASSISTANT_DENY.contains(&verb)
        && !verb.starts_with("dbg_")
        && !verb.starts_with("emu_")
}

/// Top-level request fields the app sends. Anything else (`mcp_servers`, `container`, …) could
/// send data somewhere other than the model, so it is refused.
const BODY_FIELDS: &[&str] = &[
    "model", "max_tokens", "system", "messages", "tools", "tool_choice", "thinking", "output_config", "stream",
    "cache_control", "fallbacks",
];

/// Checks a request body from the UI and returns the one to send (always streamed).
pub fn prepare_body(body: Value) -> Result<Value, String> {
    let Value::Object(mut obj) = body else { return Err("assistant request must be a JSON object".into()) };
    if let Some(k) = obj.keys().find(|k| !BODY_FIELDS.contains(&k.as_str())) {
        return Err(format!("assistant request field '{k}' is not allowed"));
    }
    let model = obj.get("model").and_then(Value::as_str).unwrap_or_default();
    if !model.starts_with("claude-") || model.len() > 64 || !model.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
        return Err(format!("unknown model '{model}'"));
    }
    if !obj.get("messages").is_some_and(Value::is_array) {
        return Err("assistant request needs 'messages'".into());
    }
    if let Some(tools) = obj.get("tools") {
        let tools = tools.as_array().ok_or("'tools' must be an array")?;
        for t in tools {
            check_tool(t)?;
        }
    }
    obj.insert("stream".into(), Value::Bool(true));
    Ok(Value::Object(obj))
}

fn check_tool(t: &Value) -> Result<(), String> {
    let name = t.get("name").and_then(Value::as_str).ok_or("tool without a name")?;
    // server tools (web fetch, code execution, MCP toolsets) carry a "type" and no schema
    if t.get("type").is_some() || !t.get("input_schema").is_some_and(Value::is_object) {
        return Err(format!("tool '{name}' is not a plain client tool"));
    }
    if LOCAL_TOOLS.contains(&name) {
        return Ok(());
    }
    let verb = crate::tool_verb(name).ok_or_else(|| format!("tool '{name}' is not an EchoDebug tool"))?;
    if !assistant_tool_allowed(&verb) {
        return Err(format!("tool '{name}' ({verb}) is not read-only; the assistant may only read"));
    }
    Ok(())
}

/// Incremental server-sent-events parser: feed it lines, get each event's JSON `data`.
#[derive(Default)]
pub struct SseParser {
    data: String,
}

impl SseParser {
    /// One line without its newline. Returns the event's data when `line` ends an event.
    pub fn feed(&mut self, line: &str) -> Option<Value> {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            if self.data.is_empty() {
                return None;
            }
            let data = std::mem::take(&mut self.data);
            return Some(serde_json::from_str(&data).unwrap_or_else(|_| json!({ "type": "unparsed", "data": data })));
        }
        if let Some(d) = line.strip_prefix("data:") {
            if !self.data.is_empty() {
                self.data.push('\n');
            }
            self.data.push_str(d.strip_prefix(' ').unwrap_or(d));
        }
        // "event:", "id:", "retry:" and ":comment" lines carry nothing we need: every data
        // payload names its own type
        None
    }
}

/// Text of an API error reply (`{"type":"error","error":{"type","message"}}`).
pub fn error_message(status: u16, body: &str) -> String {
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    let e = parsed.as_ref().and_then(|v| v.get("error"));
    let kind = e.and_then(|e| e.get("type")).and_then(Value::as_str).unwrap_or("");
    let msg = e.and_then(|e| e.get("message")).and_then(Value::as_str).unwrap_or("");
    let hint = match status {
        401 => " (check the API key in Settings → Assistant)",
        429 => " (rate limited; try again shortly)",
        529 => " (the API is overloaded; try again shortly)",
        _ => "",
    };
    if msg.is_empty() {
        format!("HTTP {status}{hint}")
    } else {
        format!("HTTP {status} {kind}: {msg}{hint}")
    }
}

/// POSTs `body` (from [`prepare_body`]) and calls `on` with every streamed event until the
/// stream ends or `cancel` is set.
pub fn stream(key: &str, body: &Value, cancel: &AtomicBool, mut on: impl FnMut(Value)) -> Result<(), String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_recv_body(Some(Duration::from_secs(600)))
        .http_status_as_error(false)
        .proxy(ureq::Proxy::try_from_env())
        .build()
        .into();
    let mut req = agent
        .post(API_URL)
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .header("anthropic-version", API_VERSION)
        .header("x-api-key", key);
    if body.get("fallbacks").is_some() {
        req = req.header("anthropic-beta", FALLBACK_BETA);
    }
    // the error never includes the request (and so never the key)
    let mut resp = req.send(body.to_string()).map_err(|e| format!("cannot reach api.anthropic.com: {e}"))?;
    let status = resp.status().as_u16();
    if status != 200 {
        let mut text = String::new();
        let _ = resp.body_mut().as_reader().take(64 * 1024).read_to_string(&mut text);
        return Err(error_message(status, &text));
    }
    let mut reader = BufReader::new(resp.body_mut().as_reader());
    let mut sse = SseParser::default();
    let mut line = String::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| format!("stream interrupted: {e}"))?;
        if n == 0 {
            if let Some(v) = sse.feed("") {
                on(v);
            }
            return Ok(());
        }
        if let Some(v) = sse.feed(line.trim_end_matches('\n')) {
            let done = v.get("type").and_then(Value::as_str) == Some("message_stop");
            on(v);
            if done {
                return Ok(());
            }
        }
    }
}

// ---- key storage ---------------------------------------------------------------------------------

pub fn key_path() -> PathBuf {
    crate::auth::config_dir().join(if cfg!(windows) { "anthropic-key.dpapi" } else { "anthropic-key" })
}

/// Where and how the key is kept, for Settings. Never contains the key.
pub fn key_info() -> Value {
    let present = load_key().is_some();
    let (storage, note) = if cfg!(windows) {
        ("dpapi", "Encrypted with Windows DPAPI for your user account.")
    } else {
        ("file", "Stored in a file readable only by your user (mode 0600); no system keychain is used on this platform.")
    };
    json!({ "present": present, "storage": storage, "path": key_path().display().to_string(), "note": note })
}

fn valid_key(k: &str) -> bool {
    (16..=512).contains(&k.len()) && k.bytes().all(|b| b.is_ascii_graphic())
}

pub fn save_key(key: &str) -> Result<Value, String> {
    let key = key.trim();
    if !valid_key(key) {
        return Err("that does not look like an API key (expected something like sk-ant-…)".into());
    }
    let path = key_path();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let bytes = protect(key.as_bytes()).map_err(|e| format!("encrypt key: {e}"))?;
    write_private(&path, &bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(key_info())
}

pub fn load_key() -> Option<String> {
    let bytes = fs::read(key_path()).ok()?;
    let plain = unprotect(&bytes).ok()?;
    let k = String::from_utf8(plain).ok()?.trim().to_owned();
    valid_key(&k).then_some(k)
}

pub fn clear_key() -> Result<(), String> {
    match fs::remove_file(key_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

#[cfg(not(windows))]
fn protect(b: &[u8]) -> io::Result<Vec<u8>> {
    Ok(b.to_vec())
}

#[cfg(not(windows))]
fn unprotect(b: &[u8]) -> io::Result<Vec<u8>> {
    Ok(b.to_vec())
}

#[cfg(windows)]
fn dpapi(b: &[u8], encrypt: bool) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
    let input = CRYPT_INTEGER_BLOB { cbData: b.len() as u32, pbData: b.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: `input` points at `b`, which outlives the call; DPAPI allocates `output` with
    // LocalAlloc and we free it with LocalFree after copying it out.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        } else {
            CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        }
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: DPAPI returned `cbData` bytes at `pbData`.
    let out = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as _) };
    Ok(out)
}

#[cfg(windows)]
fn protect(b: &[u8]) -> io::Result<Vec<u8>> {
    dpapi(b, true)
}

#[cfg(windows)]
fn unprotect(b: &[u8]) -> io::Result<Vec<u8>> {
    dpapi(b, false)
}

/// The tools the app may offer the assistant, as `(name, verb)` pairs from `tools.json`.
pub fn allowed_tools() -> Vec<(String, String)> {
    crate::tool_list()
        .iter()
        .filter_map(|t| Some((t.get("name")?.as_str()?.to_owned(), t.get("verb")?.as_str()?.to_owned())))
        .filter(|(_, v)| assistant_tool_allowed(v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_parser_reads_events() {
        let mut p = SseParser::default();
        let mut out = Vec::new();
        for l in [
            "event: message_start",
            r#"data: {"type":"message_start","message":{"id":"m"}}"#,
            "",
            ": keep-alive comment",
            "event: content_block_delta\r",
            r#"data: {"type":"content_block_delta","index":0,"#,
            r#"data: "delta":{"type":"text_delta","text":"hi"}}"#,
            "",
            "",
        ] {
            if let Some(v) = p.feed(l) {
                out.push(v);
            }
        }
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["type"], "message_start");
        assert_eq!(out[1]["delta"]["text"], "hi");
    }

    #[test]
    fn write_tools_are_never_allowed() {
        for verb in ["write", "freeze", "freeze_group", "dump", "ui_revert_patch", "ui_set_name", "ui_set_comment", "attach", "detach", "scan_new", "emu_start", "emu_run", "emulate", "alert_add", "agent_config", "cancel", "watch"] {
            assert!(!assistant_tool_allowed(verb), "{verb} must not be offered to the assistant");
        }
        for verb in ["read", "disassemble", "modules", "ui_strings", "ui_pe_info", "ui_list_names", "ui_cfg"] {
            assert!(assistant_tool_allowed(verb), "{verb} is read-only");
        }
        let names: Vec<String> = allowed_tools().into_iter().map(|(n, _)| n).collect();
        assert!(names.contains(&"read_memory".to_owned()));
        assert!(!names.iter().any(|n| n == "write_memory" || n == "freeze_value" || n == "dump_module" || n == "revert_patch" || n == "set_name"));
        // the native debugger's tools, read-only ones included (they need a debug session)
        for verb in ["dbg_trace_start", "dbg_trace_results", "dbg_trace_stop", "dbg_api_start", "dbg_api_log", "dbg_api_stop", "dbg_api_signatures", "dbg_all_regs"] {
            assert!(!assistant_tool_allowed(verb), "{verb} must not be offered to the assistant");
        }
        assert!(!names.iter().any(|n| n.starts_with("find_accesses_") || n.starts_with("api_monitor_")), "{names:?}");
    }

    #[test]
    fn prepare_body_checks_fields_and_tools() {
        let ok = json!({ "model": "claude-opus-5-5", "max_tokens": 100, "messages": [],
            "tools": [{ "name": "read_memory", "description": "", "input_schema": { "type": "object" } },
                      { "name": "submit_name_suggestions", "input_schema": { "type": "object" } }] });
        let b = prepare_body(ok).unwrap();
        assert_eq!(b["stream"], true);
        let bad_tool = json!({ "model": "claude-opus-5-5", "messages": [], "tools": [{ "name": "write_memory", "input_schema": { "type": "object" } }] });
        assert!(prepare_body(bad_tool).unwrap_err().contains("not read-only"));
        let unknown = json!({ "model": "claude-opus-5-5", "messages": [], "tools": [{ "name": "rm_rf", "input_schema": { "type": "object" } }] });
        assert!(prepare_body(unknown).is_err());
        let server = json!({ "model": "claude-opus-5-5", "messages": [], "tools": [{ "type": "web_fetch_20260209", "name": "web_fetch" }] });
        assert!(prepare_body(server).is_err());
        let extra = json!({ "model": "claude-opus-5-5", "messages": [], "mcp_servers": [] });
        assert!(prepare_body(extra).unwrap_err().contains("mcp_servers"));
        assert!(prepare_body(json!({ "model": "gpt", "messages": [] })).is_err());
        assert!(prepare_body(json!({ "model": "claude-opus-5-5" })).is_err());
    }

    #[test]
    fn error_messages() {
        let m = error_message(401, r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#);
        assert!(m.contains("401") && m.contains("invalid x-api-key") && m.contains("Settings"));
        assert_eq!(error_message(500, "oops"), "HTTP 500");
    }

    #[test]
    fn key_validation() {
        assert!(valid_key("sk-ant-api03-abcdefghijklmnop"));
        assert!(!valid_key("short"));
        assert!(!valid_key("sk-ant with space inside it"));
    }
}
