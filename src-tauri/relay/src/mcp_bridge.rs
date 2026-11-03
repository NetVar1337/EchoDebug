//! The stdio → Streamable HTTP bridge of `echodebug-relay --stdio`, used when a relay (the desktop
//! app, or a headless relay) already owns the port.
//!
//! Each stdin message becomes one `POST /mcp` with the headers its revision needs
//! (`MCP-Protocol-Version`, `Mcp-Method` / `Mcp-Name` for 2026-07-28 requests, `Mcp-Session-Id`
//! after a legacy `initialize`); JSON answers and every event of an SSE answer (progress, log
//! messages, elicitation requests, the result) go to stdout as lines. A legacy session also gets
//! its `GET /mcp` notification stream forwarded. The token comes from the config directory (stdio
//! is local, so the client's config never holds it) and is re-read once when the relay refuses it.

use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;

use crate::auth;
use crate::mcp_server::{header_encode, rpc_error, INTERNAL_ERROR};

pub(crate) struct Bridge {
    url: String,
    out: mpsc::UnboundedSender<Value>,
    token: Mutex<Option<String>>,
    session: Mutex<Option<String>>,
    version: Mutex<Option<String>>,
    /// identifies this bridge to the relay (cancellation, the panel's connection list)
    id: String,
    agent: ureq::Agent,
    events_started: AtomicBool,
}

fn get<T: Clone>(m: &Mutex<T>) -> T {
    m.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn set<T>(m: &Mutex<T>, v: T) {
    *m.lock().unwrap_or_else(|e| e.into_inner()) = v;
}

/// Reads server-sent events and hands each event's `data` (parsed) to `on`.
pub(crate) fn read_sse(reader: impl Read, mut on: impl FnMut(Value) -> bool) {
    let mut data = String::new();
    for line in BufReader::new(reader).lines() {
        let Ok(line) = line else { return };
        let line = line.strip_suffix('\r').unwrap_or(&line).to_owned();
        if line.is_empty() {
            if !data.is_empty() {
                if let Ok(v) = serde_json::from_str::<Value>(&data) {
                    if !on(v) {
                        return;
                    }
                }
                data.clear();
            }
            continue;
        }
        if let Some(d) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(d.strip_prefix(' ').unwrap_or(d));
        }
    }
}

impl Bridge {
    pub(crate) fn new(port: u16, out: mpsc::UnboundedSender<Value>) -> Self {
        let token = auth::default_token().ok().flatten();
        let agent: ureq::Agent = ureq::Agent::config_builder().timeout_connect(Some(Duration::from_secs(5))).http_status_as_error(false).build().into();
        let mut b = [0u8; 8];
        let _ = getrandom::fill(&mut b);
        Bridge {
            url: format!("http://127.0.0.1:{port}/mcp"),
            out,
            token: Mutex::new(token),
            session: Mutex::new(None),
            version: Mutex::new(None),
            id: b.iter().map(|x| format!("{x:02x}")).collect(),
            agent,
            events_started: AtomicBool::new(false),
        }
    }

    /// Forwards one message (blocking: runs on a blocking thread per message).
    pub(crate) fn forward(self: Arc<Self>, msg: Value) {
        let is_request = msg.get("method").is_some() && msg.get("id").is_some_and(|i| !i.is_null());
        if let Err(e) = self.post(&msg) {
            if is_request {
                let _ = self.out.send(rpc_error(msg["id"].clone(), INTERNAL_ERROR, e));
            } else if msg.is_array() {
                for m in msg.as_array().into_iter().flatten().filter(|m| m.get("method").is_some() && m.get("id").is_some()) {
                    let _ = self.out.send(rpc_error(m["id"].clone(), INTERNAL_ERROR, e.clone()));
                }
            }
        }
    }

    fn post(self: &Arc<Self>, msg: &Value) -> Result<(), String> {
        for attempt in 0..2 {
            let mut req = self
                .agent
                .post(&self.url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("X-EchoDebug-Bridge", &self.id)
                .header("X-EchoDebug-Transport", "stdio");
            if let Some(t) = get(&self.token) {
                req = req.header("Authorization", &format!("Bearer {t}"));
            }
            if let Some(s) = get(&self.session) {
                req = req.header("Mcp-Session-Id", &s);
            }
            let meta_ver = msg["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str();
            if let Some(v) = meta_ver.map(str::to_owned).or_else(|| get(&self.version)) {
                req = req.header("MCP-Protocol-Version", &v);
            }
            if meta_ver.is_some() {
                let method = msg["method"].as_str().unwrap_or_default();
                req = req.header("Mcp-Method", method);
                let name = match method {
                    "tools/call" | "prompts/get" => msg["params"]["name"].as_str(),
                    "resources/read" => msg["params"]["uri"].as_str(),
                    _ => None,
                };
                if let Some(n) = name {
                    req = req.header("Mcp-Name", &header_encode(n));
                }
            }
            let mut resp = req
                .send(msg.to_string())
                .map_err(|e| format!("EchoDebug is not reachable at {} ({e}): start the EchoDebug app (or echodebug-relay) and restart this MCP server", self.url))?;
            let status = resp.status().as_u16();
            if status == 401 {
                if attempt == 0 {
                    // the app may have regenerated the token since this process started
                    set(&self.token, auth::default_token().ok().flatten());
                    continue;
                }
                return Err(format!(
                    "the relay refused the token from {} (it was regenerated, or the relay uses ECHODEBUG_TOKEN): restart this MCP server, or set ECHODEBUG_TOKEN for it",
                    auth::token_path().display()
                ));
            }
            if status == 202 || status == 204 {
                return Ok(());
            }
            let sse = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).is_some_and(|c| c.starts_with("text/event-stream"));
            if sse {
                let out = self.out.clone();
                read_sse(resp.body_mut().as_reader(), |v| out.send(v).is_ok());
                return Ok(());
            }
            let session = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()).map(str::to_owned);
            let mut text = String::new();
            let _ = resp.body_mut().as_reader().take(64 << 20).read_to_string(&mut text);
            if text.trim().is_empty() {
                return Err(format!("the relay answered HTTP {status} without a body"));
            }
            let v: Value = serde_json::from_str(&text).map_err(|e| format!("the relay answered HTTP {status} with invalid JSON: {e}"))?;
            if msg["method"] == "initialize" {
                if let Some(s) = session {
                    set(&self.session, Some(s));
                    set(&self.version, v["result"]["protocolVersion"].as_str().map(str::to_owned));
                    self.start_events();
                }
            }
            if status == 404 && get(&self.session).is_some() && v["error"]["code"] == crate::mcp_server::SESSION_NOT_FOUND {
                set(&self.session, None);
            }
            let _ = self.out.send(v);
            return Ok(());
        }
        Err("unreachable".into())
    }

    /// The legacy session's GET event stream, forwarded to stdout until it ends.
    fn start_events(self: &Arc<Self>) {
        if self.events_started.swap(true, Ordering::Relaxed) {
            return;
        }
        let me = self.clone();
        std::thread::spawn(move || {
            let Some(session) = get(&me.session) else { return };
            let mut req = me.agent.get(&me.url).header("Accept", "text/event-stream").header("Mcp-Session-Id", &session).header("X-EchoDebug-Bridge", &me.id);
            if let Some(t) = get(&me.token) {
                req = req.header("Authorization", &format!("Bearer {t}"));
            }
            if let Some(v) = get(&me.version) {
                req = req.header("MCP-Protocol-Version", &v);
            }
            if let Ok(mut resp) = req.call() {
                if resp.status().as_u16() == 200 {
                    let out = me.out.clone();
                    read_sse(resp.body_mut().as_reader(), |v| out.send(v).is_ok());
                }
            }
            me.events_started.store(false, Ordering::Relaxed);
        });
    }

    /// stdin closed: end the legacy session on the relay.
    pub(crate) fn close(&self) {
        if let Some(s) = get(&self.session) {
            let mut req = self.agent.delete(&self.url).header("Mcp-Session-Id", &s);
            if let Some(t) = get(&self.token) {
                req = req.header("Authorization", &format!("Bearer {t}"));
            }
            let _ = req.call();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_events_are_split() {
        let text = "event: message\ndata: {\"a\":1}\n\n: keep-alive\n\ndata: {\"b\":\ndata: 2}\r\n\r\ndata: not json\n\n";
        let mut got = Vec::new();
        read_sse(text.as_bytes(), |v| {
            got.push(v);
            true
        });
        assert_eq!(got, vec![serde_json::json!({ "a": 1 }), serde_json::json!({ "b": 2 })]);
    }
}
