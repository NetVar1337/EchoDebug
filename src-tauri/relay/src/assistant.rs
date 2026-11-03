//! The in-app assistant's link to model providers.
//!
//! The desktop app (not the web view, and not the relay's sockets) owns every credential: the React
//! UI builds a provider-neutral request, the app's `assistant_send` command checks it with
//! [`provider::parse_request`] (read-only tools only), looks up the provider's credential in
//! [`creds`], builds that provider's own HTTP request with [`provider::build`] and streams the reply
//! with [`stream`]. Every provider's stream is translated by [`decode`] into one event shape (the
//! Messages API's `message_start` / `content_block_*` / `message_delta` / `message_stop`), so the UI
//! has one accumulator for text, thinking and tool calls whatever the provider.
//!
//! Keys are never logged, never returned to the UI and only sent to the provider they belong to:
//! built-in providers (Anthropic, OpenAI, Gemini, OpenRouter) have fixed hosts; a custom endpoint's
//! key goes to the base URL the user saved with it.
//!
//! Providers: Anthropic (API key), OpenAI (API key, Chat Completions), Google Gemini (API key,
//! Generative Language API), OpenRouter (API key, or its OAuth PKCE sign-in in [`oauth`]), and
//! custom OpenAI-compatible / Anthropic-compatible endpoints (Ollama, LM Studio, vLLM, llama.cpp,
//! LiteLLM, Azure OpenAI, gateways) with an optional key and custom headers. Subscription sign-in
//! that reuses another product's OAuth client is deliberately not offered.

pub mod convs;
pub mod creds;
pub mod decode;
#[cfg(test)]
mod mock;
pub mod models;
pub mod oauth;
pub mod provider;

use std::io::{BufRead, BufReader, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use self::decode::Decoder;
use self::provider::{Endpoint, HttpReq, Kind};

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
/// The same rule applies to every provider.
pub fn assistant_tool_allowed(verb: &str) -> bool {
    crate::mcp::is_read_only(verb)
        && !ASSISTANT_DENY.contains(&verb)
        && !verb.starts_with("dbg_")
        && !verb.starts_with("emu_")
}

/// Checks one tool of a request: a plain client tool (name, schema, no server-tool `type`) that is
/// one of the app's review tools or maps through `tools.json` to an allowed verb.
pub fn check_tool(t: &Value) -> Result<(), String> {
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

/// The tools the app may offer the assistant, as `(name, verb)` pairs from `tools.json`.
pub fn allowed_tools() -> Vec<(String, String)> {
    crate::tool_list()
        .iter()
        .filter_map(|t| Some((t.get("name")?.as_str()?.to_owned(), t.get("verb")?.as_str()?.to_owned())))
        .filter(|(_, v)| assistant_tool_allowed(v))
        .collect()
}

/// Incremental server-sent-events parser: feed it lines, get each event's JSON `data`.
/// `data: [DONE]` (OpenAI's end marker) comes back as `{"type":"[DONE]"}`.
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
            if data.trim() == "[DONE]" {
                return Some(json!({ "type": "[DONE]" }));
            }
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

/// The HTTP client every assistant request uses (system proxy honoured).
pub fn agent(recv_timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_recv_body(Some(recv_timeout))
        .http_status_as_error(false)
        .proxy(ureq::Proxy::try_from_env())
        .build()
        .into()
}

/// The most telling error kind of an error object: a string `type`, `status` or `code` first
/// (`invalid_request_error`, `RESOURCE_EXHAUSTED`, `rate_limit_exceeded`), else a numeric code.
pub fn error_kind(e: &Value) -> String {
    ["type", "status", "code"]
        .iter()
        .find_map(|k| e.get(*k).and_then(Value::as_str))
        .map(str::to_owned)
        .or_else(|| e.get("code").filter(|c| c.is_number()).map(Value::to_string))
        .unwrap_or_default()
}

/// Text of an API error reply with an actionable hint. Understands the error bodies of every
/// provider (`{"error":{"type","message"}}`, OpenAI's `{"error":{"code","message"}}`, Gemini's
/// `{"error":{"status","message"}}`, a bare string). The UI keys its buttons off the hints'
/// wording ("Settings", "retry after", "/compact"), see `src/lib/assistant/errors.ts`.
pub fn error_message(kind: Kind, status: u16, body: &str, retry_after: Option<&str>) -> String {
    let parsed: Option<Value> = serde_json::from_str(body).ok();
    let e = parsed.as_ref().and_then(|v| v.get("error"));
    let e = match e {
        Some(Value::Array(a)) => a.first(),
        other => other,
    };
    let kind_s = e.map(error_kind).unwrap_or_default();
    let mut msg = e
        .and_then(|e| e.get("message").and_then(Value::as_str).or_else(|| e.as_str()))
        .or_else(|| parsed.as_ref().and_then(|v| v.get("message")).and_then(Value::as_str))
        .unwrap_or("")
        .to_owned();
    if msg.is_empty() && parsed.is_none() && !body.trim().is_empty() && body.len() < 300 && !body.trim_start().starts_with('<') {
        msg = body.trim().to_owned();
    }
    let low = format!("{kind_s} {msg}").to_lowercase();
    let too_long = low.contains("prompt is too long")
        || low.contains("context_length_exceeded")
        || low.contains("context length")
        || low.contains("maximum context")
        || low.contains("too many tokens")
        || low.contains("exceeds the maximum number of tokens")
        || low.contains("input is too long")
        || status == 413;
    let hint = if too_long {
        " (the conversation is too long for this model; run /compact or start a /new conversation)".to_owned()
    } else {
        match status {
            401 | 403 => format!(" (check the {} credential in Settings → Assistant)", kind.label()),
            402 => " (out of credits on this provider; add credits or pick another provider)".to_owned(),
            404 => " (unknown model or endpoint; refresh the model list or check the base URL in Settings → Assistant)".to_owned(),
            408 | 504 => " (the provider timed out; /retry)".to_owned(),
            429 => match retry_after.and_then(|s| s.trim().parse::<f64>().ok()) {
                Some(s) => format!(" (rate limited; retry after {}s, then /retry)", s.ceil() as u64),
                None => " (rate limited; wait a moment, then /retry)".to_owned(),
            },
            500..=599 => " (the provider had a problem or is overloaded; /retry shortly)".to_owned(),
            _ => String::new(),
        }
    };
    if msg.is_empty() {
        format!("HTTP {status}{hint}")
    } else if kind_s.is_empty() {
        format!("HTTP {status}: {msg}{hint}")
    } else {
        format!("HTTP {status} {kind_s}: {msg}{hint}")
    }
}

/// POSTs `req` and calls `on` with every event the provider's stream turns into (one shape for
/// every provider, see [`decode`]) until the stream ends or `cancel` is set.
pub fn stream(req: &HttpReq, kind: Kind, mut dec: Box<dyn Decoder>, cancel: &AtomicBool, mut on: impl FnMut(Value)) -> Result<(), String> {
    let agent = agent(Duration::from_secs(600));
    let mut r = agent.post(&req.url);
    for (k, v) in &req.headers {
        r = r.header(k.as_str(), v.as_str());
    }
    // the error never includes the request (and so never the key)
    let host = provider::host_of(&req.url);
    let mut resp = r.send(req.body.to_string()).map_err(|e| format!("cannot reach {host}: {e}"))?;
    let status = resp.status().as_u16();
    if status != 200 {
        let retry = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).map(str::to_owned);
        let mut text = String::new();
        let _ = resp.body_mut().as_reader().take(64 * 1024).read_to_string(&mut text);
        return Err(error_message(kind, status, &text, retry.as_deref()));
    }
    let mut reader = BufReader::new(resp.body_mut().as_reader());
    let mut sse = SseParser::default();
    let mut line = String::new();
    let mut out = Vec::new();
    let mut emit = |dec: &mut Box<dyn Decoder>, v: Option<Value>, on: &mut dyn FnMut(Value)| {
        out.clear();
        match v {
            Some(v) => dec.feed(v, &mut out),
            None => dec.finish(&mut out),
        }
        for ev in out.drain(..) {
            on(ev);
        }
    };
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| format!("stream interrupted: {e}"))?;
        if n == 0 {
            if let Some(v) = sse.feed("") {
                emit(&mut dec, Some(v), &mut on);
            }
            emit(&mut dec, None, &mut on);
            return Ok(());
        }
        if let Some(v) = sse.feed(line.trim_end_matches('\n')) {
            emit(&mut dec, Some(v), &mut on);
            if dec.done() {
                emit(&mut dec, None, &mut on);
                return Ok(());
            }
        }
    }
}

/// The endpoint for a stored provider.
pub fn endpoint(store: &creds::Store, provider_id: &str) -> Result<Endpoint, String> {
    let c = store.get(provider_id).ok_or_else(|| match creds::builtin_kind(provider_id) {
        Some(k) => format!("{} is not set up: add a key{} in Settings → Assistant", k.label(), if k == Kind::OpenRouter { " or sign in" } else { "" }),
        None => format!("no endpoint '{provider_id}': add it in Settings → Assistant"),
    })?;
    Ok(Endpoint::from_cred(&c))
}

/// Checks a neutral request from the UI, builds the provider's own request and streams the reply
/// as normalised events. Nothing but [`provider::build`] decides what is sent.
pub fn send(ep: &Endpoint, body: &Value, cancel: &AtomicBool, on: impl FnMut(Value)) -> Result<(), String> {
    let req = provider::parse_request(body, ep.kind)?;
    let http = provider::build(ep, &req);
    stream(&http, ep.kind, provider::decoder_for(ep), cancel, on)
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
            "data: [DONE]",
            "",
        ] {
            if let Some(v) = p.feed(l) {
                out.push(v);
            }
        }
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["type"], "message_start");
        assert_eq!(out[1]["delta"]["text"], "hi");
        assert_eq!(out[2]["type"], "[DONE]");
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
    }

    #[test]
    fn error_messages_carry_hints() {
        let m = error_message(Kind::Anthropic, 401, r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#, None);
        assert!(m.contains("401") && m.contains("invalid x-api-key") && m.contains("Settings") && m.contains("Anthropic"), "{m}");
        assert_eq!(error_message(Kind::OpenAi, 500, "<html>oops</html>", None), "HTTP 500 (the provider had a problem or is overloaded; /retry shortly)");
        let m = error_message(Kind::OpenAi, 429, r#"{"error":{"message":"Rate limit reached","type":"requests","code":"rate_limit_exceeded"}}"#, Some("7.2"));
        assert!(m.contains("retry after 8s"), "{m}");
        let m = error_message(Kind::OpenAi, 400, r#"{"error":{"message":"This model's maximum context length is 128000 tokens","code":"context_length_exceeded"}}"#, None);
        assert!(m.contains("/compact"), "{m}");
        let m = error_message(Kind::Anthropic, 400, r#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 1200000 tokens > 1000000 maximum"}}"#, None);
        assert!(m.contains("/compact"), "{m}");
        let m = error_message(Kind::Gemini, 400, r#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT"}}"#, None);
        assert!(m.contains("API key not valid") && m.contains("INVALID_ARGUMENT"), "{m}");
        let m = error_message(Kind::Gemini, 403, r#"[{"error":{"code":403,"message":"denied","status":"PERMISSION_DENIED"}}]"#, None);
        assert!(m.contains("denied") || m.contains("Gemini"), "{m}");
        let m = error_message(Kind::OpenRouter, 402, r#"{"error":{"code":402,"message":"Insufficient credits"}}"#, None);
        assert!(m.contains("credits"), "{m}");
        assert!(error_message(Kind::OpenAiCompat, 404, "model not found", None).contains("model not found"));
    }

    #[test]
    fn check_tool_refuses_writes_and_server_tools() {
        assert!(check_tool(&json!({ "name": "read_memory", "input_schema": { "type": "object" } })).is_ok());
        assert!(check_tool(&json!({ "name": "submit_name_suggestions", "input_schema": { "type": "object" } })).is_ok());
        assert!(check_tool(&json!({ "name": "write_memory", "input_schema": { "type": "object" } })).unwrap_err().contains("not read-only"));
        assert!(check_tool(&json!({ "name": "rm_rf", "input_schema": { "type": "object" } })).is_err());
        assert!(check_tool(&json!({ "type": "web_fetch_20260209", "name": "web_fetch" })).is_err());
    }

    fn collect(ep: &Endpoint, body: &Value) -> (Result<(), String>, Vec<Value>) {
        let mut evs = Vec::new();
        let r = send(ep, body, &AtomicBool::new(false), |e| evs.push(e));
        (r, evs)
    }

    fn body(model: &str) -> Value {
        json!({ "model": model, "system": "sys", "max_tokens": 100, "messages": [{ "role": "user", "content": "hi" }],
            "tools": [{ "name": "read_memory", "description": "", "input_schema": { "type": "object", "properties": { "address": { "type": "string" } } } }] })
    }

    #[test]
    fn streams_every_provider_through_one_event_shape() {
        let fx = |n: &str| std::fs::read_to_string(format!("{}/tests/fixtures/assistant/{n}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let m = mock::serve(vec![
            mock::route("POST /v1/messages", 200, "text/event-stream", &fx("anthropic_tools.sse")),
            mock::route("POST /chat/completions", 200, "text/event-stream", &fx("openai_tools.sse")),
            mock::route("POST /models/gemini-3-pro:streamGenerateContent?alt=sse", 200, "text/event-stream", &fx("gemini_tools.sse")),
        ]);
        let ep = |kind: Kind, id: &str| Endpoint { id: id.into(), kind, base: m.base.clone(), key: Some("key-0123456789".into()), headers: vec![] };
        for (kind, id, model, tool) in [
            (Kind::Anthropic, "anthropic", "claude-opus-5-5", "read_memory"),
            (Kind::OpenAi, "openai", "gpt-5", "read_memory"),
            (Kind::OpenRouter, "openrouter", "openai/gpt-5", "read_memory"),
            (Kind::Gemini, "gemini", "gemini-3-pro", "read_memory"),
        ] {
            let (r, evs) = collect(&ep(kind, id), &body(model));
            r.unwrap_or_else(|e| panic!("{kind:?}: {e}"));
            let msg = decode::tests::fold(&evs);
            assert_eq!(msg["stop_reason"], "tool_use", "{kind:?}");
            assert!(msg["content"].as_array().unwrap().iter().any(|b| b["type"] == "tool_use" && b["name"] == tool), "{kind:?}");
        }
        let seen = m.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 4);
        assert_eq!(seen[0].header("x-api-key"), Some("key-0123456789"));
        assert_eq!(seen[1].header("authorization"), Some("Bearer key-0123456789"));
        assert_eq!(seen[2].header("x-title"), Some("EchoDebug"));
        assert_eq!(seen[3].header("x-goog-api-key"), Some("key-0123456789"));
        let gem: Value = serde_json::from_str(&seen[3].body).unwrap();
        assert_eq!(gem["contents"][0]["parts"][0]["text"], "hi");
    }

    #[test]
    fn refuses_before_sending_and_reports_http_errors() {
        let m = mock::serve(vec![mock::route("POST /chat/completions", 429, "application/json", r#"{"error":{"message":"slow down","code":"rate_limit_exceeded"}}"#)]);
        let ep = Endpoint { id: "openai".into(), kind: Kind::OpenAi, base: m.base.clone(), key: Some("key-0123456789".into()), headers: vec![] };
        let mut bad = body("gpt-5");
        bad["tools"] = json!([{ "name": "write_memory", "input_schema": { "type": "object" } }]);
        assert!(collect(&ep, &bad).0.unwrap_err().contains("not read-only"));
        // nothing went out for the refused request
        assert!(m.seen.lock().unwrap().is_empty());
        let e = collect(&ep, &body("gpt-5")).0.unwrap_err();
        assert!(e.contains("429") && e.contains("slow down") && e.contains("/retry"), "{e}");
    }

    #[test]
    fn unconfigured_providers_say_how_to_set_them_up() {
        let st = creds::Store { dir: std::env::temp_dir().join(format!("echodebug-ep-{}", std::process::id())) };
        assert!(endpoint(&st, "openrouter").unwrap_err().contains("sign in"));
        assert!(endpoint(&st, "custom-x").unwrap_err().contains("no endpoint"));
    }
}
