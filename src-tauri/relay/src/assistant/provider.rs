//! The provider abstraction: one neutral request from the UI, each provider's own HTTP request.
//!
//! The neutral request is Messages-API shaped (it is what the UI's transcript already holds):
//! `{model, system, messages: [{role, content: string | blocks}], tools: [{name, description,
//! input_schema}], max_tokens, effort?, temperature?, thinking?, fallbacks?}` with `text`,
//! `thinking` (`signature`, `origin`), `redacted_thinking`, `tool_use` (`signature` for Gemini) and
//! `tool_result` blocks. [`parse_request`] refuses anything else (unknown fields, server tools,
//! tools that are not read-only) and [`build`] writes the provider's body itself, so nothing the
//! web view sends can add a field that would send data somewhere other than the model.

use serde_json::{json, Map, Value};

use super::creds::Credential;
use super::decode::{AnthropicDecoder, Decoder, GeminiDecoder, OpenAiDecoder};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Anthropic,
    OpenAi,
    Gemini,
    OpenRouter,
    OpenAiCompat,
    AnthropicCompat,
}

impl Kind {
    pub const ALL: [Kind; 6] = [Kind::Anthropic, Kind::OpenAi, Kind::Gemini, Kind::OpenRouter, Kind::OpenAiCompat, Kind::AnthropicCompat];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Anthropic => "anthropic",
            Kind::OpenAi => "openai",
            Kind::Gemini => "gemini",
            Kind::OpenRouter => "openrouter",
            Kind::OpenAiCompat => "openai_compat",
            Kind::AnthropicCompat => "anthropic_compat",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Anthropic => "Anthropic",
            Kind::OpenAi => "OpenAI",
            Kind::Gemini => "Google Gemini",
            Kind::OpenRouter => "OpenRouter",
            Kind::OpenAiCompat => "OpenAI-compatible endpoint",
            Kind::AnthropicCompat => "Anthropic-compatible endpoint",
        }
    }

    /// Fixed host of a built-in provider (empty for custom endpoints).
    pub fn default_base(self) -> &'static str {
        match self {
            Kind::Anthropic => "https://api.anthropic.com",
            Kind::OpenAi => "https://api.openai.com/v1",
            Kind::Gemini => "https://generativelanguage.googleapis.com/v1beta",
            Kind::OpenRouter => "https://openrouter.ai/api/v1",
            Kind::OpenAiCompat | Kind::AnthropicCompat => "",
        }
    }

    pub fn is_custom(self) -> bool {
        matches!(self, Kind::OpenAiCompat | Kind::AnthropicCompat)
    }

    /// Local endpoints work without a key.
    pub fn needs_key(self) -> bool {
        !self.is_custom()
    }

    fn anthropic_shaped(self) -> bool {
        matches!(self, Kind::Anthropic | Kind::AnthropicCompat)
    }
}

pub const ANTHROPIC_VERSION: &str = "2026-10-21";
/// `fallbacks: "default"` (server-side retry of a refused request on Anthropic's recommended model).
pub const FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
const OPENROUTER_REFERER: &str = "https://github.com/NetVar1337/EchoDebug";

/// Where one provider's requests go and what they carry.
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub id: String,
    pub kind: Kind,
    /// no trailing slash
    pub base: String,
    pub key: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl Endpoint {
    /// Built-in providers always use their own host, whatever the file says.
    pub fn from_cred(c: &Credential) -> Endpoint {
        let base = if c.kind.is_custom() { c.base_url.clone().unwrap_or_default() } else { c.kind.default_base().to_owned() };
        Endpoint { id: c.id.clone(), kind: c.kind, base: base.trim_end_matches('/').to_owned(), key: c.api_key.clone(), headers: if c.kind.is_custom() { c.headers.clone() } else { vec![] } }
    }

    /// `{base}/v1/<path>` for Anthropic-shaped APIs whose base URL may or may not end in /v1.
    fn anthropic_url(&self, path: &str) -> String {
        if self.base.ends_with("/v1") { format!("{}/{path}", self.base) } else { format!("{}/v1/{path}", self.base) }
    }

    pub fn url(&self, what: &str) -> String {
        match (self.kind.anthropic_shaped(), what) {
            (true, w) => self.anthropic_url(w),
            (false, w) => format!("{}/{w}", self.base),
        }
    }

    /// Auth and provider headers, then the endpoint's custom ones.
    pub fn auth_headers(&self) -> Vec<(String, String)> {
        let mut h = Vec::new();
        match self.kind {
            Kind::Anthropic | Kind::AnthropicCompat => {
                h.push(("anthropic-version".into(), ANTHROPIC_VERSION.into()));
                if let Some(k) = &self.key {
                    h.push(("x-api-key".into(), k.clone()));
                }
            }
            Kind::Gemini => {
                if let Some(k) = &self.key {
                    h.push(("x-goog-api-key".into(), k.clone()));
                }
            }
            Kind::OpenAi | Kind::OpenRouter | Kind::OpenAiCompat => {
                if let Some(k) = &self.key {
                    h.push(("authorization".into(), format!("Bearer {k}")));
                }
                if self.kind == Kind::OpenRouter {
                    h.push(("http-referer".into(), OPENROUTER_REFERER.into()));
                    h.push(("x-title".into(), "EchoDebug".into()));
                }
            }
        }
        h.extend(self.headers.iter().cloned());
        h
    }
}

/// One HTTP request, ready to send.
#[derive(Clone, Debug)]
pub struct HttpReq {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

pub fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    rest.split(['/', '?']).next().unwrap_or(rest)
}

/// A checked neutral request.
#[derive(Clone, Debug, PartialEq)]
pub struct ChatRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<Value>,
    pub tools: Vec<Value>,
    pub max_tokens: u64,
    pub effort: Option<String>,
    pub temperature: Option<f64>,
    pub thinking: bool,
    pub fallbacks: bool,
}

const FIELDS: &[&str] = &["model", "system", "messages", "tools", "max_tokens", "effort", "temperature", "thinking", "fallbacks"];
pub const EFFORTS: &[&str] = &["low", "medium", "high", "xhigh", "max"];

pub fn valid_model(m: &str) -> bool {
    (1..=200).contains(&m.len()) && m.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._:/@+".contains(&b)) && !m.contains("..")
}

/// Checks a request body from the UI. Every provider gets the same check.
pub fn parse_request(body: &Value, kind: Kind) -> Result<ChatRequest, String> {
    let obj = body.as_object().ok_or("assistant request must be a JSON object")?;
    if let Some(k) = obj.keys().find(|k| !FIELDS.contains(&k.as_str())) {
        return Err(format!("assistant request field '{k}' is not allowed"));
    }
    let model = obj.get("model").and_then(Value::as_str).unwrap_or_default();
    if !valid_model(model) || (kind == Kind::Anthropic && !model.starts_with("claude-")) {
        return Err(format!("unknown model '{model}'"));
    }
    let messages = obj.get("messages").and_then(Value::as_array).ok_or("assistant request needs 'messages'")?.clone();
    for m in &messages {
        let role = m.get("role").and_then(Value::as_str).unwrap_or("");
        if role != "user" && role != "assistant" {
            return Err(format!("message role '{role}' is not allowed"));
        }
        match m.get("content") {
            Some(Value::String(_)) => {}
            Some(Value::Array(blocks)) => {
                for b in blocks {
                    let t = b.get("type").and_then(Value::as_str).unwrap_or("");
                    if !["text", "thinking", "redacted_thinking", "tool_use", "tool_result"].contains(&t) {
                        return Err(format!("content block '{t}' is not allowed"));
                    }
                }
            }
            _ => return Err("message content must be a string or a list of blocks".into()),
        }
    }
    let tools = match obj.get("tools") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("'tools' must be an array".into()),
    };
    for t in &tools {
        super::check_tool(t)?;
    }
    let effort = obj.get("effort").and_then(Value::as_str).map(str::to_owned);
    if let Some(e) = &effort {
        if !EFFORTS.contains(&e.as_str()) {
            return Err(format!("effort '{e}' is not one of {}", EFFORTS.join(", ")));
        }
    }
    let temperature = obj.get("temperature").and_then(Value::as_f64);
    if temperature.is_some_and(|t| !(0.0..=2.0).contains(&t)) {
        return Err("temperature must be between 0 and 2".into());
    }
    Ok(ChatRequest {
        model: model.to_owned(),
        system: obj.get("system").and_then(Value::as_str).unwrap_or_default().to_owned(),
        messages,
        tools,
        max_tokens: obj.get("max_tokens").and_then(Value::as_u64).unwrap_or(16000).clamp(1, 256_000),
        effort,
        temperature,
        thinking: obj.get("thinking").and_then(Value::as_bool).unwrap_or(false),
        fallbacks: obj.get("fallbacks").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// The provider's own request for `r`.
pub fn build(ep: &Endpoint, r: &ChatRequest) -> HttpReq {
    match ep.kind {
        Kind::Anthropic | Kind::AnthropicCompat => build_anthropic(ep, r),
        Kind::OpenAi | Kind::OpenRouter | Kind::OpenAiCompat => build_openai(ep, r),
        Kind::Gemini => build_gemini(ep, r),
    }
}

pub fn decoder_for(ep: &Endpoint) -> Box<dyn Decoder> {
    match ep.kind {
        Kind::Anthropic | Kind::AnthropicCompat => Box::new(AnthropicDecoder::new(&ep.id)),
        Kind::OpenAi | Kind::OpenRouter | Kind::OpenAiCompat => Box::new(OpenAiDecoder::new(&ep.id)),
        Kind::Gemini => Box::new(GeminiDecoder::new(&ep.id)),
    }
}

fn blocks(m: &Value) -> Vec<Value> {
    match m.get("content") {
        Some(Value::String(s)) => vec![json!({ "type": "text", "text": s })],
        Some(Value::Array(a)) => a.clone(),
        _ => vec![],
    }
}

fn str_of<'a>(b: &'a Value, k: &str) -> &'a str {
    b.get(k).and_then(Value::as_str).unwrap_or("")
}

/// Thinking is replayed only to the provider that produced it (signatures are provider-bound).
fn own_thinking(b: &Value, ep: &Endpoint) -> bool {
    b.get("origin").and_then(Value::as_str) == Some(ep.id.as_str())
}

fn tool_result_text(b: &Value) -> String {
    match b.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.get("text").and_then(Value::as_str)).collect::<Vec<_>>().join("\n"),
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

// ---- Anthropic Messages API -------------------------------------------------------------------

fn anthropic_block(b: &Value, ep: &Endpoint) -> Option<Value> {
    Some(match str_of(b, "type") {
        "text" => json!({ "type": "text", "text": str_of(b, "text") }),
        "thinking" if own_thinking(b, ep) => {
            let mut o = json!({ "type": "thinking", "thinking": str_of(b, "thinking") });
            if let Some(s) = b.get("signature").and_then(Value::as_str) {
                o["signature"] = json!(s);
            }
            o
        }
        "redacted_thinking" if own_thinking(b, ep) => json!({ "type": "redacted_thinking", "data": str_of(b, "data") }),
        "tool_use" => json!({ "type": "tool_use", "id": str_of(b, "id"), "name": str_of(b, "name"), "input": b.get("input").cloned().filter(Value::is_object).unwrap_or_else(|| json!({})) }),
        "tool_result" => {
            let mut o = json!({ "type": "tool_result", "tool_use_id": str_of(b, "tool_use_id"), "content": tool_result_text(b) });
            if b.get("is_error").and_then(Value::as_bool) == Some(true) {
                o["is_error"] = json!(true);
            }
            o
        }
        _ => return None,
    })
}

fn build_anthropic(ep: &Endpoint, r: &ChatRequest) -> HttpReq {
    let first_party = ep.kind == Kind::Anthropic;
    let messages: Vec<Value> = r
        .messages
        .iter()
        .filter_map(|m| {
            let content: Vec<Value> = blocks(m).iter().filter_map(|b| anthropic_block(b, ep)).filter(|b| !(b["type"] == "text" && b["text"] == "")).collect();
            (!content.is_empty()).then(|| json!({ "role": m["role"], "content": content }))
        })
        .collect();
    let mut body = json!({ "model": r.model, "max_tokens": r.max_tokens, "messages": messages, "stream": true });
    if !r.system.is_empty() {
        body["system"] = json!([{ "type": "text", "text": r.system }]);
    }
    if !r.tools.is_empty() {
        body["tools"] = Value::Array(
            r.tools
                .iter()
                .map(|t| {
                    let mut o = json!({ "name": t["name"], "description": t.get("description").cloned().unwrap_or(json!("")), "input_schema": t["input_schema"] });
                    // eager input streaming: inputs are validated in the app before anything runs
                    // (left off for gateways, which may reject the field)
                    if first_party {
                        o["eager_input_streaming"] = json!(true);
                    }
                    o
                })
                .collect(),
        );
    }
    if first_party {
        // the tools and system prompt are the same every turn: cache them and the history
        body["cache_control"] = json!({ "type": "ephemeral" });
    }
    if r.thinking {
        body["thinking"] = json!({ "type": "adaptive", "display": "summarized" });
    }
    if let Some(e) = &r.effort {
        body["output_config"] = json!({ "effort": e });
    }
    // sampling parameters are refused by the current API version: only gateways get them
    if let (Some(t), false) = (r.temperature, first_party) {
        body["temperature"] = json!(t);
    }
    let mut headers = vec![("content-type".into(), "application/json".into()), ("accept".into(), "text/event-stream".into())];
    if first_party && r.fallbacks {
        body["fallbacks"] = json!("default");
        headers.push(("anthropic-beta".into(), FALLBACK_BETA.into()));
    }
    headers.extend(ep.auth_headers());
    HttpReq { url: ep.url("messages"), headers, body }
}

// ---- OpenAI Chat Completions (OpenAI, OpenRouter, compatible servers) ------------------------

fn openai_effort(e: &str) -> &'static str {
    match e {
        "low" => "low",
        "medium" => "medium",
        _ => "high",
    }
}

fn openai_messages(ep: &Endpoint, r: &ChatRequest) -> Vec<Value> {
    let mut out = Vec::new();
    if !r.system.is_empty() {
        out.push(json!({ "role": "system", "content": r.system }));
    }
    for m in &r.messages {
        let bl = blocks(m);
        if m["role"] == "assistant" {
            let text: String = bl.iter().filter(|b| b["type"] == "text").map(|b| str_of(b, "text")).collect();
            let calls: Vec<Value> = bl
                .iter()
                .filter(|b| b["type"] == "tool_use")
                .map(|b| json!({ "id": str_of(b, "id"), "type": "function", "function": { "name": str_of(b, "name"), "arguments": b.get("input").cloned().filter(Value::is_object).unwrap_or_else(|| json!({})).to_string() } }))
                .collect();
            let mut o = json!({ "role": "assistant", "content": if text.is_empty() { Value::Null } else { json!(text) } });
            if !calls.is_empty() {
                o["tool_calls"] = json!(calls);
            }
            if ep.kind == Kind::OpenRouter {
                let details: Vec<Value> = bl.iter().filter(|b| b["type"] == "thinking" && own_thinking(b, ep)).filter_map(|b| b.get("details")?.as_array().cloned()).flatten().collect();
                if !details.is_empty() {
                    o["reasoning_details"] = json!(details);
                }
            }
            if text.is_empty() && calls.is_empty() {
                continue;
            }
            out.push(o);
        } else {
            for b in bl.iter().filter(|b| b["type"] == "tool_result") {
                out.push(json!({ "role": "tool", "tool_call_id": str_of(b, "tool_use_id"), "content": tool_result_text(b) }));
            }
            let text: Vec<&str> = bl.iter().filter(|b| b["type"] == "text").map(|b| str_of(b, "text")).filter(|t| !t.is_empty()).collect();
            if !text.is_empty() {
                out.push(json!({ "role": "user", "content": text.join("\n\n") }));
            }
        }
    }
    out
}

fn build_openai(ep: &Endpoint, r: &ChatRequest) -> HttpReq {
    let mut body = json!({ "model": r.model, "messages": openai_messages(ep, r), "stream": true, "stream_options": { "include_usage": true } });
    if !r.tools.is_empty() {
        body["tools"] = Value::Array(
            r.tools
                .iter()
                .map(|t| json!({ "type": "function", "function": { "name": t["name"], "description": t.get("description").cloned().unwrap_or(json!("")), "parameters": t["input_schema"] } }))
                .collect(),
        );
    }
    match ep.kind {
        Kind::OpenAi => {
            body["max_completion_tokens"] = json!(r.max_tokens);
            if let Some(e) = &r.effort {
                body["reasoning_effort"] = json!(openai_effort(e));
            }
        }
        Kind::OpenRouter => {
            body["max_tokens"] = json!(r.max_tokens);
            body["usage"] = json!({ "include": true });
            if let (Some(e), true) = (&r.effort, r.thinking) {
                body["reasoning"] = json!({ "effort": openai_effort(e) });
            } else if r.thinking {
                body["reasoning"] = json!({ "enabled": true });
            }
        }
        _ => {
            body["max_tokens"] = json!(r.max_tokens);
            if let Some(e) = &r.effort {
                body["reasoning_effort"] = json!(openai_effort(e));
            }
        }
    }
    if let Some(t) = r.temperature {
        body["temperature"] = json!(t);
    }
    let mut headers = vec![("content-type".into(), "application/json".into()), ("accept".into(), "text/event-stream".into())];
    headers.extend(ep.auth_headers());
    HttpReq { url: ep.url("chat/completions"), headers, body }
}

// ---- Gemini Generative Language API ---------------------------------------------------------

/// Gemini accepts an OpenAPI subset of JSON Schema: keep the keys it knows.
pub fn gemini_schema(s: &Value) -> Value {
    let Some(o) = s.as_object() else { return json!({ "type": "string" }) };
    let mut out = Map::new();
    for (k, v) in o {
        match k.as_str() {
            "type" | "description" | "format" | "nullable" | "minimum" | "maximum" | "minItems" | "maxItems" | "required" => {
                out.insert(k.clone(), v.clone());
            }
            "enum" if v.as_array().is_some_and(|a| a.iter().all(Value::is_string)) => {
                out.insert(k.clone(), v.clone());
            }
            "items" => {
                out.insert(k.clone(), gemini_schema(v));
            }
            "properties" => {
                if let Some(p) = v.as_object() {
                    out.insert(k.clone(), Value::Object(p.iter().map(|(n, s)| (n.clone(), gemini_schema(s))).collect()));
                }
            }
            _ => {}
        }
    }
    Value::Object(out)
}

fn build_gemini(ep: &Endpoint, r: &ChatRequest) -> HttpReq {
    let model = r.model.strip_prefix("models/").unwrap_or(&r.model);
    let mut names = std::collections::HashMap::new();
    let mut contents: Vec<Value> = Vec::new();
    for m in &r.messages {
        let role = if m["role"] == "assistant" { "model" } else { "user" };
        let mut parts = Vec::new();
        for b in blocks(m) {
            match str_of(&b, "type") {
                "text" if !str_of(&b, "text").is_empty() => {
                    let mut p = json!({ "text": str_of(&b, "text") });
                    if let (Some(sig), true) = (b.get("signature").and_then(Value::as_str), own_thinking(&b, ep)) {
                        p["thoughtSignature"] = json!(sig);
                    }
                    parts.push(p);
                }
                "tool_use" => {
                    let id = str_of(&b, "id").to_owned();
                    names.insert(id.clone(), str_of(&b, "name").to_owned());
                    let mut fc = json!({ "name": str_of(&b, "name"), "args": b.get("input").cloned().filter(Value::is_object).unwrap_or_else(|| json!({})) });
                    if !id.starts_with("gem_") && !id.is_empty() {
                        fc["id"] = json!(id);
                    }
                    let mut p = json!({ "functionCall": fc });
                    if let (Some(sig), true) = (b.get("signature").and_then(Value::as_str), own_thinking(&b, ep)) {
                        p["thoughtSignature"] = json!(sig);
                    }
                    parts.push(p);
                }
                "tool_result" => {
                    let id = str_of(&b, "tool_use_id");
                    let text = tool_result_text(&b);
                    let response = if b.get("is_error").and_then(Value::as_bool) == Some(true) { json!({ "error": text }) } else { json!({ "result": text }) };
                    let mut fr = json!({ "name": names.get(id).cloned().unwrap_or_default(), "response": response });
                    if !id.starts_with("gem_") && !id.is_empty() {
                        fr["id"] = json!(id);
                    }
                    parts.push(json!({ "functionResponse": fr }));
                }
                _ => {}
            }
        }
        if parts.is_empty() {
            continue;
        }
        match contents.last_mut() {
            Some(last) if last["role"] == role => last["parts"].as_array_mut().expect("parts").extend(parts),
            _ => contents.push(json!({ "role": role, "parts": parts })),
        }
    }
    let mut body = json!({ "contents": contents });
    if !r.system.is_empty() {
        body["systemInstruction"] = json!({ "parts": [{ "text": r.system }] });
    }
    if !r.tools.is_empty() {
        let decls: Vec<Value> = r
            .tools
            .iter()
            .map(|t| {
                let mut d = json!({ "name": t["name"], "description": t.get("description").cloned().unwrap_or(json!("")) });
                let schema = gemini_schema(&t["input_schema"]);
                if schema.get("properties").and_then(Value::as_object).is_some_and(|p| !p.is_empty()) {
                    d["parameters"] = schema;
                }
                d
            })
            .collect();
        body["tools"] = json!([{ "functionDeclarations": decls }]);
    }
    let mut gc = json!({ "maxOutputTokens": r.max_tokens });
    if let Some(t) = r.temperature {
        gc["temperature"] = json!(t);
    }
    if r.thinking {
        let mut tc = json!({ "includeThoughts": true });
        if let Some(e) = &r.effort {
            if model.starts_with("gemini-2") {
                tc["thinkingBudget"] = json!(match e.as_str() { "low" => 1024, "medium" => 8192, "high" => 24576, _ => -1 });
            } else {
                tc["thinkingLevel"] = json!(if matches!(e.as_str(), "low" | "medium") { "low" } else { "high" });
            }
        }
        gc["thinkingConfig"] = tc;
    }
    body["generationConfig"] = gc;
    let mut headers = vec![("content-type".into(), "application/json".into()), ("accept".into(), "text/event-stream".into())];
    headers.extend(ep.auth_headers());
    HttpReq { url: format!("{}/models/{model}:streamGenerateContent?alt=sse", ep.base), headers, body }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(kind: Kind) -> Endpoint {
        Endpoint { id: kind.as_str().replace('_', "-"), kind, base: kind.default_base().to_owned(), key: Some("test-key-1234567".into()), headers: vec![] }
    }

    fn convo() -> Value {
        json!({
            "model": "claude-opus-5-5", "system": "sys", "max_tokens": 1000, "effort": "medium", "thinking": true, "fallbacks": true,
            "tools": [{ "name": "read_memory", "description": "read", "input_schema": { "type": "object", "properties": { "address": { "type": "string" }, "size": { "type": "integer" } }, "required": ["address", "size"] } }],
            "messages": [
                { "role": "user", "content": "what is at 0x10?" },
                { "role": "assistant", "content": [
                    { "type": "thinking", "thinking": "look", "signature": "sig-a", "origin": "anthropic" },
                    { "type": "thinking", "thinking": "other", "signature": "sig-g", "origin": "gemini" },
                    { "type": "text", "text": "Reading." },
                    { "type": "tool_use", "id": "t1", "name": "read_memory", "input": { "address": "0x10", "size": 4 } }
                ] },
                { "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "t1", "content": "{\"hex\":\"01020304\"}" }] }
            ]
        })
    }

    #[test]
    fn parse_refuses_unknown_fields_blocks_and_tools() {
        assert!(parse_request(&convo(), Kind::Anthropic).is_ok());
        let mut extra = convo();
        extra["mcp_servers"] = json!([]);
        assert!(parse_request(&extra, Kind::Anthropic).unwrap_err().contains("mcp_servers"));
        let mut bad_tool = convo();
        bad_tool["tools"] = json!([{ "name": "write_memory", "input_schema": { "type": "object" } }]);
        // the same filter for every provider
        for k in Kind::ALL {
            assert!(parse_request(&bad_tool, k).unwrap_err().contains("not read-only"), "{k:?}");
        }
        let mut server = convo();
        server["tools"] = json!([{ "type": "web_search_20260209", "name": "web_search" }]);
        assert!(parse_request(&server, Kind::OpenAi).is_err());
        let mut doc = convo();
        doc["messages"] = json!([{ "role": "user", "content": [{ "type": "document", "source": {} }] }]);
        assert!(parse_request(&doc, Kind::Gemini).is_err());
        let mut sys = convo();
        sys["messages"] = json!([{ "role": "system", "content": "x" }]);
        assert!(parse_request(&sys, Kind::OpenAi).is_err());
        let mut gpt = convo();
        gpt["model"] = json!("gpt-5");
        assert!(parse_request(&gpt, Kind::Anthropic).is_err());
        assert!(parse_request(&gpt, Kind::OpenAi).is_ok());
        gpt["model"] = json!("anthropic/claude-opus-5-5");
        assert!(parse_request(&gpt, Kind::OpenRouter).is_ok());
        gpt["model"] = json!("llama3.1:8b-instruct-q4_K_M");
        assert!(parse_request(&gpt, Kind::OpenAiCompat).is_ok());
        gpt["model"] = json!("../etc");
        assert!(parse_request(&gpt, Kind::OpenAiCompat).is_err());
        let mut e = convo();
        e["effort"] = json!("ultra");
        assert!(parse_request(&e, Kind::Anthropic).is_err());
    }

    #[test]
    fn anthropic_body() {
        let r = parse_request(&convo(), Kind::Anthropic).unwrap();
        let h = build(&ep(Kind::Anthropic), &r);
        assert_eq!(h.url, "https://api.anthropic.com/v1/messages");
        let b = &h.body;
        assert_eq!(b["stream"], true);
        assert_eq!(b["thinking"], json!({ "type": "adaptive", "display": "summarized" }));
        assert_eq!(b["output_config"], json!({ "effort": "medium" }));
        assert_eq!(b["fallbacks"], "default");
        assert_eq!(b["cache_control"], json!({ "type": "ephemeral" }));
        assert_eq!(b["tools"][0]["eager_input_streaming"], true);
        assert_eq!(b["system"][0]["text"], "sys");
        // only Anthropic's own thinking is replayed, without our origin annotation
        let a = &b["messages"][1]["content"];
        assert_eq!(a.as_array().unwrap().len(), 3);
        assert_eq!(a[0], json!({ "type": "thinking", "thinking": "look", "signature": "sig-a" }));
        assert_eq!(b["messages"][2]["content"][0]["tool_use_id"], "t1");
        assert!(h.headers.contains(&("x-api-key".into(), "test-key-1234567".into())));
        assert!(h.headers.contains(&("anthropic-beta".into(), FALLBACK_BETA.into())));
        assert!(b.get("temperature").is_none());
    }

    #[test]
    fn anthropic_compatible_body() {
        let mut v = convo();
        v["model"] = json!("qwen3-coder");
        v["temperature"] = json!(0.2);
        let r = parse_request(&v, Kind::AnthropicCompat).unwrap();
        let mut e = ep(Kind::AnthropicCompat);
        e.base = "http://127.0.0.1:4000".into();
        e.key = None;
        e.headers = vec![("X-Team".into(), "re".into())];
        let h = build(&e, &r);
        assert_eq!(h.url, "http://127.0.0.1:4000/v1/messages");
        e.base = "https://gw.example/anthropic/v1".into();
        assert_eq!(build(&e, &r).url, "https://gw.example/anthropic/v1/messages");
        assert!(h.body.get("fallbacks").is_none() && h.body.get("cache_control").is_none());
        assert!(h.body["tools"][0].get("eager_input_streaming").is_none());
        assert_eq!(h.body["temperature"], 0.2);
        assert!(!h.headers.iter().any(|(k, _)| k == "x-api-key"));
        assert!(h.headers.contains(&("X-Team".into(), "re".into())));
        // thinking from another provider is not replayed
        assert_eq!(h.body["messages"][1]["content"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn openai_body() {
        let mut v = convo();
        v["model"] = json!("gpt-5");
        let r = parse_request(&v, Kind::OpenAi).unwrap();
        let h = build(&ep(Kind::OpenAi), &r);
        assert_eq!(h.url, "https://api.openai.com/v1/chat/completions");
        let b = &h.body;
        let m = b["messages"].as_array().unwrap();
        assert_eq!(m[0], json!({ "role": "system", "content": "sys" }));
        assert_eq!(m[1], json!({ "role": "user", "content": "what is at 0x10?" }));
        assert_eq!(m[2]["content"], "Reading.");
        assert_eq!(m[2]["tool_calls"][0]["function"]["name"], "read_memory");
        let args: Value = serde_json::from_str(m[2]["tool_calls"][0]["function"]["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args, json!({ "address": "0x10", "size": 4 }));
        assert_eq!(m[3], json!({ "role": "tool", "tool_call_id": "t1", "content": "{\"hex\":\"01020304\"}" }));
        assert_eq!(b["tools"][0]["type"], "function");
        assert_eq!(b["tools"][0]["function"]["parameters"]["required"][1], "size");
        assert_eq!(b["max_completion_tokens"], 1000);
        assert_eq!(b["reasoning_effort"], "medium");
        assert_eq!(b["stream_options"]["include_usage"], true);
        assert!(h.headers.contains(&("authorization".into(), "Bearer test-key-1234567".into())));
        assert!(b.get("fallbacks").is_none() && b.get("thinking").is_none());
    }

    #[test]
    fn openrouter_and_compatible_bodies() {
        let mut v = convo();
        v["model"] = json!("anthropic/claude-opus-5-5");
        v["messages"][1]["content"][0] = json!({ "type": "thinking", "thinking": "x", "origin": "openrouter", "details": [{ "type": "reasoning.text", "text": "x", "signature": "s" }] });
        let r = parse_request(&v, Kind::OpenRouter).unwrap();
        let h = build(&ep(Kind::OpenRouter), &r);
        assert_eq!(h.url, "https://openrouter.ai/api/v1/chat/completions");
        assert_eq!(h.body["reasoning"], json!({ "effort": "medium" }));
        assert_eq!(h.body["max_tokens"], 1000);
        assert_eq!(h.body["messages"][2]["reasoning_details"][0]["signature"], "s");
        assert!(h.headers.iter().any(|(k, v)| k == "x-title" && v == "EchoDebug"));
        let mut e = ep(Kind::OpenAiCompat);
        e.base = "http://127.0.0.1:11434/v1".into();
        e.key = None;
        let mut v = convo();
        v["model"] = json!("llama3.1");
        v.as_object_mut().unwrap().remove("effort");
        let h = build(&e, &parse_request(&v, Kind::OpenAiCompat).unwrap());
        assert_eq!(h.url, "http://127.0.0.1:11434/v1/chat/completions");
        assert!(h.body.get("reasoning_effort").is_none() && h.body.get("max_tokens").is_some());
        assert!(!h.headers.iter().any(|(k, _)| k == "authorization"));
    }

    #[test]
    fn gemini_body() {
        let mut v = convo();
        v["model"] = json!("models/gemini-3-pro");
        v["messages"][1]["content"][3]["signature"] = json!("tsig");
        v["messages"][1]["content"][3]["origin"] = json!("gemini");
        v["messages"][1]["content"][3]["id"] = json!("gem_0");
        v["messages"][2]["content"][0]["tool_use_id"] = json!("gem_0");
        let r = parse_request(&v, Kind::Gemini).unwrap();
        let h = build(&ep(Kind::Gemini), &r);
        assert_eq!(h.url, "https://generativelanguage.googleapis.com/v1beta/models/gemini-3-pro:streamGenerateContent?alt=sse");
        let b = &h.body;
        assert_eq!(b["systemInstruction"]["parts"][0]["text"], "sys");
        let c = b["contents"].as_array().unwrap();
        assert_eq!(c.len(), 3);
        assert_eq!(c[1]["role"], "model");
        assert_eq!(c[1]["parts"][0]["text"], "Reading.");
        assert_eq!(c[1]["parts"][1]["functionCall"], json!({ "name": "read_memory", "args": { "address": "0x10", "size": 4 } }));
        assert_eq!(c[1]["parts"][1]["thoughtSignature"], "tsig");
        assert_eq!(c[2]["parts"][0]["functionResponse"]["name"], "read_memory");
        assert_eq!(c[2]["parts"][0]["functionResponse"]["response"]["result"], "{\"hex\":\"01020304\"}");
        assert_eq!(b["tools"][0]["functionDeclarations"][0]["parameters"]["properties"]["size"]["type"], "integer");
        assert_eq!(b["generationConfig"]["thinkingConfig"], json!({ "includeThoughts": true, "thinkingLevel": "low" }));
        assert!(h.headers.contains(&("x-goog-api-key".into(), "test-key-1234567".into())));
        let mut v2 = v.clone();
        v2["model"] = json!("gemini-2.5-flash");
        v2["effort"] = json!("high");
        assert_eq!(build(&ep(Kind::Gemini), &parse_request(&v2, Kind::Gemini).unwrap()).body["generationConfig"]["thinkingConfig"]["thinkingBudget"], 24576);
        assert_eq!(gemini_schema(&json!({ "type": "object", "additionalProperties": false, "properties": { "k": { "type": "integer", "enum": [1, 2] } } })), json!({ "type": "object", "properties": { "k": { "type": "integer" } } }));
    }

    #[test]
    fn hosts() {
        assert_eq!(host_of("https://api.openai.com/v1/chat/completions"), "api.openai.com");
        assert_eq!(host_of("http://127.0.0.1:11434/v1"), "127.0.0.1:11434");
    }
}
