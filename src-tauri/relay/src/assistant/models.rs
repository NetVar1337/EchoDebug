//! Live model lists: each provider's list endpoint, parsed into one shape:
//! `{id, name, provider, context, max_output, tools, vision, reasoning, effort, temperature, price}`
//! where `price` is `{input, output, cache_read}` in USD per million tokens when the API gives it
//! (OpenRouter), and unknown fields are `null`. The UI adds built-in prices it knows and caches the
//! result.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::provider::{Endpoint, Kind};

fn model(provider: &str, id: &str, name: &str) -> Value {
    json!({ "id": id, "name": if name.is_empty() { id } else { name }, "provider": provider, "context": null, "max_output": null,
        "tools": null, "vision": null, "reasoning": null, "effort": null, "temperature": null, "price": null })
}

/// `GET /v1/models` (Anthropic and compatible): the page's models and the cursor of the next page.
pub fn parse_anthropic(provider: &str, v: &Value) -> (Vec<Value>, Option<String>) {
    let mut out = Vec::new();
    for m in v.get("data").and_then(Value::as_array).into_iter().flatten() {
        let Some(id) = m.get("id").and_then(Value::as_str) else { continue };
        let mut x = model(provider, id, m.get("display_name").and_then(Value::as_str).unwrap_or(""));
        let sup = |p: &str| m.pointer(p).and_then(Value::as_bool);
        x["context"] = m.get("max_input_tokens").cloned().unwrap_or(Value::Null);
        x["max_output"] = m.get("max_tokens").cloned().unwrap_or(Value::Null);
        x["tools"] = json!(true);
        x["vision"] = json!(sup("/capabilities/image_input/supported"));
        x["reasoning"] = json!(sup("/capabilities/thinking/supported"));
        x["effort"] = json!(sup("/capabilities/effort/supported"));
        // the current API version refuses sampling parameters
        x["temperature"] = json!(if m.get("capabilities").is_some() { Some(false) } else { None });
        out.push(x);
    }
    let next = if v.get("has_more").and_then(Value::as_bool) == Some(true) { v.get("last_id").and_then(Value::as_str).map(str::to_owned) } else { None };
    (out, next)
}

const OPENAI_NOT_CHAT: &[&str] = &["embedding", "tts", "whisper", "dall-e", "davinci", "babbage", "moderation", "transcribe", "image", "audio", "realtime", "search", "sora", "computer-use"];

fn openai_reasoning(id: &str) -> bool {
    let id = id.rsplit('/').next().unwrap_or(id);
    id.starts_with("o1") || id.starts_with("o3") || id.starts_with("o4") || id.starts_with("gpt-5") || id.starts_with("gpt-oss")
}

/// `GET /v1/models` (OpenAI and OpenAI-compatible servers): ids only, capabilities guessed from
/// OpenAI's own naming (other servers' entries keep `null`).
pub fn parse_openai(provider: &str, kind: Kind, v: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for m in v.get("data").and_then(Value::as_array).into_iter().flatten() {
        let Some(id) = m.get("id").and_then(Value::as_str) else { continue };
        let mut x = model(provider, id, "");
        if kind == Kind::OpenAi {
            let low = id.to_lowercase();
            if OPENAI_NOT_CHAT.iter().any(|w| low.contains(w)) || !(low.starts_with("gpt") || low.starts_with('o') || low.starts_with("chatgpt")) {
                continue;
            }
            let r = openai_reasoning(&low);
            x["tools"] = json!(true);
            x["reasoning"] = json!(r);
            x["effort"] = json!(r);
            x["temperature"] = json!(!r);
            x["vision"] = json!(low.starts_with("gpt-4o") || low.starts_with("gpt-4.1") || low.starts_with("gpt-5") || low.starts_with("o3") || low.starts_with("o4") || low == "o1");
        } else {
            // vLLM / LM Studio / llama.cpp report a context length under various names
            for k in ["max_model_len", "context_length", "context_window", "max_context_length"] {
                if let Some(c) = m.get(k).and_then(Value::as_u64) {
                    x["context"] = json!(c);
                    break;
                }
            }
            x["temperature"] = json!(true);
        }
        if let Some(c) = m.get("created").and_then(Value::as_u64) {
            x["created"] = json!(c);
        }
        out.push(x);
    }
    if kind == Kind::OpenAi {
        out.sort_by(|a, b| b["created"].as_u64().cmp(&a["created"].as_u64()));
    }
    out
}

/// `GET /v1beta/models` (Gemini): models that can generate content, and the next page token.
pub fn parse_gemini(provider: &str, v: &Value) -> (Vec<Value>, Option<String>) {
    let mut out = Vec::new();
    for m in v.get("models").and_then(Value::as_array).into_iter().flatten() {
        let Some(name) = m.get("name").and_then(Value::as_str) else { continue };
        let methods = m.get("supportedGenerationMethods").and_then(Value::as_array);
        if !methods.is_some_and(|a| a.iter().any(|x| x == "generateContent")) {
            continue;
        }
        let id = name.strip_prefix("models/").unwrap_or(name);
        if id.contains("embedding") || id.contains("-tts") || id.starts_with("imagen") || id.starts_with("aqa") {
            continue;
        }
        let mut x = model(provider, id, m.get("displayName").and_then(Value::as_str).unwrap_or(""));
        x["context"] = m.get("inputTokenLimit").cloned().unwrap_or(Value::Null);
        x["max_output"] = m.get("outputTokenLimit").cloned().unwrap_or(Value::Null);
        x["tools"] = json!(!id.contains("image"));
        x["vision"] = json!(id.starts_with("gemini"));
        let thinking = m.get("thinking").and_then(Value::as_bool).unwrap_or(false);
        x["reasoning"] = json!(thinking);
        x["effort"] = json!(thinking);
        x["temperature"] = json!(m.get("temperature").is_some() || m.get("maxTemperature").is_some());
        out.push(x);
    }
    (out, v.get("nextPageToken").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned))
}

/// OpenRouter prices are USD per token as strings ("0.000003"); per million here. `-1` means
/// variable (router models), which is unknown.
fn per_million(v: Option<&Value>) -> Option<f64> {
    let p = match v? {
        Value::String(s) => s.parse::<f64>().ok()?,
        Value::Number(n) => n.as_f64()?,
        _ => return None,
    };
    (p >= 0.0).then(|| (p * 1e6 * 1e6).round() / 1e6)
}

/// `GET /api/v1/models` (OpenRouter): context, pricing, modalities and supported parameters.
pub fn parse_openrouter(provider: &str, v: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for m in v.get("data").and_then(Value::as_array).into_iter().flatten() {
        let Some(id) = m.get("id").and_then(Value::as_str) else { continue };
        let mut x = model(provider, id, m.get("name").and_then(Value::as_str).unwrap_or(""));
        x["context"] = m.get("context_length").or_else(|| m.pointer("/top_provider/context_length")).cloned().unwrap_or(Value::Null);
        x["max_output"] = m.pointer("/top_provider/max_completion_tokens").cloned().unwrap_or(Value::Null);
        let params: Vec<&str> = m.get("supported_parameters").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        if !params.is_empty() {
            x["tools"] = json!(params.contains(&"tools"));
            x["reasoning"] = json!(params.contains(&"reasoning") || params.contains(&"include_reasoning"));
            x["effort"] = x["reasoning"].clone();
            x["temperature"] = json!(params.contains(&"temperature"));
        }
        if let Some(mods) = m.pointer("/architecture/input_modalities").and_then(Value::as_array) {
            x["vision"] = json!(mods.iter().any(|x| x == "image"));
        }
        let p = m.get("pricing");
        if let (Some(i), Some(o)) = (per_million(p.and_then(|p| p.get("prompt"))), per_million(p.and_then(|p| p.get("completion")))) {
            x["price"] = json!({ "input": i, "output": o, "cache_read": per_million(p.and_then(|p| p.get("input_cache_read"))) });
        }
        out.push(x);
    }
    out
}

/// `GET /api/tags` (Ollama): installed models, with capabilities when the server reports them.
pub fn parse_ollama(provider: &str, v: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for m in v.get("models").and_then(Value::as_array).into_iter().flatten() {
        let Some(id) = m.get("name").or_else(|| m.get("model")).and_then(Value::as_str) else { continue };
        let d = m.get("details");
        let extra: Vec<&str> = ["parameter_size", "quantization_level"].iter().filter_map(|k| d.and_then(|d| d.get(*k)).and_then(Value::as_str)).collect();
        let name = if extra.is_empty() { id.to_owned() } else { format!("{id} ({})", extra.join(", ")) };
        let mut x = model(provider, id, &name);
        if let Some(caps) = m.get("capabilities").and_then(Value::as_array) {
            let has = |c: &str| caps.iter().any(|x| x == c);
            x["tools"] = json!(has("tools"));
            x["vision"] = json!(has("vision"));
            x["reasoning"] = json!(has("thinking"));
        }
        x["temperature"] = json!(true);
        x["price"] = json!({ "input": 0.0, "output": 0.0, "cache_read": 0.0 });
        out.push(x);
    }
    out
}

fn get_json(ep: &Endpoint, url: &str) -> Result<Value, String> {
    let agent = super::agent(Duration::from_secs(30));
    let mut r = agent.get(url).header("accept", "application/json");
    for (k, v) in ep.auth_headers() {
        r = r.header(k.as_str(), v.as_str());
    }
    let host = super::provider::host_of(url).to_owned();
    let mut resp = r.call().map_err(|e| format!("cannot reach {host}: {e}"))?;
    let status = resp.status().as_u16();
    let retry = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let text = resp.body_mut().with_config().limit(32 * 1024 * 1024).read_to_string().map_err(|e| format!("{host}: {e}"))?;
    if status != 200 {
        return Err(super::error_message(ep.kind, status, &text, retry.as_deref()));
    }
    serde_json::from_str(&text).map_err(|e| format!("{host} sent a model list that is not JSON: {e}"))
}

fn looks_like_ollama(base: &str) -> bool {
    base.contains(":11434") || base.to_lowercase().contains("ollama")
}

/// The root of an OpenAI-compatible base URL (`http://host:11434/v1` → `http://host:11434`).
pub fn compat_root(base: &str) -> &str {
    base.strip_suffix("/v1").unwrap_or(base)
}

/// Every model the provider lists (all pages).
pub fn list(ep: &Endpoint) -> Result<Vec<Value>, String> {
    let id = ep.id.as_str();
    match ep.kind {
        Kind::Anthropic | Kind::AnthropicCompat => {
            let mut all = Vec::new();
            let mut after: Option<String> = None;
            for _ in 0..20 {
                let url = format!("{}?limit=1000{}", ep.url("models"), after.as_deref().map(|a| format!("&after_id={a}")).unwrap_or_default());
                let (page, next) = parse_anthropic(id, &get_json(ep, &url)?);
                all.extend(page);
                match next {
                    Some(n) => after = Some(n),
                    None => break,
                }
            }
            Ok(all)
        }
        Kind::Gemini => {
            let mut all = Vec::new();
            let mut token: Option<String> = None;
            for _ in 0..20 {
                let url = format!("{}/models?pageSize=1000{}", ep.base, token.as_deref().map(|t| format!("&pageToken={t}")).unwrap_or_default());
                let (page, next) = parse_gemini(id, &get_json(ep, &url)?);
                all.extend(page);
                match next {
                    Some(n) => token = Some(n),
                    None => break,
                }
            }
            Ok(all)
        }
        Kind::OpenRouter => Ok(parse_openrouter(id, &get_json(ep, &ep.url("models"))?)),
        Kind::OpenAi => Ok(parse_openai(id, Kind::OpenAi, &get_json(ep, &ep.url("models"))?)),
        Kind::OpenAiCompat => {
            let tags = || get_json(ep, &format!("{}/api/tags", compat_root(&ep.base))).map(|v| parse_ollama(id, &v));
            if looks_like_ollama(&ep.base) {
                if let Ok(m) = tags() {
                    return Ok(m);
                }
            }
            match get_json(ep, &ep.url("models")) {
                Ok(v) => Ok(parse_openai(id, Kind::OpenAiCompat, &v)),
                Err(e) => tags().map_err(|_| e),
            }
        }
    }
}

/// Settings' "Test connection": lists the models and says how long it took.
pub fn test(ep: &Endpoint) -> Result<Value, String> {
    let t = Instant::now();
    let models = list(ep)?;
    Ok(json!({ "ok": true, "models": models.len(), "ms": t.elapsed().as_millis() as u64, "host": super::provider::host_of(&ep.url("models")) }))
}

#[cfg(test)]
mod tests {
    use super::super::mock::{route, serve};
    use super::*;

    #[test]
    fn anthropic_models() {
        let v = json!({ "data": [{ "type": "model", "id": "claude-opus-5-5", "display_name": "Claude Opus 5.5", "max_input_tokens": 1000000, "max_tokens": 128000,
            "capabilities": { "image_input": { "supported": true }, "thinking": { "supported": true, "types": { "adaptive": { "supported": true } } }, "effort": { "supported": true } } }],
            "has_more": true, "first_id": "claude-opus-5-5", "last_id": "claude-opus-5-5" });
        let (m, next) = parse_anthropic("anthropic", &v);
        assert_eq!(next.as_deref(), Some("claude-opus-5-5"));
        assert_eq!(m[0]["name"], "Claude Opus 5.5");
        assert_eq!(m[0]["context"], 1000000);
        assert_eq!(m[0]["max_output"], 128000);
        assert_eq!(m[0]["vision"], true);
        assert_eq!(m[0]["reasoning"], true);
        assert_eq!(m[0]["temperature"], false);
        assert!(m[0]["price"].is_null());
    }

    #[test]
    fn openai_models_skip_non_chat() {
        let v = json!({ "object": "list", "data": [
            { "id": "gpt-5", "object": "model", "created": 3, "owned_by": "openai" },
            { "id": "text-embedding-3-large", "created": 2 }, { "id": "whisper-1", "created": 1 }, { "id": "gpt-4o", "created": 2 },
            { "id": "o3-mini", "created": 1 }, { "id": "tts-1", "created": 1 }, { "id": "gpt-image-1", "created": 4 } ] });
        let m = parse_openai("openai", Kind::OpenAi, &v);
        let ids: Vec<&str> = m.iter().map(|x| x["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["gpt-5", "gpt-4o", "o3-mini"]);
        assert_eq!(m[0]["reasoning"], true);
        assert_eq!(m[0]["temperature"], false);
        assert_eq!(m[1]["temperature"], true);
        // compatible servers: every id, context when reported
        let v = json!({ "data": [{ "id": "Qwen/Qwen3-32B", "max_model_len": 32768 }, { "id": "local-model" }] });
        let m = parse_openai("custom-vllm", Kind::OpenAiCompat, &v);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0]["context"], 32768);
        assert!(m[1]["context"].is_null());
    }

    #[test]
    fn gemini_models() {
        let v = json!({ "models": [
            { "name": "models/gemini-3-pro", "displayName": "Gemini 3 Pro", "inputTokenLimit": 1048576, "outputTokenLimit": 65536, "supportedGenerationMethods": ["generateContent", "countTokens"], "thinking": true, "temperature": 1.0 },
            { "name": "models/text-embedding-004", "supportedGenerationMethods": ["embedContent"] },
            { "name": "models/gemini-embedding-001", "supportedGenerationMethods": ["generateContent"] } ], "nextPageToken": "p2" });
        let (m, next) = parse_gemini("gemini", &v);
        assert_eq!(next.as_deref(), Some("p2"));
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["id"], "gemini-3-pro");
        assert_eq!(m[0]["context"], 1048576);
        assert_eq!(m[0]["reasoning"], true);
    }

    #[test]
    fn openrouter_models_with_pricing() {
        let v = json!({ "data": [
            { "id": "anthropic/claude-opus-5-5", "name": "Anthropic: Claude Opus 5.5", "context_length": 1000000,
              "architecture": { "input_modalities": ["text", "image"], "output_modalities": ["text"] },
              "pricing": { "prompt": "0.000004", "completion": "0.00002", "input_cache_read": "0.0000002" },
              "top_provider": { "context_length": 1000000, "max_completion_tokens": 128000 },
              "supported_parameters": ["tools", "tool_choice", "reasoning", "max_tokens"] },
            { "id": "openrouter/auto", "name": "Auto Router", "context_length": 2000000, "pricing": { "prompt": "-1", "completion": "-1" } } ] });
        let m = parse_openrouter("openrouter", &v);
        assert_eq!(m[0]["price"], json!({ "input": 4.0, "output": 20.0, "cache_read": 0.2 }));
        assert_eq!(m[0]["vision"], true);
        assert_eq!(m[0]["tools"], true);
        assert_eq!(m[0]["reasoning"], true);
        assert_eq!(m[0]["temperature"], false);
        assert_eq!(m[0]["max_output"], 128000);
        assert!(m[1]["price"].is_null());
    }

    #[test]
    fn ollama_tags() {
        let v = json!({ "models": [{ "name": "qwen3:8b", "model": "qwen3:8b", "size": 5, "details": { "family": "qwen3", "parameter_size": "8.2B", "quantization_level": "Q4_K_M" }, "capabilities": ["completion", "tools", "thinking"] }, { "name": "llava:7b" }] });
        let m = parse_ollama("custom-ollama", &v);
        assert_eq!(m[0]["name"], "qwen3:8b (8.2B, Q4_K_M)");
        assert_eq!(m[0]["tools"], true);
        assert_eq!(m[0]["reasoning"], true);
        assert_eq!(m[0]["vision"], false);
        assert_eq!(m[0]["price"]["input"], 0.0);
        assert!(m[1]["tools"].is_null());
        assert_eq!(compat_root("http://127.0.0.1:11434/v1"), "http://127.0.0.1:11434");
    }

    #[test]
    fn lists_over_http_with_pagination_and_fallback() {
        let page1 = r#"{"data":[{"id":"claude-opus-5-5","display_name":"Claude Opus 5.5"}],"has_more":true,"last_id":"claude-opus-5-5"}"#;
        let page2 = r#"{"data":[{"id":"claude-haiku-5-5","display_name":"Claude Haiku 5.5"}],"has_more":false,"last_id":"claude-haiku-5-5"}"#;
        let m = serve(vec![route("GET /v1/models?limit=1000&after_id=claude-opus-5-5", 200, "application/json", page2), route("GET /v1/models", 200, "application/json", page1)]);
        let ep = Endpoint { id: "anthropic".into(), kind: Kind::Anthropic, base: m.base.clone(), key: Some("sk-ant-test-123456".into()), headers: vec![] };
        let all = list(&ep).unwrap();
        assert_eq!(all.iter().map(|x| x["id"].as_str().unwrap()).collect::<Vec<_>>(), ["claude-opus-5-5", "claude-haiku-5-5"]);
        let seen = m.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].header("x-api-key"), Some("sk-ant-test-123456"));
        assert_eq!(seen[0].header("anthropic-version"), Some(super::super::provider::ANTHROPIC_VERSION));

        // an OpenAI-compatible server without /v1/models: Ollama's /api/tags
        let m = serve(vec![route("GET /api/tags", 200, "application/json", r#"{"models":[{"name":"llama3.1:8b"}]}"#)]);
        let ep = Endpoint { id: "custom-x".into(), kind: Kind::OpenAiCompat, base: format!("{}/v1", m.base), key: None, headers: vec![("X-Team".into(), "re".into())] };
        let all = list(&ep).unwrap();
        assert_eq!(all[0]["id"], "llama3.1:8b");
        let seen = m.seen.lock().unwrap().clone();
        assert!(seen[0].line.starts_with("GET /v1/models"));
        assert_eq!(seen[1].header("x-team"), Some("re"));
        assert!(seen[1].header("authorization").is_none());

        // errors carry the provider's message and a hint
        let m = serve(vec![route("GET /models", 401, "application/json", r#"{"error":{"message":"Incorrect API key provided","code":"invalid_api_key"}}"#)]);
        let ep = Endpoint { id: "openai".into(), kind: Kind::OpenAi, base: m.base.clone(), key: Some("sk-bad-0000000000".into()), headers: vec![] };
        let e = test(&ep).unwrap_err();
        assert!(e.contains("Incorrect API key") && e.contains("Settings"), "{e}");
    }
}
