//! Stream decoders: each provider's streamed reply, translated to one event shape (the Messages
//! API's): `message_start {message: {model, usage}}`, `content_block_start {index, content_block}`,
//! `content_block_delta {index, delta: text_delta | thinking_delta | signature_delta |
//! input_json_delta | details_delta}`, `content_block_stop {index}`, `message_delta {delta:
//! {stop_reason, stop_details?}, usage}`, `message_stop`, and `error {error: {type, message}}`.
//!
//! Stop reasons are normalised to `end_turn`, `tool_use`, `max_tokens` and `refusal`. Usage is
//! normalised to `input_tokens` (uncached), `output_tokens`, `cache_read_input_tokens`,
//! `cache_creation_input_tokens`, `reasoning_tokens` and, where the provider reports a price,
//! `cost` (USD). Thinking and Gemini's signed parts carry `origin` (the provider id) so they are
//! only ever replayed to the provider that made them.

use serde_json::{json, Map, Value};

pub trait Decoder: Send {
    /// One SSE `data` payload (`{"type":"[DONE]"}` for OpenAI's end marker).
    fn feed(&mut self, data: Value, out: &mut Vec<Value>);
    /// The stream ended (end marker or EOF): close what is open.
    fn finish(&mut self, out: &mut Vec<Value>);
    /// No more events are expected.
    fn done(&self) -> bool;
}

fn err_event(e: &Value) -> Value {
    let kind = Some(super::error_kind(e)).filter(|k| !k.is_empty()).unwrap_or_else(|| "error".into());
    let msg = e.get("message").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(|| e.to_string());
    json!({ "type": "error", "error": { "type": kind, "message": msg } })
}

// ---- Anthropic (and Anthropic-compatible): already the right shape ---------------------------

pub struct AnthropicDecoder {
    origin: String,
    started: bool,
    done: bool,
}

impl AnthropicDecoder {
    pub fn new(origin: &str) -> Self {
        AnthropicDecoder { origin: origin.to_owned(), started: false, done: false }
    }
}

impl Decoder for AnthropicDecoder {
    fn feed(&mut self, mut v: Value, out: &mut Vec<Value>) {
        match v.get("type").and_then(Value::as_str).unwrap_or("") {
            "[DONE]" | "ping" | "unparsed" | "" => return,
            "message_start" => self.started = true,
            "message_stop" => self.done = true,
            "error" => self.done = true,
            "content_block_start" => {
                let t = v["content_block"]["type"].as_str().unwrap_or("");
                if t == "thinking" || t == "redacted_thinking" {
                    v["content_block"]["origin"] = json!(self.origin);
                }
            }
            _ => {}
        }
        out.push(v);
    }

    fn finish(&mut self, out: &mut Vec<Value>) {
        if !self.done {
            self.done = true;
            out.push(json!({ "type": "error", "error": { "type": "stream", "message": if self.started { "the stream ended before the reply was complete" } else { "the endpoint sent no reply" } } }));
        }
    }

    fn done(&self) -> bool {
        self.done
    }
}

// ---- shared block bookkeeping ---------------------------------------------------------------

#[derive(Default)]
struct Blocks {
    next: usize,
    text: Option<usize>,
    think: Option<usize>,
    open: Vec<usize>,
    tools: usize,
}

impl Blocks {
    fn start(&mut self, block: Value, out: &mut Vec<Value>) -> usize {
        let i = self.next;
        self.next += 1;
        self.open.push(i);
        out.push(json!({ "type": "content_block_start", "index": i, "content_block": block }));
        i
    }
    fn stop(&mut self, i: usize, out: &mut Vec<Value>) {
        if let Some(p) = self.open.iter().position(|&x| x == i) {
            self.open.remove(p);
            out.push(json!({ "type": "content_block_stop", "index": i }));
        }
        if self.text == Some(i) {
            self.text = None;
        }
        if self.think == Some(i) {
            self.think = None;
        }
    }
    fn delta(i: usize, d: Value, out: &mut Vec<Value>) {
        out.push(json!({ "type": "content_block_delta", "index": i, "delta": d }));
    }
    fn stop_all(&mut self, out: &mut Vec<Value>) {
        for i in self.open.clone() {
            self.stop(i, out);
        }
    }
}

fn finish_message(stop: &str, details: Option<Value>, usage: &Map<String, Value>, out: &mut Vec<Value>) {
    let mut delta = json!({ "stop_reason": stop });
    if let Some(d) = details {
        delta["stop_details"] = d;
    }
    out.push(json!({ "type": "message_delta", "delta": delta, "usage": usage }));
    out.push(json!({ "type": "message_stop" }));
}

// ---- OpenAI Chat Completions (OpenAI, OpenRouter, compatible servers) ------------------------

pub struct OpenAiDecoder {
    origin: String,
    started: bool,
    done: bool,
    finished: bool,
    b: Blocks,
    /// tool call index → (block index)
    calls: Vec<(u64, usize)>,
    stop: Option<String>,
    usage: Map<String, Value>,
    /// OpenRouter reasoning_details of the open thinking block
    details: Vec<Value>,
}

impl OpenAiDecoder {
    pub fn new(origin: &str) -> Self {
        OpenAiDecoder { origin: origin.to_owned(), started: false, done: false, finished: false, b: Blocks::default(), calls: vec![], stop: None, usage: Map::new(), details: vec![] }
    }

    fn close_think(&mut self, out: &mut Vec<Value>) {
        if let Some(i) = self.b.think {
            if !self.details.is_empty() {
                Blocks::delta(i, json!({ "type": "details_delta", "details": std::mem::take(&mut self.details) }), out);
            }
            self.b.stop(i, out);
        }
    }

    fn think(&mut self, out: &mut Vec<Value>) -> usize {
        if let Some(i) = self.b.think {
            return i;
        }
        if let Some(t) = self.b.text {
            self.b.stop(t, out);
        }
        let i = self.b.start(json!({ "type": "thinking", "thinking": "", "origin": self.origin }), out);
        self.b.think = Some(i);
        i
    }

    /// Merges streamed reasoning_details fragments by their `index`.
    fn add_details(&mut self, items: &[Value]) {
        for it in items {
            let idx = it.get("index").cloned();
            match self.details.iter_mut().find(|d| idx.is_some() && d.get("index") == idx.as_ref()) {
                Some(d) => {
                    for (k, v) in it.as_object().into_iter().flatten() {
                        match (d.get_mut(k), v) {
                            (Some(Value::String(a)), Value::String(b)) if k == "text" || k == "summary" || k == "data" => a.push_str(b),
                            (_, Value::Null) => {}
                            _ => {
                                d[k] = v.clone();
                            }
                        }
                    }
                }
                None => self.details.push(it.clone()),
            }
        }
    }
}

pub fn openai_usage(u: &Value) -> Map<String, Value> {
    let n = |v: Option<&Value>| v.and_then(Value::as_u64).unwrap_or(0);
    let prompt = n(u.get("prompt_tokens"));
    let cached = n(u.pointer("/prompt_tokens_details/cached_tokens"));
    let mut m = Map::new();
    m.insert("input_tokens".into(), json!(prompt.saturating_sub(cached)));
    m.insert("output_tokens".into(), json!(n(u.get("completion_tokens"))));
    m.insert("cache_read_input_tokens".into(), json!(cached));
    if let Some(r) = u.pointer("/completion_tokens_details/reasoning_tokens").and_then(Value::as_u64) {
        m.insert("reasoning_tokens".into(), json!(r));
    }
    if let Some(c) = u.get("cost").and_then(Value::as_f64) {
        m.insert("cost".into(), json!(c));
    }
    m
}

impl Decoder for OpenAiDecoder {
    fn feed(&mut self, v: Value, out: &mut Vec<Value>) {
        if v.get("type").and_then(Value::as_str) == Some("[DONE]") {
            self.done = true;
            return;
        }
        if v.get("type").and_then(Value::as_str) == Some("unparsed") {
            return;
        }
        if let Some(e) = v.get("error") {
            out.push(err_event(e));
            self.done = true;
            self.finished = true;
            return;
        }
        if !self.started {
            self.started = true;
            out.push(json!({ "type": "message_start", "message": { "model": v.get("model").cloned().unwrap_or(json!("")), "usage": {} } }));
        }
        if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
            self.usage = openai_usage(u);
        }
        let Some(ch) = v.get("choices").and_then(Value::as_array).and_then(|a| a.first()) else { return };
        let d = ch.get("delta").or_else(|| ch.get("message")).cloned().unwrap_or(Value::Null);
        let reasoning = d.get("reasoning_content").and_then(Value::as_str).filter(|s| !s.is_empty()).or_else(|| d.get("reasoning").and_then(Value::as_str).filter(|s| !s.is_empty()));
        if let Some(r) = reasoning {
            let i = self.think(out);
            Blocks::delta(i, json!({ "type": "thinking_delta", "thinking": r }), out);
        }
        if let Some(items) = d.get("reasoning_details").and_then(Value::as_array).filter(|a| !a.is_empty()) {
            self.think(out);
            let items = items.clone();
            self.add_details(&items);
        }
        if let Some(t) = d.get("content").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            self.close_think(out);
            let i = match self.b.text {
                Some(i) => i,
                None => {
                    let i = self.b.start(json!({ "type": "text", "text": "" }), out);
                    self.b.text = Some(i);
                    i
                }
            };
            Blocks::delta(i, json!({ "type": "text_delta", "text": t }), out);
        }
        if let Some(calls) = d.get("tool_calls").and_then(Value::as_array) {
            for (pos, c) in calls.iter().enumerate() {
                let idx = c.get("index").and_then(Value::as_u64).unwrap_or(pos as u64);
                let args = c.pointer("/function/arguments").and_then(Value::as_str).unwrap_or("");
                let block = match self.calls.iter().find(|(k, _)| *k == idx) {
                    Some((_, b)) => *b,
                    None => {
                        self.close_think(out);
                        if let Some(t) = self.b.text {
                            self.b.stop(t, out);
                        }
                        let id = c.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned).unwrap_or_else(|| format!("call_{}", self.b.tools));
                        self.b.tools += 1;
                        let name = c.pointer("/function/name").and_then(Value::as_str).unwrap_or("");
                        let b = self.b.start(json!({ "type": "tool_use", "id": id, "name": name, "input": {} }), out);
                        self.calls.push((idx, b));
                        b
                    }
                };
                if !args.is_empty() {
                    Blocks::delta(block, json!({ "type": "input_json_delta", "partial_json": args }), out);
                }
            }
        }
        if let Some(f) = ch.get("finish_reason").and_then(Value::as_str) {
            self.stop = Some(
                match f {
                    "length" => "max_tokens",
                    "tool_calls" | "function_call" => "tool_use",
                    "content_filter" => "refusal",
                    _ => "end_turn",
                }
                .to_owned(),
            );
        }
    }

    fn finish(&mut self, out: &mut Vec<Value>) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.done = true;
        if !self.started {
            out.push(json!({ "type": "error", "error": { "type": "stream", "message": "the endpoint sent no reply" } }));
            return;
        }
        self.close_think(out);
        self.b.stop_all(out);
        let mut stop = self.stop.clone().unwrap_or_else(|| "end_turn".into());
        // some servers say "stop" after tool calls
        if stop == "end_turn" && self.b.tools > 0 {
            stop = "tool_use".into();
        }
        let details = (stop == "refusal").then(|| json!({ "type": "refusal", "category": "content_filter", "explanation": null }));
        finish_message(&stop, details, &self.usage, out);
    }

    fn done(&self) -> bool {
        self.done
    }
}

// ---- Gemini ---------------------------------------------------------------------------------

pub struct GeminiDecoder {
    origin: String,
    started: bool,
    finished: bool,
    b: Blocks,
    stop: Option<String>,
    details: Option<Value>,
    usage: Map<String, Value>,
}

impl GeminiDecoder {
    pub fn new(origin: &str) -> Self {
        GeminiDecoder { origin: origin.to_owned(), started: false, finished: false, b: Blocks::default(), stop: None, details: None, usage: Map::new() }
    }
}

pub fn gemini_usage(u: &Value) -> Map<String, Value> {
    let n = |k: &str| u.get(k).and_then(Value::as_u64).unwrap_or(0);
    let cached = n("cachedContentTokenCount");
    let mut m = Map::new();
    m.insert("input_tokens".into(), json!(n("promptTokenCount").saturating_sub(cached)));
    m.insert("output_tokens".into(), json!(n("candidatesTokenCount") + n("thoughtsTokenCount")));
    m.insert("cache_read_input_tokens".into(), json!(cached));
    if u.get("thoughtsTokenCount").is_some() {
        m.insert("reasoning_tokens".into(), json!(n("thoughtsTokenCount")));
    }
    m
}

const GEMINI_REFUSALS: &[&str] = &["SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY", "LANGUAGE"];

impl Decoder for GeminiDecoder {
    fn feed(&mut self, v: Value, out: &mut Vec<Value>) {
        if matches!(v.get("type").and_then(Value::as_str), Some("[DONE]" | "unparsed")) {
            return;
        }
        let v = match v {
            Value::Array(mut a) if !a.is_empty() => a.remove(0),
            v => v,
        };
        if let Some(e) = v.get("error") {
            out.push(err_event(e));
            self.finished = true;
            return;
        }
        if !self.started {
            self.started = true;
            out.push(json!({ "type": "message_start", "message": { "model": v.get("modelVersion").cloned().unwrap_or(json!("")), "usage": {} } }));
        }
        if let Some(u) = v.get("usageMetadata") {
            self.usage = gemini_usage(u);
        }
        if let Some(r) = v.pointer("/promptFeedback/blockReason").and_then(Value::as_str) {
            self.stop = Some("refusal".into());
            self.details = Some(json!({ "type": "refusal", "category": r, "explanation": v.pointer("/promptFeedback/blockReasonMessage") }));
        }
        let Some(cand) = v.get("candidates").and_then(Value::as_array).and_then(|a| a.first()) else { return };
        for p in cand.pointer("/content/parts").and_then(Value::as_array).into_iter().flatten() {
            let sig = p.get("thoughtSignature").and_then(Value::as_str);
            if let Some(fc) = p.get("functionCall") {
                if let Some(t) = self.b.text {
                    self.b.stop(t, out);
                }
                if let Some(t) = self.b.think {
                    self.b.stop(t, out);
                }
                let id = fc.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned).unwrap_or_else(|| format!("gem_{}", self.b.tools));
                self.b.tools += 1;
                let mut block = json!({ "type": "tool_use", "id": id, "name": fc.get("name").cloned().unwrap_or(json!("")), "input": {}, "origin": self.origin });
                if let Some(s) = sig {
                    block["signature"] = json!(s);
                }
                let i = self.b.start(block, out);
                let args = fc.get("args").cloned().filter(Value::is_object).unwrap_or_else(|| json!({}));
                Blocks::delta(i, json!({ "type": "input_json_delta", "partial_json": args.to_string() }), out);
                self.b.stop(i, out);
                continue;
            }
            let text = p.get("text").and_then(Value::as_str).unwrap_or("");
            if p.get("thought").and_then(Value::as_bool) == Some(true) {
                let i = match self.b.think {
                    Some(i) => i,
                    None => {
                        if let Some(t) = self.b.text {
                            self.b.stop(t, out);
                        }
                        let i = self.b.start(json!({ "type": "thinking", "thinking": "", "origin": self.origin }), out);
                        self.b.think = Some(i);
                        i
                    }
                };
                if !text.is_empty() {
                    Blocks::delta(i, json!({ "type": "thinking_delta", "thinking": text }), out);
                }
                if let Some(s) = sig {
                    Blocks::delta(i, json!({ "type": "signature_delta", "signature": s }), out);
                }
            } else if !text.is_empty() || sig.is_some() {
                if let Some(t) = self.b.think {
                    self.b.stop(t, out);
                }
                let i = match self.b.text {
                    Some(i) => i,
                    None => {
                        let i = self.b.start(json!({ "type": "text", "text": "", "origin": self.origin }), out);
                        self.b.text = Some(i);
                        i
                    }
                };
                if !text.is_empty() {
                    Blocks::delta(i, json!({ "type": "text_delta", "text": text }), out);
                }
                if let Some(s) = sig {
                    Blocks::delta(i, json!({ "type": "signature_delta", "signature": s }), out);
                }
            }
        }
        if let Some(f) = cand.get("finishReason").and_then(Value::as_str) {
            let s = if f == "MAX_TOKENS" {
                "max_tokens"
            } else if GEMINI_REFUSALS.contains(&f) {
                self.details = Some(json!({ "type": "refusal", "category": f.to_lowercase(), "explanation": cand.get("finishMessage") }));
                "refusal"
            } else {
                "end_turn"
            };
            self.stop = Some(s.into());
        }
    }

    fn finish(&mut self, out: &mut Vec<Value>) {
        if self.finished {
            return;
        }
        self.finished = true;
        if !self.started {
            out.push(json!({ "type": "error", "error": { "type": "stream", "message": "the endpoint sent no reply" } }));
            return;
        }
        self.b.stop_all(out);
        let mut stop = self.stop.clone().unwrap_or_else(|| "end_turn".into());
        if stop == "end_turn" && self.b.tools > 0 {
            stop = "tool_use".into();
        }
        finish_message(&stop, self.details.take(), &self.usage, out);
    }

    fn done(&self) -> bool {
        self.finished
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::SseParser;
    use super::*;

    /// Runs an SSE fixture through the parser and a decoder.
    pub fn decode_sse(text: &str, dec: &mut dyn Decoder) -> Vec<Value> {
        let mut sse = SseParser::default();
        let mut out = Vec::new();
        for line in text.lines().chain(std::iter::once("")) {
            if let Some(v) = sse.feed(line) {
                dec.feed(v, &mut out);
                if dec.done() {
                    break;
                }
            }
        }
        dec.finish(&mut out);
        out
    }

    /// The UI's accumulator in miniature: the finished message from normalised events.
    pub fn fold(events: &[Value]) -> Value {
        let mut content: Vec<Value> = vec![];
        let mut partial: std::collections::HashMap<usize, String> = Default::default();
        let mut msg = json!({ "content": [], "stop_reason": null, "usage": {}, "model": "", "error": null });
        for e in events {
            match e["type"].as_str().unwrap() {
                "message_start" => msg["model"] = e["message"]["model"].clone(),
                "content_block_start" => {
                    let i = e["index"].as_u64().unwrap() as usize;
                    assert_eq!(i, content.len(), "block indexes are dense and in order");
                    content.push(e["content_block"].clone());
                }
                "content_block_delta" => {
                    let i = e["index"].as_u64().unwrap() as usize;
                    let b = &mut content[i];
                    let d = &e["delta"];
                    match d["type"].as_str().unwrap() {
                        "text_delta" => b["text"] = json!(format!("{}{}", b["text"].as_str().unwrap_or(""), d["text"].as_str().unwrap())),
                        "thinking_delta" => b["thinking"] = json!(format!("{}{}", b["thinking"].as_str().unwrap_or(""), d["thinking"].as_str().unwrap())),
                        "signature_delta" => b["signature"] = json!(format!("{}{}", b["signature"].as_str().unwrap_or(""), d["signature"].as_str().unwrap())),
                        "input_json_delta" => partial.entry(i).or_default().push_str(d["partial_json"].as_str().unwrap()),
                        "details_delta" => b["details"] = d["details"].clone(),
                        other => panic!("unknown delta {other}"),
                    }
                }
                "content_block_stop" => {
                    let i = e["index"].as_u64().unwrap() as usize;
                    if content[i]["type"] == "tool_use" {
                        content[i]["input"] = serde_json::from_str(partial.get(&i).map(String::as_str).unwrap_or("{}")).unwrap();
                    }
                }
                "message_delta" => {
                    msg["stop_reason"] = e["delta"]["stop_reason"].clone();
                    if let Some(d) = e["delta"].get("stop_details") {
                        msg["stop_details"] = d.clone();
                    }
                    msg["usage"] = e["usage"].clone();
                }
                "message_stop" => {}
                "error" => msg["error"] = e["error"].clone(),
                other => panic!("unknown event {other}"),
            }
        }
        msg["content"] = json!(content);
        msg
    }

    const OPENAI: &str = include_str!("../../tests/fixtures/assistant/openai_tools.sse");
    const OPENROUTER: &str = include_str!("../../tests/fixtures/assistant/openrouter_reasoning.sse");
    const GEMINI: &str = include_str!("../../tests/fixtures/assistant/gemini_tools.sse");
    const ANTHROPIC: &str = include_str!("../../tests/fixtures/assistant/anthropic_tools.sse");
    const OLLAMA: &str = include_str!("../../tests/fixtures/assistant/ollama_compat.sse");

    #[test]
    fn openai_stream_with_parallel_tool_calls() {
        let m = fold(&decode_sse(OPENAI, &mut OpenAiDecoder::new("openai")));
        assert_eq!(m["model"], "gpt-5-2026");
        let c = m["content"].as_array().unwrap();
        assert_eq!(c[0], json!({ "type": "text", "text": "Let me read both." }));
        assert_eq!(c[1], json!({ "type": "tool_use", "id": "call_A", "name": "read_memory", "input": { "address": "0x10", "size": 4 } }));
        assert_eq!(c[2], json!({ "type": "tool_use", "id": "call_B", "name": "disassemble", "input": { "address": "0x20" } }));
        assert_eq!(m["stop_reason"], "tool_use");
        assert_eq!(m["usage"], json!({ "input_tokens": 80, "output_tokens": 40, "cache_read_input_tokens": 20, "reasoning_tokens": 12 }));
    }

    #[test]
    fn openrouter_reasoning_and_cost() {
        let m = fold(&decode_sse(OPENROUTER, &mut OpenAiDecoder::new("openrouter")));
        let c = m["content"].as_array().unwrap();
        assert_eq!(c[0]["type"], "thinking");
        assert_eq!(c[0]["thinking"], "Think about it.");
        assert_eq!(c[0]["origin"], "openrouter");
        assert_eq!(c[0]["details"], json!([{ "type": "reasoning.text", "text": "Think about it.", "signature": "sigX", "format": "anthropic-claude-v1", "index": 0 }]));
        assert_eq!(c[1]["text"], "Answer.");
        assert_eq!(m["stop_reason"], "end_turn");
        assert_eq!(m["usage"]["cost"], 0.00042);
    }

    #[test]
    fn ollama_compatible_without_done_marker() {
        let m = fold(&decode_sse(OLLAMA, &mut OpenAiDecoder::new("custom-ollama")));
        let c = m["content"].as_array().unwrap();
        assert_eq!(c[0]["thinking"], "hmm");
        assert_eq!(c[1]["text"], "Hi");
        assert_eq!(c[2]["name"], "list_modules");
        assert_eq!(c[2]["id"], "call_0");
        // "stop" after a tool call still runs the tools
        assert_eq!(m["stop_reason"], "tool_use");
    }

    #[test]
    fn gemini_stream_with_thoughts_and_function_calls() {
        let m = fold(&decode_sse(GEMINI, &mut GeminiDecoder::new("gemini")));
        assert_eq!(m["model"], "gemini-3-pro");
        let c = m["content"].as_array().unwrap();
        assert_eq!(c[0], json!({ "type": "thinking", "thinking": "Plan: read memory.", "origin": "gemini" }));
        assert_eq!(c[1], json!({ "type": "text", "text": "Reading now.", "origin": "gemini" }));
        assert_eq!(c[2], json!({ "type": "tool_use", "id": "gem_0", "name": "read_memory", "input": { "address": "0x10", "size": 8 }, "origin": "gemini", "signature": "SIG1" }));
        assert_eq!(m["stop_reason"], "tool_use");
        assert_eq!(m["usage"], json!({ "input_tokens": 90, "output_tokens": 30, "cache_read_input_tokens": 10, "reasoning_tokens": 5 }));
    }

    #[test]
    fn gemini_refusal_and_errors() {
        let mut d = GeminiDecoder::new("gemini");
        let mut out = vec![];
        d.feed(json!({ "promptFeedback": { "blockReason": "PROHIBITED_CONTENT" }, "modelVersion": "gemini-3-pro" }), &mut out);
        d.finish(&mut out);
        let m = fold(&out);
        assert_eq!(m["stop_reason"], "refusal");
        assert_eq!(m["stop_details"]["category"], "PROHIBITED_CONTENT");
        let mut d = GeminiDecoder::new("gemini");
        let mut out = vec![];
        d.feed(json!({ "error": { "code": 429, "message": "quota", "status": "RESOURCE_EXHAUSTED" } }), &mut out);
        d.finish(&mut out);
        assert_eq!(fold(&out)["error"]["type"], "RESOURCE_EXHAUSTED");
        let mut d = OpenAiDecoder::new("openrouter");
        let mut out = vec![];
        d.feed(json!({ "id": "x", "model": "m", "choices": [{ "delta": { "content": "a" } }] }), &mut out);
        d.feed(json!({ "error": { "code": 502, "message": "upstream died" } }), &mut out);
        d.finish(&mut out);
        assert_eq!(fold(&out)["error"]["message"], "upstream died");
        let mut d = OpenAiDecoder::new("openai");
        let mut out = vec![];
        d.feed(json!({ "model": "m", "choices": [{ "delta": { "content": "x" }, "finish_reason": "length" }] }), &mut out);
        d.finish(&mut out);
        assert_eq!(fold(&out)["stop_reason"], "max_tokens");
    }

    #[test]
    fn anthropic_passthrough_marks_thinking() {
        let m = fold(&decode_sse(ANTHROPIC, &mut AnthropicDecoder::new("anthropic")));
        let c = m["content"].as_array().unwrap();
        assert_eq!(c[0]["origin"], "anthropic");
        assert_eq!(c[0]["signature"], "sig");
        assert_eq!(c[1]["text"], "Reading.");
        assert_eq!(c[2]["input"], json!({ "address": "0x10", "size": 4 }));
        assert_eq!(m["stop_reason"], "tool_use");
        assert!(m["error"].is_null());
        // a cut-off stream is an error, not a silent end
        let m = fold(&decode_sse(&ANTHROPIC[..ANTHROPIC.find("message_delta").unwrap()], &mut AnthropicDecoder::new("anthropic")));
        assert!(m["error"]["message"].as_str().unwrap().contains("ended"));
    }
}
