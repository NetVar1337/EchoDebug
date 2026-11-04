//! The MCP server's protocol features, per revision: version negotiation, sessions, 2026-07-28's
//! stateless requests (headers, server/discover, subscriptions/listen, input_required elicitation),
//! pagination, structured output, list_changed, logging, progress, cancellation, JSON-RPC errors,
//! the health endpoint and stdio (embedded and bridged).

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use echo_debug_relay::{bind, router, run, Relay};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tower::ServiceExt;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const MODERN: &str = "2026-07-28";

async fn start() -> (SocketAddr, Relay) {
    start_with(Relay::new("1.2.3", Duration::from_secs(5)).with_local_backend(false)).await
}

async fn start_with(relay: Relay) -> (SocketAddr, Relay) {
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay.clone()));
    (addr, relay)
}

async fn ws(addr: SocketAddr, path: &str) -> Ws {
    connect_async(format!("ws://{addr}{path}")).await.unwrap().0
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

async fn recv_until(ws: &mut Ws, pred: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Message::Text(t) = ws.next().await.unwrap().unwrap() {
                let v: Value = serde_json::from_str(t.as_str()).unwrap();
                if pred(&v) {
                    return v;
                }
            }
        }
    })
    .await
    .expect("timed out waiting for frame")
}

/// A `/client` socket that set the policy.
async fn policy(addr: SocketAddr, p: Value) -> Ws {
    let mut c = ws(addr, "/client").await;
    let mut m = p.as_object().unwrap().clone();
    m.insert("type".into(), json!("mcp_policy"));
    m.insert("id".into(), json!(900));
    send(&mut c, Value::Object(m)).await;
    let r = recv_until(&mut c, |v| v["id"] == 900).await;
    assert_eq!(r["type"], "mcp_policy_result", "{r}");
    c
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    text: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }
    /// The JSON-RPC messages of an SSE body.
    fn events(&self) -> Vec<Value> {
        sse(&self.text)
    }
}

fn sse(text: &str) -> Vec<Value> {
    text.split("\n\n")
        .filter_map(|ev| {
            let data: Vec<&str> = ev.lines().filter_map(|l| l.strip_prefix("data:").map(|d| d.trim_start())).collect();
            (!data.is_empty()).then(|| serde_json::from_str(&data.join("\n")).ok()).flatten()
        })
        .collect()
}

async fn post(relay: &Relay, headers: &[(&str, String)], body: Value) -> Resp {
    let mut req = Request::post("/mcp").header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, v.as_str());
    }
    let resp = router(relay.clone()).oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    Resp { status, headers, text: String::from_utf8_lossy(&bytes).into_owned() }
}

fn meta(caps: Value) -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientInfo": { "name": "test-client", "version": "9.1" },
        "io.modelcontextprotocol/clientCapabilities": caps,
    })
}

/// A 2026-07-28 request with its headers.
fn modern(id: u64, method: &str, mut params: Value, caps: Value) -> (Vec<(&'static str, String)>, Value) {
    let mut m = meta(caps);
    if let Some(extra) = params.get("_meta").and_then(Value::as_object).cloned() {
        m.as_object_mut().unwrap().extend(extra);
    }
    params["_meta"] = m;
    let mut h = vec![("mcp-protocol-version", MODERN.to_owned()), ("mcp-method", method.to_owned()), ("accept", "application/json, text/event-stream".to_owned())];
    let name = match method {
        "tools/call" | "prompts/get" => params["name"].as_str().map(str::to_owned),
        "resources/read" => params["uri"].as_str().map(str::to_owned),
        _ => None,
    };
    if let Some(n) = name {
        h.push(("mcp-name", echo_debug_relay::mcp_server::header_encode(&n)));
    }
    (h, json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
}

async fn modern_call(relay: &Relay, id: u64, method: &str, params: Value, caps: Value) -> Resp {
    let (h, body) = modern(id, method, params, caps);
    post(relay, &h, body).await
}

fn legacy(id: u64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

async fn initialize(relay: &Relay, version: &str, caps: Value) -> (String, Value) {
    let r = post(relay, &[], legacy(1, "initialize", json!({ "protocolVersion": version, "capabilities": caps, "clientInfo": { "name": "legacy-client", "version": "1.0" } }))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let sid = r.headers.get("mcp-session-id").expect("session id").to_str().unwrap().to_owned();
    (sid, r.json())
}

#[tokio::test]
async fn version_negotiation_and_sessions() {
    let (addr, relay) = start().await;
    for (asked, got) in [("2025-03-26", "2025-03-26"), ("2025-06-18", "2025-06-18"), ("2025-11-25", "2025-11-25"), ("2024-11-05", "2024-11-05"), ("1999-01-01", "2025-11-25"), (MODERN, "2025-11-25")] {
        let (sid, r) = initialize(&relay, asked, json!({})).await;
        assert_eq!(r["result"]["protocolVersion"], got, "{asked}");
        assert_eq!(sid.len(), 32);
        assert_eq!(r["result"]["capabilities"]["tools"]["listChanged"], true);
    }
    // the session carries its version: 2025-03-26 results have no structuredContent / titles
    let (old, _) = initialize(&relay, "2025-03-26", json!({})).await;
    let h = [("mcp-session-id", old.clone())];
    let r = post(&relay, &h, legacy(2, "tools/list", json!({}))).await.json();
    let read = r["result"]["tools"].as_array().unwrap().iter().find(|t| t["name"] == "read_memory").unwrap().clone();
    assert!(read.get("title").is_none() && read.get("outputSchema").is_none(), "{read}");
    assert_eq!(read["annotations"]["readOnlyHint"], true);
    let (new, _) = initialize(&relay, "2025-06-18", json!({})).await;
    let r = post(&relay, &[("mcp-session-id", new.clone())], legacy(3, "tools/list", json!({}))).await.json();
    let read = r["result"]["tools"].as_array().unwrap().iter().find(|t| t["name"] == "read_memory").unwrap().clone();
    assert_eq!(read["title"], "Read memory");
    assert_eq!(read["outputSchema"]["properties"]["data"]["type"], "string");
    assert!(r["result"].get("resultType").is_none(), "legacy results carry no resultType");
    let r = post(&relay, &[("mcp-session-id", new.clone())], legacy(3, "prompts/list", json!({}))).await.json();
    assert!(r["result"]["prompts"][0]["title"].is_string());
    // ping
    let r = post(&relay, &h, legacy(4, "ping", json!({}))).await.json();
    assert_eq!(r, json!({ "jsonrpc": "2.0", "id": 4, "result": {} }));
    // an unsupported MCP-Protocol-Version header is a 400
    let r = post(&relay, &[("mcp-protocol-version", "1999-01-01".into())], legacy(5, "ping", json!({}))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.json()["error"]["code"], -32022);

    // the panel lists the sessions with what initialize said
    let mut c = ws(addr, "/client").await;
    send(&mut c, json!({ "type": "mcp_sessions", "id": 1 })).await;
    let s = recv_until(&mut c, |v| v["id"] == 1).await;
    let mine = s["sessions"].as_array().unwrap().iter().find(|x| x["id"] == old).unwrap().clone();
    assert_eq!(mine["client"]["name"], "legacy-client");
    assert_eq!(mine["protocolVersion"], "2025-03-26");
    assert_eq!(mine["era"], "session");
    assert_eq!(mine["transport"], "http");
    // disconnect: the session id is gone (404), a client must initialize again
    send(&mut c, json!({ "type": "mcp_disconnect", "id": 2, "session": old })).await;
    assert_eq!(recv_until(&mut c, |v| v["id"] == 2).await["disconnected"], true);
    let r = post(&relay, &h, legacy(6, "ping", json!({}))).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.json()["error"]["code"], 404);
    // DELETE ends a session too
    let del = |sid: &str| router(relay.clone()).oneshot(Request::delete("/mcp").header("mcp-session-id", sid).body(Body::empty()).unwrap());
    assert_eq!(del(&new).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert_eq!(del(&new).await.unwrap().status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn modern_requests_discover_headers_and_errors() {
    let (_, relay) = start().await;
    // server/discover: supported versions newest first, identity in _meta, cache hints
    let r = modern_call(&relay, 1, "server/discover", json!({}), json!({})).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.text);
    let d = r.json()["result"].clone();
    assert_eq!(d["resultType"], "complete");
    assert_eq!(d["supportedVersions"], json!(["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]));
    assert_eq!(d["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "echodebug");
    assert!(d["ttlMs"].is_u64() && d["cacheScope"].is_string());
    // also as a dual-era probe without _meta
    let r = post(&relay, &[], legacy(2, "server/discover", json!({}))).await.json();
    assert_eq!(r["result"]["supportedVersions"][0], MODERN);

    // tools/list: resultType, serverInfo, cache fields, titles
    let r = modern_call(&relay, 3, "tools/list", json!({}), json!({})).await.json();
    let res = &r["result"];
    assert_eq!(res["resultType"], "complete");
    assert_eq!((res["ttlMs"].as_u64(), res["cacheScope"].as_str()), (Some(0), Some("private")));
    assert_eq!(res["_meta"]["io.modelcontextprotocol/serverInfo"]["version"], "1.2.3");
    assert!(res["tools"].as_array().unwrap().iter().all(|t| t["title"].is_string()));

    // header checks: missing, mismatched, base64 Mcp-Name
    let (mut h, body) = modern(4, "tools/call", json!({ "name": "is_alive", "arguments": {} }), json!({}));
    h.retain(|(k, _)| *k != "mcp-name");
    let r = post(&relay, &h, body.clone()).await;
    assert_eq!((r.status, r.json()["error"]["code"].as_i64()), (StatusCode::BAD_REQUEST, Some(-32020)), "{}", r.text);
    h.push(("mcp-name", "status".into()));
    let r = post(&relay, &h, body.clone()).await;
    assert_eq!(r.json()["error"]["code"], -32020);
    assert!(r.json()["error"]["message"].as_str().unwrap().contains("does not match"));
    h.pop();
    h.push(("mcp-name", "=?base64?aXNfYWxpdmU=?=".into()));
    assert_eq!(post(&relay, &h, body.clone()).await.status, StatusCode::OK);
    let (mut h2, body2) = modern(5, "tools/list", json!({}), json!({}));
    h2[0].1 = "2025-06-18".into();
    assert_eq!(post(&relay, &h2, body2).await.json()["error"]["code"], -32020);

    // unsupported version: 400 with the supported list
    let (mut h, mut body) = modern(6, "tools/list", json!({}), json!({}));
    body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
    h[0].1 = "2099-01-01".into();
    let r = post(&relay, &h, body).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let e = r.json()["error"].clone();
    assert_eq!((e["code"].as_i64(), e["data"]["requested"].as_str()), (Some(-32022), Some("2099-01-01")));
    assert_eq!(e["data"]["supported"][0], MODERN);
    // missing clientCapabilities: -32602, 400
    let (h, mut body) = modern(7, "tools/list", json!({}), json!({}));
    body["params"]["_meta"].as_object_mut().unwrap().remove("io.modelcontextprotocol/clientCapabilities");
    let r = post(&relay, &h, body).await;
    assert_eq!((r.status, r.json()["error"]["code"].as_i64()), (StatusCode::BAD_REQUEST, Some(-32602)));
    // unknown method: 404 + -32601; legacy-only methods are unknown in 2026-07-28
    for m in ["bogus/method", "logging/setLevel", "resources/subscribe", "initialize"] {
        let r = modern_call(&relay, 8, m, json!({}), json!({})).await;
        assert_eq!((r.status, r.json()["error"]["code"].as_i64()), (StatusCode::NOT_FOUND, Some(-32601)), "{m}");
    }
    // a resource that does not exist: -32602 here, -32002 in legacy revisions
    let r = modern_call(&relay, 9, "resources/read", json!({ "uri": "echodebug://nope" }), json!({})).await.json();
    assert_eq!(r["error"]["code"], -32602);
    assert_eq!(r["error"]["data"]["uri"], "echodebug://nope");
    let r = post(&relay, &[], legacy(10, "resources/read", json!({ "uri": "echodebug://nope" }))).await.json();
    assert_eq!(r["error"]["code"], -32002);
    // resources/read carries cache hints and resultType
    let r = modern_call(&relay, 11, "resources/read", json!({ "uri": "echodebug://status" }), json!({})).await.json();
    assert_eq!(r["result"]["resultType"], "complete");
    assert_eq!(r["result"]["ttlMs"], 0);
    // GET without a session or SSE accept: 405 that points at the health endpoint
    let resp = router(relay.clone()).oneshot(Request::get("/mcp").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn json_rpc_errors() {
    let (_, relay) = start().await;
    let raw = |body: &'static str| {
        let relay = relay.clone();
        async move {
            let resp = router(relay).oneshot(Request::post("/mcp").body(Body::from(body)).unwrap()).await.unwrap();
            let s = resp.status();
            let b = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
            (s, serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null))
        }
    };
    let (s, r) = raw("{not json").await;
    assert_eq!((s, r["error"]["code"].as_i64(), r["id"].clone()), (StatusCode::BAD_REQUEST, Some(-32700), Value::Null));
    let (_, r) = raw(r#"{"id":1,"method":"ping"}"#).await;
    assert_eq!(r["error"]["code"], -32600, "missing jsonrpc");
    let (_, r) = raw(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).await;
    assert_eq!(r["error"]["code"], -32600, "null id");
    let (_, r) = raw(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[1]}"#).await;
    assert_eq!(r["error"]["code"], -32602);
    let (_, r) = raw(r#"[]"#).await;
    assert_eq!(r["error"]["code"], -32600);
    let (_, r) = raw(r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope"}}"#).await;
    assert_eq!(r["error"]["code"], -32602);
    let (_, r) = raw(r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_memory","arguments":"x"}}"#).await;
    assert_eq!(r["error"]["code"], -32602);
    let (_, r) = raw(r#"{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"explain_function"}}"#).await;
    assert_eq!(r["error"]["code"], -32602, "missing required prompt argument");
    let (_, r) = raw(r#"{"jsonrpc":"2.0","id":5,"method":"no/such"}"#).await;
    assert_eq!(r["error"]["code"], -32601);
    let (_, r) = raw(r#"{"jsonrpc":"2.0","id":6,"method":"logging/setLevel","params":{"level":"loud"}}"#).await;
    assert_eq!(r["error"]["code"], -32602);
    // a missing required tool argument is a tool error the model can fix, not a protocol error
    let (_, r) = raw(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_memory","arguments":{"address":"0x1"}}}"#).await;
    assert_eq!(r["result"]["isError"], true);
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("missing required argument"), "{r}");
    // batches answer every request, skip notifications, and refuse 2026-07-28 messages
    let (_, r) = raw(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/x"},{"jsonrpc":"2.0","id":2,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}]"#).await;
    let arr = r.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert!(arr.iter().any(|m| m["id"] == 1 && m["result"] == json!({})));
    assert!(arr.iter().any(|m| m["id"] == 2 && m["error"]["code"] == -32600));
}

#[tokio::test]
async fn pagination_cursors() {
    let (_, relay) = start_with(Relay::new("1.2.3", Duration::from_secs(5)).with_local_backend(false).with_mcp_page_size(25)).await;
    let mut names = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let r = modern_call(&relay, 1, "tools/list", params, json!({})).await.json();
        let page = r["result"]["tools"].as_array().unwrap().clone();
        assert!(page.len() <= 25);
        names.extend(page.iter().map(|t| t["name"].as_str().unwrap().to_owned()));
        pages += 1;
        match r["result"]["nextCursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert!(pages > 2, "{pages} pages");
    let mut dedup = names.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), names.len(), "no tool twice");
    // the same set as one big page on a default relay
    let (_, big) = start().await;
    let r = modern_call(&big, 2, "tools/list", json!({}), json!({})).await.json();
    assert_eq!(r["result"]["tools"].as_array().unwrap().len(), names.len());
    assert!(r["result"].get("nextCursor").is_none());
    // legacy requests paginate the same way; a cursor of another list or garbage is invalid params
    let r = post(&relay, &[], legacy(3, "tools/list", json!({}))).await.json();
    let next = r["result"]["nextCursor"].as_str().unwrap().to_owned();
    let r2 = post(&relay, &[], legacy(4, "tools/list", json!({ "cursor": next.clone() }))).await.json();
    assert_eq!(r2["result"]["tools"][0]["name"], names[25]);
    assert_eq!(post(&relay, &[], legacy(5, "prompts/list", json!({ "cursor": next }))).await.json()["error"]["code"], -32602);
    assert_eq!(post(&relay, &[], legacy(6, "tools/list", json!({ "cursor": "zz" }))).await.json()["error"]["code"], -32602);
}

#[tokio::test]
async fn structured_output_and_resource_links() {
    let (addr, relay) = start().await;
    let mut agent = ws(addr, "/agent").await;
    // wait for the agent to register
    let mut c = ws(addr, "/client").await;
    for _ in 0..50 {
        send(&mut c, json!({ "type": "status", "id": 1 })).await;
        if recv_until(&mut c, |v| v["id"] == 1).await["agent"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let answer = tokio::spawn(async move {
        for _ in 0..2 {
            let req = recv_until(&mut agent, |v| v["type"] == "read").await;
            send(&mut agent, json!({ "type": "read_result", "id": req["id"], "success": true, "data": "beef" })).await;
        }
    });
    let args = json!({ "name": "read_memory", "arguments": { "address": "game.exe+0x10", "size": 2 } });
    let r = modern_call(&relay, 1, "tools/call", args.clone(), json!({})).await.json();
    let res = &r["result"];
    assert_eq!(res["resultType"], "complete");
    assert_eq!(res["isError"], false);
    assert_eq!(res["structuredContent"], json!({ "success": true, "data": "beef" }));
    let link = res["content"].as_array().unwrap().iter().find(|c| c["type"] == "resource_link").unwrap().clone();
    assert_eq!(link["uri"], "echodebug://memory/game.exe%2B0x10/2");
    // the link is readable as a resource template (here without an app window: a clear error)
    let rr = modern_call(&relay, 2, "resources/read", json!({ "uri": link["uri"] }), json!({})).await.json();
    assert!(rr["error"]["message"].as_str().unwrap().contains("app window"), "{rr}");
    // 2025-03-26: text only
    let r = post(&relay, &[("mcp-protocol-version", "2025-03-26".into())], legacy(3, "tools/call", args)).await.json();
    assert!(r["result"].get("structuredContent").is_none());
    assert_eq!(r["result"]["content"].as_array().unwrap().len(), 1);
    answer.await.unwrap();
}

#[tokio::test]
async fn batch_runs_read_only_calls_concurrently_and_list_modules_filters() {
    let (addr, relay) = start().await;
    let mut agent = ws(addr, "/agent").await;
    let mut c = ws(addr, "/client").await;
    for _ in 0..50 {
        send(&mut c, json!({ "type": "status", "id": 1 })).await;
        if recv_until(&mut c, |v| v["id"] == 1).await["agent"] == true {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // the agent answers only once both reads arrived: a sequential batch would time out
    let answer = tokio::spawn(async move {
        let a = recv_until(&mut agent, |v| v["type"] == "read").await;
        let b = recv_until(&mut agent, |v| v["type"] == "read").await;
        for req in [b, a] {
            let data = if req["address"] == "0x1000" { "01" } else { "02" };
            send(&mut agent, json!({ "type": "read_result", "id": req["id"], "success": true, "data": data })).await;
        }
        let m = recv_until(&mut agent, |v| v["type"] == "modules").await;
        assert!(m.get("filter").is_none(), "{m}");
        let modules = json!([{ "name": "game.exe", "base": "0x1000", "size": 1 }, { "name": "KERNEL32.dll", "base": "0x2000", "size": 1 }, { "name": "client.dll", "base": "0x3000", "size": 1 }]);
        send(&mut agent, json!({ "type": "modules_result", "id": m["id"], "success": true, "modules": modules })).await;
    });
    let calls = json!({ "calls": [
        { "tool": "read_memory", "arguments": { "address": "0x1000", "size": 1 } },
        { "tool": "read_memory", "arguments": { "address": "0x2000", "size": 1 } },
        { "tool": "write_memory", "arguments": { "address": "0x1000", "data": "00" } },
        { "tool": "batch", "arguments": { "calls": [] } },
        { "tool": "read_memory", "arguments": { "address": "0x1000" } },
    ] });
    let r = modern_call(&relay, 1, "tools/call", json!({ "name": "batch", "arguments": calls }), json!({})).await.json();
    let sc = &r["result"]["structuredContent"];
    assert_eq!(sc["count"], 5, "{r}");
    assert_eq!(sc["failed"], 3);
    let res = sc["results"].as_array().unwrap();
    assert_eq!(res[0]["result"]["data"], "01");
    assert_eq!(res[1]["result"]["data"], "02");
    assert!(res[2]["error"].as_str().unwrap().contains("on its own"));
    assert!(res[3]["error"].as_str().unwrap().contains("on its own"));
    assert!(res[4]["error"].as_str().unwrap().contains("size"));
    // compact JSON text
    assert!(!r["result"]["content"][0]["text"].as_str().unwrap().contains('\n'));
    // too many calls
    let many: Vec<Value> = (0..33).map(|_| json!({ "tool": "status" })).collect();
    let r = modern_call(&relay, 2, "tools/call", json!({ "name": "batch", "arguments": { "calls": many } }), json!({})).await.json();
    assert_eq!(r["result"]["isError"], true, "{r}");

    let r = modern_call(&relay, 3, "tools/call", json!({ "name": "list_modules", "arguments": { "filter": "DLL" } }), json!({})).await.json();
    let names: Vec<&str> = r["result"]["structuredContent"]["modules"].as_array().unwrap().iter().map(|m| m["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["KERNEL32.dll", "client.dll"]);
    answer.await.unwrap();
}

/// Reads an SSE body until `want` shows up; returns everything read.
async fn read_until(stream: &mut axum::body::BodyDataStream, want: &str) -> String {
    let mut text = String::new();
    while !text.contains(want) {
        let chunk = tokio::time::timeout(Duration::from_secs(5), stream.next()).await.unwrap_or_else(|_| panic!("no {want} in {text}")).unwrap().unwrap();
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    text
}

#[tokio::test]
async fn tools_list_changed_on_legacy_streams_and_subscriptions() {
    let (addr, relay) = start().await;
    let (sid, _) = initialize(&relay, "2025-06-18", json!({})).await;
    // legacy: the session's GET stream
    let resp = router(relay.clone())
        .oneshot(Request::get("/mcp").header("accept", "text/event-stream").header("mcp-session-id", sid.as_str()).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut legacy_body = resp.into_body().into_data_stream();
    // modern: subscriptions/listen with a filter
    let (h, body) = modern(77, "subscriptions/listen", json!({ "notifications": { "toolsListChanged": true, "resourceSubscriptions": ["echodebug://status", "echodebug://unknown"], "promptsListChanged": true } }), json!({}));
    let mut req = Request::post("/mcp").header("content-type", "application/json");
    for (k, v) in &h {
        req = req.header(*k, v.as_str());
    }
    let resp = router(relay.clone()).oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut listen = resp.into_body().into_data_stream();
    let ack = sse(&read_until(&mut listen, "acknowledged").await);
    assert_eq!(ack[0]["method"], "notifications/subscriptions/acknowledged");
    assert_eq!(ack[0]["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], 77);
    // only what the server honours: the unknown resource and prompt list changes are left out
    assert_eq!(ack[0]["params"]["notifications"], json!({ "toolsListChanged": true, "resourceSubscriptions": ["echodebug://status"] }));

    // the app window connects: ui_* tools appear
    let mut app = ws(addr, "/client").await;
    send(&mut app, json!({ "type": "provide", "id": 1 })).await;
    recv_until(&mut app, |v| v["type"] == "provide_result").await;
    let legacy_text = read_until(&mut legacy_body, "tools/list_changed").await;
    assert!(!legacy_text.contains("resources/updated"), "a session gets only what it subscribed to: {legacy_text}");
    let text = read_until(&mut listen, "tools/list_changed").await;
    let notes = sse(&text);
    let tl = notes.iter().find(|n| n["method"] == "notifications/tools/list_changed").unwrap();
    assert_eq!(tl["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"], 77);
    assert!(notes.iter().all(|n| n["method"] != "notifications/message"), "no log messages on listen streams");
    // a policy change that hides tools also announces it
    let _p = policy(addr, json!({ "mode": "readonly", "deny": ["read_memory"] })).await;
    read_until(&mut listen, "tools/list_changed").await;
    let r = modern_call(&relay, 5, "tools/list", json!({}), json!({})).await.json();
    let names: Vec<&str> = r["result"]["tools"].as_array().unwrap().iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(!names.contains(&"read_memory") && !names.contains(&"write_memory") && names.contains(&"disassemble"));
    assert!(names.contains(&"list_names"), "app window tools listed");
    // legacy subscribe makes the session's stream carry resource updates
    let r = post(&relay, &[("mcp-session-id", sid.clone())], legacy(9, "resources/subscribe", json!({ "uri": "echodebug://status" }))).await.json();
    assert_eq!(r["result"], json!({}));
    drop(app);
    read_until(&mut legacy_body, "resources/updated").await;

    // disconnecting the modern client in the panel closes its listen stream gracefully
    let mut c = ws(addr, "/client").await;
    send(&mut c, json!({ "type": "mcp_sessions", "id": 1 })).await;
    let s = recv_until(&mut c, |v| v["id"] == 1).await;
    let m = s["sessions"].as_array().unwrap().iter().find(|x| x["era"] == "stateless").unwrap().clone();
    assert_eq!(m["client"]["name"], "test-client");
    assert_eq!(m["streams"], 1);
    send(&mut c, json!({ "type": "mcp_disconnect", "id": 2, "session": m["id"] })).await;
    recv_until(&mut c, |v| v["id"] == 2).await;
    let text = read_until(&mut listen, "\"resultType\":\"complete\"").await;
    let end = sse(&text).into_iter().find(|n| n["id"] == 77).unwrap();
    assert_eq!(end["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"], 77);
}

#[tokio::test]
async fn logging_levels_and_progress() {
    let (addr, relay) = start().await;
    let mut ext = ws(addr, "/ext").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // legacy setLevel on a session
    let (sid, _) = initialize(&relay, "2025-11-25", json!({})).await;
    let r = post(&relay, &[("mcp-session-id", sid.clone())], legacy(2, "logging/setLevel", json!({ "level": "warning" }))).await.json();
    assert_eq!(r["result"], json!({}));
    // 2026-07-28: logLevel and progressToken on one call → its response stream carries both
    let relay2 = relay.clone();
    let call = tokio::spawn(async move {
        modern_call(&relay2, 3, "tools/call", json!({ "name": "value_scan_clear", "arguments": {}, "_meta": { "progressToken": "tok-1", "io.modelcontextprotocol/logLevel": "debug" } }), json!({})).await
    });
    let req = recv_until(&mut ext, |v| v["type"] == "scan_clear").await;
    send(&mut ext, json!({ "type": "event", "event": "progress", "job": "scan", "done": 1, "total": 4 })).await;
    send(&mut ext, json!({ "type": "event", "event": "progress", "job": "scan", "done": 1, "total": 4 })).await;
    send(&mut ext, json!({ "type": "event", "event": "progress", "job": "scan", "done": 3, "total": 4 })).await;
    send(&mut ext, json!({ "type": "event", "event": "freeze_failed", "level": "warn", "address": "0x1" })).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    send(&mut ext, json!({ "type": "scan_clear_result", "id": req["id"], "success": true })).await;
    let r = call.await.unwrap();
    assert_eq!(r.headers["content-type"], "text/event-stream");
    let ev = r.events();
    let progress: Vec<f64> = ev.iter().filter(|e| e["method"] == "notifications/progress").map(|e| e["params"]["progress"].as_f64().unwrap()).collect();
    assert_eq!(progress, [1.0, 3.0], "monotonic, duplicates dropped");
    assert!(ev.iter().any(|e| e["method"] == "notifications/progress" && e["params"]["progressToken"] == "tok-1" && e["params"]["total"] == 4.0));
    let logs: Vec<&Value> = ev.iter().filter(|e| e["method"] == "notifications/message").collect();
    assert!(logs.iter().any(|l| l["params"]["level"] == "warning" && l["params"]["logger"] == "freeze_failed"), "{ev:?}");
    assert!(logs.iter().any(|l| l["params"]["level"] == "debug"), "relay's own debug log");
    assert_eq!(ev.last().unwrap()["id"], 3);
    assert_eq!(ev.last().unwrap()["result"]["resultType"], "complete");
    // without logLevel and progressToken: a plain JSON answer, no messages
    let relay3 = relay.clone();
    let call = tokio::spawn(async move { modern_call(&relay3, 4, "tools/call", json!({ "name": "value_scan_clear", "arguments": {} }), json!({})).await });
    let req = recv_until(&mut ext, |v| v["type"] == "scan_clear").await;
    send(&mut ext, json!({ "type": "scan_clear_result", "id": req["id"], "success": true })).await;
    let r = call.await.unwrap();
    assert!(r.headers["content-type"].to_str().unwrap().starts_with("application/json"));
    assert_eq!(r.json()["result"]["isError"], false);
}

#[tokio::test]
async fn cancellation_stops_the_call_and_the_backend_job() {
    let (addr, relay) = start().await;
    let mut ext = ws(addr, "/ext").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // legacy: notifications/cancelled on the same session
    let (sid, _) = initialize(&relay, "2025-06-18", json!({})).await;
    let relay2 = relay.clone();
    let sid2 = sid.clone();
    let call = tokio::spawn(async move { post(&relay2, &[("mcp-session-id", sid2)], legacy(41, "tools/call", json!({ "name": "value_scan_clear", "arguments": {} }))).await });
    recv_until(&mut ext, |v| v["type"] == "scan_clear").await;
    let r = post(&relay, &[("mcp-session-id", sid.clone())], json!({ "jsonrpc": "2.0", "method": "notifications/cancelled", "params": { "requestId": 41, "reason": "user" } })).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let cancel = recv_until(&mut ext, |v| v["type"] == "cancel").await;
    assert!(cancel["id"].is_u64());
    let r = call.await.unwrap();
    assert_eq!(r.status, StatusCode::NO_CONTENT, "a cancelled request gets no response: {}", r.text);

    // 2026-07-28: closing the response stream is the cancellation
    let (h, body) = modern(42, "tools/call", json!({ "name": "value_scan_clear", "arguments": {}, "_meta": { "progressToken": 1 } }), json!({}));
    let mut req = Request::post("/mcp").header("content-type", "application/json");
    for (k, v) in &h {
        req = req.header(*k, v.as_str());
    }
    let resp = router(relay.clone()).oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    recv_until(&mut ext, |v| v["type"] == "scan_clear").await;
    drop(resp);
    recv_until(&mut ext, |v| v["type"] == "cancel").await;
}

#[tokio::test]
async fn ask_policy_uses_elicitation_when_the_client_has_it() {
    let (addr, relay) = start().await;
    let mut ext = ws(addr, "/ext").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _p = policy(addr, json!({ "mode": "ask" })).await;
    let caps = json!({ "elicitation": { "form": {} } });
    let write = json!({ "name": "write_memory", "arguments": { "address": "0x1000", "data": "90" } });

    // 2026-07-28: an input_required result first
    let r = modern_call(&relay, 1, "tools/call", write.clone(), caps.clone()).await.json();
    let res = r["result"].clone();
    assert_eq!(res["resultType"], "input_required", "{r}");
    let ask = &res["inputRequests"]["echodebug_approval"];
    assert_eq!(ask["method"], "elicitation/create");
    assert_eq!(ask["params"]["mode"], "form");
    assert_eq!(ask["params"]["requestedSchema"]["properties"]["allow"]["type"], "boolean");
    assert!(ask["params"]["message"].as_str().unwrap().contains("write_memory"));
    let state = res["requestState"].as_str().unwrap().to_owned();
    // a retry with other arguments does not reuse the approval
    let mut tampered = write.clone();
    tampered["arguments"]["data"] = json!("cc");
    tampered["requestState"] = json!(state.clone());
    tampered["inputResponses"] = json!({ "echodebug_approval": { "action": "accept", "content": { "allow": true } } });
    assert_eq!(modern_call(&relay, 2, "tools/call", tampered, caps.clone()).await.json()["error"]["code"], -32602);
    // ... the state was consumed, so ask again and accept
    let r = modern_call(&relay, 3, "tools/call", write.clone(), caps.clone()).await.json();
    let state = r["result"]["requestState"].as_str().unwrap().to_owned();
    let mut retry = write.clone();
    retry["requestState"] = json!(state.clone());
    retry["inputResponses"] = json!({ "echodebug_approval": { "action": "accept", "content": { "allow": true } } });
    let relay2 = relay.clone();
    let caps2 = caps.clone();
    let call = tokio::spawn(async move { modern_call(&relay2, 4, "tools/call", retry, caps2).await });
    let req = recv_until(&mut ext, |v| v["type"] == "write").await;
    send(&mut ext, json!({ "type": "write_result", "id": req["id"], "success": true })).await;
    let r = call.await.unwrap().json();
    assert_eq!(r["result"]["isError"], false, "{r}");
    // replaying the same state fails
    let mut replay = write.clone();
    replay["requestState"] = json!(state);
    replay["inputResponses"] = json!({ "echodebug_approval": { "action": "accept", "content": { "allow": true } } });
    assert_eq!(modern_call(&relay, 5, "tools/call", replay, caps.clone()).await.json()["error"]["code"], -32602);
    // declining
    let r = modern_call(&relay, 6, "tools/call", write.clone(), caps.clone()).await.json();
    let mut decline = write.clone();
    decline["requestState"] = r["result"]["requestState"].clone();
    decline["inputResponses"] = json!({ "echodebug_approval": { "action": "decline" } });
    let r = modern_call(&relay, 7, "tools/call", decline, caps.clone()).await.json();
    assert_eq!(r["result"]["isError"], true);
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("declined"));

    // 2025-06-18 session: elicitation/create on the call's stream, answered with a POST
    let (sid, _) = initialize(&relay, "2025-06-18", json!({ "elicitation": {} })).await;
    let h = [("mcp-session-id", sid.clone()), ("accept", "application/json, text/event-stream".to_owned())];
    let mut req = Request::post("/mcp").header("content-type", "application/json");
    for (k, v) in &h {
        req = req.header(*k, v.as_str());
    }
    let resp = router(relay.clone()).oneshot(req.body(Body::from(legacy(8, "tools/call", write.clone()).to_string())).unwrap()).await.unwrap();
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut stream = resp.into_body().into_data_stream();
    let mut text = String::new();
    while !text.contains("elicitation/create") {
        let chunk = tokio::time::timeout(Duration::from_secs(5), stream.next()).await.unwrap().unwrap().unwrap();
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    let el = sse(&text).into_iter().find(|m| m["method"] == "elicitation/create").unwrap();
    assert!(el["params"].get("mode").is_none(), "2025-06-18 has no elicitation modes");
    let r = post(&relay, &[("mcp-session-id", sid.clone())], json!({ "jsonrpc": "2.0", "id": el["id"], "result": { "action": "accept", "content": { "allow": true } } })).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    let wreq = recv_until(&mut ext, |v| v["type"] == "write").await;
    send(&mut ext, json!({ "type": "write_result", "id": wreq["id"], "success": true })).await;
    let mut rest = String::new();
    while let Ok(Some(Ok(chunk))) = tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
        rest.push_str(&String::from_utf8_lossy(&chunk));
    }
    let done = sse(&rest).into_iter().find(|m| m["id"] == 8).unwrap();
    assert_eq!(done["result"]["isError"], false, "{done}");

    // the policy can send every approval to the app window instead
    let _p2 = policy(addr, json!({ "mode": "ask", "elicit": false })).await;
    let r = modern_call(&relay, 9, "tools/call", write.clone(), caps).await.json();
    assert_eq!(r["result"]["resultType"], "complete");
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("EchoDebug window"), "{r}");

    // the call log says how each call was approved
    let mut c = ws(addr, "/client").await;
    send(&mut c, json!({ "type": "mcp_log", "id": 1 })).await;
    let log = recv_until(&mut c, |v| v["id"] == 1).await;
    assert!(log["entries"].as_array().unwrap().iter().any(|e| e["approved_via"] == "MCP client (elicitation)" && e["client"] == "test-client"));
}

#[tokio::test]
async fn health_endpoint_and_auth_errors() {
    let relay = Relay::new("1.2.3", Duration::from_secs(5)).with_local_backend(false).with_token(Some("tok-0123456789abcdef0123456789abcdef".into()));
    let get = |auth: Option<&'static str>| {
        let relay = relay.clone();
        async move {
            let mut r = Request::get("/mcp/health");
            if let Some(a) = auth {
                r = r.header("authorization", a);
            }
            let resp = router(relay).oneshot(r.body(Body::empty()).unwrap()).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            serde_json::from_slice::<Value>(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap()
        }
    };
    let h = get(None).await;
    assert_eq!((h["ok"].as_bool(), h["auth"].as_str(), h["latest"].as_str()), (Some(true), Some("bearer"), Some(MODERN)));
    assert!(h["authorized"].is_null() && h["appWindow"] == false && h["tools"].as_u64().unwrap() > 50);
    assert_eq!(get(Some("Bearer wrong")).await["authorized"], false);
    assert_eq!(get(Some("Bearer tok-0123456789abcdef0123456789abcdef")).await["authorized"], true);
    // POST /mcp without / with a wrong token: 401 and a message that says what to do
    let r = post(&relay, &[], legacy(1, "ping", json!({}))).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(r.json()["error"]["message"].as_str().unwrap().contains("needs its relay token"));
    let r = post(&relay, &[("authorization", "Bearer nope".into())], legacy(1, "ping", json!({}))).await;
    assert!(r.json()["error"]["message"].as_str().unwrap().contains("wrong or was regenerated"));
    assert!(r.headers["www-authenticate"].to_str().unwrap().contains("invalid_token"));
}

#[tokio::test]
async fn cors_for_the_app_window_only() {
    let (_, relay) = start().await;
    let pre = |origin: &'static str| {
        router(relay.clone()).oneshot(
            Request::options("/mcp").header("origin", origin).header("access-control-request-method", "POST").header("access-control-request-headers", "authorization, mcp-protocol-version").body(Body::empty()).unwrap(),
        )
    };
    let ok = pre("tauri://localhost").await.unwrap();
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);
    assert_eq!(ok.headers()["access-control-allow-origin"], "tauri://localhost");
    assert!(ok.headers()["access-control-allow-headers"].to_str().unwrap().contains("mcp-protocol-version"));
    assert_eq!(pre("https://evil.example").await.unwrap().status(), StatusCode::FORBIDDEN);
    let r = post(&relay, &[("origin", "http://127.0.0.1:1430".into())], legacy(1, "ping", json!({}))).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["access-control-allow-origin"], "http://127.0.0.1:1430");
    assert!(r.headers["access-control-expose-headers"].to_str().unwrap().contains("mcp-session-id"));
    let r = post(&relay, &[], legacy(1, "ping", json!({}))).await;
    assert!(r.headers.get("access-control-allow-origin").is_none(), "native clients send no Origin");
}

#[tokio::test]
async fn panel_test_call_uses_the_mcp_path() {
    let (addr, relay) = start().await;
    let mut c = ws(addr, "/client").await;
    send(&mut c, json!({ "type": "mcp_test_call", "id": 1, "name": "status", "arguments": {} })).await;
    let r = recv_until(&mut c, |v| v["id"] == 1).await;
    assert_eq!(r["success"], true, "{r}");
    assert_eq!(r["result"]["isError"], false);
    assert_eq!(r["result"]["structuredContent"]["app_version"], "1.2.3");
    // the policy applies to it like to any client
    let _p = policy(addr, json!({ "deny": ["status"] })).await;
    send(&mut c, json!({ "type": "mcp_test_call", "id": 2, "name": "status" })).await;
    let r = recv_until(&mut c, |v| v["id"] == 2).await;
    assert_eq!(r["result"]["isError"], true);
    send(&mut c, json!({ "type": "mcp_log", "id": 3 })).await;
    let log = recv_until(&mut c, |v| v["id"] == 3).await;
    assert!(log["entries"].as_array().unwrap().iter().any(|e| e["transport"] == "panel" && e["outcome"] == "denied"));
    let _ = relay;
}

// ---- stdio ---------------------------------------------------------------------------------------------

struct Child {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::sync::mpsc::Receiver<Value>,
}

impl Child {
    fn spawn(port: u16, config: &std::path::Path, env_token: Option<&str>) -> Child {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_echodebug-relay"));
        cmd.arg("--stdio").arg(port.to_string()).env("XDG_CONFIG_HOME", config).env("HOME", config).env_remove("ECHODEBUG_TOKEN").env_remove("ECHODEBUG_AUTH").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        if let Some(t) = env_token {
            cmd.env("ECHODEBUG_TOKEN", t);
        }
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines() {
                let Ok(l) = l else { return };
                if let Ok(v) = serde_json::from_str(&l) {
                    if tx.send(v).is_err() {
                        return;
                    }
                }
            }
        });
        Child { child, stdin, lines }
    }

    fn send(&mut self, v: Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn until(&self, pred: impl Fn(&Value) -> bool) -> Value {
        loop {
            let v = self.lines.recv_timeout(Duration::from_secs(20)).expect("no answer on stdout");
            if pred(&v) {
                return v;
            }
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn temp_config(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("echodebug-stdio-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdio_embedded_needs_no_token() {
    let cfg = temp_config("embedded");
    let port = free_port();
    let out = tokio::task::spawn_blocking(move || {
        let mut c = Child::spawn(port, &cfg, None);
        // legacy client
        c.send(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "stdio-test", "version": "1" } } }));
        let init = c.until(|v| v["id"] == 1);
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        c.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        c.send(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "status", "arguments": {} } }));
        let st = c.until(|v| v["id"] == 2);
        assert_eq!(st["result"]["isError"], false, "{st}");
        // a 2026-07-28 request on the same pipe (stateless, no headers on stdio)
        c.send(json!({ "jsonrpc": "2.0", "id": 3, "method": "server/discover", "params": { "_meta": meta(json!({})) } }));
        let d = c.until(|v| v["id"] == 3);
        assert_eq!(d["result"]["supportedVersions"][0], MODERN);
        c.send(json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": { "_meta": { "io.modelcontextprotocol/protocolVersion": "2099-01-01", "io.modelcontextprotocol/clientCapabilities": {} } } }));
        assert_eq!(c.until(|v| v["id"] == 4)["error"]["code"], -32022);
        c.send(json!("not an object"));
        assert_eq!(c.until(|v| v["error"]["code"] == -32600)["id"], Value::Null);
        // the embedded relay serves Echo and the app on the port, with the token it created
        let token = std::fs::read_to_string(cfg.join("EchoDebug").join("relay-token")).unwrap();
        (port, token)
    })
    .await
    .unwrap();
    assert_eq!(out.1.trim().len(), 64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdio_bridges_to_a_running_relay_with_the_stored_token() {
    let cfg = temp_config("bridge");
    let token = "bridge-token-0123456789abcdef0123456789";
    std::fs::create_dir_all(cfg.join("EchoDebug")).unwrap();
    std::fs::write(cfg.join("EchoDebug").join("relay-token"), token).unwrap();
    let relay = Relay::new("1.2.3", Duration::from_secs(5)).with_local_backend(false).with_token(Some(token.into()));
    let listener = bind(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(run(listener, relay.clone()));
    let cfg2 = cfg.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Child::spawn(port, &cfg2, None);
        c.send(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": { "name": "bridged", "version": "2" } } }));
        assert_eq!(c.until(|v| v["id"] == 1)["result"]["protocolVersion"], "2025-11-25");
        c.send(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "status", "arguments": {} } }));
        let st = c.until(|v| v["id"] == 2);
        assert_eq!(st["result"]["structuredContent"]["app_version"], "1.2.3", "{st}");
        // modern requests get their headers added by the bridge
        c.send(json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "status", "arguments": {}, "_meta": meta(json!({})) } }));
        assert_eq!(c.until(|v| v["id"] == 3)["result"]["resultType"], "complete");
    })
    .await
    .unwrap();
    // the bridged session shows up in the panel as stdio
    let s = relay_sessions(&relay).await;
    assert!(s.iter().any(|x| x["transport"] == "stdio (bridged)" && x["client"]["name"] == "bridged"), "{s:?}");

    // a token that no longer matches (regenerated in the app): a clear error, not a hang
    std::fs::write(cfg.join("EchoDebug").join("relay-token"), "stale-token-0123456789abcdef0123456789").unwrap();
    tokio::task::spawn_blocking(move || {
        let mut c = Child::spawn(port, &cfg, None);
        c.send(json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }));
        let e = c.until(|v| v["id"] == 1);
        assert!(e["error"]["message"].as_str().unwrap().contains("refused the token"), "{e}");
    })
    .await
    .unwrap();
}

async fn relay_sessions(relay: &Relay) -> Vec<Value> {
    let r = relay.request(json!({ "type": "mcp_sessions", "id": 1 })).await;
    r["sessions"].as_array().cloned().unwrap_or_default()
}
