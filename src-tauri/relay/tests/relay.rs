use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use echo_debug_relay::{bind, router, run, Relay};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tower::ServiceExt;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start() -> (SocketAddr, Relay) {
    let relay = Relay::new("1.2.3", Duration::from_secs(5)).with_local_backend(false);
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay.clone()));
    (addr, relay)
}

async fn connect(addr: SocketAddr, path: &str) -> Ws {
    connect_async(format!("ws://{addr}{path}")).await.unwrap().0
}

async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::text(v.to_string())).await.unwrap();
}

/// Next text frame matching `pred`, skipping others (status broadcasts etc.).
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

/// Client socket whose initial status shows the wanted upstream state (avoids racing upstream registration).
async fn client_when(addr: SocketAddr, agent: bool, ext: bool) -> Ws {
    for _ in 0..50 {
        let mut c = connect(addr, "/client").await;
        let s = recv_until(&mut c, |v| v["type"] == "status").await;
        if s["agent"] == agent && s["ext"] == ext {
            return c;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("upstreams never reached agent={agent} ext={ext}");
}

#[tokio::test]
async fn routes_native_and_ext_with_id_rewrite() {
    let (addr, _) = start().await;
    let mut agent = connect(addr, "/agent").await;
    let mut ext = connect(addr, "/ext").await;
    let mut client = client_when(addr, true, true).await;

    send(
        &mut client,
        json!({ "type": "read", "id": "abc", "address": "0x1000", "size": 4 }),
    )
    .await;
    let req = recv_until(&mut agent, |_| true).await;
    assert_eq!(req["type"], "read");
    assert_eq!(req["address"], "0x1000");
    assert!(req["id"].is_u64(), "relay id is an integer: {req}");
    send(
        &mut agent,
        json!({ "type": "read_result", "id": req["id"], "success": true, "data": "deadbeef" }),
    )
    .await;
    let reply = recv_until(&mut client, |v| v["type"] == "read_result").await;
    assert_eq!(reply["id"], "abc");
    assert_eq!(reply["data"], "deadbeef");

    // Ext verb, missing id defaults to 0.
    send(&mut client, json!({ "type": "regions" })).await;
    let req = recv_until(&mut ext, |_| true).await;
    assert_eq!(req["type"], "regions");
    send(
        &mut ext,
        json!({ "type": "regions_result", "id": req["id"], "success": true, "regions": [] }),
    )
    .await;
    let reply = recv_until(&mut client, |v| v["type"] == "regions_result").await;
    assert_eq!(reply["id"], 0);
}

#[tokio::test]
async fn missing_upstreams_fail_immediately() {
    let (addr, _) = start().await;
    let mut client = connect(addr, "/client").await;
    send(&mut client, json!({ "type": "modules", "id": 1 })).await;
    let r = recv_until(&mut client, |v| v["id"] == 1).await;
    assert_eq!(
        (r["type"].as_str(), r["code"].as_u64()),
        (Some("error"), Some(2001))
    );
    send(
        &mut client,
        json!({ "type": "attach", "id": [2], "name": "x.exe" }),
    )
    .await;
    let r = recv_until(&mut client, |v| v["id"] == json!([2])).await;
    assert_eq!(r["code"], 2002);
}

#[tokio::test]
async fn upstream_disconnect_fails_in_flight() {
    let (addr, _) = start().await;
    let mut agent = connect(addr, "/agent").await;
    let mut client = client_when(addr, true, false).await;
    send(&mut client, json!({ "type": "ping", "id": 7 })).await;
    recv_until(&mut agent, |v| v["type"] == "ping").await;
    agent.close(None).await.unwrap();
    let r = recv_until(&mut client, |v| v["id"] == 7).await;
    assert_eq!(r["code"], 2004);
}

#[tokio::test]
async fn timeout_is_2003() {
    let relay = Relay::new("1.2.3", Duration::from_millis(200));
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay));
    let mut _ext = connect(addr, "/ext").await;
    let mut client = client_when(addr, false, true).await;
    send(&mut client, json!({ "type": "alive", "id": 9 })).await;
    let r = recv_until(&mut client, |v| v["id"] == 9).await;
    assert_eq!(r["code"], 2003);
}

#[tokio::test]
async fn ext_events_broadcast_and_status_tracks_hello_and_attach() {
    let (addr, _) = start().await;
    let mut ext = connect(addr, "/ext").await;
    let mut client = client_when(addr, false, true).await;

    send(&mut ext, json!({ "type": "event", "event": "hello", "version": "0.9.0", "protocol": 1, "attached": false })).await;
    let hello = recv_until(&mut client, |v| v["event"] == "hello").await;
    assert_eq!(hello["version"], "0.9.0");
    send(
        &mut ext,
        json!({ "type": "event", "event": "log", "level": "info", "message": "hi" }),
    )
    .await;
    let log = recv_until(&mut client, |v| v["event"] == "log").await;
    assert_eq!(log["message"], "hi");

    send(
        &mut client,
        json!({ "type": "attach", "id": "a", "name": "game.exe" }),
    )
    .await;
    let req = recv_until(&mut ext, |v| v["type"] == "attach").await;
    send(&mut ext, json!({ "type": "attach_result", "id": req["id"], "success": true, "pid": 42, "base": "0x140000000", "name": "game.exe" })).await;
    let st = recv_until(&mut client, |v| {
        v["type"] == "status" && v["target"]["pid"] == 42
    })
    .await;
    assert_eq!(st["ext_version"], "0.9.0");
    recv_until(&mut client, |v| {
        v["type"] == "attach_result" && v["id"] == "a"
    })
    .await;

    send(&mut client, json!({ "type": "status", "id": 5 })).await;
    let s = recv_until(&mut client, |v| v["type"] == "status_result").await;
    assert_eq!(s["id"], 5);
    assert_eq!(s["success"], true);
    assert_eq!(
        (s["agent"].as_bool(), s["ext"].as_bool()),
        (Some(false), Some(true))
    );
    assert_eq!(s["ext_version"], "0.9.0");
    assert_eq!(s["app_version"], "1.2.3");
    assert_eq!(s["target"]["name"], "game.exe");
    assert!(s["target"].get("type").is_none());

    send(&mut client, json!({ "type": "processes", "id": 6 })).await;
    let p = recv_until(&mut client, |v| v["type"] == "processes_result").await;
    let procs = p["processes"].as_array().unwrap();
    assert!(!procs.is_empty());
    let names: Vec<String> = procs
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_lowercase())
        .collect();
    assert!(names.windows(2).all(|w| w[0] <= w[1]), "sorted by name");
}

#[tokio::test]
async fn origin_checks() {
    let (addr, _) = start().await;
    let reject = |path: &str, origin: &str| {
        let mut req = format!("ws://{addr}{path}").into_client_request().unwrap();
        req.headers_mut().insert("origin", origin.parse().unwrap());
        async move {
            match connect_async(req).await {
                Err(WsError::Http(resp)) => resp.status(),
                Ok(_) => StatusCode::SWITCHING_PROTOCOLS,
                Err(e) => panic!("{e}"),
            }
        }
    };
    assert_eq!(
        reject("/client", "https://evil.example").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        reject("/client", "http://localhost:1420").await,
        StatusCode::SWITCHING_PROTOCOLS
    );
    assert_eq!(
        reject("/agent", "http://localhost:1420").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        reject("/ext", "tauri://localhost").await,
        StatusCode::FORBIDDEN
    );
}

async fn mcp(relay: &Relay, body: Value, origin: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::post("/mcp").header(header::CONTENT_TYPE, "application/json");
    if let Some(o) = origin {
        req = req.header(header::ORIGIN, o);
    }
    let resp = router(relay.clone())
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn mcp_round_trip() {
    let (addr, relay) = start().await;

    let (s, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-03-26" } }), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(r["result"]["serverInfo"]["name"], "echodebug");
    assert_eq!(r["result"]["serverInfo"]["version"], "1.2.3");

    let (s, _) = mcp(
        &relay,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);

    let (_, r) = mcp(
        &relay,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        None,
    )
    .await;
    let tools = r["result"]["tools"].as_array().unwrap();
    let read = tools.iter().find(|t| t["name"] == "read_memory").unwrap();
    assert!(read["inputSchema"].is_object());
    assert!(read.get("verb").is_none() && read.get("input_schema").is_none());

    // Upstream missing → tool error, not RPC error.
    let call = json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "read_memory", "arguments": { "address": "0x10", "size": 2 } } });
    let (_, r) = mcp(&relay, call.clone(), None).await;
    assert_eq!(r["result"]["isError"], true);
    assert!(r["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("2001"));

    // Real round trip through /agent.
    let mut agent = connect(addr, "/agent").await;
    drop(client_when(addr, true, false).await);
    let agent_task = tokio::spawn(async move {
        let req = recv_until(&mut agent, |v| v["type"] == "read").await;
        assert_eq!(req["address"], "0x10");
        send(
            &mut agent,
            json!({ "type": "read_result", "id": req["id"], "success": true, "data": "beef" }),
        )
        .await;
        agent
    });
    let (_, r) = mcp(&relay, call, None).await;
    agent_task.await.unwrap();
    assert_eq!(r["id"], 3);
    assert_eq!(r["result"]["isError"], false);
    let text: Value =
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, json!({ "success": true, "data": "beef" }));

    let (_, r) = mcp(
        &relay,
        json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": { "name": "nope" } }),
        None,
    )
    .await;
    assert_eq!(r["error"]["code"], -32602);
    let (_, r) = mcp(
        &relay,
        json!({ "jsonrpc": "2.0", "id": 5, "method": "bogus" }),
        None,
    )
    .await;
    assert_eq!(r["error"]["code"], -32601);

    // Batch: ping + notification → one reply.
    let (_, r) = mcp(&relay, json!([{ "jsonrpc": "2.0", "id": 6, "method": "ping" }, { "jsonrpc": "2.0", "method": "notifications/x" }]), None).await;
    assert_eq!(r, json!([{ "jsonrpc": "2.0", "id": 6, "result": {} }]));

    let (s, _) = mcp(
        &relay,
        json!({ "jsonrpc": "2.0", "id": 7, "method": "ping" }),
        Some("https://evil.example"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    let resp = router(relay.clone())
        .oneshot(Request::get("/mcp").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    let resp = router(relay)
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({ "ok": true, "version": "1.2.3" })
    );
}

#[tokio::test]
async fn newer_upstream_replaces_old() {
    let (addr, _) = start().await;
    let mut old = connect(addr, "/agent").await;
    let mut client = client_when(addr, true, false).await;
    send(&mut client, json!({ "type": "ping", "id": 1 })).await;
    recv_until(&mut old, |v| v["type"] == "ping").await;

    let mut new = connect(addr, "/agent").await;
    assert_eq!(
        recv_until(&mut client, |v| v["id"] == 1).await["code"],
        2004
    );
    send(&mut client, json!({ "type": "ping", "id": 2 })).await;
    let req = recv_until(&mut new, |v| v["type"] == "ping").await;
    send(
        &mut new,
        json!({ "type": "ping_result", "id": req["id"], "success": true }),
    )
    .await;
    assert_eq!(
        recv_until(&mut client, |v| v["id"] == 2).await["type"],
        "ping_result"
    );
    // Old socket was closed by the relay.
    assert!(matches!(
        old.next().await,
        Some(Ok(Message::Close(_))) | None | Some(Err(_))
    ));
}

#[tokio::test]
async fn hello_attached_without_agent_pokes_reopen_socket() {
    let (addr, _) = start().await;
    let mut ext = connect(addr, "/ext").await;
    let mut client = client_when(addr, false, true).await;

    // attached per the agent, but no /agent (native memory server) connection
    send(
        &mut ext,
        json!({ "type": "event", "event": "hello", "version": "0.4.0", "protocol": 1,
                "attached": true, "pid": 42, "base": "0x140000000", "peb": "0x1f3a0000b40", "name": "game.exe" }),
    )
    .await;
    // the relay pokes the agent to re-open the native socket
    let req = recv_until(&mut ext, |v| v["type"] == "reopen_socket").await;
    assert!(req["id"].is_u64());
    send(&mut ext, json!({ "type": "reopen_socket_result", "id": req["id"], "success": true, "ok": true })).await;
    // status carries the target incl. name/peb from hello
    let st = recv_until(&mut client, |v| {
        v["type"] == "status" && v["target"]["pid"] == 42
    })
    .await;
    assert_eq!(st["target"]["name"], "game.exe");
    assert_eq!(st["target"]["peb"], "0x1f3a0000b40");
    assert_eq!(st["agent"], false);

    // not poked when the native server is connected, or when not attached
    let _agent = connect(addr, "/agent").await;
    let _ = recv_until(&mut client, |v| v["type"] == "status" && v["agent"] == true).await;
    send(
        &mut ext,
        json!({ "type": "event", "event": "hello", "version": "0.4.0", "protocol": 1,
                "attached": true, "pid": 42, "base": "0x140000000" }),
    )
    .await;
    send(
        &mut ext,
        json!({ "type": "event", "event": "hello", "version": "0.4.0", "protocol": 1, "attached": false }),
    )
    .await;
    // give the relay a moment; the only frames the ext should get are none
    let mut got_poke = false;
    while let Ok(Some(Ok(Message::Text(t)))) =
        tokio::time::timeout(Duration::from_millis(300), ext.next()).await
    {
        let v: Value = serde_json::from_str(t.as_str()).unwrap();
        if v["type"] == "reopen_socket" {
            got_poke = true;
        }
    }
    assert!(!got_poke, "reopen_socket poked although agent upstream is connected / not attached");
}

#[tokio::test]
async fn mcp_prompts_resources_and_call_log() {
    let (addr, relay) = start().await;

    // initialize advertises tools + prompts + resources
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }), None).await;
    assert_eq!(r["result"]["capabilities"], json!({ "tools": { "listChanged": false }, "prompts": {}, "resources": { "subscribe": true }, "logging": {}, "completions": {} }));
    assert!(r["result"]["instructions"].as_str().unwrap().contains("attach"));

    // prompts/list + prompts/get with argument substitution
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 2, "method": "prompts/list" }), None).await;
    let names: Vec<&str> = r["result"]["prompts"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    for want in ["explain_function", "find_pattern", "find_string", "pointer_path", "scan_value", "triage_module", "find_vtable", "make_signature", "diff_snapshots", "unpack_module", "decrypt_strings", "find_value_references", "rebuild_class", "update_signatures_after_patch"] {
        assert!(names.contains(&want), "missing prompt {want}");
    }
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 3, "method": "prompts/get", "params": { "name": "explain_function", "arguments": { "address": "0x140001000" } } }), None).await;
    let text = r["result"]["messages"][0]["content"]["text"].as_str().unwrap();
    assert!(text.contains("0x140001000") && !text.contains("{{"), "args substituted: {text}");
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 4, "method": "prompts/get", "params": { "name": "nope" } }), None).await;
    assert_eq!(r["error"]["code"], -32602);

    // resources/list + resources/read (status works without upstreams)
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 5, "method": "resources/list" }), None).await;
    let uris: Vec<&str> = r["result"]["resources"].as_array().unwrap().iter().map(|x| x["uri"].as_str().unwrap()).collect();
    assert!(uris.contains(&"echodebug://status") && uris.contains(&"echodebug://mcp/log"));
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 6, "method": "resources/read", "params": { "uri": "echodebug://status" } }), None).await;
    let status: Value = serde_json::from_str(r["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(status["type"], "status");
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 7, "method": "resources/read", "params": { "uri": "echodebug://target/modules" } }), None).await;
    assert_eq!(r["error"]["code"], -32000, "modules resource needs the memory server");

    // a tools/call lands in the ring buffer → echodebug://mcp/log and the local mcp_log verb
    let mut ext = connect(addr, "/ext").await;
    let _ = client_when(addr, false, true).await;
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": { "name": "is_alive", "arguments": {} } }), None).await;
    assert_eq!(r["result"]["isError"], true, "no agent needed for ext verb, but ext not attached → error");
    let req = recv_until(&mut ext, |v| v["type"] == "alive").await;
    send(&mut ext, json!({ "type": "alive_result", "id": req["id"], "success": true, "alive": true, "pid": 7 })).await;

    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 9, "method": "resources/read", "params": { "uri": "echodebug://mcp/log" } }), None).await;
    let log: Value = serde_json::from_str(r["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
    let entries = log["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["tool"] == "is_alive" && e["verb"] == "alive"), "call logged: {log}");

    // local verbs for the app's MCP panel
    let mut client = client_when(addr, false, true).await;
    send(&mut client, json!({ "type": "mcp_log", "id": 1 })).await;
    let r = recv_until(&mut client, |v| v["type"] == "mcp_log_result").await;
    assert!(r["entries"].as_array().unwrap().iter().any(|e| e["tool"] == "is_alive"));
    send(&mut client, json!({ "type": "mcp_meta", "id": 2 })).await;
    let r = recv_until(&mut client, |v| v["type"] == "mcp_meta_result").await;
    assert_eq!(r["serverInfo"]["name"], "echodebug");
    assert!(r["prompts"].as_array().unwrap().len() >= 6);
    assert!(r["resources"].as_array().unwrap().len() >= 4);
    assert!(r["tools"].as_u64().unwrap() >= 30);
}

// Linux-only: with the local backend enabled and no Echo upstream, the relay serves verbs
// from /proc itself — attach to our own pid, then list modules.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn local_backend_serves_verbs_without_upstream() {
    let relay = Relay::new("1.2.3", Duration::from_secs(5)).with_local_backend(true);
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay.clone()));
    let mut client = client_when(addr, false, false).await;

    // native verb without attach -> local "not attached" (1001), not 2001
    send(&mut client, json!({ "type": "ping", "id": 1 })).await;
    let r = recv_until(&mut client, |v| v["id"] == 1).await;
    assert_eq!(r["code"], 1001, "{r}");

    // attach to ourselves via the local backend
    let me = std::process::id();
    send(&mut client, json!({ "type": "attach", "id": 2, "pid": me })).await;
    let r = recv_until(&mut client, |v| v["id"] == 2).await;
    assert_eq!(r["type"], "attach_result");
    assert_eq!(r["success"], true);
    assert_eq!(r["pid"], me);

    // modules of our own process via /proc/pid/maps
    send(&mut client, json!({ "type": "modules", "id": 3 })).await;
    let r = recv_until(&mut client, |v| v["id"] == 3).await;
    assert_eq!(r["type"], "modules_result");
    assert!(!r["modules"].as_array().unwrap().is_empty(), "own process has modules: {r}");

    // status reports the local backend
    send(&mut client, json!({ "type": "status", "id": 4 })).await;
    let r = recv_until(&mut client, |v| v["type"] == "status_result").await;
    assert_eq!(r["backend"], "local");
    assert_eq!(r["local"], true);
}

#[tokio::test]
async fn token_guards_client_and_mcp() {
    let relay = Relay::new("1.2.3", Duration::from_secs(5))
        .with_local_backend(false)
        .with_token(Some("s3cret-token-0123456789abcdef0123".into()));
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay.clone()));

    match connect_async(format!("ws://{addr}/client")).await {
        Err(WsError::Http(resp)) => assert_eq!(resp.status(), StatusCode::UNAUTHORIZED),
        other => panic!("expected 401, got {:?}", other.map(|_| ())),
    }
    let mut ok = connect(addr, "/client?token=s3cret-token-0123456789abcdef0123").await;
    let s = recv_until(&mut ok, |v| v["type"] == "status").await;
    assert_eq!(s["provider"], false);
    // upstream endpoints stay open (Echo cannot send headers)
    let _agent = connect(addr, "/agent").await;

    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let (s, _) = mcp(&relay, ping.clone(), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let resp = router(relay.clone())
        .oneshot(
            Request::post("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer s3cret-token-0123456789abcdef0123")
                .body(Body::from(ping.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = router(relay.clone())
        .oneshot(
            Request::post("/mcp")
                .header(header::AUTHORIZATION, "Bearer wrong")
                .body(Body::from(ping.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // regeneration (the app's set_token) takes effect immediately; open sockets stay up
    relay.set_token(Some("rotated-token-0123456789abcdef01234".into()));
    let post = |auth: &'static str| {
        router(relay.clone()).oneshot(
            Request::post("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, auth)
                .body(Body::from(ping.to_string()))
                .unwrap(),
        )
    };
    assert_eq!(post("Bearer s3cret-token-0123456789abcdef0123").await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(post("Bearer rotated-token-0123456789abcdef01234").await.unwrap().status(), StatusCode::OK);
    send(&mut ok, json!({ "type": "status", "id": 2 })).await;
    assert_eq!(recv_until(&mut ok, |v| v["id"] == 2).await["type"], "status_result");
}

#[tokio::test]
async fn provider_serves_ui_verbs() {
    let (addr, relay) = start().await;
    // no app window: clear error
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "ui_pe_info", "arguments": {} } }), None).await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("app window"));

    let mut app = connect(addr, "/client").await;
    send(&mut app, json!({ "type": "provide", "id": 9, "verbs": ["ui_pe_info"] })).await;
    recv_until(&mut app, |v| v["type"] == "provide_result" && v["id"] == 9).await;

    let relay2 = relay.clone();
    let call = tokio::spawn(async move {
        mcp(&relay2, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "ui_pe_info", "arguments": { "module": "game.exe" } } }), None).await
    });
    let req = recv_until(&mut app, |v| v["type"] == "provider_call").await;
    assert_eq!(req["verb"], "ui_pe_info");
    assert_eq!(req["args"]["module"], "game.exe");
    send(&mut app, json!({ "type": "provider_reply", "call": req["call"], "verb": "ui_pe_info", "result": { "is64": true } })).await;
    let (_, r) = call.await.unwrap();
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body: Value = serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["is64"], true);

    // provider errors come back as tool errors; a closed window fails in-flight calls
    let relay3 = relay.clone();
    let call = tokio::spawn(async move {
        mcp(&relay3, json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "ui_strings", "arguments": {} } }), None).await
    });
    let req = recv_until(&mut app, |v| v["type"] == "provider_call").await;
    send(&mut app, json!({ "type": "provider_reply", "call": req["call"], "verb": "ui_strings", "error": "no modules" })).await;
    let (_, r) = call.await.unwrap();
    assert_eq!(r["result"]["isError"], true);
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("no modules"));
}

#[tokio::test]
async fn mcp_event_stream_and_progress() {
    let (addr, relay) = start().await;
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }), None).await;
    assert_eq!(r["result"]["capabilities"]["resources"]["subscribe"], true);
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 2, "method": "resources/subscribe", "params": { "uri": "echodebug://status" } }), None).await;
    assert_eq!(r["result"], json!({}));

    // GET /mcp as SSE: an upstream connecting produces resources/updated
    let resp = router(relay.clone())
        .oneshot(Request::get("/mcp").header(header::ACCEPT, "text/event-stream").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body().into_data_stream();
    let _ext = connect(addr, "/ext").await;
    let chunk = tokio::time::timeout(Duration::from_secs(5), body.next()).await.unwrap().unwrap().unwrap();
    let text = String::from_utf8_lossy(&chunk);
    assert!(text.contains("notifications/resources/updated"), "{text}");

    // tools/call with a progressToken over SSE: progress events, then the result
    let mut ext = connect(addr, "/ext").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let relay2 = relay.clone();
    let streamed = tokio::spawn(async move {
        let msg = json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": { "name": "value_scan_clear", "arguments": {}, "_meta": { "progressToken": "p1" } } });
        let resp = router(relay2)
            .oneshot(Request::post("/mcp").header(header::ACCEPT, "application/json, text/event-stream").body(Body::from(msg.to_string())).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "text/event-stream");
        String::from_utf8_lossy(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).into_owned()
    });
    let req = recv_until(&mut ext, |v| v["type"] == "scan_clear").await;
    send(&mut ext, json!({ "type": "event", "event": "progress", "job": "scan_new", "done": 1, "total": 2 })).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    send(&mut ext, json!({ "type": "scan_clear_result", "id": req["id"], "success": true })).await;
    let text = streamed.await.unwrap();
    assert!(text.contains("notifications/progress") && text.contains("\"p1\""), "{text}");
    assert!(text.contains("\"id\":5"), "{text}");
}

#[tokio::test]
async fn mcp_policy_annotations_templates_completion() {
    let (addr, relay) = start().await;
    // annotations + outputSchema on every tool
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }), None).await;
    let tools = r["result"]["tools"].as_array().unwrap();
    let w = tools.iter().find(|t| t["name"] == "write_memory").unwrap();
    assert_eq!(w["annotations"]["destructiveHint"], true, "{w}");
    let rd = tools.iter().find(|t| t["name"] == "read_memory").unwrap();
    assert_eq!(rd["annotations"]["readOnlyHint"], true);
    assert_eq!(rd["outputSchema"]["type"], "object");
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {} }), None).await;
    assert!(r["result"]["capabilities"]["completions"].is_object());

    // read-only policy refuses writes without reaching any upstream
    let mut c = connect(addr, "/client").await;
    send(&mut c, json!({ "type": "mcp_policy", "id": 5, "mode": "readonly" })).await;
    let p = recv_until(&mut c, |v| v["id"] == 5).await;
    assert_eq!(p["mode"], "readonly", "{p}");
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "write_memory", "arguments": { "address": "0x1000", "data": "90" } } }), None).await;
    assert_eq!(r["result"]["isError"], true);
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("read-only"), "{r}");
    assert_eq!(r["result"]["structuredContent"]["code"], 4003);
    send(&mut c, json!({ "type": "mcp_policy", "id": 6, "mode": "nonsense" })).await;
    assert_eq!(recv_until(&mut c, |v| v["id"] == 6).await["type"], "error");

    // deny list
    send(&mut c, json!({ "type": "mcp_policy", "id": 7, "mode": "allow", "deny": ["ui_pe_info"] })).await;
    recv_until(&mut c, |v| v["id"] == 7).await;
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": { "name": "ui_pe_info", "arguments": {} } }), None).await;
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("deny list"), "{r}");

    // ask: no window → refused; with a window that approves → forwarded
    send(&mut c, json!({ "type": "mcp_policy", "id": 8, "mode": "ask", "deny": [] })).await;
    recv_until(&mut c, |v| v["id"] == 8).await;
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": { "name": "write_memory", "arguments": { "address": "0x1000", "data": "90" } } }), None).await;
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("approval"), "{r}");
    send(&mut c, json!({ "type": "provide", "id": 9, "verbs": ["ui_approve", "ui_names", "ui_pe_info"] })).await;
    recv_until(&mut c, |v| v["id"] == 9).await;
    let relay2 = relay.clone();
    let call = tokio::spawn(async move {
        mcp(&relay2, json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": { "name": "write_memory", "arguments": { "address": "0x1000", "data": "90" } } }), None).await
    });
    let ask = recv_until(&mut c, |v| v["type"] == "provider_call").await;
    assert_eq!(ask["verb"], "ui_approve");
    assert_eq!(ask["args"]["tool"], "write_memory");
    send(&mut c, json!({ "type": "provider_reply", "call": ask["call"], "verb": "ui_approve", "result": { "approved": false } })).await;
    let (_, r) = call.await.unwrap();
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("denied"), "{r}");
    // read-only tools are not asked about
    let relay3 = relay.clone();
    let call = tokio::spawn(async move {
        mcp(&relay3, json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": { "name": "ui_pe_info", "arguments": {} } }), None).await
    });
    let req = recv_until(&mut c, |v| v["type"] == "provider_call").await;
    assert_eq!(req["verb"], "ui_pe_info");
    send(&mut c, json!({ "type": "provider_reply", "call": req["call"], "verb": "ui_pe_info", "result": { "is64": true } })).await;
    let (_, r) = call.await.unwrap();
    assert_eq!(r["result"]["structuredContent"]["is64"], true, "{r}");
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 8, "method": "resources/read", "params": { "uri": "echodebug://mcp/log" } }), None).await;
    let log: Value = serde_json::from_str(r["result"]["contents"][0]["text"].as_str().unwrap()).unwrap();
    let outcomes: Vec<&str> = log["entries"].as_array().unwrap().iter().map(|e| e["outcome"].as_str().unwrap()).collect();
    assert_eq!(outcomes, ["denied", "denied", "denied", "denied", "ok"]);

    // resource templates route to provider verbs
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 9, "method": "resources/templates/list" }), None).await;
    assert!(r["result"]["resourceTemplates"].as_array().unwrap().len() >= 5);
    let relay4 = relay.clone();
    let read = tokio::spawn(async move {
        mcp(&relay4, json!({ "jsonrpc": "2.0", "id": 10, "method": "resources/read", "params": { "uri": "echodebug://module/game.exe/pe" } }), None).await
    });
    let req = recv_until(&mut c, |v| v["type"] == "provider_call").await;
    assert_eq!((req["verb"].as_str(), req["args"]["module"].as_str()), (Some("ui_pe_info"), Some("game.exe")));
    send(&mut c, json!({ "type": "provider_reply", "call": req["call"], "verb": "ui_pe_info", "result": { "machine": "x64" } })).await;
    let (_, r) = read.await.unwrap();
    assert!(r["result"]["contents"][0]["text"].as_str().unwrap().contains("x64"), "{r}");

    // completion: value types locally, names from the window
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 11, "method": "completion/complete", "params": { "ref": { "type": "ref/prompt", "name": "scan_value" }, "argument": { "name": "value_type", "value": "f" } } }), None).await;
    assert_eq!(r["result"]["completion"]["values"], json!(["f32", "f64"]), "{r}");
    let relay5 = relay.clone();
    let comp = tokio::spawn(async move {
        mcp(&relay5, json!({ "jsonrpc": "2.0", "id": 12, "method": "completion/complete", "params": { "ref": { "type": "ref/prompt", "name": "explain_function" }, "argument": { "name": "address", "value": "dec" } } }), None).await
    });
    let req = recv_until(&mut c, |v| v["type"] == "provider_call").await;
    assert_eq!(req["verb"], "ui_names");
    send(&mut c, json!({ "type": "provider_reply", "call": req["call"], "verb": "ui_names", "result": { "names": [{ "name": "decrypt_string" }, { "name": "main" }] } })).await;
    let (_, r) = comp.await.unwrap();
    assert_eq!(r["result"]["completion"]["values"], json!(["decrypt_string"]), "{r}");
}

#[tokio::test]
async fn annotation_tools_go_through_provider_and_policy() {
    let (addr, relay) = start().await;
    let call = |id: u64, name: &str, args: Value| json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": args } });
    let text = |r: &Value| r["result"]["content"][0]["text"].as_str().unwrap().to_owned();

    // annotations: listing is read-only, naming changes EchoDebug state, revert writes the target
    let (_, r) = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }), None).await;
    let tools = r["result"]["tools"].as_array().unwrap();
    let tool = |n: &str| tools.iter().find(|t| t["name"] == n).unwrap_or_else(|| panic!("missing tool {n}")).clone();
    for n in ["list_names", "list_comments", "list_patches", "list_signatures"] {
        assert_eq!(tool(n)["annotations"]["readOnlyHint"], true, "{n}");
    }
    assert_eq!(tool("set_name")["annotations"]["readOnlyHint"], false);
    assert_eq!(tool("set_name")["annotations"]["destructiveHint"], false);
    assert_eq!(tool("set_comment")["annotations"]["readOnlyHint"], false);
    assert_eq!(tool("revert_patch")["annotations"]["destructiveHint"], true);

    // no app window: the provider error, not a hang
    let (_, r) = mcp(&relay, call(2, "list_names", json!({})), None).await;
    assert_eq!(r["result"]["isError"], true);
    assert!(text(&r).contains("app window"), "{r}");

    // the window serves them as ui_* provider verbs
    let mut app = connect(addr, "/client").await;
    send(&mut app, json!({ "type": "provide", "id": 9, "verbs": ["ui_set_name", "ui_revert_patch", "ui_approve"] })).await;
    recv_until(&mut app, |v| v["type"] == "provide_result" && v["id"] == 9).await;
    let relay2 = relay.clone();
    let pending = tokio::spawn(async move { mcp(&relay2, call(3, "set_name", json!({ "address": "0x140001000", "name": "main" })), None).await });
    let req = recv_until(&mut app, |v| v["type"] == "provider_call").await;
    assert_eq!(req["verb"], "ui_set_name");
    assert_eq!((req["args"]["address"].as_str(), req["args"]["name"].as_str()), (Some("0x140001000"), Some("main")));
    send(&mut app, json!({ "type": "provider_reply", "call": req["call"], "verb": "ui_set_name", "result": { "address": "0x140001000", "name": "main" } })).await;
    let (_, r) = pending.await.unwrap();
    assert_eq!(r["result"]["isError"], false, "{r}");
    assert_eq!(r["result"]["structuredContent"]["name"], "main");

    // read-only policy: revert_patch is refused before reaching the window; naming still works
    send(&mut app, json!({ "type": "mcp_policy", "id": 10, "mode": "readonly" })).await;
    recv_until(&mut app, |v| v["id"] == 10).await;
    let (_, r) = mcp(&relay, call(4, "revert_patch", json!({ "patch_id": "p1" })), None).await;
    assert!(text(&r).contains("read-only"), "{r}");

    // ask policy: the window is asked first, and a refusal stops the revert
    send(&mut app, json!({ "type": "mcp_policy", "id": 11, "mode": "ask" })).await;
    recv_until(&mut app, |v| v["id"] == 11).await;
    let relay3 = relay.clone();
    let pending = tokio::spawn(async move { mcp(&relay3, call(5, "revert_patch", json!({ "patch_id": "p1" })), None).await });
    let ask = recv_until(&mut app, |v| v["type"] == "provider_call").await;
    assert_eq!((ask["verb"].as_str(), ask["args"]["tool"].as_str()), (Some("ui_approve"), Some("revert_patch")));
    send(&mut app, json!({ "type": "provider_reply", "call": ask["call"], "verb": "ui_approve", "result": { "approved": false } })).await;
    let (_, r) = pending.await.unwrap();
    assert!(text(&r).contains("denied"), "{r}");
}

#[tokio::test]
async fn arm64_disassembly_goes_through_read_on_the_echo_backend() {
    let (addr, _) = start().await;
    let mut agent = connect(addr, "/agent").await;
    let mut client = client_when(addr, true, false).await;
    send(&mut client, json!({ "type": "disassemble", "id": 7, "address": "0x14000104c", "size": 12, "arch": "arm64" })).await;
    let req = recv_until(&mut agent, |_| true).await;
    assert_eq!(req["type"], "read", "the relay reads the code instead of asking Echo's x86 decoder");
    assert_eq!(req["size"], 12);
    // adrp x0, 0x140002000 ; add x0, x0, #0x0 ; bl 0x14000100c
    send(&mut agent, json!({ "type": "read_result", "id": req["id"], "success": true, "data": "000000b000000091eeffff97" })).await;
    let reply = recv_until(&mut client, |v| v["type"] == "disassemble_result").await;
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["arch"], "arm64");
    let lines = reply["results"].as_array().unwrap();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["text"], "adrp x0, 0x140002000");
    assert_eq!(lines[1]["text"], "add x0, x0, #0x0  ; 0x140002000");
    assert_eq!(lines[2]["text"], "bl 0x14000100c");
    assert_eq!(lines[2]["length"], 4);
    assert_eq!(lines[2]["bytes"], "eeffff97");

    // x86-64 (no arch) still goes to Echo verbatim
    send(&mut client, json!({ "type": "disassemble", "id": 8, "address": "0x1000", "size": 4 })).await;
    let req = recv_until(&mut agent, |_| true).await;
    assert_eq!(req["type"], "disassemble");

    // disasm_bytes decodes either architecture in the relay
    send(&mut client, json!({ "type": "disasm_bytes", "id": 9, "data": "c0035fd6", "address": "0x0", "arch": "aarch64" })).await;
    let reply = recv_until(&mut client, |v| v["type"] == "disasm_bytes_result").await;
    assert_eq!(reply["results"][0]["text"], "ret");
}
