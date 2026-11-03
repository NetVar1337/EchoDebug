//! `/sync` end to end: fake disassembler plugins and a fake app window over real sockets.

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::{header, StatusCode};
use echo_debug_relay::{bind, run, Relay};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const TOKEN: &str = "sync-token-0123456789abcdef0123456789";

async fn start() -> (SocketAddr, Relay) {
    let relay = Relay::new("1.2.3", Duration::from_secs(5)).with_local_backend(false).with_token(Some(TOKEN.into()));
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay.clone()));
    (addr, relay)
}

async fn connect(addr: SocketAddr, path: &str) -> Ws {
    connect_async(format!("ws://{addr}{path}")).await.unwrap().0
}

/// A plugin connects with the bearer header (IDA / Binja / Ghidra all can send headers).
async fn plugin(addr: SocketAddr, tool: &str, modules: Value) -> Ws {
    let mut req = format!("ws://{addr}/sync").into_client_request().unwrap();
    req.headers_mut().insert(header::AUTHORIZATION, format!("Bearer {TOKEN}").parse().unwrap());
    let mut ws = connect_async(req).await.unwrap().0;
    send(&mut ws, json!({ "type": "hello", "tool": tool, "version": "test", "file": "game.i64", "modules": modules })).await;
    let r = recv_until(&mut ws, |v| v["type"] == "hello_result").await;
    assert_eq!(r["protocol"], 1);
    ws
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

/// Nothing matching `pred` arrives within `ms`.
async fn quiet(ws: &mut Ws, ms: u64, pred: impl Fn(&Value) -> bool) {
    let r = tokio::time::timeout(Duration::from_millis(ms), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) => {
                    let v: Value = serde_json::from_str(t.as_str()).unwrap();
                    if pred(&v) {
                        return v;
                    }
                }
                Some(Ok(_)) => {}
                _ => futures_util::future::pending::<()>().await,
            }
        }
    })
    .await;
    if let Ok(v) = r {
        panic!("unexpected frame {v}");
    }
}

async fn call(app: &mut Ws, id: u64, v: Value) -> Value {
    let mut v = v;
    v["id"] = json!(id);
    send(app, v).await;
    recv_until(app, |f| f["id"] == id).await
}

#[tokio::test]
async fn sync_needs_the_token() {
    let (addr, _) = start().await;
    match connect_async(format!("ws://{addr}/sync")).await {
        Err(WsError::Http(resp)) => assert_eq!(resp.status(), StatusCode::UNAUTHORIZED),
        other => panic!("expected 401, got {:?}", other.map(|_| ())),
    }
    match connect_async(format!("ws://{addr}/sync?token=wrong")).await {
        Err(WsError::Http(resp)) => assert_eq!(resp.status(), StatusCode::UNAUTHORIZED),
        other => panic!("expected 401, got {:?}", other.map(|_| ())),
    }
    // a browser page cannot reach it even with the token
    let mut req = format!("ws://{addr}/sync?token={TOKEN}").into_client_request().unwrap();
    req.headers_mut().insert(header::ORIGIN, "https://evil.example".parse().unwrap());
    match connect_async(req).await {
        Err(WsError::Http(resp)) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
        other => panic!("expected 403, got {:?}", other.map(|_| ())),
    }
    // ?token= works too; frames before hello are refused
    let mut ws = connect(addr, &format!("/sync?token={TOKEN}")).await;
    send(&mut ws, json!({ "type": "cursor", "module": "a.exe", "rva": 1 })).await;
    let e = recv_until(&mut ws, |v| v["type"] == "error").await;
    assert!(e["message"].as_str().unwrap().contains("hello"));
}

#[tokio::test]
async fn cursor_names_comments_and_types_round_trip() {
    let (addr, relay) = start().await;
    let mut app = connect(addr, &format!("/client?token={TOKEN}")).await;
    let mut ida = plugin(addr, "ida", json!([{ "name": "game.exe", "base": "0x140000000" }])).await;
    recv_until(&mut app, |v| v["type"] == "sync_event" && v["kind"] == "peers").await;

    // IDA moves: the app hears it as module + RVA
    send(&mut ida, json!({ "type": "cursor", "module": "game.exe", "rva": "0x1abc" })).await;
    let c = recv_until(&mut app, |v| v["type"] == "sync_event" && v["kind"] == "cursor").await;
    assert_eq!((c["module"].as_str(), c["rva"].as_str(), c["from"].as_str()), (Some("game.exe"), Some("0x1abc"), Some("ida")));

    // a second tool with a dumped file name, mapped onto the live module
    let mut ghidra = plugin(addr, "ghidra", json!(["game_dump.exe"])).await;
    let r = call(&mut app, 1, json!({ "type": "sync_config", "map": { "game_dump.exe": "game.exe" }, "directions": { "comments_out": true } })).await;
    assert_eq!(r["type"], "sync_config_result");
    assert_eq!(r["map"]["game_dump.exe"], "game.exe");
    recv_until(&mut ghidra, |v| v["type"] == "config").await;

    // the app moves: both tools follow, each with its own module name
    let r = call(&mut app, 2, json!({ "type": "sync_send", "kind": "cursor", "module": "game.exe", "rva": "0x2000" })).await;
    assert_eq!(r["peers"], 2);
    let f = recv_until(&mut ida, |v| v["type"] == "cursor").await;
    assert_eq!((f["module"].as_str(), f["rva"].as_str()), (Some("game.exe"), Some("0x2000")));
    let f = recv_until(&mut ghidra, |v| v["type"] == "cursor").await;
    assert_eq!(f["module"], "game_dump.exe");
    // IDA reports the place it just jumped to: no echo back to anyone
    send(&mut ida, json!({ "type": "cursor", "module": "game.exe", "rva": "0x2000" })).await;
    quiet(&mut ghidra, 200, |v| v["type"] == "cursor").await;

    // names: Ghidra renames, IDA and the app get it
    send(&mut ghidra, json!({ "type": "name", "module": "game_dump.exe", "rva": "0x2000", "name": "decrypt_config" })).await;
    let n = recv_until(&mut app, |v| v["type"] == "sync_event" && v["kind"] == "name").await;
    assert_eq!((n["module"].as_str(), n["name"].as_str(), n["from"].as_str()), (Some("game.exe"), Some("decrypt_config"), Some("ghidra")));
    let n = recv_until(&mut ida, |v| v["type"] == "name").await;
    assert_eq!(n["name"], "decrypt_config");
    // the app overwrites it: last writer wins, the conflict is in the log
    call(&mut app, 3, json!({ "type": "sync_send", "kind": "name", "module": "game.exe", "rva": "0x2000", "name": "load_config" })).await;
    assert_eq!(recv_until(&mut ghidra, |v| v["type"] == "name").await["name"], "load_config");
    let st = call(&mut app, 4, json!({ "type": "sync_status" })).await;
    let log = st["log"].as_array().unwrap();
    assert!(log.iter().any(|e| e["dir"] == "conflict"), "{log:?}");
    assert_eq!(st["peers"].as_array().unwrap().len(), 2);
    assert_eq!(st["cursor"]["rva"], "0x2000");

    // comments keep newlines
    send(&mut ida, json!({ "type": "comment", "module": "game.exe", "rva": 16, "comment": "xor key\nsee 0x40" })).await;
    let cm = recv_until(&mut app, |v| v["type"] == "sync_event" && v["kind"] == "comment").await;
    assert_eq!(cm["comment"], "xor key\nsee 0x40");
    assert_eq!(cm["rva"], "0x10");

    // struct types go to every tool
    let r = call(&mut app, 5, json!({ "type": "sync_send", "kind": "types", "decls": "struct Player { int hp; };", "names": ["Player"] })).await;
    assert_eq!(r["peers"], 2);
    assert_eq!(recv_until(&mut ida, |v| v["type"] == "types").await["names"][0], "Player");

    // turning a direction off stops it
    call(&mut app, 6, json!({ "type": "sync_config", "directions": { "cursor_in": false } })).await;
    send(&mut ida, json!({ "type": "cursor", "module": "game.exe", "rva": "0x3000" })).await;
    quiet(&mut app, 200, |v| v["type"] == "sync_event" && v["kind"] == "cursor").await;
    // ghidra still follows (cursor_out)
    assert_eq!(recv_until(&mut ghidra, |v| v["type"] == "cursor").await["rva"], "0x3000");

    // errors stay with their sender; pings are answered
    send(&mut ida, json!({ "type": "name", "module": "game.exe", "rva": "nope", "name": "x" })).await;
    assert_eq!(recv_until(&mut ida, |v| v["type"] == "error").await["for"], "name");
    send(&mut ida, json!({ "type": "ping" })).await;
    recv_until(&mut ida, |v| v["type"] == "pong").await;

    // a closed plugin leaves the peer list
    ida.close(None).await.unwrap();
    for _ in 0..50 {
        let st = call(&mut app, 7, json!({ "type": "sync_status", "log_limit": 0 })).await;
        if st["peers"].as_array().unwrap().len() == 1 {
            assert_eq!(st["log"].as_array().unwrap().len(), 0);
            return drop(relay);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("peer was not removed");
}

#[tokio::test]
async fn sync_status_is_a_read_only_mcp_tool() {
    let (addr, relay) = start().await;
    let _ida = plugin(addr, "ida", json!(["game.exe"])).await;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
    let r = mcp(&relay, body).await;
    let tool = r["result"]["tools"].as_array().unwrap().iter().find(|t| t["name"] == "sync_status").cloned().expect("sync_status listed");
    assert_eq!(tool["annotations"]["readOnlyHint"], true);
    assert!(!r["result"]["tools"].as_array().unwrap().iter().any(|t| t["name"].as_str().unwrap().starts_with("sync_") && t["name"] != "sync_status"), "only the status is exposed");
    let r = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "sync_status", "arguments": {} } })).await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    assert_eq!(r["result"]["structuredContent"]["peers"][0]["tool"], "ida");
    // read-only policy does not gate it
    let mut app = connect(addr, &format!("/client?token={TOKEN}")).await;
    call(&mut app, 1, json!({ "type": "mcp_policy", "mode": "readonly" })).await;
    let r = mcp(&relay, json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "sync_status", "arguments": {} } })).await;
    assert_eq!(r["result"]["isError"], false);
}

async fn mcp(relay: &Relay, body: Value) -> Value {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    let resp = echo_debug_relay::router(relay.clone())
        .oneshot(
            Request::post("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header("mcp-protocol-version", "2025-06-18")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
