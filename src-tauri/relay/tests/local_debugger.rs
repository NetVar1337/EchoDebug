//! End-to-end test of the ptrace debugger's access finder ("find what writes / accesses this
//! address") and API call monitor: a small C program compiled at test time, the real relay, a real
//! /client WebSocket. Linux only; skipped when no C compiler is installed or ptrace is refused.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use echo_debug_relay::{bind, run, Relay};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Increments a global (one writer instruction, one reader), and calls write(-1, "hi", 2) and
/// getpid() in a loop. Prints the global's address.
const PROGRAM: &str = r#"
#include <stdio.h>
#include <unistd.h>
volatile long counter;
volatile long sink;
int main(void) {
    printf("%p\n", (void *)&counter);
    fflush(stdout);
    for (;;) {
        counter = counter + 1;
        sink = counter;
        write(-1, "hi", 2);
        getpid();
        usleep(500);
    }
}
"#;

fn build_program() -> Option<std::path::PathBuf> {
    let dir = std::env::temp_dir().join(format!("echodebug-dbgtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let src = dir.join("target.c");
    let bin = dir.join("target");
    std::fs::write(&src, PROGRAM).ok()?;
    let ok = Command::new("cc").args(["-O0", "-o"]).arg(&bin).arg(&src).status().ok()?.success();
    ok.then_some(bin)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn access_finder_and_api_monitor_on_a_live_process() {
    let cfg = std::env::temp_dir().join(format!("echodebug-dbgtest-cfg-{}", std::process::id()));
    std::env::set_var("XDG_CONFIG_HOME", &cfg);
    let Some(bin) = build_program() else {
        eprintln!("no C compiler here, skipping");
        return;
    };
    let mut proc = Command::new(&bin).stdout(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(proc.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let child = Child(proc);
    let pid = child.0.id();
    let counter = line.trim().to_owned();

    let relay = Relay::new("1.2.3", Duration::from_secs(30)).with_local_backend(true);
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay));
    let (mut ws, _) = connect_async(format!("ws://{addr}/client")).await.unwrap();
    let mut next = 0u64;
    let mut events: Vec<Value> = Vec::new();
    let mut call = async |v: Value, events: &mut Vec<Value>| -> Value {
        next += 1;
        let mut v = v;
        v["id"] = json!(next);
        ws.send(Message::text(v.to_string())).await.unwrap();
        loop {
            let m = tokio::time::timeout(Duration::from_secs(30), ws.next()).await.expect("reply").unwrap().unwrap();
            if let Message::Text(t) = m {
                let f: Value = serde_json::from_str(t.as_str()).unwrap();
                if f["id"] == json!(next) {
                    return f;
                }
                if f["type"] == "event" {
                    events.push(f);
                }
            }
        }
    };

    let r = call(json!({ "type": "attach", "pid": pid }), &mut events).await;
    if r["type"] == "error" {
        eprintln!("cannot attach here, skipping: {r}");
        return;
    }
    let st = call(json!({ "type": "status" }), &mut events).await;
    assert_eq!(st["debugger"], "ptrace", "{st}");

    // find what writes: the session attaches on its own and the process keeps running
    let t = call(json!({ "type": "dbg_trace_start", "address": counter, "size": 8, "kind": "write" }), &mut events).await;
    if t["type"] == "error" && t["detail"].as_str().unwrap_or("").contains("PTRACE_SEIZE") {
        eprintln!("ptrace not permitted here, skipping: {t}");
        return;
    }
    assert_eq!(t["success"], true, "{t}");
    assert_eq!(t["auto"], true, "{t}");
    let slot = t["slot"].as_u64().unwrap();
    let s = call(json!({ "type": "dbg_status" }), &mut events).await;
    assert_eq!(s["state"], "running", "{s}");
    assert_eq!(s["hardware"][slot as usize]["trace"], true, "{s}");
    let mut hits = Value::Null;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let r = call(json!({ "type": "dbg_trace_results", "slot": slot }), &mut events).await;
        if r["traces"][0]["total"].as_u64().unwrap_or(0) >= 5 {
            hits = r["traces"][0].clone();
            break;
        }
    }
    assert!(hits["total"].as_u64().unwrap_or(0) >= 5, "the writer was caught: {hits}");
    let list = hits["hits"].as_array().unwrap();
    assert_eq!(list.len(), 1, "one instruction writes the counter: {hits}");
    assert!(list[0]["text"].as_str().unwrap().starts_with("mov"), "{hits}");
    assert!(list[0]["regs"]["rip"].as_str().unwrap().starts_with("0x"), "{hits}");
    // the writer is a store to the counter, decoded from the bytes before the trap address
    let dis = call(json!({ "type": "dbg_disasm", "address": list[0]["address"], "size": 16 }), &mut events).await;
    assert_eq!(dis["results"][0]["text"], list[0]["text"], "{dis}");

    // stopping the last monitor of an auto-started session detaches cleanly
    let stop = call(json!({ "type": "dbg_trace_stop", "slot": slot }), &mut events).await;
    assert_eq!(stop["success"], true, "{stop}");
    assert_eq!(stop["detached"], true, "{stop}");
    assert_eq!(call(json!({ "type": "dbg_status" }), &mut events).await["active"], false);
    let kept = call(json!({ "type": "dbg_trace_results" }), &mut events).await;
    assert_eq!(kept["traces"][0]["active"], false, "results stay readable: {kept}");
    assert!(events.iter().any(|e| e["event"] == "dbg_access"), "a new accessor is broadcast");

    // find what accesses: the reader shows up too
    let t = call(json!({ "type": "dbg_trace_start", "address": counter, "size": 8, "kind": "access" }), &mut events).await;
    assert_eq!(t["success"], true, "{t}");
    let mut n = 0;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let r = call(json!({ "type": "dbg_trace_results", "slot": t["slot"] }), &mut events).await;
        n = r["traces"][0]["hits"].as_array().map(|a| a.len()).unwrap_or(0);
        if n >= 2 {
            break;
        }
    }
    assert!(n >= 2, "reads and writes of the counter are both found");
    call(json!({ "type": "dbg_trace_stop" }), &mut events).await;

    // API monitor: libc write and getpid, arguments decoded, return values matched
    let sigs = call(json!({ "type": "dbg_api_signatures" }), &mut events).await;
    assert!(sigs["signatures"].as_array().unwrap().iter().any(|s| s["name"] == "write"), "{sigs}");
    let a = call(json!({ "type": "dbg_api_start", "functions": ["libc.so.6!write", "getpid", "nope!nothing"] }), &mut events).await;
    assert_eq!(a["success"], true, "{a}");
    assert_eq!(a["hooked"].as_array().unwrap().len(), 2, "{a}");
    assert_eq!(a["unresolved"][0]["name"], "nope!nothing", "{a}");
    // the entry int3 is hidden from reads
    let hook = a["hooked"][0]["address"].as_str().unwrap().to_owned();
    let byte = call(json!({ "type": "read", "address": hook, "size": 1 }), &mut events).await;
    assert_ne!(byte["data"], "cc", "{byte}");
    let mut log = Value::Null;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        log = call(json!({ "type": "dbg_api_log", "since": 0, "limit": 200 }), &mut events).await;
        let es = log["entries"].as_array().unwrap();
        if es.iter().filter(|e| e["returned"] == true && e["function"] == "getpid").count() >= 2 && es.iter().any(|e| e["returned"] == true && e["function"] == "libc.so.6!write") {
            break;
        }
    }
    let es = log["entries"].as_array().unwrap();
    let w = es.iter().find(|e| e["function"] == "libc.so.6!write" && e["returned"] == true).unwrap_or_else(|| panic!("write was logged: {log}"));
    assert_eq!(w["args"][0]["text"], "-1", "{w}");
    assert!(w["args"][1]["text"].as_str().unwrap().ends_with("\"hi\""), "{w}");
    assert_eq!(w["args"][2]["text"], "2", "{w}");
    assert_eq!(w["ret_text"], "-1", "write(-1, …) fails: {w}");
    assert!(w["caller"].as_str().unwrap() != "0x0", "{w}");
    let g = es.iter().find(|e| e["function"] == "getpid" && e["returned"] == true).unwrap();
    assert_eq!(g["ret_text"], pid.to_string(), "{g}");
    // filtering and paging
    let f = call(json!({ "type": "dbg_api_log", "filter": "getpid" }), &mut events).await;
    assert!(f["entries"].as_array().unwrap().iter().all(|e| e["function"] == "getpid"), "{f}");
    let next_seq = log["next"].as_u64().unwrap();
    let later = call(json!({ "type": "dbg_api_log", "since": next_seq }), &mut events).await;
    assert!(later["entries"].as_array().unwrap().iter().all(|e| e["seq"].as_u64().unwrap() > next_seq));

    let stop = call(json!({ "type": "dbg_api_stop" }), &mut events).await;
    assert_eq!(stop["detached"], true, "{stop}");
    let byte2 = call(json!({ "type": "read", "address": hook, "size": 1 }), &mut events).await;
    assert_eq!(byte2["data"], byte["data"], "original byte restored");
    // the target survived all of it
    let alive = call(json!({ "type": "alive" }), &mut events).await;
    assert_eq!(alive["alive"], true, "{alive}");
    let s = call(json!({ "type": "dbg_status" }), &mut events).await;
    assert_eq!(s["active"], false);
}
