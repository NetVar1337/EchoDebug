//! Time-travel traces end to end on the Linux local backend: record the Emu Debugger's Unicorn
//! session and a real ptrace'd thread through the relay's /client socket, then query, export and
//! import. Linux only.
#![cfg(target_os = "linux")]

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

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_query_export_import() {
    let cfg = std::env::temp_dir().join(format!("echodebug-trace-test-{}", std::process::id()));
    std::env::set_var("XDG_CONFIG_HOME", &cfg);
    let relay = Relay::new("1.2.3", Duration::from_secs(60)).with_local_backend(true);
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay));
    let (mut ws, _) = connect_async(format!("ws://{addr}/client")).await.unwrap();
    let mut next = 0u64;
    let mut progress_events = 0usize;
    let mut call = async |v: Value| -> Value {
        next += 1;
        let mut v = v;
        v["id"] = json!(next);
        ws.send(Message::text(v.to_string())).await.unwrap();
        loop {
            let m = tokio::time::timeout(Duration::from_secs(120), ws.next()).await.expect("reply").unwrap().unwrap();
            if let Message::Text(t) = m {
                let f: Value = serde_json::from_str(t.as_str()).unwrap();
                if f["event"] == "trace_progress" {
                    progress_events += 1;
                }
                if f["id"] == json!(next) {
                    return f;
                }
            }
        }
    };

    // ---- emulator: a blank session running caller-supplied code, recorded natively ------------
    // 0x400000: mov rcx, 3 ; loop: mov [0x500000+rcx*8], rcx ; dec rcx ; jnz loop ; mov rax, [0x500008] ; ret
    let code = "48c7c103000000 48890ccd00005000 48ffc9 75f3 488b042508005000 c3".replace(' ', "");
    let r = call(json!({ "type": "trace_record", "source": "emu", "start": "0x400000", "code": code, "max_steps": 1000, "keyframe": 4, "name": "loop" })).await;
    assert_eq!(r["success"], true, "{r}");
    let t = &r["trace"];
    // mov + 3 × (store, dec, jnz) + load + ret = 12
    assert_eq!(t["steps"], 12, "{r}");
    assert_eq!(t["stop_reason"], "returned", "{r}");
    assert_eq!(t["source"], "emu");
    let emu_id = t["trace_id"].as_str().unwrap().to_owned();
    // 3 stores, plus the call's return-address push is not in the trace (the session starts inside)
    assert!(t["writes"].as_u64().unwrap() >= 3, "{t}");
    // when did [0x500010] (rcx = 2) change? step 4 (mov rcx; store 3; dec; jnz; store 2)
    let q = call(json!({ "type": "trace_query", "kind": "last_write", "address": "0x500010", "size": 8 })).await;
    assert_eq!(q["write"]["step"], 4, "{q}");
    assert_eq!(q["write"]["new"], "0200000000000000", "{q}");
    // memory reconstructed before and after that store
    let before = call(json!({ "type": "trace_query", "kind": "mem_at", "address": "0x500010", "size": 8, "pos": 4 })).await;
    assert_eq!(before["data"], "0000000000000000", "{before}");
    let after = call(json!({ "type": "trace_query", "kind": "mem_at", "address": "0x500010", "size": 8, "pos": 5 })).await;
    assert_eq!(after["data"], "0200000000000000", "{after}");
    // the loop body ran three times; rax at the end came from [0x500008] ← rcx ← dec …
    let ex = call(json!({ "type": "trace_query", "kind": "executions_of", "address": "0x400007" })).await;
    assert_eq!(ex["steps"], json!([1, 4, 7]), "{ex}");
    let rax = call(json!({ "type": "trace_query", "kind": "reg_at", "reg": "rax" })).await;
    assert_eq!(rax["value"], "0x1", "{rax}");
    let taint = call(json!({ "type": "trace_query", "kind": "taint", "reg": "rax" })).await;
    let hops = taint["hops"].as_array().unwrap();
    assert_eq!(hops[0]["kind"], "mov", "{taint}");
    assert!(hops.iter().any(|h| h["loc"]["kind"] == "mem" && h["step"] == 7), "the store of rcx = 1 at step 7: {taint}");
    let series = call(json!({ "type": "trace_query", "kind": "reg_series", "reg": "rcx" })).await;
    assert!(series["points"].as_array().unwrap().len() >= 4, "{series}");

    // ---- ptrace: a few hundred single-steps of a real thread ---------------------------------
    let child = Child(std::process::Command::new("sh").args(["-c", "while :; do :; done"]).spawn().unwrap());
    let pid = child.0.id();
    let a = call(json!({ "type": "attach", "pid": pid })).await;
    if a["type"] == "error" {
        eprintln!("cannot attach here, skipping the ptrace half: {a}");
        return;
    }
    let d = call(json!({ "type": "dbg_attach" })).await;
    if d["type"] == "error" {
        eprintln!("ptrace not permitted here, skipping the ptrace half: {d}");
        return;
    }
    let regs0 = call(json!({ "type": "dbg_regs" })).await["regs"].clone();
    let r = call(json!({ "type": "trace_record", "source": "ptrace", "max_steps": 400, "keyframe": 32, "name": "sh" })).await;
    assert_eq!(r["success"], true, "{r}");
    let t = r["trace"].clone();
    assert_eq!(t["steps"], 400, "{t}");
    assert_eq!(t["source"], "ptrace");
    assert_eq!(t["pid"], pid);
    assert_eq!(t["initial_regs"]["rip"], regs0["rip"], "{t}");
    // the trace's final state is where the thread really is now
    let now = call(json!({ "type": "dbg_regs" })).await;
    for k in ["rip", "rsp", "rax", "rbx", "rcx"] {
        assert_eq!(t["final_regs"][k], now["regs"][k], "{k}: {t} vs {now}");
    }
    let id = t["trace_id"].as_str().unwrap().to_owned();
    // seeking through keyframes agrees with each step's own "registers before"
    for pos in [0u64, 31, 32, 33, 200, 399] {
        let s = call(json!({ "type": "trace_query", "trace": id, "kind": "step", "pos": pos })).await;
        let r = call(json!({ "type": "trace_query", "trace": id, "kind": "reg_at", "pos": pos })).await;
        assert_eq!(s["regs_before"], r["regs"], "pos {pos}");
        assert_eq!(s["pc"], r["regs"]["rip"], "pos {pos}");
    }
    // every recorded write is what memory holds right after its step
    let touched = call(json!({ "type": "trace_query", "trace": id, "kind": "touched" })).await;
    let ranges = touched["ranges"].as_array().unwrap();
    assert!(!ranges.is_empty(), "a shell loop touches its stack: {touched}");
    let w = ranges.iter().find(|r| r["writes"].as_u64().unwrap() > 0);
    if let Some(w) = w {
        let all = call(json!({ "type": "trace_query", "trace": id, "kind": "writes_to", "address": w["address"], "size": w["size"] })).await;
        let first = &all["writes"][0];
        let step = first["step"].as_u64().unwrap();
        let m = call(json!({ "type": "trace_query", "trace": id, "kind": "mem_at", "address": first["address"], "size": first["size"], "pos": step + 1 })).await;
        assert_eq!(m["data"], first["new"], "{m} vs {first}");
        let lw = call(json!({ "type": "trace_query", "trace": id, "kind": "last_write", "address": first["address"], "size": first["size"], "pos": step + 1, "changed_only": false })).await;
        assert_eq!(lw["write"]["step"], step, "{lw}");
        assert!(hex(&first["address"]) > 0);
    }

    // ---- export, import, list, delete --------------------------------------------------------
    let ex = call(json!({ "type": "trace_export", "trace": id })).await;
    assert_eq!(ex["success"], true, "{ex}");
    let im = call(json!({ "type": "trace_import", "data": ex["data"], "name": "copy" })).await;
    assert_eq!(im["success"], true, "{im}");
    assert_eq!(im["steps"], 400);
    assert_eq!(im["final_regs"], t["final_regs"]);
    let copy = im["trace_id"].as_str().unwrap().to_owned();
    let a = call(json!({ "type": "trace_query", "trace": id, "kind": "reg_at", "pos": 123 })).await;
    let b = call(json!({ "type": "trace_query", "trace": copy, "kind": "reg_at", "pos": 123 })).await;
    assert_eq!(a["regs"], b["regs"]);
    let l = call(json!({ "type": "trace_list" })).await;
    let ids: Vec<&str> = l["traces"].as_array().unwrap().iter().filter_map(|t| t["trace_id"].as_str()).collect();
    for want in [&emu_id, &id, &copy] {
        assert!(ids.contains(&want.as_str()), "{want} in {l}");
    }
    let del = call(json!({ "type": "trace_delete", "trace": copy })).await;
    assert_eq!(del["removed"], true, "{del}");
    let bad = call(json!({ "type": "trace_import", "data": "AAAA" })).await;
    assert_eq!(bad["type"], "error");
    call(json!({ "type": "dbg_detach" })).await;
    let _ = progress_events;
    let _ = std::fs::remove_dir_all(&cfg);
    drop(child);
}
