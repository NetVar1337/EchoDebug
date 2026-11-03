//! End-to-end test of the Linux local backend: a real child process, the real relay, a real
//! /client WebSocket. Linux only (the backend reads /proc/<pid>).
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_backend_against_a_live_process() {
    // journal and pointer maps go to a scratch config dir, not the user's
    let cfg = std::env::temp_dir().join(format!("echodebug-test-{}", std::process::id()));
    std::env::set_var("XDG_CONFIG_HOME", &cfg);
    let child = Child(std::process::Command::new("sh").args(["-c", "while :; do :; done"]).spawn().unwrap());
    let pid = child.0.id();
    let relay = Relay::new("1.2.3", Duration::from_secs(30)).with_local_backend(true);
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay));
    let (mut ws, _) = connect_async(format!("ws://{addr}/client")).await.unwrap();
    let mut next = 0u64;
    let mut call = async |v: Value| -> Value {
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
            }
        }
    };

    let r = call(json!({ "type": "attach", "pid": pid })).await;
    if r["type"] == "error" {
        eprintln!("cannot attach here, skipping: {r}");
        return;
    }
    assert_eq!(r["pid"], pid);

    let mods = call(json!({ "type": "modules" })).await;
    let list = mods["modules"].as_array().unwrap();
    assert!(list.iter().any(|m| m["name"].as_str().unwrap().starts_with("libc")), "{mods}");

    // writable region for freeze/watch
    let regions = call(json!({ "type": "regions" })).await;
    let rw = regions["regions"].as_array().unwrap().iter().find(|r| r["writable"] == true && r["size"].as_u64().unwrap() >= 0x1000).unwrap().clone();
    let a = rw["base"].as_str().unwrap().to_owned();
    let before = call(json!({ "type": "read", "address": a, "size": 4 })).await;
    assert_eq!(before["success"], true, "{before}");

    // page monitor: a write to the watched page is seen on the next tick
    let pm = call(json!({ "type": "page_monitor", "address": a, "size": 0x1000, "interval_ms": 100 })).await;
    assert_eq!(pm["readable"], 1, "{pm}");
    let orig4 = before["data"].as_str().unwrap().to_owned();
    let flipped: String = if orig4 == "01020304" { "05060708".into() } else { "01020304".into() };
    call(json!({ "type": "write", "address": a, "data": flipped })).await;
    let mut seen = 0;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let l = call(json!({ "type": "page_monitor_list" })).await;
        seen = l["entries"][0]["changes"].as_u64().unwrap_or(0);
        if seen > 0 {
            break;
        }
    }
    assert!(seen > 0, "page change detected");
    call(json!({ "type": "write", "address": a, "data": orig4 })).await;
    let off = call(json!({ "type": "page_monitor", "address": a, "enabled": false })).await;
    assert_eq!(off["removed"], true);
    let mm = call(json!({ "type": "module_monitor", "interval_ms": 200 })).await;
    assert!(mm["modules"].as_u64().unwrap() >= 2, "{mm}");
    let tl = call(json!({ "type": "module_timeline" })).await;
    assert_eq!(tl["enabled"], true);
    call(json!({ "type": "module_monitor", "enabled": false })).await;

    // hashing, snapshots and diffs in the backend
    let hp = call(json!({ "type": "hash_pages", "ranges": [{ "address": a, "size": 0x2000 }] })).await;
    assert_eq!(hp["ranges"][0]["hashes"].as_str().unwrap().len(), 32, "{hp}");
    let ms = call(json!({ "type": "mem_snapshot", "name": "t", "address": a, "size": 0x1000 })).await;
    assert_eq!(ms["success"], true, "{ms}");
    call(json!({ "type": "write", "address": a, "data": "a1b2c3d4" })).await;
    let md = call(json!({ "type": "mem_diff", "name": "t" })).await;
    assert_eq!(md["ranges"][0]["address"], a, "{md}");
    assert_eq!(md["ranges"][0]["new"], "a1b2c3d4");
    call(json!({ "type": "write", "address": a, "data": orig4 })).await;
    // a pointer we plant is found as an "instance" and as an absolute-pointer xref
    let a8 = format!("0x{:x}", u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap() + 0x100);
    let planted = list.iter().find(|m| m["name"].as_str().unwrap().starts_with("libc")).unwrap()["base"].as_str().unwrap().to_owned();
    let le: String = u64::from_str_radix(planted.trim_start_matches("0x"), 16).unwrap().to_le_bytes().iter().map(|b| format!("{b:02x}")).collect();
    call(json!({ "type": "write", "address": a8, "data": le })).await;
    let fi = call(json!({ "type": "find_instances", "vtable": planted, "max": 50 })).await;
    assert!(fi["instances"].as_array().unwrap().iter().any(|x| *x == json!(a8)), "{fi}");
    let xr = call(json!({ "type": "xref_scan", "target": planted, "max": 200 })).await;
    assert!(xr["results"].as_array().unwrap().iter().any(|x| x["address"] == json!(a8) && x["kind"] == "pointer"), "{xr}");
    // typed watch with a condition, clamp freeze in a group
    let wc = call(json!({ "type": "watch", "address": a, "value_type": "u32", "condition": "gt", "value": 5 })).await;
    assert_eq!(wc["success"], true, "{wc}");
    let fz = call(json!({ "type": "freeze", "address": a8, "mode": "clamp", "value_type": "u32", "min": 0, "max": 7, "group": "g" })).await;
    assert_eq!(fz["success"], true, "{fz}");
    let mut clamped = String::new();
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        clamped = call(json!({ "type": "read", "address": a8, "size": 4 })).await["data"].as_str().unwrap().to_owned();
        if clamped == "07000000" {
            break;
        }
    }
    assert_eq!(clamped, "07000000", "clamp freeze holds the value at max");
    let fg = call(json!({ "type": "freeze_group", "group": "g", "enabled": false })).await;
    assert_eq!(fg["entries"], 1, "{fg}");
    call(json!({ "type": "freeze", "address": a8, "enabled": false })).await;
    call(json!({ "type": "unwatch", "address": a })).await;
    let st = call(json!({ "type": "stats" })).await;
    assert!(st["verbs"].as_array().unwrap().iter().any(|v| v["verb"] == "mem_diff"), "{st}");
    let jr = call(json!({ "type": "journal", "limit": 10 })).await;
    assert!(jr["entries"].as_array().unwrap().iter().any(|e| e["kind"] == "write"), "{jr}");

    let w = call(json!({ "type": "watch", "address": a, "size": 4, "label": "t" })).await;
    assert_eq!(w["watched"], 1, "{w}");
    let f = call(json!({ "type": "freeze", "address": a, "data": "deadbeef", "enabled": true })).await;
    assert_eq!(f["frozen"], 1, "{f}");
    tokio::time::sleep(Duration::from_millis(250)).await;
    let now = call(json!({ "type": "read", "address": a, "size": 4 })).await;
    assert_eq!(now["data"], "deadbeef");
    let fl = call(json!({ "type": "freeze_list" })).await;
    assert_eq!(fl["entries"][0]["data"], "deadbeef");
    call(json!({ "type": "freeze", "address": a, "enabled": false })).await;
    let back = call(json!({ "type": "read", "address": a, "size": 4 })).await;
    assert_eq!(back["data"], before["data"], "unfreeze restores the original bytes");

    // loader list: r_debug/link_map when the program is dynamically linked
    // threads + call stack (ptrace: interrupt, read, resume) and open fds
    let th = call(json!({ "type": "threads", "stacks": true })).await;
    assert_eq!(th["success"], true, "{th}");
    let t0 = &th["threads"][0];
    assert_eq!(t0["tid"], pid, "{th}");
    if t0.get("registers_error").is_none() {
        assert!(t0["frames"].as_array().unwrap().iter().any(|f| f["module"].as_str().is_some_and(|m| m.starts_with("libc")) || f["module"] == "sh" || f["module"] == "dash"), "{th}");
        let st = call(json!({ "type": "stack", "tid": pid, "max_frames": 4 })).await;
        assert!(st["frames"].as_array().unwrap().len() <= 4, "{st}");
    }
    let fds = call(json!({ "type": "handles" })).await;
    assert!(fds["count"].as_u64().unwrap() >= 1, "{fds}");

    let peb = call(json!({ "type": "peb_walk" })).await;
    assert!(peb["count"].as_u64().unwrap() >= 2, "{peb}");
    assert!(peb["modules"].as_array().unwrap().iter().any(|m| m["name"].as_str().unwrap().contains("libc")), "{peb}");

    // export lookup in libc, checked against the bytes at the address (a function starts there)
    let libc = list.iter().find(|m| m["name"].as_str().unwrap().starts_with("libc")).unwrap()["name"].as_str().unwrap().to_owned();
    let ex = call(json!({ "type": "resolve_export", "module": libc, "name": "getpid" })).await;
    assert_eq!(ex["success"], true, "{ex}");
    let fns = call(json!({ "type": "enumerate_functions", "module": libc })).await;
    assert!(fns["count"].as_u64().unwrap() > 100, "shared-library symbols are rebased: {}", fns["count"]);
    assert!(fns["results"].as_array().unwrap().iter().any(|f| f["address"] == ex["address"]), "getpid is among the enumerated functions");

    // process-backed emulation of real libc code: run getpid's first instruction only
    let emu = call(json!({ "type": "emulate", "start": ex["address"], "end": "0x1", "max_insns": 1 })).await;
    assert_eq!(emu["instructions"], 1, "{emu}");

    // bulk verbs: one request for several patterns / a whole function / many fields
    let first = call(json!({ "type": "read", "address": ex["address"], "size": 8 })).await;
    let ida: String = first["data"].as_str().unwrap().as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap().to_owned()).collect::<Vec<_>>().join(" ");
    let sb = call(json!({ "type": "sig_scan_batch", "module": libc, "patterns": [ida, "de ad be ef de ad be ef 01 02"] })).await;
    assert!(sb["results"][0]["count"].as_u64().unwrap() >= 1, "{sb}");
    assert_eq!(sb["results"][1]["count"], 0);
    let df = call(json!({ "type": "disasm_function", "address": ex["address"] })).await;
    assert!(df["count"].as_u64().unwrap() >= 1 && df["size"].as_u64().unwrap() > 0, "{df}");
    let rf = call(json!({ "type": "read_fields", "address": ex["address"], "fields": [{ "offset": 0, "type": "u8" }, { "offset": "0x1", "type": "ptr" }] })).await;
    assert_eq!(rf["fields"][0]["value"], u64::from_str_radix(&first["data"].as_str().unwrap()[..2], 16).unwrap().to_string(), "{rf}");

    // lifting over live code: a block, and a trace the relay emulates itself
    let lb = call(json!({ "type": "lift_block", "address": ex["address"] })).await;
    assert_eq!(lb["success"], true, "{lb}");
    assert!(!lb["instructions"].as_array().unwrap().is_empty(), "{lb}");
    let lt = call(json!({ "type": "lift_trace", "start": ex["address"], "max_insns": 200 })).await;
    assert_eq!(lt["success"], true, "{lt}");
    assert!(lt["executed"].as_u64().unwrap() >= 1, "{lt}");
    let dv = call(json!({ "type": "devirt", "start": ex["address"], "max_insns": 200 })).await;
    assert_eq!(dv["success"], true, "{dv}");

    // libc stand-ins: injected code calls memcpy through its export (an IFUNC resolver in glibc)
    let mc = call(json!({ "type": "resolve_export", "module": libc, "name": "memcpy" })).await;
    let mc = u64::from_str_radix(mc["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let scratch = 0x7fe0_0000_0000u64;
    let imm = |v: u64| v.to_le_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
    let code = format!("48bf{}48be{}48c7c20400000048b8{}ffd0c3", imm(scratch + 0x100), imm(scratch + 0x200), imm(mc));
    let em = call(json!({ "type": "emulate", "start": format!("0x{scratch:x}"), "end": "0x1", "stubs": true, "trace_regs": true,
        "write": [{ "address": format!("0x{scratch:x}"), "data": code }, { "address": format!("0x{:x}", scratch + 0x200), "data": "deadbeef" }],
        "read": [{ "address": format!("0x{:x}", scratch + 0x100), "size": 4 }] })).await;
    assert_eq!(em["api_calls"][0]["api"], "memcpy", "{em}");
    assert_eq!(em["mem"][0]["data"], "deadbeef", "the stand-in copied: {em}");
    assert!(em["reg_trace"].as_array().unwrap().len() >= 4, "{em}");
    assert!(em["xmm"]["xmm0"].is_string());

    // emulated debugger over the same code: step twice, edit a register, break, close
    let es = call(json!({ "type": "emu_start", "start": ex["address"] })).await;
    assert_eq!(es["success"], true, "{es}");
    assert_eq!(es["rip"], ex["address"]);
    assert!(!es["next"].as_array().unwrap().is_empty(), "decodes from process memory: {es}");
    let st = call(json!({ "type": "emu_step", "count": 1 })).await;
    assert_eq!(st["stop"]["reason"], "step", "{st}");
    assert_eq!(st["instructions"], 1);
    let ed = call(json!({ "type": "emu_set", "regs": { "r15": "0x1234" } })).await;
    assert_eq!(ed["regs"]["r15"], "0x1234", "{ed}");
    let rd = call(json!({ "type": "emu_read", "address": ex["address"], "size": 8 })).await;
    assert_eq!(rd["success"], true, "{rd}");
    let cl = call(json!({ "type": "emu_close" })).await;
    assert_eq!(cl["closed"], true);

    // pointer scan runs (results depend on the process)
    let ps = call(json!({ "type": "pointer_scan", "target": a, "max_depth": 1, "max_results": 10 })).await;
    assert_eq!(ps["type"], "pointer_scan_result", "{ps}");
    let sv = call(json!({ "type": "ptr_save", "name": "run1" })).await;
    assert_eq!(sv["success"], true, "{sv}");
    let pc = call(json!({ "type": "ptr_compare", "names": ["run1", "@last"] })).await;
    assert_eq!(pc["count"], ps["results"].as_array().unwrap().len(), "{pc}");

    // debugger round trip
    let d = call(json!({ "type": "dbg_attach" })).await;
    assert_eq!(d["state"], "stopped", "{d}");
    let st = call(json!({ "type": "dbg_step" })).await;
    assert_eq!(st["success"], true, "{st}");
    // a planted int3 is invisible to read (the original byte comes back, like gdb's shadow)
    let orig = call(json!({ "type": "read", "address": ex["address"], "size": 1 })).await;
    let bp = call(json!({ "type": "dbg_break", "address": ex["address"] })).await;
    assert_eq!(bp["success"], true, "{bp}");
    let shown = call(json!({ "type": "read", "address": ex["address"], "size": 1 })).await;
    assert_eq!(shown["data"], orig["data"], "breakpoint byte hidden from reads");
    call(json!({ "type": "dbg_break", "address": ex["address"], "enabled": false })).await;
    let c = call(json!({ "type": "dbg_continue" })).await;
    assert_eq!(c["state"], "running");
    let dd = call(json!({ "type": "detach" })).await;
    assert_eq!(dd["success"], true, "detach also ends the debug session");
    let s = call(json!({ "type": "dbg_status" })).await;
    assert_eq!(s["active"], false);
}
