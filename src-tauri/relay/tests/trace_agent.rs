//! Trace recording through the Windows agent's emulator session: the relay drives a (fake) `/ext`
//! agent with emu_state / emu_step / emu_read and records the run like the local recorder does.

use std::collections::HashMap;
use std::time::Duration;

use echo_debug_relay::{bind, run, Relay};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

/// A tiny machine: 0x1000 mov [0x2000], rax · 0x1008 inc rax · 0x100b jmp 0x1000
struct Machine {
    rax: u64,
    rip: u64,
    mem: HashMap<u64, u8>,
}

impl Machine {
    fn new() -> Machine {
        let mut mem = HashMap::new();
        let code: [u8; 13] = [0x48, 0x89, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, 0x48, 0xff, 0xc0, 0xeb, 0xf3];
        for (i, b) in code.iter().enumerate() {
            mem.insert(0x1000 + i as u64, *b);
        }
        for i in 0..8 {
            mem.insert(0x2000 + i, 0xee);
        }
        Machine { rax: 0x10, rip: 0x1000, mem }
    }
    fn regs(&self) -> Value {
        json!({ "rax": format!("0x{:x}", self.rax), "rip": format!("0x{:x}", self.rip), "rsp": "0x8000", "eflags": "0x202" })
    }
    fn step(&mut self) {
        match self.rip {
            0x1000 => {
                for (i, b) in self.rax.to_le_bytes().iter().enumerate() {
                    self.mem.insert(0x2000 + i as u64, *b);
                }
                self.rip = 0x1008;
            }
            0x1008 => {
                self.rax += 1;
                self.rip = 0x100b;
            }
            _ => self.rip = 0x1000,
        }
    }
    fn answer(&mut self, req: &Value) -> Value {
        let id = req["id"].clone();
        match req["type"].as_str().unwrap_or_default() {
            "emu_state" => json!({ "type": "emu_state_result", "id": id, "success": true, "regs": self.regs(), "stop": { "reason": "state" } }),
            "emu_step" => {
                self.step();
                json!({ "type": "emu_step_result", "id": id, "success": true, "regs": self.regs(), "stop": { "reason": "step", "ran": 1 } })
            }
            "emu_read" => {
                let a = u64::from_str_radix(req["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                let n = req["size"].as_u64().unwrap();
                // unmapped bytes read as 0x90 (enough for the decoder's 16-byte window)
                let data: String = (0..n).map(|i| format!("{:02x}", self.mem.get(&(a + i)).copied().unwrap_or(0x90))).collect();
                json!({ "type": "emu_read_result", "id": id, "success": true, "address": req["address"], "size": n, "data": data })
            }
            other => json!({ "type": "error", "id": id, "code": 3000, "message": "unknown verb", "detail": other }),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_the_agents_emulator_step_by_step() {
    let cfg = std::env::temp_dir().join(format!("echodebug-trace-agent-{}", std::process::id()));
    std::env::set_var("XDG_CONFIG_HOME", &cfg);
    let relay = Relay::new("1.2.3", Duration::from_secs(10)).with_local_backend(false);
    let listener = bind(0).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(run(listener, relay));

    let (mut ext, _) = connect_async(format!("ws://{addr}/ext")).await.unwrap();
    tokio::spawn(async move {
        let mut m = Machine::new();
        while let Some(Ok(msg)) = ext.next().await {
            if let Message::Text(t) = msg {
                let req: Value = serde_json::from_str(t.as_str()).unwrap();
                if req["id"].is_null() {
                    continue;
                }
                let r = m.answer(&req);
                if ext.send(Message::text(r.to_string())).await.is_err() {
                    break;
                }
            }
        }
    });

    let (mut c, _) = connect_async(format!("ws://{addr}/client")).await.unwrap();
    // wait until the relay sees the agent
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), c.next()).await.unwrap().unwrap().unwrap();
        if let Message::Text(t) = m {
            let v: Value = serde_json::from_str(t.as_str()).unwrap();
            if v["type"] == "status" && v["ext"] == true {
                break;
            }
            if v["type"] == "status" {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let (nc, _) = connect_async(format!("ws://{addr}/client")).await.unwrap();
                c = nc;
            }
        }
    }
    let mut n = 0;
    let mut call = async |v: Value| -> Value {
        n += 1;
        let mut v = v;
        v["id"] = json!(n);
        c.send(Message::text(v.to_string())).await.unwrap();
        loop {
            let m = tokio::time::timeout(Duration::from_secs(30), c.next()).await.expect("reply").unwrap().unwrap();
            if let Message::Text(t) = m {
                let f: Value = serde_json::from_str(t.as_str()).unwrap();
                if f["id"] == json!(n) {
                    return f;
                }
            }
        }
    };

    let r = call(json!({ "type": "trace_record", "source": "emu", "max_steps": 9, "keyframe": 2, "save": false })).await;
    assert_eq!(r["success"], true, "{r}");
    assert_eq!(r["trace"]["source"], "emu-agent", "{r}");
    assert_eq!(r["trace"]["steps"], 9, "{r}");
    assert_eq!(r["trace"]["stop_reason"], "count");
    // three iterations: rax 0x10, 0x11, 0x12 stored at 0x2000
    let w = call(json!({ "type": "trace_query", "kind": "writes_to", "address": "0x2000", "size": 8 })).await;
    assert_eq!(w["total"], 3, "{w}");
    assert_eq!(w["writes"][0]["old"], "eeeeeeeeeeeeeeee");
    assert_eq!(w["writes"][2]["new"], "1200000000000000");
    let m = call(json!({ "type": "trace_query", "kind": "mem_at", "address": "0x2000", "size": 8, "pos": 4 })).await;
    assert_eq!(m["data"], "1100000000000000", "{m}");
    let lw = call(json!({ "type": "trace_query", "kind": "last_write", "address": "0x2000", "size": 1, "pos": 9 })).await;
    assert_eq!(lw["write"]["step"], 6, "{lw}");
    let rax = call(json!({ "type": "trace_query", "kind": "reg_at", "reg": "rax", "pos": 5 })).await;
    assert_eq!(rax["value"], "0x12", "{rax}");
    let ex = call(json!({ "type": "trace_query", "kind": "executions_of", "address": "0x1008" })).await;
    assert_eq!(ex["steps"], json!([1, 4, 7]));
    // the stored value came from rax, which came from inc rax at step 4
    let t = call(json!({ "type": "trace_query", "kind": "taint", "address": "0x2000", "size": 8, "pos": 9 })).await;
    let hops = t["hops"].as_array().unwrap();
    assert_eq!((hops[0]["step"].clone(), hops[0]["kind"].clone()), (json!(6), json!("mov")), "{t}");
    assert!(hops.iter().any(|h| h["step"] == 4 && h["kind"] == "arith"), "{t}");
    let _ = std::fs::remove_dir_all(&cfg);
}
