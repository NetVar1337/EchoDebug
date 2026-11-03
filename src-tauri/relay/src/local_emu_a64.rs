//! `emulate` for AArch64 (Linux arm64 targets) on the local backend: Unicorn's `UC_ARCH_ARM64`.
//!
//! Same request/reply shape as the x86-64 emulator (PROTOCOL.md) with the arm64 register set:
//! `regs` takes and returns `x0`..`x30` (`fp`/`lr` accepted as aliases of x29/x30), `sp`, `pc`,
//! `nzcv` and `tpidr_el0`; `v` takes `{"v0": "<32 hex>"}` and, when given (or with `simd: true`),
//! the reply carries `v0`..`v31` as little-endian hex. Without `code`, pages fault in from the
//! attached process on first access, so the process is never modified. `x30` starts at `end`, so a
//! `ret` from the emulated function ends the run. `trace`, `mem_log`, `read`, `write`,
//! `max_insns`, `timeout_us` and `on_unmapped` work as on x86-64 (`mem_log` entries and `faults`
//! name the instruction as `pc` instead of `rip`); the x86-only extras (`stubs`, `layers`,
//! `trace_regs`, `xmm`) are refused with an explanation.

use serde_json::{json, Map, Value};

use crate::local::MemIo;

#[cfg(not(target_os = "linux"))]
pub fn emulate(_mem: &impl MemIo, _req: &Map<String, Value>) -> Value {
    json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": "local emulation is built on Linux only" })
}

#[cfg(target_os = "linux")]
pub use imp::emulate;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::local::{arg_addr, hex_addr, hex_bytes};
    use crate::local_emu::imp::{error_name, parse_hex, parse_u64};
    use unicorn_engine::unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Prot};
    use unicorn_engine::{RegisterARM64, Unicorn};

    const PAGE: u64 = 0x1000;
    const STACK_SIZE: u64 = 0x100000;
    const TLS_SIZE: u64 = 0x10000;

    /// Register names in reply order, with their Unicorn ids.
    pub fn regs() -> Vec<(String, i32)> {
        let mut out: Vec<(String, i32)> = (0..29).map(|i| (format!("x{i}"), RegisterARM64::X0 as i32 + i)).collect();
        out.push(("x29".into(), RegisterARM64::X29 as i32));
        out.push(("x30".into(), RegisterARM64::X30 as i32));
        out.push(("sp".into(), RegisterARM64::SP as i32));
        out.push(("pc".into(), RegisterARM64::PC as i32));
        out.push(("nzcv".into(), RegisterARM64::NZCV as i32));
        out.push(("tpidr_el0".into(), RegisterARM64::TPIDR_EL0 as i32));
        out
    }

    fn reg_id(name: &str) -> Option<i32> {
        let n = name.trim().to_ascii_lowercase();
        let n = match n.as_str() {
            "fp" => "x29".to_owned(),
            "lr" => "x30".to_owned(),
            _ => n,
        };
        regs().into_iter().find(|(r, _)| *r == n).map(|(_, id)| id)
    }

    struct Data<'m, M: MemIo> {
        mem: Option<&'m M>,
        trace: Vec<u64>,
        trace_limit: usize,
        log: Vec<Value>,
        log_limit: usize,
        log_truncated: bool,
        insns: u64,
        stack: (u64, u64),
        pc: u64,
        zero_unmapped: bool,
        faults: Vec<Value>,
        fault_count: u64,
    }

    fn fault_in<M: MemIo>(uc: &mut Unicorn<Data<M>>, addr: u64, zero_ok: bool) -> bool {
        let page = addr & !(PAGE - 1);
        let mut buf = vec![0u8; PAGE as usize];
        let readable = uc.get_data().mem.is_some_and(|m| m.read_at(page, &mut buf).map(|n| n == PAGE as usize).unwrap_or(false));
        if !readable && !zero_ok {
            return false;
        }
        if uc.mem_map(page, PAGE, Prot::ALL).is_err() {
            return false;
        }
        uc.mem_write(page, &buf).is_ok()
    }

    fn bad(detail: &str) -> Value {
        json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": detail })
    }

    pub fn emulate<M: MemIo>(mem: &M, req: &Map<String, Value>) -> Value {
        let Some(start) = arg_addr(req, "start") else {
            return bad("emulate requires 'start'");
        };
        if start & 3 != 0 {
            return bad("arm64 code is 4-byte aligned: 'start' is not");
        }
        for k in ["stubs", "layers", "trace_regs"] {
            if req.get(k).and_then(Value::as_bool).unwrap_or(false) {
                return bad(&format!("'{k}' is only implemented for x86-64 emulation"));
            }
        }
        if req.contains_key("xmm") {
            return bad("'xmm' is x86-64; pass arm64 vector registers as 'v' ({\"v0\": \"<32 hex>\"})");
        }
        let end = arg_addr(req, "end").unwrap_or(0);
        let max_insns = req.get("max_insns").and_then(Value::as_u64).unwrap_or(100_000).clamp(1, 5_000_000);
        let timeout_us = req.get("timeout_us").and_then(Value::as_u64).unwrap_or(1_000_000).clamp(1, 5_000_000);
        let want_trace = req.get("trace").and_then(Value::as_bool).unwrap_or(false);
        let trace_limit = req.get("trace_limit").and_then(Value::as_u64).unwrap_or(2000).min(100_000) as usize;
        let want_log = req.get("mem_log").and_then(Value::as_bool).unwrap_or(false);
        let log_limit = req.get("mem_log_limit").and_then(Value::as_u64).unwrap_or(2000).min(20_000) as usize;
        let want_v = req.contains_key("v") || req.get("simd").and_then(Value::as_bool).unwrap_or(false);
        let zero_unmapped = match req.get("on_unmapped").and_then(Value::as_str).unwrap_or("stop") {
            "stop" => false,
            "zero" => true,
            _ => return bad("on_unmapped must be 'stop' or 'zero'"),
        };
        let code = match req.get("code").and_then(Value::as_str) {
            Some(c) => match parse_hex(c) {
                Some(b) if !b.is_empty() => Some(b),
                _ => return bad("'code' must be hex"),
            },
            None => None,
        };

        let maps = mem.maps().unwrap_or_default();
        let mut stack_base = 0x7ffe_0000_0000u64;
        while maps.iter().any(|m| m.end > stack_base && m.start < stack_base + STACK_SIZE + TLS_SIZE) {
            stack_base -= 0x10_0000_0000;
        }
        let data = Data {
            mem: if code.is_some() { None } else { Some(mem) },
            trace: Vec::new(),
            trace_limit,
            log: Vec::new(),
            log_limit,
            log_truncated: false,
            insns: 0,
            stack: (stack_base, STACK_SIZE),
            pc: start,
            zero_unmapped,
            faults: Vec::new(),
            fault_count: 0,
        };
        crate::local_more::CANCEL.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut uc = match Unicorn::new_with_data(Arch::ARM64, Mode::ARM, data) {
            Ok(u) => u,
            Err(e) => return json!({ "type": "error", "code": 3003, "message": "emulation failed", "detail": format!("{e:?}") }),
        };
        // FP/SIMD on (CPACR_EL1.FPEN), so vector code does not trap
        let cpacr = uc.reg_read(RegisterARM64::CPACR_EL1).unwrap_or(0);
        let _ = uc.reg_write(RegisterARM64::CPACR_EL1, cpacr | (3 << 20));
        let _ = uc.mem_map(stack_base, STACK_SIZE, Prot::READ | Prot::WRITE);
        let _ = uc.mem_map(stack_base + STACK_SIZE, TLS_SIZE, Prot::READ | Prot::WRITE);
        let _ = uc.reg_write(RegisterARM64::TPIDR_EL0, stack_base + STACK_SIZE + TLS_SIZE / 2);
        let _ = uc.reg_write(RegisterARM64::SP, stack_base + STACK_SIZE - 0x1000);
        // `ret` returns to x30: point it at `end` (0 ends the run cleanly when 'end' is not given)
        let _ = uc.reg_write(RegisterARM64::X30, end);

        if let Some(c) = &code {
            let lo = start & !(PAGE - 1);
            let hi = (start + c.len() as u64 + PAGE - 1) & !(PAGE - 1);
            if uc.mem_map(lo, hi - lo, Prot::ALL).is_err() || uc.mem_write(start, c).is_err() {
                return json!({ "type": "error", "code": 3003, "message": "emulation failed", "detail": "cannot map code" });
            }
        }
        if let Some(Value::Object(regs)) = req.get("regs") {
            for (k, v) in regs {
                match (reg_id(k), parse_u64(v)) {
                    (Some(r), Some(val)) => {
                        let _ = uc.reg_write(r, val);
                    }
                    (None, _) => return bad(&format!("unknown arm64 register '{k}' (x0-x30, fp, lr, sp, pc, nzcv, tpidr_el0)")),
                    _ => return bad(&format!("register '{k}' needs a number")),
                }
            }
        }
        if let Some(Value::Object(vs)) = req.get("v") {
            for (k, v) in vs {
                let idx = k.trim().to_ascii_lowercase().strip_prefix('v').and_then(|n| n.parse::<i32>().ok()).filter(|n| (0..32).contains(n));
                let bytes = v.as_str().and_then(parse_hex).filter(|b| b.len() <= 16);
                let (Some(i), Some(mut b)) = (idx, bytes) else {
                    return bad("'v' maps v0..v31 to up to 16 bytes of little-endian hex");
                };
                b.resize(16, 0);
                let _ = uc.reg_write_long(RegisterARM64::V0 as i32 + i, &b);
            }
        }
        if let Some(Value::Array(writes)) = req.get("write") {
            for w in writes {
                let (Some(a), Some(d)) = (w.get("address").and_then(parse_u64), w.get("data").and_then(Value::as_str).and_then(parse_hex)) else { continue };
                let mut p = a & !(PAGE - 1);
                while p < a + d.len() as u64 {
                    let mut probe = [0u8; 1];
                    if uc.mem_read(p, &mut probe).is_err() {
                        fault_in(&mut uc, p, true);
                    }
                    p += PAGE;
                }
                let _ = uc.mem_write(a, &d);
            }
        }

        let _ = uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _ty, addr, _size, _v| {
            if fault_in(uc, addr, false) {
                return true;
            }
            let pc = uc.get_data().pc;
            let d = uc.get_data_mut();
            d.fault_count += 1;
            if d.faults.len() < 256 {
                d.faults.push(json!({ "pc": hex_addr(pc), "address": hex_addr(addr) }));
            }
            d.zero_unmapped && fault_in(uc, addr, true)
        });
        let _ = uc.add_code_hook(1, 0, move |uc, addr, _size| {
            if crate::local_more::CANCEL.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = uc.emu_stop();
                return;
            }
            let d = uc.get_data_mut();
            d.insns += 1;
            d.pc = addr;
            if want_trace && d.trace.len() < d.trace_limit {
                d.trace.push(addr);
            }
        });
        if want_log {
            let _ = uc.add_mem_hook(HookType::MEM_READ | HookType::MEM_WRITE, 1, 0, |uc, ty, addr, size, value| {
                let (sb, ss) = uc.get_data().stack;
                if addr >= sb && addr < sb + ss {
                    return true; // stack traffic (spills, frame records)
                }
                let mut before = vec![0u8; size];
                let _ = uc.mem_read(addr, &mut before);
                let pc = uc.get_data().pc;
                let d = uc.get_data_mut();
                if d.log.len() >= d.log_limit {
                    d.log_truncated = true;
                    return true;
                }
                let mut e = json!({ "pc": hex_addr(pc), "address": hex_addr(addr), "size": size, "access": if ty == MemType::WRITE { "w" } else { "r" }, "before": hex_bytes(&before) });
                if ty == MemType::WRITE {
                    e["after"] = json!(hex_bytes(&value.to_le_bytes()[..size.min(8)]));
                }
                d.log.push(e);
                true
            });
        }

        let res = uc.emu_start(start, end, timeout_us, max_insns as usize);
        let final_pc = uc.reg_read(RegisterARM64::PC).unwrap_or(0);
        let reached = end != 0 && final_pc == end;
        let (err, fault) = match res {
            Ok(()) => (uc_error::OK, 0),
            Err(e) => (e, uc.get_data().pc),
        };
        let mut regs_out = Map::new();
        for (n, r) in regs() {
            regs_out.insert(n, json!(hex_addr(uc.reg_read(r).unwrap_or(0))));
        }
        let mut reads = Vec::new();
        if let Some(Value::Array(rs)) = req.get("read") {
            for r in rs.iter().take(256) {
                let Some(a) = r.get("address").and_then(parse_u64) else { continue };
                let n = r.get("size").and_then(Value::as_u64).unwrap_or(16).clamp(1, 0x10000) as usize;
                let mut b = vec![0u8; n];
                let mut ok = uc.mem_read(a, &mut b).is_ok();
                if !ok {
                    ok = mem.read_at(a, &mut b).map(|k| k == n).unwrap_or(false);
                }
                reads.push(json!({ "address": hex_addr(a), "size": n, "ok": ok, "data": if ok { hex_bytes(&b) } else { String::new() } }));
            }
        }
        let mut v_out = Map::new();
        if want_v {
            for i in 0..32 {
                let b = uc.reg_read_long(RegisterARM64::V0 as i32 + i).map(|b| hex_bytes(&b)).unwrap_or_default();
                v_out.insert(format!("v{i}"), json!(b));
            }
        }
        let d = uc.get_data();
        let mut out = json!({
            "type": "emulate_result", "success": true, "arch": "arm64",
            "error": err as i32, "error_name": error_name(err), "fault_address": hex_addr(fault),
            "regs": regs_out, "trace": d.trace.iter().map(|a| hex_addr(*a)).collect::<Vec<_>>(), "mem": reads,
            "instructions": d.insns, "reached_end": reached,
        });
        if want_v {
            out["v"] = Value::Object(v_out);
        }
        if want_log {
            out["mem_log"] = json!(d.log);
            out["mem_log_truncated"] = json!(d.log_truncated);
        }
        if !d.faults.is_empty() {
            out["faults"] = json!(d.faults);
            out["fault_count"] = json!(d.fault_count);
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::local::MapLine;
        use std::collections::BTreeMap;
        use std::sync::Mutex;

        struct Fake(Mutex<BTreeMap<u64, u8>>);
        impl MemIo for Fake {
            fn read_at(&self, addr: u64, buf: &mut [u8]) -> std::io::Result<usize> {
                if !(0x10000..0x20000).contains(&addr) {
                    return Err(std::io::Error::other("unmapped"));
                }
                let d = self.0.lock().unwrap();
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = d.get(&(addr + i as u64)).copied().unwrap_or(0);
                }
                Ok(buf.len())
            }
            fn write_at(&self, _: u64, _: &[u8]) -> std::io::Result<()> {
                panic!("the emulator must never write the process");
            }
            fn maps(&self) -> std::io::Result<Vec<MapLine>> {
                Ok(vec![MapLine { start: 0x10000, end: 0x20000, writable: true, executable: true, path: "/t".into() }])
            }
            fn alive(&self) -> bool {
                true
            }
        }
        fn obj(v: Value) -> Map<String, Value> {
            match v {
                Value::Object(m) => m,
                _ => unreachable!(),
            }
        }
        fn hex_words(words: &[u32]) -> String {
            words.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
        }

        #[test]
        fn runs_arm64_code_blank() {
            // add_scaled() from fix-a64.elf: add x8, x1, x1, lsl #1 ; add x0, x8, x0 ; ret
            let code = hex_words(&[0x8b010428, 0x8b000100, 0xd65f03c0]);
            // through the x86-64 entry point: `arch` routes it here
            let r = crate::local_emu::emulate(&Fake(Mutex::new(BTreeMap::new())), &obj(json!({
                "start": "0x400000", "end": "0x500000", "code": code, "arch": "arm64", "regs": { "x0": "10", "x1": "5" }, "trace": true,
            })));
            assert_eq!(r["error_name"], "OK", "{r}");
            assert_eq!(r["reached_end"], true, "ret returns to x30 = end");
            assert_eq!(r["regs"]["x0"], "0x19");
            assert_eq!(r["regs"]["pc"], "0x500000");
            assert_eq!(r["instructions"], 3);
            assert_eq!(r["trace"], json!(["0x400000", "0x400004", "0x400008"]));
        }

        #[test]
        fn process_backed_loop_flags_memory_and_vectors() {
            let mem = Fake(Mutex::new(BTreeMap::new()));
            {
                let mut d = mem.0.lock().unwrap();
                // walk() from fix-a64.elf over the string at 0x18000, with its ret replaced by
                // str x0, [x8] ; ret
                let code = [0xaa0003e8u32, 0xaa1f03e0, 0x39400109, 0xb40000a9, 0x8b090000, 0x91000508, 0xf10fa41f, 0x54ffff63, 0xf9000100, 0xd65f03c0];
                for (i, b) in code.iter().flat_map(|w| w.to_le_bytes()).enumerate() {
                    d.insert(0x10000 + i as u64, b);
                }
                for (i, b) in b"AB\0".iter().enumerate() {
                    d.insert(0x18000 + i as u64, *b);
                }
            }
            // the loop leaves through cbz (0x1000c -> 0x10020), which lands on the str
            let r = emulate(&mem, &obj(json!({
                "start": "0x10000", "end": "0x7000", "regs": { "x0": "0x18000" }, "mem_log": true,
                "v": { "v1": "0102030405060708090a0b0c0d0e0f10" },
            })));
            assert_eq!(r["error_name"], "OK", "{r}");
            assert_eq!(r["reached_end"], true);
            assert_eq!(r["regs"]["x0"], format!("0x{:x}", b'A' as u64 + b'B' as u64));
            // the last cmp (0x83 vs 0x3e9) leaves "lower": N=1, C=0
            let nzcv = u64::from_str_radix(r["regs"]["nzcv"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            assert_eq!(nzcv >> 28, 0b1000, "{r}");
            let log = r["mem_log"].as_array().unwrap();
            assert_eq!(log.len(), 4, "three byte loads and the store: {r}");
            assert_eq!(log[0]["access"], "r");
            assert_eq!(log[0]["address"], "0x18000");
            assert_eq!(log[3]["access"], "w");
            assert_eq!(log[3]["address"], "0x18002");
            assert_eq!(log[3]["after"], "8300000000000000");
            assert_eq!(r["v"]["v1"], "0102030405060708090a0b0c0d0e0f10");
            assert_eq!(r["v"]["v0"], "00000000000000000000000000000000");
        }

        #[test]
        fn rejects_x86_only_options_and_bad_registers() {
            let mem = Fake(Mutex::new(BTreeMap::new()));
            let r = emulate(&mem, &obj(json!({ "start": "0x10000", "stubs": true })));
            assert_eq!(r["type"], "error");
            let r = emulate(&mem, &obj(json!({ "start": "0x10000", "regs": { "rax": "1" } })));
            assert!(r["detail"].as_str().unwrap().contains("rax"), "{r}");
            let r = emulate(&mem, &obj(json!({ "start": "0x10002" })));
            assert_eq!(r["type"], "error");
        }
    }
}
