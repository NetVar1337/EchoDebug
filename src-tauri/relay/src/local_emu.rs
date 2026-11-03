//! `emulate` for the local backend: Unicorn (x86-64; AArch64 in `local_emu_a64.rs`) backed by the
//! attached process.
//!
//! Same request/reply shape as the agent's verb (PROTOCOL.md). Without `code`, every page the
//! emulated code touches is faulted in from the live process on first access, so the process
//! itself is never modified. With `code`, the bytes are mapped at `start` in a blank emulator.
//! `mem_log` comes from Unicorn's read/write hooks (implicit stack accesses are skipped, as in
//! the agent).
//!
//! Unicorn is a native dependency, built only on Linux (the Windows build uses the Echo agent).

use serde_json::{json, Map, Value};

use crate::local::MemIo;

#[cfg(not(target_os = "linux"))]
pub fn emulate(_mem: &impl MemIo, _req: &Map<String, Value>) -> Value {
    json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": "local emulation is built on Linux only" })
}

#[cfg(target_os = "linux")]
pub use imp::emulate;

#[cfg(target_os = "linux")]
pub(crate) mod imp {
    use super::*;
    use crate::local::{arg_addr, hex_addr, hex_bytes};
    use unicorn_engine::unicorn_const::{uc_error, Arch, HookType, MemType, Mode, Prot};
    use unicorn_engine::{RegisterX86, Unicorn};

    const PAGE: u64 = 0x1000;
    const STACK_SIZE: u64 = 0x100000;
    const TLS_SIZE: u64 = 0x10000;

    const REGS: &[(&str, RegisterX86)] = &[
        ("rax", RegisterX86::RAX), ("rbx", RegisterX86::RBX), ("rcx", RegisterX86::RCX), ("rdx", RegisterX86::RDX),
        ("rsi", RegisterX86::RSI), ("rdi", RegisterX86::RDI), ("rbp", RegisterX86::RBP), ("rsp", RegisterX86::RSP),
        ("r8", RegisterX86::R8), ("r9", RegisterX86::R9), ("r10", RegisterX86::R10), ("r11", RegisterX86::R11),
        ("r12", RegisterX86::R12), ("r13", RegisterX86::R13), ("r14", RegisterX86::R14), ("r15", RegisterX86::R15),
        ("rip", RegisterX86::RIP), ("eflags", RegisterX86::EFLAGS),
        ("fs_base", RegisterX86::FS_BASE), ("gs_base", RegisterX86::GS_BASE),
    ];

    struct Data<'m, M: MemIo> {
        mem: Option<&'m M>,
        trace: Vec<u64>,
        trace_limit: usize,
        log: Vec<Value>,
        log_limit: usize,
        log_truncated: bool,
        insns: u64,
        stack: (u64, u64),
        rip: u64,
        x: crate::emux::Extras,
    }

    pub(crate) fn error_name(e: uc_error) -> &'static str {
        match e {
            uc_error::OK => "OK",
            uc_error::READ_UNMAPPED => "READ_UNMAPPED",
            uc_error::WRITE_UNMAPPED => "WRITE_UNMAPPED",
            uc_error::FETCH_UNMAPPED => "FETCH_UNMAPPED",
            uc_error::INSN_INVALID => "INSN_INVALID",
            uc_error::WRITE_PROT => "WRITE_PROT",
            uc_error::READ_PROT => "READ_PROT",
            uc_error::FETCH_PROT => "FETCH_PROT",
            uc_error::EXCEPTION => "EXCEPTION",
            uc_error::MAP => "MAP",
            uc_error::ARG => "ARG",
            uc_error::NOMEM => "NOMEM",
            _ => "ERROR",
        }
    }

    pub(crate) fn parse_hex(s: &str) -> Option<Vec<u8>> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
    }

    pub(crate) fn parse_u64(v: &Value) -> Option<u64> {
        match v {
            Value::String(s) => {
                let t = s.trim();
                match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    Some(h) => u64::from_str_radix(h, 16).ok(),
                    None => t.parse().ok(),
                }
            }
            Value::Number(n) => n.as_u64().or_else(|| n.as_i64().map(|x| x as u64)),
            _ => None,
        }
    }

    /// Maps the page holding `addr` from the process (or zeroes for injected writes).
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

    pub fn emulate<M: MemIo>(mem: &M, req: &Map<String, Value>) -> Value {
        let Some(start) = arg_addr(req, "start") else {
            return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "emulate requires 'start'" });
        };
        // AArch64: an explicit `arch`, else the architecture of the module that holds `start`
        let arch = crate::arch::from_req(req).unwrap_or_else(|| if req.contains_key("code") { crate::arch::Arch::X86_64 } else { crate::local::arch_at(mem, start) });
        if arch == crate::arch::Arch::Arm64 {
            return crate::local_emu_a64::emulate(mem, req);
        }
        let end = arg_addr(req, "end").unwrap_or(0);
        let max_insns = req.get("max_insns").and_then(Value::as_u64).unwrap_or(100_000).clamp(1, 5_000_000);
        let timeout_us = req.get("timeout_us").and_then(Value::as_u64).unwrap_or(1_000_000).clamp(1, 5_000_000);
        let want_trace = req.get("trace").and_then(Value::as_bool).unwrap_or(false);
        let trace_limit = req.get("trace_limit").and_then(Value::as_u64).unwrap_or(2000).min(100_000) as usize;
        let want_log = req.get("mem_log").and_then(Value::as_bool).unwrap_or(false);
        let log_limit = req.get("mem_log_limit").and_then(Value::as_u64).unwrap_or(2000).min(20_000) as usize;
        let code = match req.get("code").and_then(Value::as_str) {
            Some(c) => match parse_hex(c) {
                Some(b) if !b.is_empty() => Some(b),
                _ => return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "'code' must be hex" }),
            },
            None => None,
        };

        // Stack below the lowest mapping the process uses, so it never shadows real memory.
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
            rip: start,
            x: crate::emux::Extras::default(),
        };
        let mut data = data;
        if let Err(e) = crate::emux::parse(req, &mut data.x) {
            return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": e });
        }
        if code.is_none() && req.get("stubs").and_then(Value::as_bool).unwrap_or(false) {
            data.x.stubs = crate::emux::resolve_stubs(mem);
        }
        crate::local_more::CANCEL.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut uc = match Unicorn::new_with_data(Arch::X86, Mode::MODE_64, data) {
            Ok(u) => u,
            Err(e) => return json!({ "type": "error", "code": 3003, "message": "emulation failed", "detail": e.to_string() }),
        };
        let _ = uc.mem_map(stack_base, STACK_SIZE, Prot::READ | Prot::WRITE);
        // a zeroed TLS block for fs:/gs: (stack canaries, errno): base it just above the stack
        let _ = uc.mem_map(stack_base + STACK_SIZE, TLS_SIZE, Prot::READ | Prot::WRITE);
        let _ = uc.reg_write(RegisterX86::FS_BASE, stack_base + STACK_SIZE + TLS_SIZE / 2);
        let _ = uc.reg_write(RegisterX86::GS_BASE, stack_base + STACK_SIZE + TLS_SIZE / 2);
        let _ = uc.reg_write(RegisterX86::RSP, stack_base + STACK_SIZE - 0x1000);
        // returning to 0 ends the run cleanly when 'end' is not given
        let _ = uc.mem_write(stack_base + STACK_SIZE - 0x1000, &end.to_le_bytes());

        if let Some(c) = &code {
            let lo = start & !(PAGE - 1);
            let hi = (start + c.len() as u64 + PAGE - 1) & !(PAGE - 1);
            if uc.mem_map(lo, hi - lo, Prot::ALL).is_err() || uc.mem_write(start, c).is_err() {
                return json!({ "type": "error", "code": 3003, "message": "emulation failed", "detail": "cannot map code" });
            }
        }
        if let Some(Value::Object(regs)) = req.get("regs") {
            for (k, v) in regs {
                if let (Some((_, r)), Some(val)) = (REGS.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)), parse_u64(v)) {
                    let _ = uc.reg_write(*r, val);
                }
            }
        }
        // Injected bytes: fault the page in from the process (or zeroes), then overwrite.
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

        if let Err(e) = crate::emux::set_xmm(&mut uc, req) {
            return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": e });
        }
        {
            let mut x = std::mem::take(&mut uc.get_data_mut().x);
            crate::emux::baseline(&uc, &mut x);
            uc.get_data_mut().x = x;
        }
        let _ = uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _ty, addr, _size, _v| {
            if fault_in(uc, addr, false) {
                return true;
            }
            let rip = uc.get_data().rip;
            let d = uc.get_data_mut();
            crate::emux::on_fault(&mut d.x, addr, rip);
            d.x.zero_unmapped && fault_in(uc, addr, true)
        });
        let _ = uc.add_code_hook(1, 0, |uc, addr, _size| {
            if crate::local_more::CANCEL.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = uc.emu_stop();
                return;
            }
            {
                let d = uc.get_data_mut();
                d.insns += 1;
                d.rip = addr;
                if want_trace && d.trace.len() < d.trace_limit {
                    d.trace.push(addr);
                }
            }
            let mut x = std::mem::take(&mut uc.get_data_mut().x);
            crate::emux::code(uc, &mut x, addr);
            uc.get_data_mut().x = x;
        });
        if uc.get_data().x.layers {
            let _ = uc.add_mem_hook(HookType::MEM_WRITE, 1, 0, |uc, _ty, addr, size, _v| {
                crate::emux::on_write(&mut uc.get_data_mut().x, addr, size);
                true
            });
        }
        if want_log {
            let _ = uc.add_mem_hook(HookType::MEM_READ | HookType::MEM_WRITE, 1, 0, |uc, ty, addr, size, value| {
                let (sb, ss) = uc.get_data().stack;
                if addr >= sb && addr < sb + ss {
                    return true; // implicit stack traffic
                }
                let mut before = vec![0u8; size];
                let _ = uc.mem_read(addr, &mut before);
                let rip = uc.get_data().rip;
                let d = uc.get_data_mut();
                if d.log.len() >= d.log_limit {
                    d.log_truncated = true;
                    return true;
                }
                let mut e = json!({ "rip": hex_addr(rip), "address": hex_addr(addr), "size": size, "access": if ty == MemType::WRITE { "w" } else { "r" }, "before": hex_bytes(&before) });
                if ty == MemType::WRITE {
                    e["after"] = json!(hex_bytes(&value.to_le_bytes()[..size.min(8)]));
                }
                d.log.push(e);
                true
            });
        }

        let res = uc.emu_start(start, end, timeout_us, max_insns as usize);
        let final_rip = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
        let reached = end != 0 && final_rip == end;
        let (err, fault) = match res {
            Ok(()) => (uc_error::OK, 0),
            Err(e) => (e, uc.get_data().rip),
        };
        let mut regs = Map::new();
        for (n, r) in REGS {
            regs.insert((*n).into(), json!(hex_addr(uc.reg_read(*r).unwrap_or(0))));
        }
        let mut reads = Vec::new();
        if let Some(Value::Array(rs)) = req.get("read") {
            for r in rs.iter().take(256) {
                let Some(a) = r.get("address").and_then(parse_u64) else { continue };
                let n = r.get("size").and_then(Value::as_u64).unwrap_or(16).clamp(1, 0x10000) as usize;
                let mut b = vec![0u8; n];
                let mut ok = uc.mem_read(a, &mut b).is_ok();
                if !ok {
                    // never touched by the run: show the process bytes
                    ok = mem.read_at(a, &mut b).map(|k| k == n).unwrap_or(false);
                }
                reads.push(json!({ "address": hex_addr(a), "size": n, "ok": ok, "data": if ok { hex_bytes(&b) } else { String::new() } }));
            }
        }
        let xmm = crate::emux::xmm_json(&uc);
        let d = uc.get_data();
        let mut out = json!({
            "type": "emulate_result", "success": true,
            "error": err as i32, "error_name": error_name(err), "fault_address": hex_addr(fault),
            "regs": regs, "trace": d.trace.iter().map(|a| hex_addr(*a)).collect::<Vec<_>>(), "mem": reads,
            "instructions": d.insns, "reached_end": reached,
        });
        if want_log {
            out["mem_log"] = json!(d.log);
            out["mem_log_truncated"] = json!(d.log_truncated);
        }
        crate::emux::report(&mut out, &d.x, xmm);
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

        #[test]
        fn runs_process_backed_code_with_mem_log() {
            let mem = Fake(Mutex::new(BTreeMap::new()));
            {
                let mut d = mem.0.lock().unwrap();
                // mov rax, [0x18000] ; add rax, rcx ; mov [0x18008], rax ; (end)
                let code = [0x48, 0x8b, 0x04, 0x25, 0x00, 0x80, 0x01, 0x00, 0x48, 0x01, 0xc8, 0x48, 0x89, 0x04, 0x25, 0x08, 0x80, 0x01, 0x00];
                for (i, b) in code.iter().enumerate() {
                    d.insert(0x10000 + i as u64, *b);
                }
                for (i, b) in 40u64.to_le_bytes().iter().enumerate() {
                    d.insert(0x18000 + i as u64, *b);
                }
            }
            let r = emulate(&mem, &obj(json!({
                "start": "0x10000", "end": "0x10013", "regs": { "rcx": "2" }, "trace": true, "mem_log": true,
                "read": [{ "address": "0x18008", "size": 8 }],
            })));
            assert_eq!(r["error_name"], "OK", "{r}");
            assert_eq!(r["reached_end"], true);
            assert_eq!(r["regs"]["rax"], "0x2a");
            assert_eq!(r["instructions"], 3);
            assert_eq!(r["trace"].as_array().unwrap().len(), 3);
            assert_eq!(r["mem"][0]["data"], hex_bytes(&42u64.to_le_bytes()));
            let log = r["mem_log"].as_array().unwrap();
            assert_eq!(log[0]["access"], "r");
            assert_eq!(log[1]["access"], "w");
            assert_eq!(log[1]["after"], hex_bytes(&42u64.to_le_bytes()));
        }

        #[test]
        fn blank_emulator_with_code_and_fault() {
            let mem = Fake(Mutex::new(BTreeMap::new()));
            // inc rax ; mov rax, [0x900000] (unmapped everywhere -> fault)
            let r = emulate(&mem, &obj(json!({ "start": "0x400000", "end": "0x400100", "code": "48ffc0488b042500009000" })));
            assert_eq!(r["error_name"], "READ_UNMAPPED", "{r}");
            assert_eq!(r["regs"]["rax"], "0x1");
            assert_eq!(r["reached_end"], false);
        }
    }
}
