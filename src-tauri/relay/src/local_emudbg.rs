//! Emulated debugger for the local backend: one persistent Unicorn (x86-64) session that you
//! step, run to an address or breakpoint, and inspect or edit (registers and memory), without
//! ever touching the real process. Pages are faulted in from the attached process on first use
//! (or, with `code`, a blank emulator runs caller-supplied bytes).
//!
//! Verbs (PROTOCOL.md "Emulated debugger"): emu_start, emu_step, emu_run, emu_break, emu_set,
//! emu_read, emu_state, emu_close. Unicorn handles are not Send, so the session lives on its own
//! thread and requests travel over a channel.

use serde_json::{json, Map, Value};

#[cfg(not(target_os = "linux"))]
pub fn handle(req: &Map<String, Value>) -> Value {
    let _ = req;
    json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": "the local emulated debugger is built on Linux only" })
}

#[cfg(target_os = "linux")]
pub use imp::handle;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::local::{arg_addr, disasm_one, hex_addr, hex_bytes, MemIo, ProcIo};
    use std::collections::BTreeSet;
    use std::sync::mpsc;
    use std::sync::Mutex;
    use unicorn_engine::unicorn_const::{uc_error, Arch, HookType, Mode, Prot};
    use unicorn_engine::{RegisterX86, Unicorn};

    const PAGE: u64 = 0x1000;
    const STACK_SIZE: u64 = 0x100000;
    const TLS_SIZE: u64 = 0x10000;
    /// Returning here ends the emulated function ("returned").
    const RET_SENTINEL: u64 = 0;

    const REGS: &[(&str, RegisterX86)] = &[
        ("rax", RegisterX86::RAX), ("rbx", RegisterX86::RBX), ("rcx", RegisterX86::RCX), ("rdx", RegisterX86::RDX),
        ("rsi", RegisterX86::RSI), ("rdi", RegisterX86::RDI), ("rbp", RegisterX86::RBP), ("rsp", RegisterX86::RSP),
        ("r8", RegisterX86::R8), ("r9", RegisterX86::R9), ("r10", RegisterX86::R10), ("r11", RegisterX86::R11),
        ("r12", RegisterX86::R12), ("r13", RegisterX86::R13), ("r14", RegisterX86::R14), ("r15", RegisterX86::R15),
        ("rip", RegisterX86::RIP), ("eflags", RegisterX86::EFLAGS),
        ("fs_base", RegisterX86::FS_BASE), ("gs_base", RegisterX86::GS_BASE),
    ];

    struct Sess {
        mem: Option<ProcIo>,
        bps: BTreeSet<u64>,
        /// a resumed run must not stop on the breakpoint it is sitting on
        skip: Option<u64>,
        hit: Option<u64>,
        insns: u64,
        last_rip: u64,
        stack: (u64, u64),
        /// pages written by the session (shown as "dirty" so the UI can diff against the process)
        dirty: BTreeSet<u64>,
        trace: Vec<u64>,
        x: crate::emux::Extras,
        /// breakpoint address -> condition ("rax==0x10")
        conds: std::collections::HashMap<u64, String>,
        /// memory watchpoints: (address, size, 1 read | 2 write)
        wps: Vec<(u64, u64, u8)>,
        wp_hit: Option<Value>,
    }

    struct Snap {
        regs: Vec<u64>,
        xmm: Vec<Box<[u8]>>,
        mem: Vec<(u64, Vec<u8>)>,
        insns: u64,
    }

    /// "rax==0x10", "rcx!=0", "rdx<0x100", "r8&1"
    fn cond_true(uc: &Unicorn<'_, Sess>, c: &str) -> bool {
        for op in ["==", "!=", "<=", ">=", "<", ">", "&"] {
            if let Some((l, r)) = c.split_once(op) {
                let Some((_, reg)) = REGS.iter().find(|(n, _)| n.eq_ignore_ascii_case(l.trim())) else { return true };
                let Some(v) = parse_u64(&json!(r.trim())) else { return true };
                let cur = uc.reg_read(*reg).unwrap_or(0);
                return match op {
                    "==" => cur == v,
                    "!=" => cur != v,
                    "<=" => cur <= v,
                    ">=" => cur >= v,
                    "<" => cur < v,
                    ">" => cur > v,
                    _ => cur & v != 0,
                };
            }
        }
        true
    }

    fn watch_check(uc: &mut Unicorn<'_, Sess>, addr: u64, size: usize, write: bool) {
        let rip = uc.get_data().last_rip;
        let d = uc.get_data_mut();
        if d.wps.is_empty() || d.wp_hit.is_some() {
            return;
        }
        let want = if write { 2 } else { 1 };
        if let Some((a, _, _)) = d.wps.iter().find(|(a, n, m)| m & want != 0 && addr < a + n && addr + size as u64 > *a) {
            d.wp_hit = Some(json!({ "rip": hex_addr(rip), "address": hex_addr(addr), "size": size, "access": if write { "write" } else { "read" }, "watch": hex_addr(*a) }));
            let _ = uc.emu_stop();
        }
    }

    type Uc = Unicorn<'static, Sess>;
    type Job = (Map<String, Value>, mpsc::Sender<Value>);

    static SESSION: Mutex<Option<mpsc::Sender<Job>>> = Mutex::new(None);

    fn failed(detail: &str) -> Value {
        json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": detail })
    }

    fn bad(detail: &str) -> Value {
        json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": detail })
    }

    fn error_name(e: uc_error) -> &'static str {
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
            _ => "ERROR",
        }
    }

    fn parse_hex(s: &str) -> Option<Vec<u8>> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
    }

    fn parse_u64(v: &Value) -> Option<u64> {
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

    fn fault_in(uc: &mut Unicorn<'_, Sess>, addr: u64, zero_ok: bool) -> bool {
        let page = addr & !(PAGE - 1);
        if page == RET_SENTINEL {
            return false;
        }
        // a blank (code) session has no process behind it: untouched memory reads as zeroes
        let zero_ok = zero_ok || uc.get_data().mem.is_none();
        let mut buf = vec![0u8; PAGE as usize];
        let readable = uc.get_data().mem.as_ref().is_some_and(|m| m.read_at(page, &mut buf).map(|n| n == PAGE as usize).unwrap_or(false));
        if !readable && !zero_ok {
            return false;
        }
        uc.mem_map(page, PAGE, Prot::ALL).is_ok() && uc.mem_write(page, &buf).is_ok()
    }

    fn ensure_mapped(uc: &mut Unicorn<'_, Sess>, addr: u64, len: u64, zero_ok: bool) -> bool {
        let mut p = addr & !(PAGE - 1);
        while p < addr + len.max(1) {
            let mut probe = [0u8; 1];
            if uc.mem_read(p, &mut probe).is_err() && !fault_in(uc, p, zero_ok) {
                return false;
            }
            p += PAGE;
        }
        true
    }

    fn read_mem(uc: &mut Unicorn<'_, Sess>, addr: u64, n: usize) -> Option<Vec<u8>> {
        if !ensure_mapped(uc, addr, n as u64, false) {
            return None;
        }
        uc.mem_read_as_vec(addr, n).ok()
    }

    fn set_regs(uc: &mut Unicorn<'_, Sess>, regs: &Map<String, Value>) -> Result<(), String> {
        for (k, v) in regs {
            let Some((_, r)) = REGS.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)) else { return Err(format!("unknown register '{k}'")) };
            let Some(val) = parse_u64(v) else { return Err(format!("bad value for {k}")) };
            uc.reg_write(*r, val).map_err(|e| format!("{e:?}"))?;
        }
        Ok(())
    }

    fn apply_writes(uc: &mut Unicorn<'_, Sess>, writes: &[Value]) -> Result<usize, String> {
        let mut n = 0;
        for w in writes {
            let (Some(a), Some(d)) = (w.get("address").and_then(parse_u64), w.get("data").and_then(Value::as_str).and_then(parse_hex)) else {
                return Err("each write needs 'address' and hex 'data'".into());
            };
            if !ensure_mapped(uc, a, d.len() as u64, true) || uc.mem_write(a, &d).is_err() {
                return Err(format!("cannot write at {}", hex_addr(a)));
            }
            let mut p = a & !(PAGE - 1);
            while p < a + d.len() as u64 {
                uc.get_data_mut().dirty.insert(p);
                p += PAGE;
            }
            n += d.len();
        }
        Ok(n)
    }

    fn state(uc: &mut Unicorn<'_, Sess>, stop: Value) -> Value {
        let mut regs = Map::new();
        for (n, r) in REGS {
            regs.insert((*n).into(), json!(hex_addr(uc.reg_read(*r).unwrap_or(0))));
        }
        let rip = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
        // the next few instructions, decoded from emulator memory
        let mut next = Vec::new();
        if rip != RET_SENTINEL {
            if let Some(code) = read_mem(uc, rip, 64) {
                let mut off = 0usize;
                while next.len() < 6 && off < code.len() {
                    let Some((len, text)) = disasm_one(&code[off..], rip + off as u64) else { break };
                    next.push(json!({ "address": hex_addr(rip + off as u64), "bytes": hex_bytes(&code[off..off + len]), "text": text }));
                    off += len;
                }
            }
        }
        let rsp = uc.reg_read(RegisterX86::RSP).unwrap_or(0);
        let stack: Vec<Value> = read_mem(uc, rsp, 64)
            .map(|b| b.as_chunks::<8>().0.iter().enumerate().map(|(i, c)| json!({ "address": hex_addr(rsp + i as u64 * 8), "value": hex_addr(u64::from_le_bytes(*c)) })).collect())
            .unwrap_or_default();
        let d = uc.get_data();
        json!({
            "success": true,
            "regs": regs,
            "rip": hex_addr(rip),
            "instructions": d.insns,
            "stop": stop,
            "next": next,
            "stack": stack,
            "breakpoints": d.bps.iter().map(|a| hex_addr(*a)).collect::<Vec<_>>(),
            "dirty_pages": d.dirty.iter().map(|a| hex_addr(*a)).collect::<Vec<_>>(),
        })
    }

    /// Runs from rip: `count` instructions (0 = no limit), stopping early at breakpoints / `until`.
    fn run(uc: &mut Unicorn<'_, Sess>, count: usize, until: u64, timeout_us: u64, trace: bool) -> Value {
        let rip = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
        if rip == RET_SENTINEL {
            return json!({ "reason": "returned", "detail": "the function already returned; emu_set rip to continue" });
        }
        {
            let d = uc.get_data_mut();
            d.skip = Some(rip);
            d.hit = None;
            d.wp_hit = None;
            d.trace.clear();
            crate::emux::reset_run(&mut d.x);
        }
        {
            let mut x = std::mem::take(&mut uc.get_data_mut().x);
            crate::emux::baseline(uc, &mut x);
            uc.get_data_mut().x = x;
        }
        crate::local_more::CANCEL.store(false, std::sync::atomic::Ordering::SeqCst);
        let before = uc.get_data().insns;
        let res = uc.emu_start(rip, until, timeout_us, count);
        let now = uc.reg_read(RegisterX86::RIP).unwrap_or(0);
        let ran = uc.get_data().insns - before;
        let d = uc.get_data();
        let mut stop = match res {
            Err(e) if now == RET_SENTINEL || (e == uc_error::FETCH_UNMAPPED && d.last_rip == RET_SENTINEL) => json!({ "reason": "returned" }),
            Err(e) => json!({ "reason": "fault", "error_name": error_name(e).to_lowercase(), "fault_rip": hex_addr(d.last_rip) }),
            Ok(()) if d.hit.is_some() => json!({ "reason": "breakpoint", "address": hex_addr(d.hit.unwrap_or(0)) }),
            // the access has happened: rip is after the instruction that touched the range
            Ok(()) if d.wp_hit.is_some() => json!({ "reason": "watchpoint", "hit": d.wp_hit }),
            Ok(()) if crate::local_more::CANCEL.load(std::sync::atomic::Ordering::SeqCst) => json!({ "reason": "cancelled" }),
            Ok(()) if now == RET_SENTINEL => json!({ "reason": "returned" }),
            Ok(()) if until != 0 && now == until => json!({ "reason": "until", "address": hex_addr(until) }),
            Ok(()) if count != 0 && ran as usize >= count => json!({ "reason": if count == 1 { "step" } else { "count" } }),
            Ok(()) => json!({ "reason": "timeout" }),
        };
        stop["ran"] = json!(ran);
        if trace {
            stop["trace"] = json!(d.trace.iter().map(|a| hex_addr(*a)).collect::<Vec<_>>());
        }
        if stop["reason"] == "fault" {
            // leave rip at the faulting instruction so it can be fixed and retried
            let fr = d.last_rip;
            let _ = uc.reg_write(RegisterX86::RIP, fr);
        }
        stop
    }

    fn new_session(req: &Map<String, Value>) -> Result<Uc, String> {
        let start = arg_addr(req, "start").ok_or("emu_start requires 'start'")?;
        let code = match req.get("code").and_then(Value::as_str) {
            Some(c) => Some(parse_hex(c).filter(|b| !b.is_empty()).ok_or("'code' must be hex")?),
            None => None,
        };
        let mem = if code.is_some() {
            None
        } else {
            let pid = crate::local::attached_pid().ok_or("attach to a process first (or pass 'code')")?;
            Some(ProcIo::open(pid).map_err(|e| e.to_string())?)
        };
        let maps = mem.as_ref().and_then(|m| m.maps().ok()).unwrap_or_default();
        let mut stack_base = 0x7ffe_0000_0000u64;
        while maps.iter().any(|m| m.end > stack_base && m.start < stack_base + STACK_SIZE + TLS_SIZE) {
            stack_base -= 0x10_0000_0000;
        }
        let mut x = crate::emux::Extras::default();
        crate::emux::parse(req, &mut x)?;
        if req.get("stubs").and_then(Value::as_bool).unwrap_or(false) {
            if let Some(m) = &mem {
                x.stubs = crate::emux::resolve_stubs(m);
            }
        }
        let sess = Sess { mem, bps: BTreeSet::new(), skip: None, hit: None, insns: 0, last_rip: start, stack: (stack_base, STACK_SIZE), dirty: BTreeSet::new(), trace: Vec::new(), x, conds: Default::default(), wps: Vec::new(), wp_hit: None };
        let mut uc = Unicorn::new_with_data(Arch::X86, Mode::MODE_64, sess).map_err(|e| format!("{e:?}"))?;
        uc.mem_map(stack_base, STACK_SIZE, Prot::READ | Prot::WRITE).map_err(|e| format!("{e:?}"))?;
        // a zeroed TLS block for fs:/gs: (stack canaries, errno)
        uc.mem_map(stack_base + STACK_SIZE, TLS_SIZE, Prot::READ | Prot::WRITE).map_err(|e| format!("{e:?}"))?;
        let _ = uc.reg_write(RegisterX86::FS_BASE, stack_base + STACK_SIZE + TLS_SIZE / 2);
        let _ = uc.reg_write(RegisterX86::GS_BASE, stack_base + STACK_SIZE + TLS_SIZE / 2);
        let sp = stack_base + STACK_SIZE - 0x1000;
        uc.reg_write(RegisterX86::RSP, sp).map_err(|e| format!("{e:?}"))?;
        uc.mem_write(sp, &RET_SENTINEL.to_le_bytes()).map_err(|e| format!("{e:?}"))?;
        uc.reg_write(RegisterX86::RIP, start).map_err(|e| format!("{e:?}"))?;
        if let Some(c) = &code {
            let lo = start & !(PAGE - 1);
            let hi = (start + c.len() as u64 + PAGE - 1) & !(PAGE - 1);
            uc.mem_map(lo, hi - lo, Prot::ALL).map_err(|e| format!("{e:?}"))?;
            uc.mem_write(start, c).map_err(|e| format!("{e:?}"))?;
        }
        if let Some(Value::Object(regs)) = req.get("regs") {
            set_regs(&mut uc, regs)?;
        }
        if let Some(Value::Array(w)) = req.get("write") {
            apply_writes(&mut uc, w)?;
        }
        if let Some(Value::Array(b)) = req.get("breakpoints") {
            let set: BTreeSet<u64> = b.iter().filter_map(parse_u64).collect();
            uc.get_data_mut().bps = set;
        }
        crate::emux::set_xmm(&mut uc, req)?;
        uc.add_mem_hook(HookType::MEM_UNMAPPED, 1, 0, |uc, _ty, addr, _size, _v| {
            if fault_in(uc, addr, false) {
                return true;
            }
            let rip = uc.get_data().last_rip;
            let d = uc.get_data_mut();
            crate::emux::on_fault(&mut d.x, addr, rip);
            d.x.zero_unmapped && fault_in(uc, addr, true)
        })
        .map_err(|e| format!("{e:?}"))?;
        uc.add_mem_hook(HookType::MEM_READ, 1, 0, |uc, _ty, addr, size, _v| {
            watch_check(uc, addr, size, false);
            true
        })
        .map_err(|e| format!("{e:?}"))?;
        uc.add_mem_hook(HookType::MEM_WRITE, 1, 0, |uc, _ty, addr, size, _v| {
            watch_check(uc, addr, size, true);
            crate::emux::on_write(&mut uc.get_data_mut().x, addr, size);
            let (sb, ss) = uc.get_data().stack;
            if !(sb..sb + ss).contains(&addr) {
                let d = uc.get_data_mut();
                d.dirty.insert(addr & !(PAGE - 1));
                d.dirty.insert((addr + size as u64 - 1) & !(PAGE - 1));
            }
            true
        })
        .map_err(|e| format!("{e:?}"))?;
        uc.add_code_hook(1, 0, |uc, addr, _size| {
            if crate::local_more::CANCEL.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = uc.emu_stop();
                return;
            }
            let skipped = uc.get_data_mut().skip.take() == Some(addr);
            let at_bp = !skipped && uc.get_data().bps.contains(&addr);
            if at_bp {
                let cond = uc.get_data().conds.get(&addr).cloned().unwrap_or_default();
                if cond.is_empty() || cond_true(uc, &cond) {
                    let d = uc.get_data_mut();
                    d.hit = Some(addr);
                    d.last_rip = addr;
                    let _ = uc.emu_stop();
                    return;
                }
            }
            {
                let d = uc.get_data_mut();
                d.insns += 1;
                d.last_rip = addr;
                if d.trace.len() < 10_000 {
                    d.trace.push(addr);
                }
            }
            let mut x = std::mem::take(&mut uc.get_data_mut().x);
            crate::emux::code(uc, &mut x, addr);
            uc.get_data_mut().x = x;
        })
        .map_err(|e| format!("{e:?}"))?;
        Ok(uc)
    }

    /// Adds the extras (register trace, API calls, layers, faults, xmm) to a step/run reply.
    fn with_extras(uc: &mut Unicorn<'_, Sess>, mut v: Value) -> Value {
        let xmm = crate::emux::xmm_json(uc);
        crate::emux::report(&mut v, &uc.get_data().x, xmm);
        v
    }

    fn serve(mut uc: Uc, rx: mpsc::Receiver<Job>) {
        let mut snaps: Vec<(String, Snap)> = Vec::new();
        while let Ok((req, reply)) = rx.recv() {
            let verb = req.get("type").and_then(Value::as_str).unwrap_or_default().to_owned();
            let timeout = req.get("timeout_us").and_then(Value::as_u64).unwrap_or(2_000_000).clamp(1000, 10_000_000);
            let trace = req.get("trace").and_then(Value::as_bool).unwrap_or(false);
            let out = match verb.as_str() {
                "emu_step" => {
                    let n = req.get("count").and_then(Value::as_u64).unwrap_or(1).clamp(1, 1_000_000) as usize;
                    let stop = run(&mut uc, n, 0, timeout, trace);
                    { let st = state(&mut uc, stop); with_extras(&mut uc, st) }
                }
                "emu_run" => {
                    let until = arg_addr(&req, "until").unwrap_or(0);
                    let max = req.get("max_insns").and_then(Value::as_u64).unwrap_or(1_000_000).clamp(1, 50_000_000) as usize;
                    let stop = run(&mut uc, max, until, timeout, trace);
                    { let st = state(&mut uc, stop); with_extras(&mut uc, st) }
                }
                // time-travel recording of the session (trace_record source "emu", see trace_emu.rs)
                "emu_record" => {
                    let lim = crate::trace_rec::Limits::from_req(&req);
                    let until = lim.until.unwrap_or(0);
                    let run_timeout = req.get("timeout_us").and_then(Value::as_u64).unwrap_or(120_000_000).min(3_600_000_000);
                    let meta = crate::trace::Meta {
                        name: req.get("name").and_then(Value::as_str).unwrap_or_default().to_owned(),
                        source: "emu".into(),
                        created_ms: crate::trace_rec::now_ms(),
                        pid: if uc.get_data().mem.is_some() { crate::local::attached_pid() } else { None },
                        ..Default::default()
                    };
                    let save = req.get("save").and_then(Value::as_bool).unwrap_or(true);
                    match crate::trace_emu::record(&mut uc, meta, &lim, |uc, a, buf| match &uc.get_data().mem {
                        Some(m) => m.read_at(a, buf).map(|n| n == buf.len()).unwrap_or(false),
                        None => { buf.fill(0); true }
                    }, |uc, n| run(uc, n, until, run_timeout, false)) {
                        Ok((t, stop)) => {
                            let summary = crate::trace_rec::deposit(t, save);
                            let mut v = state(&mut uc, stop);
                            v["trace"] = summary;
                            v
                        }
                        Err(e) => failed(&e),
                    }
                }
                "emu_watch" => {
                    if req.get("clear").and_then(Value::as_bool) == Some(true) {
                        uc.get_data_mut().wps.clear();
                    }
                    if let Some(a) = arg_addr(&req, "address") {
                        let n = req.get("size").and_then(Value::as_u64).unwrap_or(8).max(1);
                        let m = match req.get("access").and_then(Value::as_str).unwrap_or("rw") { "r" => 1, "w" => 2, _ => 3 };
                        let on = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                        let wps = &mut uc.get_data_mut().wps;
                        wps.retain(|w| w.0 != a);
                        if on {
                            wps.push((a, n, m));
                        }
                    }
                    let list: Vec<Value> = uc.get_data().wps.iter().map(|(a, n, m)| json!({ "address": hex_addr(*a), "size": n, "access": match m { 1 => "r", 2 => "w", _ => "rw" } })).collect();
                    json!({ "success": true, "watchpoints": list })
                }
                "emu_snapshot" => {
                    let name = req.get("name").and_then(Value::as_str).unwrap_or("default").to_owned();
                    let regs: Vec<u64> = REGS.iter().map(|(_, r)| uc.reg_read(*r).unwrap_or(0)).collect();
                    let xmm: Vec<Box<[u8]>> = crate::emux::XMM.iter().map(|r| uc.reg_read_long(*r).unwrap_or_default()).collect();
                    let mut mem = Vec::new();
                    let mut bytes = 0u64;
                    for r in uc.mem_regions().unwrap_or_default() {
                        let n = r.end - r.begin + 1;
                        bytes += n;
                        if bytes > 128 << 20 {
                            break;
                        }
                        if let Ok(b) = uc.mem_read_as_vec(r.begin, n as usize) {
                            mem.push((r.begin, b));
                        }
                    }
                    let insns = uc.get_data().insns;
                    snaps.retain(|(n, _)| *n != name);
                    if snaps.len() >= 8 {
                        snaps.remove(0);
                    }
                    let regions = mem.len();
                    snaps.push((name.clone(), Snap { regs, xmm, mem, insns }));
                    json!({ "success": true, "name": name, "regions": regions, "bytes": bytes.min(128 << 20), "instructions": insns, "snapshots": snaps.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>() })
                }
                "emu_restore" => {
                    let name = req.get("name").and_then(Value::as_str).unwrap_or("default");
                    match snaps.iter().find(|(n, _)| n == name) {
                        Some((_, sn)) => {
                            for (a, b) in &sn.mem {
                                let _ = uc.mem_write(*a, b);
                            }
                            for ((_, r), v) in REGS.iter().zip(&sn.regs) {
                                let _ = uc.reg_write(*r, *v);
                            }
                            for (r, v) in crate::emux::XMM.iter().zip(&sn.xmm) {
                                if v.len() >= 16 {
                                    let _ = uc.reg_write_long(*r, v);
                                }
                            }
                            uc.get_data_mut().insns = sn.insns;
                            state(&mut uc, json!({ "reason": "restored" }))
                        }
                        None => failed(&format!("no snapshot named {name}")),
                    }
                }
                "emu_break" => {
                    let mut err = None;
                    if req.get("clear").and_then(Value::as_bool) == Some(true) {
                        uc.get_data_mut().bps.clear();
                    }
                    if let Some(a) = req.get("address") {
                        match parse_u64(a) {
                            Some(a) => {
                                let on = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                                let cond = req.get("condition").and_then(Value::as_str).unwrap_or("").to_owned();
                                let d = uc.get_data_mut();
                                if on {
                                    d.bps.insert(a);
                                    if cond.is_empty() { d.conds.remove(&a); } else { d.conds.insert(a, cond); }
                                } else {
                                    d.bps.remove(&a);
                                    d.conds.remove(&a);
                                }
                            }
                            None => err = Some(bad("'address' must be a 0x address")),
                        }
                    }
                    err.unwrap_or_else(|| {
                        let mut v = state(&mut uc, json!({ "reason": "edit" }));
                        v["conditions"] = json!(uc.get_data().conds.iter().map(|(a, c)| (hex_addr(*a), json!(c))).collect::<Map<String, Value>>());
                        v
                    })
                }
                "emu_set" => {
                    let mut r = Ok(0);
                    if let Some(Value::Object(regs)) = req.get("regs") {
                        r = set_regs(&mut uc, regs).map(|_| 0);
                    }
                    if r.is_ok() {
                        if let Some(Value::Array(w)) = req.get("write") {
                            r = apply_writes(&mut uc, w);
                        }
                    }
                    match r {
                        Ok(_) => state(&mut uc, json!({ "reason": "edit" })),
                        Err(e) => bad(&e),
                    }
                }
                "emu_read" => match arg_addr(&req, "address") {
                    Some(a) => {
                        let n = req.get("size").and_then(Value::as_u64).unwrap_or(256).clamp(1, 0x10000) as usize;
                        match read_mem(&mut uc, a, n) {
                            Some(b) => json!({ "success": true, "address": hex_addr(a), "size": n, "data": hex_bytes(&b) }),
                            None => failed(&format!("{} is not mapped in the emulator or the process", hex_addr(a))),
                        }
                    }
                    None => bad("emu_read requires 'address'"),
                },
                "emu_state" => state(&mut uc, json!({ "reason": "state" })),
                _ => bad(&format!("unknown emulated-debugger verb {verb}")),
            };
            let _ = reply.send(out);
        }
    }

    pub fn handle(req: &Map<String, Value>) -> Value {
        let verb = req.get("type").and_then(Value::as_str).unwrap_or_default().to_owned();
        let mut out = match verb.as_str() {
            "emu_start" => {
                let (tx, rx) = mpsc::channel::<Job>();
                let (ready_tx, ready_rx) = mpsc::channel::<Value>();
                let req2 = req.clone();
                std::thread::spawn(move || match new_session(&req2) {
                    Ok(mut uc) => {
                        let _ = ready_tx.send(state(&mut uc, json!({ "reason": "start" })));
                        serve(uc, rx);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(bad(&e));
                    }
                });
                let r = ready_rx.recv().unwrap_or_else(|_| failed("emulator thread died"));
                if r["type"] != "error" {
                    // a new session replaces the old one (its thread ends when the sender drops)
                    *SESSION.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
                }
                r
            }
            "emu_close" => {
                let had = SESSION.lock().unwrap_or_else(|e| e.into_inner()).take().is_some();
                json!({ "success": true, "closed": had })
            }
            _ => {
                let tx = SESSION.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let Some(tx) = tx else { return failed("no emulator session: emu_start first") };
                let (rtx, rrx) = mpsc::channel();
                if tx.send((req.clone(), rtx)).is_err() {
                    return failed("the emulator session ended");
                }
                rrx.recv().unwrap_or_else(|_| failed("the emulator session ended"))
            }
        };
        if out["type"].is_null() {
            out["type"] = json!(format!("{verb}_result"));
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn call(v: Value) -> Value {
            let Value::Object(m) = v else { unreachable!() };
            handle(&m)
        }

        /// the session is process-global: tests take turns
        static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());

        #[test]
        fn watchpoints_conditions_layers_snapshots() {
            let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
            // mov rax,1 ; mov [0x500000],rax ; inc rax ; mov rcx,0x600000 ; mov byte [rcx],0xc3 ; call rcx ; ret
            let code = "48c7c001000000 48890425000050 00 48ffc0 48c7c100006000 c601c3 ffd1 c3".replace(' ', "");
            let r = call(json!({ "type": "emu_start", "start": "0x400000", "code": code, "trace_regs": true, "layers": true }));
            assert_eq!(r["success"], true, "{r}");
            let w = call(json!({ "type": "emu_watch", "address": "0x500000", "size": 8, "access": "w" }));
            assert_eq!(w["watchpoints"][0]["access"], "w", "{w}");
            let r = call(json!({ "type": "emu_run" }));
            assert_eq!(r["stop"]["reason"], "watchpoint", "{r}");
            assert_eq!(r["stop"]["hit"]["access"], "write");
            assert!(r["reg_trace"].as_array().unwrap().iter().any(|e| e["changes"]["rax"] == "0x1"), "{r}");
            let snap = call(json!({ "type": "emu_snapshot", "name": "s1" }));
            assert_eq!(snap["name"], "s1", "{snap}");
            // a conditional breakpoint that never holds, then one that does
            call(json!({ "type": "emu_watch", "clear": true }));
            call(json!({ "type": "emu_break", "address": "0x40000f", "condition": "rax==0x5" }));
            let r = call(json!({ "type": "emu_run" }));
            assert_eq!(r["stop"]["reason"], "returned", "the false condition does not stop: {r}");
            assert_eq!(r["layers"][0]["entry"], "0x600000", "written then executed: {r}");
            let back = call(json!({ "type": "emu_restore", "name": "s1" }));
            assert_eq!(back["regs"]["rax"], "0x1", "{back}");
            call(json!({ "type": "emu_break", "address": "0x40000f", "condition": "rax==0x1" }));
            let r = call(json!({ "type": "emu_run" }));
            assert_eq!((r["stop"]["reason"].as_str(), r["rip"].as_str()), (Some("breakpoint"), Some("0x40000f")), "{r}");
            assert_eq!(call(json!({ "type": "emu_close" }))["closed"], true);
        }

        #[test]
        fn step_break_edit_run() {
            let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
            // 0x400000: mov eax, 1 ; add eax, ecx ; mov [0x500000], eax ; inc eax ; ret
            let code = "b80100000001c8890425000050".to_owned() + "00ffc0c3";
            let r = call(json!({ "type": "emu_start", "start": "0x400000", "code": code, "regs": { "rcx": "0x10" } }));
            assert_eq!(r["success"], true, "{r}");
            assert!(r["next"][0]["text"].as_str().unwrap().contains("mov"), "{r}");
            let r = call(json!({ "type": "emu_step" }));
            assert_eq!((r["stop"]["reason"].as_str(), r["regs"]["rax"].as_str(), r["rip"].as_str()), (Some("step"), Some("0x1"), Some("0x400005")), "{r}");
            // breakpoint on inc eax (0x400007 + 7 = 0x40000e)
            let r = call(json!({ "type": "emu_break", "address": "0x40000e" }));
            assert_eq!(r["breakpoints"], json!(["0x40000e"]));
            let r = call(json!({ "type": "emu_run" }));
            assert_eq!(r["stop"]["reason"], "breakpoint", "{r}");
            assert_eq!(r["rip"], "0x40000e");
            assert_eq!(r["regs"]["rax"], "0x11");
            // the store landed in emulator memory (zero page: no process)
            let m = call(json!({ "type": "emu_read", "address": "0x500000", "size": 4 }));
            assert_eq!(m["data"], "11000000", "{m}");
            // edit a register, resume past the breakpoint and return
            call(json!({ "type": "emu_set", "regs": { "rax": "0x41" } }));
            let r = call(json!({ "type": "emu_run" }));
            assert_eq!(r["stop"]["reason"], "returned", "{r}");
            assert_eq!(r["regs"]["rax"], "0x42");
            assert!(r["dirty_pages"].as_array().is_some());
            let c = call(json!({ "type": "emu_close" }));
            assert_eq!(c["closed"], true);
            assert_eq!(call(json!({ "type": "emu_step" }))["type"], "error");
        }
    }
}
