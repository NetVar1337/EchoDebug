//! Emulation extras for the local Unicorn emulators (`emulate` and the `emu_*` session), the
//! Linux counterparts of the agent's: register-change traces, libc stand-ins, write-then-execute
//! unpacking layers, zero-filled unmapped reads and xmm registers.
//!
//! Stand-ins are keyed by address: the exported symbol and, because glibc resolves memcpy and
//! friends through IFUNCs, every GOT slot of the loaded modules that names the function (the
//! value the program actually calls).

#[cfg(target_os = "linux")]
pub use imp::*;

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::{HashMap, HashSet};

    use serde_json::{json, Map, Value};
    use unicorn_engine::unicorn_const::Prot;
    use unicorn_engine::{RegisterX86, Unicorn};

    use crate::local::{hex_addr, MemIo};

    pub const STUB_NAMES: &[&str] = &["memcpy", "memmove", "memset", "strlen", "malloc", "calloc", "free", "strcmp", "puts", "usleep", "sleep", "getpid"];
    const HEAP: u64 = 0x5f00_0000_0000;

    #[derive(Default)]
    pub struct Extras {
        pub regs_on: bool,
        pub regs_limit: usize,
        pub prev: [u64; 16],
        pub reg_trace: Vec<Value>,
        pub stubs: HashMap<u64, &'static str>,
        pub api_calls: Vec<Value>,
        pub api_count: u64,
        pub heap_next: u64,
        pub layers: bool,
        pub written: HashSet<u64>,
        pub entered: HashSet<u64>,
        pub layer_out: Vec<Value>,
        pub zero_unmapped: bool,
        pub faults: Vec<Value>,
        pub fault_count: u64,
    }

    pub const GPRS: [(&str, RegisterX86); 16] = [
        ("rax", RegisterX86::RAX), ("rbx", RegisterX86::RBX), ("rcx", RegisterX86::RCX), ("rdx", RegisterX86::RDX),
        ("rsi", RegisterX86::RSI), ("rdi", RegisterX86::RDI), ("rbp", RegisterX86::RBP), ("rsp", RegisterX86::RSP),
        ("r8", RegisterX86::R8), ("r9", RegisterX86::R9), ("r10", RegisterX86::R10), ("r11", RegisterX86::R11),
        ("r12", RegisterX86::R12), ("r13", RegisterX86::R13), ("r14", RegisterX86::R14), ("r15", RegisterX86::R15),
    ];

    pub const XMM: [RegisterX86; 16] = [
        RegisterX86::XMM0, RegisterX86::XMM1, RegisterX86::XMM2, RegisterX86::XMM3, RegisterX86::XMM4, RegisterX86::XMM5,
        RegisterX86::XMM6, RegisterX86::XMM7, RegisterX86::XMM8, RegisterX86::XMM9, RegisterX86::XMM10, RegisterX86::XMM11,
        RegisterX86::XMM12, RegisterX86::XMM13, RegisterX86::XMM14, RegisterX86::XMM15,
    ];

    /// Reads the options from a request; Err is the problem.
    pub fn parse(req: &Map<String, Value>, x: &mut Extras) -> Result<(), String> {
        let b = |k: &str| req.get(k).and_then(Value::as_bool).unwrap_or(false);
        x.regs_on = b("trace_regs");
        x.regs_limit = req.get("trace_limit").and_then(Value::as_u64).unwrap_or(2000).min(100_000) as usize;
        x.layers = b("layers");
        x.zero_unmapped = match req.get("on_unmapped").and_then(Value::as_str).unwrap_or("stop") {
            "stop" => false,
            "zero" => true,
            _ => return Err("on_unmapped must be 'stop' or 'zero'".into()),
        };
        x.heap_next = HEAP;
        Ok(())
    }

    /// Stand-in table from the attached process: exports of libc plus resolved GOT slots.
    pub fn resolve_stubs(mem: &impl MemIo) -> HashMap<u64, &'static str> {
        use object::{Object, ObjectSymbol};
        let mut out = HashMap::new();
        let Ok(mods) = mem.modules() else { return out };
        for (name, base, _) in mods.iter().filter(|(n, _, _)| !n.starts_with('[')) {
            let Some((path, _, _)) = crate::local_ext::module_path(mem, name) else { continue };
            let Ok(data) = std::fs::read(&path) else { continue };
            let Ok(file) = object::File::parse(&*data) else { continue };
            let bias = crate::local::load_bias(&file, *base);
            if name.starts_with("libc") {
                for s in file.dynamic_symbols() {
                    if let (Ok(n), true) = (s.name(), s.is_definition()) {
                        if let Some(k) = STUB_NAMES.iter().find(|k| **k == n) {
                            out.insert(s.address().wrapping_add(bias), *k);
                        }
                    }
                }
            }
            // GOT slots: the address the program jumps to through the PLT
            if let Some(relocs) = file.dynamic_relocations() {
                let syms: Vec<_> = file.dynamic_symbols().collect();
                for (off, r) in relocs {
                    let object::RelocationTarget::Symbol(idx) = r.target() else { continue };
                    let Some(sym) = syms.iter().find(|s| s.index() == idx) else { continue };
                    let Ok(n) = sym.name() else { continue };
                    let Some(k) = STUB_NAMES.iter().find(|k| **k == n) else { continue };
                    if let Some(v) = crate::local_ext::read_u64(mem, off.wrapping_add(bias)) {
                        if v > 0x10000 {
                            out.insert(v, *k);
                        }
                    }
                }
            }
        }
        out
    }

    pub fn set_xmm<D>(uc: &mut Unicorn<'_, D>, req: &Map<String, Value>) -> Result<(), String> {
        let Some(Value::Object(m)) = req.get("xmm") else { return Ok(()) };
        for (k, v) in m {
            let Some(i) = k.strip_prefix("xmm").and_then(|n| n.parse::<usize>().ok()).filter(|i| *i < 16) else { return Err(format!("unknown xmm register {k}")) };
            let hx = v.as_str().unwrap_or("");
            let b: Option<Vec<u8>> = (0..hx.len() / 2).map(|j| u8::from_str_radix(&hx[j * 2..j * 2 + 2], 16).ok()).collect();
            let Some(b) = b.filter(|b| b.len() == 16) else { return Err(format!("{k} must be 16 bytes of hex")) };
            uc.reg_write_long(XMM[i], &b).map_err(|e| format!("{e:?}"))?;
        }
        Ok(())
    }

    pub fn xmm_json<D>(uc: &Unicorn<'_, D>) -> Value {
        let mut m = Map::new();
        for (i, r) in XMM.iter().enumerate() {
            if let Ok(b) = uc.reg_read_long(*r) {
                m.insert(format!("xmm{i}"), json!(b.iter().take(16).map(|x| format!("{x:02x}")).collect::<String>()));
            }
        }
        Value::Object(m)
    }

    pub fn baseline<D>(uc: &Unicorn<'_, D>, x: &mut Extras) {
        for (i, (_, r)) in GPRS.iter().enumerate() {
            x.prev[i] = uc.reg_read(*r).unwrap_or(0);
        }
    }

    pub fn reset_run(x: &mut Extras) {
        x.reg_trace.clear();
        x.api_calls.clear();
        x.api_count = 0;
        x.layer_out.clear();
        x.faults.clear();
        x.fault_count = 0;
    }

    fn rd<D>(uc: &Unicorn<'_, D>, r: RegisterX86) -> u64 {
        uc.reg_read(r).unwrap_or(0)
    }

    fn mem_read<D>(uc: &mut Unicorn<'_, D>, a: u64, n: usize) -> Option<Vec<u8>> {
        let mut b = vec![0u8; n];
        if uc.mem_read(a, &mut b).is_ok() {
            return Some(b);
        }
        None
    }

    fn ensure<D>(uc: &mut Unicorn<'_, D>, a: u64, n: u64) {
        let mut p = a & !0xfff;
        while p < a + n.max(1) {
            let mut t = [0u8; 1];
            if uc.mem_read(p, &mut t).is_err() {
                let _ = uc.mem_map(p, 0x1000, Prot::ALL);
            }
            p += 0x1000;
        }
    }

    fn cstr<D>(uc: &mut Unicorn<'_, D>, a: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut p = a;
        while out.len() < 1 << 20 {
            let Some(b) = mem_read(uc, p, 1) else { break };
            if b[0] == 0 {
                break;
            }
            out.push(b[0]);
            p += 1;
        }
        out
    }

    /// Runs the stand-in for `name` (SysV: rdi, rsi, rdx -> rax) and returns to the caller.
    /// Memory goes through `mem` for pages the emulator has not mapped yet (fault-in).
    pub fn stub<D>(uc: &mut Unicorn<'_, D>, x: &mut Extras, addr: u64, name: &'static str) {
        let (a1, a2, a3) = (rd(uc, RegisterX86::RDI), rd(uc, RegisterX86::RSI), rd(uc, RegisterX86::RDX));
        let mut ret = 0u64;
        let mut note = String::new();
        match name {
            "memcpy" | "memmove" => {
                if a3 <= 1 << 24 {
                    if let Some(b) = mem_read(uc, a2, a3 as usize) {
                        ensure(uc, a1, a3);
                        let _ = uc.mem_write(a1, &b);
                    }
                }
                ret = a1;
            }
            "memset" => {
                if a3 <= 1 << 24 {
                    ensure(uc, a1, a3);
                    let _ = uc.mem_write(a1, &vec![a2 as u8; a3 as usize]);
                }
                ret = a1;
            }
            "strlen" => ret = cstr(uc, a1).len() as u64,
            "strcmp" => {
                let (s1, s2) = (cstr(uc, a1), cstr(uc, a2));
                ret = match s1.cmp(&s2) { std::cmp::Ordering::Less => u64::MAX, std::cmp::Ordering::Equal => 0, _ => 1 };
            }
            "malloc" | "calloc" => {
                let n = if name == "calloc" { a1.saturating_mul(a2) } else { a1 };
                let size = n.max(1).div_ceil(0x1000) * 0x1000;
                let at = x.heap_next;
                if uc.mem_map(at, size, Prot::ALL).is_ok() {
                    x.heap_next += size + 0x1000;
                    ret = at;
                }
                note = format!("{n:#x} bytes");
            }
            "puts" => {
                note = String::from_utf8_lossy(&cstr(uc, a1)).into_owned();
                ret = note.len() as u64 + 1;
            }
            "getpid" => ret = crate::local::attached_pid().unwrap_or(0) as u64,
            _ => {} // free, sleep, usleep: nothing to do
        }
        let rsp = rd(uc, RegisterX86::RSP);
        let back = mem_read(uc, rsp, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))).unwrap_or(0);
        let _ = uc.reg_write(RegisterX86::RAX, ret);
        let _ = uc.reg_write(RegisterX86::RSP, rsp + 8);
        let _ = uc.reg_write(RegisterX86::RIP, back);
        x.api_count += 1;
        if x.api_calls.len() < 2000 {
            let mut c = json!({ "api": name, "address": hex_addr(addr), "return_to": hex_addr(back), "result": hex_addr(ret), "args": format!("{}, {}, {}", hex_addr(a1), hex_addr(a2), hex_addr(a3)) });
            if !note.is_empty() {
                c["note"] = json!(note);
            }
            x.api_calls.push(c);
        }
    }

    /// Per instruction: stand-ins, layer entry, register-change trace. true = a stand-in ran.
    pub fn code<D>(uc: &mut Unicorn<'_, D>, x: &mut Extras, addr: u64) -> bool {
        if let Some(name) = x.stubs.get(&addr).copied() {
            stub(uc, x, addr, name);
            return true;
        }
        if x.layers {
            let page = addr & !0xfff;
            if x.written.contains(&page) && x.entered.insert(page) && x.layer_out.len() < 256 {
                x.layer_out.push(json!({ "entry": hex_addr(addr), "page": hex_addr(page) }));
            }
        }
        if x.regs_on && x.reg_trace.len() < x.regs_limit {
            let mut ch = Map::new();
            for (i, (n, r)) in GPRS.iter().enumerate() {
                let v = rd(uc, *r);
                if v != x.prev[i] {
                    ch.insert((*n).into(), json!(hex_addr(v)));
                    x.prev[i] = v;
                }
            }
            let mut e = json!({ "rip": hex_addr(addr) });
            if !ch.is_empty() {
                e["changes"] = Value::Object(ch);
            }
            x.reg_trace.push(e);
        }
        false
    }

    pub fn on_write(x: &mut Extras, addr: u64, size: usize) {
        if x.layers {
            x.written.insert(addr & !0xfff);
            x.written.insert((addr + size.max(1) as u64 - 1) & !0xfff);
        }
    }

    pub fn on_fault(x: &mut Extras, addr: u64, rip: u64) {
        x.fault_count += 1;
        if x.faults.len() < 256 {
            x.faults.push(json!({ "address": hex_addr(addr), "rip": hex_addr(rip) }));
        }
    }

    pub fn report(out: &mut Value, x: &Extras, xmm: Value) {
        if x.regs_on {
            out["reg_trace"] = json!(x.reg_trace);
        }
        if !x.stubs.is_empty() {
            out["api_calls"] = json!(x.api_calls);
            out["api_call_count"] = json!(x.api_count);
        }
        if x.layers {
            out["layers"] = json!(x.layer_out);
        }
        if x.fault_count > 0 {
            out["faults"] = json!(x.faults);
            out["fault_count"] = json!(x.fault_count);
        }
        out["xmm"] = xmm;
    }
}
