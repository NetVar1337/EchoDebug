//! Local memory backend for non-Windows hosts (Linux preview builds).
//!
//! Echo's agent (AngelScript inside the Discord overlay) only exists on Windows, so on Linux the
//! relay serves the same verb surface itself from `/proc/<pid>`: `mem` for reads/writes, `maps`
//! for regions and modules, ELF symbols for function enumeration, and iced-x86 for disassembly
//! and RIP-relative resolution. Everything is behind a `MemIo` trait so the logic is unit-testable
//! on any OS with an in-memory implementation.
//!
//! Limitations vs. the Echo backend: no physical-memory tricks (ptrace rules apply — same-user
//! processes, or `kernel.yama.ptrace_scope=0`), no RTTI (MSVC concept), no Unicorn emulation,
//! no freeze/watch/pointer-scan (those stay agent verbs and return a clear error here).

use std::io;
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::Relay;

// ---------------------------------------------------------------------------------------------
// Memory access abstraction
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct MapLine {
    pub start: u64,
    pub end: u64,
    pub writable: bool,
    pub executable: bool,
    pub path: String,
}

pub trait MemIo: Send + Sync {
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize>;
    fn write_at(&self, addr: u64, buf: &[u8]) -> io::Result<()>;
    fn maps(&self) -> io::Result<Vec<MapLine>>;
    /// Module list: (name, base, size).
    fn modules(&self) -> io::Result<Vec<(String, u64, u64)>> {
        let maps = self.maps()?;
        let mut out: Vec<(String, u64, u64)> = Vec::new();
        for m in maps.iter().filter(|m| !m.path.is_empty()) {
            let name = m.path.rsplit('/').next().unwrap_or(&m.path).to_string();
            match out.iter_mut().find(|(n, _, _)| *n == name) {
                Some(e) => {
                    e.1 = e.1.min(m.start);
                    e.2 = (m.end - e.1).max(e.2);
                }
                None => out.push((name, m.start, m.end - m.start)),
            }
        }
        Ok(out)
    }
    fn alive(&self) -> bool;
}

// ---------------------------------------------------------------------------------------------
// /proc-backed implementation (Linux)
// ---------------------------------------------------------------------------------------------

pub struct ProcIo {
    pub pid: u32,
}

#[cfg(target_os = "linux")]
impl ProcIo {
    fn mem_path(pid: u32) -> String {
        format!("/proc/{pid}/mem")
    }
    fn maps_path(pid: u32) -> String {
        format!("/proc/{pid}/maps")
    }
    pub fn open(pid: u32) -> io::Result<Self> {
        std::fs::metadata(format!("/proc/{pid}")).map(|_| ProcIo { pid })
    }
    fn mem_file(&self) -> io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(Self::mem_path(self.pid))
    }
}

#[cfg(target_os = "linux")]
impl MemIo for ProcIo {
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        self.mem_file()?.read_at(buf, addr)
    }
    fn write_at(&self, addr: u64, buf: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        self.mem_file()?.write_all_at(buf, addr)
    }
    fn maps(&self) -> io::Result<Vec<MapLine>> {
        let text = std::fs::read_to_string(Self::maps_path(self.pid))?;
        Ok(parse_maps(&text))
    }
    fn alive(&self) -> bool {
        std::path::Path::new(&format!("/proc/{}", self.pid)).exists()
    }
}

// Non-Linux: compiles so CI and tests run everywhere, but never used (available() is false).
#[cfg(not(target_os = "linux"))]
impl ProcIo {
    pub fn open(_pid: u32) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "local backend is Linux-only"))
    }
}

#[cfg(not(target_os = "linux"))]
impl MemIo for ProcIo {
    fn read_at(&self, _addr: u64, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "local backend is Linux-only"))
    }
    fn write_at(&self, _addr: u64, _buf: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "local backend is Linux-only"))
    }
    fn maps(&self) -> io::Result<Vec<MapLine>> {
        Ok(Vec::new())
    }
    fn alive(&self) -> bool {
        false
    }
}

pub fn parse_maps(text: &str) -> Vec<MapLine> {
    let mut out = Vec::new();
    for line in text.lines() {
        // 7f0a1b2c000-7f0a1b2d000 r-xp 00000000 08:01 1234    /usr/lib/x.so
        let mut it = line.split_whitespace();
        let Some(range) = it.next() else { continue };
        let Some(perms) = it.next() else { continue };
        let path = it.nth(3).unwrap_or("").to_string();
        let Some((s, e)) = range.split_once('-') else { continue };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16)) else {
            continue;
        };
        out.push(MapLine {
            start,
            end,
            writable: perms.contains('w'),
            executable: perms.contains('x'),
            path,
        });
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Backend state
// ---------------------------------------------------------------------------------------------

pub struct LocalState {
    pub pid: u32,
    pub scan: Option<LocalScan>,
}

pub struct LocalScan {
    pub vtype: String,
    pub width: usize,
    pub op: String,
    pub f1: f64,
    pub f2: f64,
    pub raw1: u64,
    pub t1: u64,
    pub t2: u64,
    pub pattern: Vec<u8>,
    pub addrs: Vec<u64>,
    pub prev_bits: Vec<u64>,
    pub prev_raw: Vec<u8>,
    pub truncated: bool,
}

static STATE: Mutex<Option<LocalState>> = Mutex::new(None);

/// The local backend exists on Linux only; on Windows the Echo agent is the backend.
pub fn available() -> bool {
    // ECHODEBUG_LOCAL_BACKEND=1 forces the local backend on (tests simulate Linux on any host);
    // =0 forces it off.
    match std::env::var("ECHODEBUG_LOCAL_BACKEND") {
        Ok(v) if v == "1" => true,
        Ok(v) if v == "0" => false,
        _ => std::env::consts::OS == "linux",
    }
}

fn with_state<R>(f: impl FnOnce(&mut LocalState) -> R) -> Option<R> {
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    g.as_mut().map(f)
}

pub fn attached_pid() -> Option<u32> {
    STATE.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|s| s.pid)
}

fn io(pid: u32) -> Option<ProcIo> {
    ProcIo::open(pid).ok()
}

fn err(id: &Value, code: i64, message: &str, detail: &str) -> Value {
    json!({ "type": "error", "id": id, "code": code, "message": message, "detail": detail })
}

fn hex_addr(v: u64) -> String {
    format!("0x{v:x}")
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------------------------
// Verb dispatch — returns Some(reply) when the local backend handled the request
// ---------------------------------------------------------------------------------------------

/// Native (Echo memory-server) verbs.
pub async fn handle_native(_relay: &Relay, req: Map<String, Value>, orig: &Value) -> Option<Value> {
    if !available() {
        return None;
    }
    let Some(pid) = attached_pid() else {
        return Some(err(orig, 1001, "not attached to a process", "attach first (local backend)"));
    };
    let Some(mem) = io(pid) else {
        return Some(err(orig, 1001, "not attached to a process", "target pid vanished"));
    };
    let verb = req.get("type").and_then(Value::as_str).unwrap_or_default().to_string();
    let reply = match verb.as_str() {
        "ping" => json!({ "type": "ping_result", "attached": true, "pid": pid, "base": modules_base(&mem) }),
        "read" => native_read(&mem, &req),
        "read_batch" => native_read_batch(&mem, &req),
        "modules" => native_modules(&mem),
        "sig_scan" => native_sig_scan(&mem, &req, false),
        "sig_scan_ida" => native_sig_scan(&mem, &req, true),
        "string_scan" => native_string_scan(&mem, &req),
        "disassemble" => native_disassemble(&mem, &req),
        "enumerate_functions" => native_functions(&mem, &req),
        "resolve_relative" => native_resolve_relative(&mem, &req),
        "rtti_resolve" | "rtti_resolve_batch" => {
            return Some(err(orig, 1008, "not supported by the local Linux backend", "RTTI is an MSVC/Windows concept"));
        }
        _ => return Some(err(orig, 1000, "unknown message type", &verb)),
    };
    let mut r = match reply {
        Value::Object(m) => m,
        other => return Some(other),
    };
    r.insert("id".into(), orig.clone());
    Some(Value::Object(r))
}

/// Ext (agent) verbs. attach/detach/alive work without a prior attach; the rest need one.
pub async fn handle_ext(relay: &Relay, req: Map<String, Value>, orig: &Value) -> Option<Value> {
    if !available() {
        return None;
    }
    let verb = req.get("type").and_then(Value::as_str).unwrap_or_default().to_string();
    let reply = match verb.as_str() {
        "attach" => return Some(local_attach(relay, &req, orig)),
        "detach" => return Some(local_detach(relay, orig)),
        "alive" => {
            let pid = attached_pid().unwrap_or(0);
            let alive = pid != 0 && io(pid).map(|m| m.alive()).unwrap_or(false);
            json!({ "type": "alive_result", "alive": alive, "pid": pid })
        }
        "reopen_socket" => {
            return Some(err(orig, 3003, "operation failed", "no Echo memory socket on the local Linux backend"));
        }
        "freeze" | "freeze_list" | "emulate" | "pointer_scan" | "peb_walk" | "watch" | "unwatch"
        | "watch_list" | "resolve_export" => {
            return Some(err(
                orig,
                3003,
                "requires the Echo agent",
                "this verb only exists in the Windows AngelScript agent (echo_debug.as)",
            ));
        }
        _ => {
            let Some(pid) = attached_pid() else {
                return Some(err(orig, 3001, "not attached", "attach to a process first"));
            };
            let Some(mem) = io(pid) else {
                return Some(err(orig, 3001, "not attached", "target pid vanished"));
            };
            match verb.as_str() {
                "write" => ext_write(&mem, &req),
                "query" => ext_query(&mem, &req),
                "regions" => ext_regions(&mem, &req),
                "chain" => ext_chain(&mem, &req),
                "scan_new" => ext_scan_new(&mem, &req),
                "scan_next" => ext_scan_next(&mem, &req),
                "scan_results" => ext_scan_results(&mem, &req),
                "scan_clear" => ext_scan_clear(),
                "read_typed" => ext_read_typed(&mem, &req),
                "region_stats" => ext_region_stats(&mem, &req),
                "dump" => ext_dump(&mem, &req),
                _ => return Some(err(orig, 3000, "unknown verb", &verb)),
            }
        }
    };
    let mut r = match reply {
        Value::Object(m) => m,
        other => return Some(other),
    };
    r.insert("id".into(), orig.clone());
    Some(Value::Object(r))
}

fn modules_base(mem: &impl MemIo) -> Value {
    mem.modules()
        .ok()
        .and_then(|m| m.iter().max_by_key(|(_, _, sz)| *sz).map(|(_, b, _)| hex_addr(*b)))
        .map(Value::String)
        .unwrap_or(Value::String("0x0".into()))
}

// ---------------------------------------------------------------------------------------------
// Native verbs
// ---------------------------------------------------------------------------------------------

fn arg_addr(req: &Map<String, Value>, k: &str) -> Option<u64> {
    match req.get(k)? {
        Value::String(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16).ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn native_read(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let (Some(addr), Some(size)) = (arg_addr(req, "address"), req.get("size").and_then(Value::as_u64)) else {
        return json!({ "type": "error", "code": 1002, "message": "invalid or missing arguments", "detail": "read requires 'address' and 'size'" });
    };
    if !(1..=1_048_576).contains(&size) {
        return json!({ "type": "error", "code": 1004, "message": "size out of range (1..1048576)" });
    }
    let mut buf = vec![0u8; size as usize];
    match mem.read_at(addr, &mut buf) {
        Ok(n) if n == size as usize => json!({ "type": "read_result", "success": true, "address": hex_addr(addr), "size": size, "data": hex_bytes(&buf) }),
        _ => json!({ "type": "read_result", "success": false, "address": hex_addr(addr), "size": 0, "data": "" }),
    }
}

fn native_read_batch(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(reads) = req.get("reads").and_then(Value::as_array) else {
        return json!({ "type": "error", "code": 1002, "message": "invalid or missing arguments", "detail": "read_batch requires 'reads'" });
    };
    let results: Vec<Value> = reads
        .iter()
        .map(|r| {
            let addr = r.get("address").and_then(Value::as_str).and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
            let size = r.get("size").and_then(Value::as_u64).unwrap_or(0);
            let ok = addr.is_some() && (1..=0x10000).contains(&size);
            if !ok {
                return json!({ "success": false, "address": r.get("address").cloned().unwrap_or(Value::Null), "data": "" });
            }
            let mut buf = vec![0u8; size as usize];
            match mem.read_at(addr.unwrap(), &mut buf) {
                Ok(n) if n == size as usize => json!({ "success": true, "address": hex_addr(addr.unwrap()), "data": hex_bytes(&buf) }),
                _ => json!({ "success": false, "address": hex_addr(addr.unwrap()), "data": "" }),
            }
        })
        .collect();
    json!({ "type": "read_batch_result", "success": true, "results": results })
}

fn native_modules(mem: &impl MemIo) -> Value {
    match mem.modules() {
        Ok(mods) => {
            let list: Vec<Value> = mods
                .iter()
                .map(|(name, base, size)| json!({ "name": name, "base": hex_addr(*base), "size": size }))
                .collect();
            json!({ "type": "modules_result", "success": true, "modules": list })
        }
        Err(e) => json!({ "type": "error", "code": 1005, "message": "memory read failed", "detail": e.to_string() }),
    }
}

/// Converts an IDA-style pattern ("48 83 ?? ..") to (bytes, mask); sig_scan passes hex+mask directly.
fn parse_pattern(req: &Map<String, Value>, ida: bool) -> Option<(Vec<u8>, Vec<bool>)> {
    if ida {
        let pat = req.get("pattern")?.as_str()?;
        let toks: Vec<&str> = pat.split_whitespace().collect();
        let mut bytes = Vec::with_capacity(toks.len());
        let mut mask = Vec::with_capacity(toks.len());
        for t in toks {
            if t == "?" || t == "??" {
                bytes.push(0);
                mask.push(false);
            } else {
                bytes.push(u8::from_str_radix(t, 16).ok()?);
                mask.push(true);
            }
        }
        Some((bytes, mask))
    } else {
        let sig = req.get("sig")?.as_str()?;
        let mask = req.get("mask")?.as_str()?;
        if sig.len() % 2 != 0 || sig.len() / 2 != mask.len() {
            return None;
        }
        let bytes: Option<Vec<u8>> = (0..sig.len() / 2).map(|i| u8::from_str_radix(&sig[i * 2..i * 2 + 2], 16).ok()).collect();
        let mask: Vec<bool> = mask.chars().map(|c| c == 'x' || c == 'X').collect();
        bytes.map(|b| (b, mask))
    }
}

fn region_bounds(mem: &impl MemIo, req: &Map<String, Value>) -> (u64, u64) {
    // module restriction, else the whole readable address space
    if let Some(mod_name) = req.get("module").and_then(Value::as_str) {
        if let Ok(mods) = mem.modules() {
            if let Some((_, base, size)) = mods.iter().find(|(n, _, _)| n == mod_name) {
                return (*base, base + size);
            }
        }
    }
    (0x1000, u64::MAX >> 12 << 12)
}

fn scan_regions(mem: &impl MemIo, lo: u64, hi: u64) -> Vec<MapLine> {
    mem.maps()
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m.end > lo && m.start < hi)
        .map(|mut m| {
            m.start = m.start.max(lo);
            m.end = m.end.min(hi);
            m
        })
        .collect()
}

fn find_pattern(mem: &impl MemIo, bytes: &[u8], mask: &[bool], lo: u64, hi: u64, find_all: bool) -> Vec<u64> {
    let mut hits = Vec::new();
    if bytes.is_empty() {
        return hits;
    }
    let chunk = 0x100000usize; // 1 MiB
    for m in scan_regions(mem, lo, hi) {
        let mut pos = m.start;
        while pos + bytes.len() as u64 <= m.end {
            let want = ((m.end - pos) as usize).min(chunk + bytes.len() - 1);
            let mut buf = vec![0u8; want];
            if mem.read_at(pos, &mut buf).map(|n| n == want).unwrap_or(false) {
                for off in 0..=(want - bytes.len()) {
                    if (0..bytes.len()).all(|k| !mask[k] || buf[off + k] == bytes[k]) {
                        hits.push(pos + off as u64);
                        if !find_all {
                            return hits;
                        }
                    }
                }
            }
            pos += chunk as u64;
        }
    }
    hits
}

fn native_sig_scan(mem: &impl MemIo, req: &Map<String, Value>, ida: bool) -> Value {
    let Some((bytes, mask)) = parse_pattern(req, ida) else {
        return json!({ "type": "error", "code": 1002, "message": "invalid or missing arguments", "detail": "bad sig/mask or pattern" });
    };
    let (lo, hi) = region_bounds(mem, req);
    let find_all = req.get("find_all").and_then(Value::as_bool).unwrap_or(false);
    let results = find_pattern(mem, &bytes, &mask, lo, hi, find_all);
    let found = !results.is_empty();
    let list: Vec<Value> = results.iter().map(|a| Value::String(hex_addr(*a))).collect();
    let mut r = json!({ "type": if ida { "sig_scan_ida_result" } else { "sig_scan_result" }, "success": found, "results": list });
    if let Some(m) = r.as_object_mut() {
        if let Some(modname) = req.get("module") {
            m.insert("module".into(), modname.clone());
        }
    }
    r
}

fn native_string_scan(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(text) = req.get("text").and_then(Value::as_str) else {
        return json!({ "type": "error", "code": 1002, "message": "invalid or missing arguments", "detail": "string_scan requires 'text'" });
    };
    let (lo, hi) = region_bounds(mem, req);
    let find_all = req.get("find_all").and_then(Value::as_bool).unwrap_or(true);
    let hits = find_pattern(mem, text.as_bytes(), &vec![true; text.len()], lo, hi, find_all);
    let found = !hits.is_empty();
    let list: Vec<Value> = hits.iter().map(|a| Value::String(hex_addr(*a))).collect();
    json!({ "type": "string_scan_result", "success": found, "results": list, "text": text })
}

fn native_disassemble(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(addr) = arg_addr(req, "address") else {
        return json!({ "type": "error", "code": 1002, "message": "invalid or missing arguments", "detail": "disassemble requires 'address'" });
    };
    let size = req.get("size").and_then(Value::as_u64).unwrap_or(0).clamp(1, 1_048_576) as usize;
    let mut buf = vec![0u8; size];
    if !mem.read_at(addr, &mut buf).map(|n| n == size).unwrap_or(false) {
        return json!({ "type": "error", "code": 1005, "message": "memory read failed" });
    }
    let mut out = Vec::new();
    let mut ip = addr;
    let mut off = 0usize;
    while off < size {
        match disasm_one(&buf[off..], ip) {
            Some((len, text)) => {
                out.push(json!({ "address": hex_addr(ip), "length": len, "bytes": hex_bytes(&buf[off..off + len]), "text": text }));
                ip += len as u64;
                off += len;
            }
            None => break,
        }
    }
    json!({ "type": "disassemble_result", "success": true, "complete": off >= size, "address": hex_addr(addr), "count": out.len(), "results": out })
}

/// Decodes one x86-64 instruction at `ip`; returns (length, text). Pure Rust via iced-x86.
pub fn disasm_one(code: &[u8], ip: u64) -> Option<(usize, String)> {
    use iced_x86::{Decoder, DecoderOptions, Formatter, GasFormatter, OpKind};
    let mut dec = Decoder::with_ip(64, code, ip, DecoderOptions::NONE);
    let insn = dec.decode();
    if insn.is_invalid() {
        return None;
    }
    let len = insn.len();
    let mut text = String::new();
    let mut fmt = GasFormatter::new();
    fmt.format(&insn, &mut text);
    // annotate RIP-relative operands with their resolved target (what resolve_relative needs)
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Memory && insn.memory_base() == iced_x86::Register::RIP {
            let target = insn.ip_rel_memory_address();
            text.push_str(&format!("  ; 0x{target:x}"));
            break;
        }
    }
    Some((len, text))
}

fn native_resolve_relative(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let (Some(addr), off, size) = (
        arg_addr(req, "address"),
        req.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize,
        req.get("inst_size").and_then(Value::as_u64).unwrap_or(0) as usize,
    ) else {
        return json!({ "type": "error", "code": 1002, "message": "invalid or missing arguments", "detail": "resolve_relative requires 'address'" });
    };
    let mut buf = [0u8; 16];
    match mem.read_at(addr, &mut buf) {
        Ok(n) if n >= 1 => {}
        _ => return json!({ "type": "error", "code": 1005, "message": "memory read failed" }),
    }
    let target = resolve_rip_relative(&buf, addr, off, size);
    match target {
        Some(t) => json!({ "type": "resolve_relative_result", "success": true, "address": hex_addr(t) }),
        None => json!({ "type": "resolve_relative_result", "success": false, "address": "0x0" }),
    }
}

/// addr + inst_size + disp32 of the RIP-relative operand at `off` (default: first instruction).
pub fn resolve_rip_relative(code: &[u8], ip: u64, off: usize, inst_size: usize) -> Option<u64> {
    use iced_x86::{Decoder, DecoderOptions, OpKind};
    let mut dec = Decoder::with_ip(64, &code[off..], ip + off as u64, DecoderOptions::NONE);
    let insn = dec.decode();
    if insn.is_invalid() {
        return None;
    }
    let isz = if inst_size > 0 { inst_size } else { insn.len() };
    for i in 0..insn.op_count() {
        if insn.op_kind(i) == OpKind::Memory && insn.memory_base() == iced_x86::Register::RIP {
            return Some(insn.ip_rel_memory_address());
        }
    }
    let _ = isz;
    None
}

fn native_functions(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let module = req.get("module").and_then(Value::as_str).unwrap_or("");
    let mods = mem.modules().unwrap_or_default();
    let picked = if module.is_empty() { mods.iter().max_by_key(|(_, _, s)| *s).cloned() } else { mods.iter().find(|(n, _, _)| *n == module || n.ends_with(module) || n.rsplit('/').next() == Some(module)).cloned() };
    let Some((name, base, size)) = picked else {
        return json!({ "type": "error", "code": 1003, "message": "module not found", "detail": module });
    };
    let Some(line) = mem.maps().ok().and_then(|maps| maps.iter().find(|m| m.path.contains(name.as_str())).cloned()) else {
        return json!({ "type": "error", "code": 1006, "message": "function enumeration failed" });
    };
    match functions_in_file(&line.path, base, size) {
        Ok(funcs) => json!({ "type": "enumerate_functions_result", "success": true, "module": name, "count": funcs.len(),
            "results": funcs.iter().map(|(a, s)| json!({ "address": hex_addr(*a), "size": s, "method": 0 })).collect::<Vec<_>>() }),
        Err(e) => json!({ "type": "error", "code": 1006, "message": "function enumeration failed", "detail": e }),
    }
}

/// ELF symbol table (.symtab + .dynsym) functions inside [base, base+size). Best-effort preview data.
pub fn functions_in_file(path: &str, base: u64, size: u64) -> Result<Vec<(u64, u64)>, String> {
    use object::{Object, ObjectSymbol};
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let file = object::File::parse(&*data).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    let push = |sym: object::Symbol, out: &mut Vec<(u64, u64)>| {
        if sym.kind() == object::SymbolKind::Text {
            let addr = sym.address();
            if addr >= base && addr < base + size {
                out.push((addr, sym.size().max(1)));
            }
        }
    };
    for sym in file.symbols() {
        push(sym, &mut out);
    }
    for sym in file.dynamic_symbols() {
        push(sym, &mut out);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Ext verbs
// ---------------------------------------------------------------------------------------------

fn local_attach(relay: &Relay, req: &Map<String, Value>, orig: &Value) -> Value {
    let pid = match (req.get("pid").and_then(Value::as_u64), req.get("name").and_then(Value::as_str)) {
        (Some(p), _) if p > 0 => Some(p as u32),
        (_, Some(name)) => find_pid_by_name(name),
        _ => None,
    };
    let Some(pid) = pid.and_then(|p| ProcIo::open(p).ok().map(|_| p)) else {
        return err(orig, 3003, "attach failed", "process not found");
    };
    {
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        *g = Some(LocalState { pid, scan: None });
    }
    relay.broadcast_status();
    let mem = io(pid).unwrap();
    let base = modules_base(&mem);
    let name = req.get("name").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(|| {
        mem.modules().ok().and_then(|m| m.iter().max_by_key(|(_, _, s)| *s).map(|(n, _, _)| n.clone())).unwrap_or_default()
    });
    json!({ "type": "attach_result", "id": orig, "success": true, "pid": pid, "base": base, "name": name, "native_socket": false })
}

fn local_detach(relay: &Relay, orig: &Value) -> Value {
    {
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        *g = None;
    }
    relay.broadcast_status();
    json!({ "type": "detach_result", "id": orig, "success": true })
}

fn find_pid_by_name(name: &str) -> Option<u32> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    sys.processes()
        .values()
        .find(|p| p.name().to_string_lossy().eq_ignore_ascii_case(name))
        .map(|p| p.pid().as_u32())
}

fn ext_write(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let (Some(addr), Some(data)) = (arg_addr(req, "address"), req.get("data").and_then(Value::as_str)) else {
        return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "write requires 'address' and 'data'" });
    };
    let bytes: Option<Vec<u8>> = (0..data.len() / 2).map(|i| u8::from_str_radix(&data[i * 2..i * 2 + 2], 16).ok()).collect();
    let Some(bytes) = bytes.filter(|b| !b.is_empty() && b.len() <= 0x100000) else {
        return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "data must be non-empty hex, max 1 MiB" });
    };
    match mem.write_at(addr, &bytes) {
        Ok(()) => {
            let m = region_of(mem, addr);
            json!({ "type": "write_result", "success": true, "written": bytes.len(), "region": m })
        }
        Err(e) => json!({ "type": "error", "code": 3003, "message": "write failed", "detail": format!("{addr:#x}: {e}") }),
    }
}

fn region_of(mem: &impl MemIo, addr: u64) -> Value {
    let maps = mem.maps().unwrap_or_default();
    for m in &maps {
        if addr >= m.start && addr < m.end {
            return json!({ "base": hex_addr(m.start), "size": m.end - m.start, "present": true, "writable": m.writable, "executable": m.executable });
        }
    }
    json!({ "base": hex_addr(addr & !0xfff), "size": 0, "present": false, "writable": false, "executable": false })
}

fn ext_query(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    match arg_addr(req, "address") {
        Some(a) => json!({ "type": "query_result", "success": true, "region": region_of(mem, a) }),
        None => json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "query requires 'address'" }),
    }
}

fn ext_regions(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let lo = arg_addr(req, "start").unwrap_or(0x1000);
    let hi = arg_addr(req, "end").unwrap_or(u64::MAX >> 12 << 12);
    let max = req.get("max").and_then(Value::as_u64).unwrap_or(20000).min(200_000) as usize;
    let present_only = req.get("present_only").and_then(Value::as_bool).unwrap_or(true);
    let maps = mem.maps().unwrap_or_default();
    let mut regions = Vec::new();
    let mut truncated = false;
    for m in &maps {
        if m.end <= lo || m.start >= hi || (present_only && m.path.is_empty() && false) {
            continue;
        }
        if regions.len() >= max {
            truncated = true;
            break;
        }
        regions.push(json!({ "base": hex_addr(m.start.max(lo)), "size": m.end.min(hi) - m.start.max(lo), "present": true, "writable": m.writable, "executable": m.executable }));
    }
    json!({ "type": "regions_result", "success": true, "regions": regions, "truncated": truncated })
}

fn ext_chain(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let (Some(base), Some(offs)) = (arg_addr(req, "base"), req.get("offsets").and_then(Value::as_array)) else {
        return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "chain requires 'base' and 'offsets'" });
    };
    let mut hops = Vec::new();
    let mut cur = base;
    let mut ok = true;
    for o in offs.iter().take(64) {
        let off = match o {
            Value::Number(n) => n.as_i64().unwrap_or(0),
            Value::String(s) => s.parse::<i64>().unwrap_or(0),
            _ => 0,
        };
        let mut buf = [0u8; 8];
        let rd = mem.read_at(cur, &mut buf).map(|n| n == 8).unwrap_or(false);
        let value = u64::from_le_bytes(buf);
        hops.push(json!({ "address": hex_addr(cur), "value": hex_addr(value) }));
        if !rd || value == 0 {
            ok = false;
            break;
        }
        cur = value.wrapping_add(off as u64);
    }
    json!({ "type": "chain_result", "success": true, "hops": hops, "final": hex_addr(cur), "ok": ok })
}

fn ext_read_typed(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let (Some(addr), Some(vt)) = (arg_addr(req, "address"), req.get("type").and_then(Value::as_str)) else {
        return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "read_typed requires 'address' and 'type'" });
    };
    let width = match vt {
        "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" => 8,
        _ => 0,
    };
    if width > 0 {
        let mut buf = vec![0u8; width];
        if !mem.read_at(addr, &mut buf).map(|n| n == width).unwrap_or(false) {
            return json!({ "type": "read_typed_result", "success": true, "ok": false, "address": hex_addr(addr), "type": vt });
        }
        let mut bits = 0u64;
        for (i, b) in buf.iter().enumerate() {
            bits |= (*b as u64) << (8 * i);
        }
        let value = match vt {
            "f32" => format!("{}", f32::from_bits(bits as u32)),
            "f64" => format!("{}", f64::from_bits(bits)),
            "i8" | "i16" | "i32" | "i64" => format!("{}", sign_extend(bits, width)),
            _ => format!("{bits}"),
        };
        return json!({ "type": "read_typed_result", "success": true, "ok": true, "address": hex_addr(addr), "type": vt, "value": value, "raw": hex_bytes(&buf) });
    }
    let n = match vt {
        "string" => 256usize,
        "wstring" => 1024,
        "bytes" => req.get("length").and_then(Value::as_u64).unwrap_or(16).clamp(1, 4096) as usize,
        _ => return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": format!("unknown type: {vt}") }),
    };
    let mut buf = vec![0u8; n];
    if !mem.read_at(addr, &mut buf).map(|x| x == n).unwrap_or(false) {
        return json!({ "type": "read_typed_result", "success": true, "ok": false, "address": hex_addr(addr), "type": vt });
    }
    match vt {
        "string" => {
            let k = buf.iter().position(|&b| b == 0).unwrap_or(n);
            json!({ "type": "read_typed_result", "success": true, "ok": true, "address": hex_addr(addr), "type": vt, "value": String::from_utf8_lossy(&buf[..k]), "raw": hex_bytes(&buf[..k]) })
        }
        "wstring" => {
            let mut k = 0;
            while k + 1 < n && (buf[k] != 0 || buf[k + 1] != 0) {
                k += 2;
            }
            let wide: Vec<u16> = buf[..k].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            json!({ "type": "read_typed_result", "success": true, "ok": true, "address": hex_addr(addr), "type": vt, "value": String::from_utf16_lossy(&wide), "raw": hex_bytes(&buf[..k]) })
        }
        _ => json!({ "type": "read_typed_result", "success": true, "ok": true, "address": hex_addr(addr), "type": vt, "value": hex_bytes(&buf) }),
    }
}

fn sign_extend(bits: u64, width: usize) -> i64 {
    let shift = 64 - width * 8;
    ((bits << shift) as i64) >> shift
}

fn ext_region_stats(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let lo = arg_addr(req, "start").unwrap_or(0x1000);
    let hi = arg_addr(req, "end").unwrap_or(u64::MAX >> 12 << 12);
    let maps = mem.maps().unwrap_or_default();
    let (mut n, mut nw, mut nx, mut np, mut bnp, mut bnw, mut bnx) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for m in &maps {
        if m.end <= lo || m.start >= hi {
            continue;
        }
        n += 1;
        np += 1;
        bnp += m.end - m.start;
        if m.writable {
            nw += 1;
            bnw += m.end - m.start;
        }
        if m.executable {
            nx += 1;
            bnx += m.end - m.start;
        }
    }
    json!({ "type": "region_stats_result", "success": true, "regions": n, "present": np, "writable": nw, "executable": nx,
        "rw_regions": maps.iter().filter(|m| m.writable && !m.executable).count(),
        "rx_regions": maps.iter().filter(|m| m.executable && !m.writable).count(),
        "present_bytes": bnp, "writable_bytes": bnw, "executable_bytes": bnx, "truncated": false })
}

fn ext_dump(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let fname = req.get("filename").and_then(Value::as_str).unwrap_or("");
    if fname.is_empty() || fname.contains('/') || fname.contains("\\") || fname.contains(':') || fname.contains("..") {
        return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "filename must be a flat name" });
    }
    let module = req.get("module").and_then(Value::as_str);
    let (base, size) = match module {
        Some(m) if !m.is_empty() => match mem.modules().ok().and_then(|v| v.into_iter().find(|(n, _, _)| n == m)) {
            Some((_, b, s)) => (b, s),
            None => return json!({ "type": "error", "code": 3003, "message": "dump failed", "detail": format!("module not found: {m}") }),
        },
        _ => match mem.modules().ok().and_then(|v| v.into_iter().max_by_key(|(_, _, s)| *s)) {
            Some((_, b, s)) => (b, s),
            None => return json!({ "type": "error", "code": 3003, "message": "dump failed", "detail": "no modules" }),
        },
    };
    let size = size.min(0x10000000); // 256 MiB cap
    let mut buf = vec![0u8; size as usize];
    match mem.read_at(base, &mut buf) {
        Ok(n) if n == size as usize => {
            let dir = dirs_home().join("EchoDebug").join("dmp");
            let path = dir.join(fname);
            match std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&path, &buf)) {
                Ok(()) => json!({ "type": "dump_result", "success": true, "path": path.display().to_string() }),
                Err(e) => json!({ "type": "error", "code": 3003, "message": "dump failed", "detail": e.to_string() }),
            }
        }
        _ => json!({ "type": "error", "code": 3003, "message": "dump failed", "detail": "read failed" }),
    }
}

fn dirs_home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(Into::into)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

// ---------------------------------------------------------------------------------------------
// Value scanner (generic, in-memory candidate list)
// ---------------------------------------------------------------------------------------------

const SCAN_CAP: usize = 4_000_000;
const SCAN_CHUNK: u64 = 0x100000;

fn vt_width(vt: &str) -> usize {
    match vt {
        "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" => 8,
        _ => 0,
    }
}

fn parse_num_target(req: &Map<String, Value>, k: &str, vt: &str) -> Option<(u64, f64)> {
    let v = req.get(k)?;
    let width = vt_width(vt).max(1);
    match v {
        Value::Number(n) => {
            let d = n.as_f64()?;
            if vt == "f32" || vt == "f64" {
                return Some((0, d));
            }
            let bits = if d < 0.0 { sign_extend(((-d) as u64).wrapping_neg(), width) as u64 } else { d as u64 };
            Some((bits & mask_for(width), d))
        }
        Value::String(s) => {
            let t = s.trim();
            if vt == "f32" || vt == "f64" {
                return t.parse::<f64>().ok().map(|d| (0, d));
            }
            let (neg, mag) = match t.strip_prefix('-') {
                Some(r) => (true, u64::from_str_radix(r.trim_start_matches("0x"), if r.starts_with("0x") { 16 } else { 10 }).ok()?),
                None => (false, u64::from_str_radix(t.trim_start_matches("0x"), if t.starts_with("0x") { 16 } else { 10 }).ok()?),
            };
            let bits = if neg { (!mag + 1) & mask_for(width) } else { mag & mask_for(width) };
            Some((bits, 0.0))
        }
        _ => None,
    }
}

fn mask_for(width: usize) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (width * 8)) - 1
    }
}

fn pattern_target(req: &Map<String, Value>, k: &str, vt: &str) -> Option<Vec<u8>> {
    let s = req.get(k)?.as_str()?;
    match vt {
        "bytes" => {
            let b: Option<Vec<u8>> = (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect();
            b.filter(|b| !b.is_empty() && b.len() <= 256)
        }
        "wstring" => Some(s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()),
        "string" => Some(s.as_bytes().to_vec()).filter(|b| !b.is_empty() && b.len() <= 256),
        _ => None,
    }
}

fn int_key(signed: bool, width: usize, bits: u64) -> u64 {
    if !signed {
        return bits;
    }
    let mut b = bits;
    if width < 8 {
        let sb = 1u64 << (width * 8 - 1);
        if b & sb != 0 {
            b |= !((sb << 1) - 1);
        }
    }
    b ^ 0x8000000000000000
}

#[allow(clippy::too_many_arguments)]
fn test_num(op: &str, vt: &str, width: usize, cur: u64, prev: u64, t1: u64, t2: u64, f1: f64, f2: f64, eps: f64) -> bool {
    let signed = matches!(vt, "i8" | "i16" | "i32" | "i64");
    match op {
        "changed" => return cur != prev,
        "unchanged" => return cur == prev,
        _ => {}
    }
    if vt == "f32" || vt == "f64" {
        let c = if vt == "f32" { f32::from_bits(cur as u32) as f64 } else { f64::from_bits(cur) };
        let p = if vt == "f32" { f32::from_bits(prev as u32) as f64 } else { f64::from_bits(prev) };
        return match op {
            "exact" => (c - f1).abs() <= eps,
            "greater" => c > f1,
            "less" => c < f1,
            "between" => c >= f1 && c <= f2,
            "increased" => c > p,
            "decreased" => c < p,
            _ => false,
        };
    }
    let k = int_key(signed, width, cur);
    let t1k = int_key(signed, width, t1);
    let t2k = int_key(signed, width, t2);
    match op {
        "exact" => k == t1k,
        "greater" => k > t1k,
        "less" => k < t1k,
        "between" => k >= t1k.min(t2k) && k <= t1k.max(t2k),
        "increased" => k > int_key(signed, width, prev),
        "decreased" => k < int_key(signed, width, prev),
        _ => false,
    }
}

fn scan_range(mem: &impl MemIo, lo: u64, hi: u64, writable_only: bool) -> Vec<MapLine> {
    scan_regions(mem, lo, hi)
        .into_iter()
        .filter(|m| !writable_only || m.writable)
        .collect()
}

fn ext_scan_new(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let vt = req.get("value_type").and_then(Value::as_str).unwrap_or("");
    let op = req.get("compare").and_then(Value::as_str).unwrap_or("exact");
    let width = vt_width(vt);
    let pattern = if matches!(vt, "bytes" | "string" | "wstring") {
        pattern_target(req, "value", vt)
    } else {
        None
    };
    if width == 0 && pattern.is_none() {
        return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": format!("unknown value_type: {vt}") });
    }
    let width = match &pattern { Some(p) => p.len(), None => width };
    let (raw1, f1) = if pattern.is_none() { parse_num_target(req, "value", vt).unwrap_or((0, 0.0)) } else { (0, 0.0) };
    let (_, f2raw) = parse_num_target(req, "value2", vt).unwrap_or((0, 0.0));
    let (t2raw, f2) = if op == "between" { parse_num_target(req, "value2", vt).unwrap_or((0, 0.0)) } else { (0, f2raw) };
    let eps = req.get("float_epsilon").and_then(Value::as_f64).unwrap_or(0.0001).max(0.0);
    let writable_only = req.get("writable_only").and_then(Value::as_bool).unwrap_or(true);
    let (lo, hi) = region_bounds(mem, req);
    let align = req.get("alignment").and_then(Value::as_u64).unwrap_or(width.max(1) as u64).max(1);

    let mut st = LocalScan {
        vtype: vt.to_string(),
        width,
        op: op.to_string(),
        f1,
        f2,
        raw1,
        t1: raw1,
        t2: t2raw,
        pattern: pattern.clone().unwrap_or_default(),
        addrs: Vec::new(),
        prev_bits: Vec::new(),
        prev_raw: Vec::new(),
        truncated: false,
    };
    let is_pattern = !st.pattern.is_empty();
    for m in scan_range(mem, lo, hi, writable_only) {
        let mut pos = m.start;
        while pos + width as u64 <= m.end {
            let core = (m.end - pos).min(SCAN_CHUNK) as usize;
            let want = (core + width - 1).min((m.end - pos) as usize);
            let mut buf = vec![0u8; want];
            if !mem.read_at(pos, &mut buf).map(|n| n == want).unwrap_or(false) {
                pos += SCAN_CHUNK;
                continue;
            }
            let limit = want - width + 1;
            let first = (align - pos % align) % align;
            let mut o = first as usize;
            while o < limit {
                let a = pos + o as u64;
                let hit = if is_pattern {
                    buf[o..o + width] == st.pattern[..]
                } else {
                    let mut bits = 0u64;
                    for k in 0..width {
                        bits |= (buf[o + k] as u64) << (8 * k);
                    }
                    test_num(&st.op, &st.vtype, width, bits, 0, st.t1, st.t2, st.f1, st.f2, eps)
                        || st.op == "unknown"
                };
                if hit {
                    st.addrs.push(a);
                    if is_pattern {
                        st.prev_raw.extend_from_slice(&buf[o..o + width]);
                    } else {
                        let mut bits = 0u64;
                        for k in 0..width {
                            bits |= (buf[o + k] as u64) << (8 * k);
                        }
                        st.prev_bits.push(bits);
                    }
                    if st.addrs.len() >= SCAN_CAP {
                        st.truncated = true;
                        break;
                    }
                }
                o += align as usize;
            }
            if st.truncated {
                break;
            }
            pos += SCAN_CHUNK;
        }
        if st.truncated {
            break;
        }
    }
    let count = st.addrs.len();
    let sample: Vec<Value> = st
        .addrs
        .iter()
        .take(200)
        .enumerate()
        .map(|(i, a)| {
            let value = if is_pattern {
                hex_bytes(&st.prev_raw[i * width..(i + 1) * width])
            } else {
                let bits = st.prev_bits[i];
                hex_bytes(&bits.to_le_bytes()[..width])
            };
            json!({ "address": hex_addr(*a), "value": value })
        })
        .collect();
    with_state(|s| s.scan = Some(st));
    json!({ "type": "scan_new_result", "success": true, "count": count, "sample": sample, "truncated": st_truncated() })
}

fn st_truncated() -> bool {
    with_state(|s| s.scan.as_ref().map(|x| x.truncated).unwrap_or(false)).unwrap_or(false)
}

fn ext_scan_next(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let op = req.get("compare").and_then(Value::as_str).unwrap_or("");
    let addrs = with_state(|s| s.scan.as_ref().map(|x| (x.addrs.clone(), x.prev_bits.clone(), x.prev_raw.clone(), x.vtype.clone(), x.width, x.pattern.clone(), x.f1, x.f2, x.t1, x.t2))).flatten();
    let Some((old_addrs, old_bits, old_raw, vt, width, pattern, f1, f2, t1, t2)) = addrs else {
        return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "no active scan; run scan_new first" });
    };
    let eps = req.get("float_epsilon").and_then(Value::as_f64).unwrap_or(0.0001).max(0.0);
    let is_pattern = !pattern.is_empty();
    let (raw1, nf1) = if is_pattern { (0, f1) } else { parse_num_target(req, "value", &vt).unwrap_or((t1, f1)) };
    let (t2n, f2n) = if op == "between" { parse_num_target(req, "value2", &vt).unwrap_or((t2, f2)) } else { (t2, f2) };

    let mut st = LocalScan {
        vtype: vt.clone(),
        width,
        op: op.to_string(),
        f1: nf1,
        f2: f2n,
        raw1,
        t1: raw1,
        t2: t2n,
        pattern: pattern.clone(),
        addrs: Vec::new(),
        prev_bits: Vec::new(),
        prev_raw: Vec::new(),
        truncated: false,
    };
    let mut buf = vec![0u8; width.max(1)];
    for (i, a) in old_addrs.iter().enumerate() {
        if is_pattern {
            if !mem.read_at(*a, &mut buf).map(|n| n == width).unwrap_or(false) {
                continue;
            }
            let cur = buf.clone();
            let eq = if op == "exact" && !pattern.is_empty() {
                cur == pattern
            } else {
                cur == old_raw[i * width..(i + 1) * width]
            };
            let keep = match op {
                "exact" => eq,
                "changed" => !eq,
                "unchanged" => eq,
                _ => false,
            };
            if keep {
                st.addrs.push(*a);
                st.prev_raw.extend_from_slice(&cur);
                if st.addrs.len() >= SCAN_CAP {
                    st.truncated = true;
                    break;
                }
            }
        } else {
            if !mem.read_at(*a, &mut buf).map(|n| n == width).unwrap_or(false) {
                continue;
            }
            let mut bits = 0u64;
            for (k, b) in buf[..width].iter().enumerate() {
                bits |= (*b as u64) << (8 * k);
            }
            if test_num(op, &vt, width, bits, old_bits[i], st.t1, st.t2, st.f1, st.f2, eps) {
                st.addrs.push(*a);
                st.prev_bits.push(bits);
                if st.addrs.len() >= SCAN_CAP {
                    st.truncated = true;
                    break;
                }
            }
        }
    }
    let count = st.addrs.len();
    let sample: Vec<Value> = st
        .addrs
        .iter()
        .take(200)
        .enumerate()
        .map(|(i, a)| {
            let value = if is_pattern {
                hex_bytes(&st.prev_raw[i * width..(i + 1) * width])
            } else {
                hex_bytes(&st.prev_bits[i].to_le_bytes()[..width])
            };
            json!({ "address": hex_addr(*a), "value": value })
        })
        .collect();
    let trunc = st.truncated;
    with_state(|s| s.scan = Some(st));
    json!({ "type": "scan_next_result", "success": true, "count": count, "sample": sample, "truncated": trunc })
}

fn ext_scan_results(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let off = req.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
    let lim = req.get("limit").and_then(Value::as_u64).unwrap_or(100).min(2000) as usize;
    let data = with_state(|s| s.scan.as_ref().map(|x| (x.addrs.clone(), x.prev_bits.clone(), x.prev_raw.clone(), x.width, !x.pattern.is_empty()))).flatten();
    let Some((addrs, bits, raw, width, is_pattern)) = data else {
        return json!({ "type": "scan_results_result", "success": true, "count": 0, "results": [] });
    };
    let mut results = Vec::new();
    for (i, a) in addrs.iter().enumerate().skip(off).take(lim) {
        let mut buf = vec![0u8; width];
        let cur = mem.read_at(*a, &mut buf).map(|n| n == width).unwrap_or(false);
        results.push(json!({
            "address": hex_addr(*a),
            "value": if cur { hex_bytes(&buf) } else { String::new() },
            "previous": if is_pattern { hex_bytes(&raw[i * width..(i + 1) * width]) } else { hex_bytes(&bits[i].to_le_bytes()[..width]) },
        }));
    }
    json!({ "type": "scan_results_result", "success": true, "count": addrs.len(), "results": results })
}

fn ext_scan_clear() -> Value {
    with_state(|s| s.scan = None);
    json!({ "type": "scan_clear_result", "success": true })
}

// ---------------------------------------------------------------------------------------------
// Tests (in-memory MemIo, run on any OS)
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex as StdMutex;

    struct FakeMem {
        data: StdMutex<BTreeMap<u64, u8>>, // sparse bytes
    }
    impl FakeMem {
        fn new() -> Self {
            FakeMem { data: StdMutex::new(BTreeMap::new()) }
        }
        fn put(&self, addr: u64, bytes: &[u8]) {
            let mut d = self.data.lock().unwrap();
            for (i, b) in bytes.iter().enumerate() {
                d.insert(addr + i as u64, *b);
            }
        }
    }
    impl MemIo for FakeMem {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            let d = self.data.lock().unwrap();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = d.get(&(addr + i as u64)).copied().unwrap_or(0);
            }
            Ok(buf.len())
        }
        fn write_at(&self, addr: u64, buf: &[u8]) -> io::Result<()> {
            self.put(addr, buf);
            Ok(())
        }
        fn maps(&self) -> io::Result<Vec<MapLine>> {
            Ok(vec![MapLine { start: 0x1000, end: 0x5000, writable: true, executable: false, path: "/fake/a.out".into() }])
        }
        fn alive(&self) -> bool {
            true
        }
    }

    #[test]
    fn maps_parser() {
        let maps = parse_maps("7f0a1b2c000-7f0a1b2d000 r-xp 00000000 08:01 1234    /usr/lib/x.so\n7ffd-7fff rw-p 0 00:00 0 \n");
        assert_eq!(maps.len(), 2);
        assert_eq!(maps[0].start, 0x7f0a1b2c000);
        assert!(maps[0].executable && !maps[0].writable);
        assert_eq!(maps[0].path, "/usr/lib/x.so");
        assert!(maps[1].writable && maps[1].path.is_empty());
    }

    #[test]
    fn pattern_parsing() {
        let req = |v: Value| match v { Value::Object(m) => m, _ => unreachable!() };
        let m = req(json!({ "sig": "4883ec", "mask": "xxx" }));
        let (b, mask) = parse_pattern(&m, false).unwrap();
        assert_eq!(b, vec![0x48, 0x83, 0xec]);
        assert_eq!(mask, vec![true, true, true]);
        let m = req(json!({ "pattern": "48 83 ?? 28" }));
        let (b, mask) = parse_pattern(&m, true).unwrap();
        assert_eq!(b.len(), 4);
        assert_eq!(mask, vec![true, true, false, true]);
    }

    #[test]
    fn find_pattern_hits() {
        let mem = FakeMem::new();
        mem.put(0x1000, &[0x90, 0x48, 0x83, 0xec, 0x28, 0x90]);
        mem.put(0x2000, &[0x48, 0x83, 0xec, 0x28]);
        let hits = find_pattern(&mem, &[0x48, 0x83, 0xec, 0x28], &[true; 4], 0x1000, 0x5000, true);
        assert_eq!(hits, vec![0x1001, 0x2000]);
        let one = find_pattern(&mem, &[0x48, 0x83], &[true; 2], 0x1000, 0x5000, false);
        assert_eq!(one, vec![0x1001]);
    }

    #[test]
    fn disasm_and_relative() {
        // sub rsp, 0x28 ; call qword ptr [rip+0x10]
        let code = [0x48u8, 0x83, 0xec, 0x28, 0xff, 0x15, 0x10, 0x00, 0x00, 0x00];
        let (len, text) = disasm_one(&code, 0x1000).unwrap();
        assert_eq!(len, 4);
        assert!(text.contains("rsp"));
        let target = resolve_rip_relative(&code, 0x1000, 4, 6).unwrap();
        assert_eq!(target, 0x1000 + 4 + 6 + 0x10);
    }

    #[test]
    fn scanner_numeric() {
        let mem = FakeMem::new();
        mem.put(0x1000, &42u32.to_le_bytes());
        mem.put(0x1004, &7u32.to_le_bytes());
        mem.put(0x1008, &99u32.to_le_bytes());
        *STATE.lock().unwrap() = Some(LocalState { pid: 1, scan: None });
        let req = match json!({ "value_type": "u32", "compare": "exact", "value": 42 }) { Value::Object(m) => m, _ => unreachable!() };
        let r = ext_scan_new(&mem, &req);
        assert_eq!(r["count"], 1);
        assert_eq!(r["sample"][0]["address"], "0x1000");

        // unknown first scan captures all aligned u32s, then "changed" narrows after a mutation
        *STATE.lock().unwrap() = Some(LocalState { pid: 1, scan: None });
        let req = match json!({ "value_type": "u32", "compare": "unknown" }) { Value::Object(m) => m, _ => unreachable!() };
        let r = ext_scan_new(&mem, &req);
        assert_eq!(r["count"], 4096, "{r}");
        mem.put(0x1004, &8u32.to_le_bytes());
        let req = match json!({ "compare": "changed" }) { Value::Object(m) => m, _ => unreachable!() };
        let r = ext_scan_next(&mem, &req);
        assert_eq!(r["count"], 1, "{r}");
        assert_eq!(r["sample"][0]["address"], "0x1004");
        let r = ext_scan_results(&mem, &match json!({ "offset": 0, "limit": 10 }) { Value::Object(m) => m, _ => unreachable!() });
        assert_eq!(r["count"], 1);
        assert_eq!(r["results"][0]["value"], hex_bytes(&8u32.to_le_bytes()));
        assert_eq!(r["results"][0]["previous"], hex_bytes(&8u32.to_le_bytes()), "previous = value at the last scan");
    }

    #[test]
    fn int_ordering_keys() {
        assert!(int_key(true, 4, 0xffffffff) < int_key(true, 4, 0));
        assert_eq!(int_key(false, 4, 5), 5);
        assert_eq!(sign_extend(0xffff, 2), -1);
        assert_eq!(mask_for(1), 0xff);
    }
}
