//! Local-backend versions of the verbs that used to need the Windows agent: freeze and watch
//! (one 20 Hz ticker per attach), pointer scan, ELF export lookup, the dynamic loader's
//! `r_debug`/`link_map` walk (the Linux counterpart of the PEB walk), Itanium C++ ABI type info
//! (GCC/Clang's RTTI) and raw module-file reads for the ELF browser.
//!
//! All logic runs against `MemIo`, so the tests use an in-memory process.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::local::{arg_addr, attached_pid, hex_addr, hex_bytes, io, MapLine, MemIo};
use crate::Relay;

fn bad(detail: &str) -> Value {
    json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": detail })
}

fn failed(detail: impl Into<String>) -> Value {
    json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": detail.into() })
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

fn read_vec(mem: &impl MemIo, addr: u64, n: usize) -> Option<Vec<u8>> {
    let mut b = vec![0u8; n];
    mem.read_at(addr, &mut b).ok().filter(|&k| k == n).map(|_| b)
}

pub(crate) fn read_u64(mem: &impl MemIo, addr: u64) -> Option<u64> {
    read_vec(mem, addr, 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

fn read_u32(mem: &impl MemIo, addr: u64) -> Option<u32> {
    read_vec(mem, addr, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_cstr(mem: &impl MemIo, addr: u64, max: usize) -> Option<String> {
    let mut out = Vec::new();
    let mut a = addr;
    while out.len() < max {
        let chunk = read_vec(mem, a, 64).or_else(|| read_vec(mem, a, 1))?;
        let k = chunk.len();
        if let Some(z) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..z]);
            return Some(String::from_utf8_lossy(&out).into_owned());
        }
        out.extend_from_slice(&chunk);
        a = a.wrapping_add(k as u64);
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

// ---------------------------------------------------------------------------------------------
// Freeze + watch
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Frozen {
    addr: u64,
    data: Vec<u8>,
    before: Vec<u8>,
    /// "set" (write data), "add" (value += step per second), "clamp" (keep within min..max)
    mode: String,
    vtype: String,
    step: f64,
    min: f64,
    max: f64,
    group: String,
    paused: bool,
}

#[derive(Clone)]
struct Watched {
    addr: u64,
    size: usize,
    label: String,
    last: Vec<u8>,
    vtype: String,
    cond: String,
    value: f64,
    hits: u64,
    history: Vec<String>,
}

#[derive(Default)]
struct Live {
    frozen: Vec<Frozen>,
    watched: Vec<Watched>,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);
static TICKER_GEN: AtomicU64 = AtomicU64::new(0);

fn with_live<R>(f: impl FnOnce(&mut Live) -> R) -> R {
    let mut g = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Live::default))
}

/// Byte width of a numeric value type (0 = not numeric).
pub(crate) fn vt_width(vt: &str) -> usize {
    match vt {
        "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" => 8,
        _ => 0,
    }
}

pub(crate) fn num_decode(vt: &str, b: &[u8]) -> Option<f64> {
    let w = vt_width(vt);
    if w == 0 || b.len() < w {
        return None;
    }
    let mut x = [0u8; 8];
    x[..w].copy_from_slice(&b[..w]);
    let u = u64::from_le_bytes(x);
    Some(match vt {
        "f32" => f32::from_bits(u as u32) as f64,
        "f64" => f64::from_bits(u),
        v if v.starts_with('i') => (((u << (64 - w * 8)) as i64) >> (64 - w * 8)) as f64,
        _ => u as f64,
    })
}

pub(crate) fn num_encode(vt: &str, v: f64) -> Vec<u8> {
    match vt {
        "f32" => (v as f32).to_le_bytes().to_vec(),
        "f64" => v.to_le_bytes().to_vec(),
        "u8" | "i8" => vec![(v as i64) as u8],
        "u16" | "i16" => ((v as i64) as u16).to_le_bytes().to_vec(),
        "u32" | "i32" => ((v as i64) as u32).to_le_bytes().to_vec(),
        "u64" => (v as u64).to_le_bytes().to_vec(),
        _ => (v as i64).to_le_bytes().to_vec(),
    }
}

/// Starts the 20 Hz ticker that rewrites frozen values and samples watches (10 Hz).
pub fn start_ticker(relay: &Relay, pid: u32) {
    with_live(|l| *l = Live::default());
    let gen = TICKER_GEN.fetch_add(1, Ordering::SeqCst) + 1;
    let relay = relay.clone();
    let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
    handle.spawn(async move {
        let mut n: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if TICKER_GEN.load(Ordering::SeqCst) != gen || attached_pid() != Some(pid) {
                break;
            }
            let Some(mem) = io(pid) else { break };
            n += 1;
            for ev in tick_n(&mem, n) {
                relay.emit(ev);
            }
        }
    });
}

pub fn stop_ticker() {
    TICKER_GEN.fetch_add(1, Ordering::SeqCst);
}

/// One ticker step; returns the events to broadcast. Public for tests.
pub fn tick(mem: &impl MemIo, sample: bool) -> Vec<Value> {
    tick_n(mem, if sample { 20 } else { 1 })
}

fn tick_n(mem: &impl MemIo, n: u64) -> Vec<Value> {
    let (frozen, watched) = with_live(|l| (l.frozen.clone(), l.watched.clone()));
    let mut events = Vec::new();
    for f in frozen.iter().filter(|f| !f.paused) {
        let res = match f.mode.as_str() {
            "set" => mem.write_at(f.addr, &f.data),
            _ => match read_vec(mem, f.addr, vt_width(&f.vtype)).and_then(|b| num_decode(&f.vtype, &b)) {
                Some(v) => {
                    let nv = if f.mode == "add" { if n.is_multiple_of(20) { v + f.step } else { v } } else { v.clamp(f.min.min(f.max), f.max.max(f.min)) };
                    if nv != v { mem.write_at(f.addr, &num_encode(&f.vtype, nv)) } else { Ok(()) }
                }
                None => Err(std::io::Error::other("unreadable")),
            },
        };
        if res.is_err() {
            events.push(json!({ "type": "event", "event": "freeze_error", "address": hex_addr(f.addr) }));
        }
    }
    if n.is_multiple_of(2) {
        let mut updates = Vec::new();
        for w in &watched {
            let Some(cur) = read_vec(mem, w.addr, w.size) else { continue };
            if cur == w.last {
                continue;
            }
            let (ov, nv) = (num_decode(&w.vtype, &w.last), num_decode(&w.vtype, &cur));
            let fire = match (w.cond.as_str(), ov, nv) {
                ("any", ..) => true,
                ("eq", _, Some(v)) => v == w.value,
                ("ne", _, Some(v)) => v != w.value,
                ("gt", _, Some(v)) => v > w.value,
                ("lt", _, Some(v)) => v < w.value,
                ("delta", Some(o), Some(v)) => (v - o).abs() >= w.value,
                _ => true,
            };
            if fire {
                let mut ev = json!({ "type": "event", "event": "watch_event", "address": hex_addr(w.addr), "old": hex_bytes(&w.last), "new": hex_bytes(&cur), "hits": w.hits + 1 });
                if !w.label.is_empty() {
                    ev["label"] = json!(w.label);
                }
                if let (Some(o), Some(v)) = (ov, nv) {
                    ev["old_value"] = json!(o);
                    ev["new_value"] = json!(v);
                    ev["value_type"] = json!(w.vtype);
                }
                events.push(ev);
            }
            updates.push((w.addr, cur, fire));
        }
        with_live(|l| {
            for (a, cur, fire) in updates {
                if let Some(w) = l.watched.iter_mut().find(|w| w.addr == a) {
                    w.history.push(hex_bytes(&cur));
                    if w.history.len() > 16 {
                        w.history.remove(0);
                    }
                    w.last = cur;
                    if fire {
                        w.hits += 1;
                    }
                }
            }
        });
    }
    events
}

pub fn freeze(relay: &Relay, mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(addr) = arg_addr(req, "address") else { return bad("freeze requires 'address'") };
    let enabled = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    if !enabled {
        let restored = with_live(|l| {
            let pos = l.frozen.iter().position(|f| f.addr == addr)?;
            Some(l.frozen.remove(pos))
        });
        if let Some(f) = restored {
            let _ = mem.write_at(f.addr, &f.before);
        }
        return json!({ "type": "freeze_result", "success": true, "frozen": with_live(|l| l.frozen.len()) });
    }
    let s = |k: &str, d: &str| req.get(k).and_then(Value::as_str).unwrap_or(d).to_owned();
    let f = |k: &str, d: f64| req.get(k).and_then(Value::as_f64).unwrap_or(d);
    let (mode, vtype, group) = (s("mode", "set"), s("value_type", ""), s("group", ""));
    if !matches!(mode.as_str(), "set" | "add" | "clamp") {
        return bad("mode must be set, add or clamp");
    }
    if mode != "set" && vt_width(&vtype) == 0 {
        return bad("add/clamp need a numeric value_type");
    }
    let data = if mode == "set" {
        match req.get("data").and_then(Value::as_str).and_then(parse_hex).filter(|d| !d.is_empty() && d.len() <= 4096) {
            Some(d) => d,
            None => return bad("freeze requires hex 'data' (1..4096 bytes)"),
        }
    } else {
        match read_vec(mem, addr, vt_width(&vtype)) {
            Some(d) => d,
            None => return failed(format!("{addr:#x} is not readable")),
        }
    };
    let Some(before) = read_vec(mem, addr, data.len()) else { return failed(format!("{addr:#x} is not readable")) };
    if mode == "set" {
        if let Err(e) = mem.write_at(addr, &data) {
            return failed(format!("{addr:#x}: {e}"));
        }
    }
    let entry = Frozen { addr, data: data.clone(), before: before.clone(), mode, vtype, step: f("step", 1.0), min: f("min", 0.0), max: f("max", 0.0), group, paused: false };
    let count = with_live(|l| {
        match l.frozen.iter_mut().find(|x| x.addr == addr) {
            Some(x) => {
                let keep = x.before.clone();
                *x = Frozen { before: keep, ..entry };
            }
            None => l.frozen.push(entry),
        }
        l.frozen.len()
    });
    relay.emit(json!({ "type": "event", "event": "patched", "address": hex_addr(addr), "old": hex_bytes(&before), "new": hex_bytes(&data) }));
    crate::local_more::journal("freeze", addr, &before, &data);
    json!({ "type": "freeze_result", "success": true, "frozen": count })
}

pub fn freeze_group(req: &Map<String, Value>) -> Value {
    let Some(group) = req.get("group").and_then(Value::as_str).filter(|g| !g.is_empty()) else { return bad("freeze_group needs 'group'") };
    let on = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let n = with_live(|l| {
        let mut n = 0;
        for f in l.frozen.iter_mut().filter(|f| f.group == group) {
            f.paused = !on;
            n += 1;
        }
        n
    });
    json!({ "type": "freeze_group_result", "success": true, "group": group, "enabled": on, "entries": n })
}

pub fn freeze_list() -> Value {
    let entries: Vec<Value> = with_live(|l| {
        l.frozen
            .iter()
            .map(|f| {
                let mut e = json!({ "address": hex_addr(f.addr), "data": hex_bytes(&f.data), "mode": f.mode, "paused": f.paused });
                if !f.vtype.is_empty() { e["value_type"] = json!(f.vtype); }
                if f.mode == "add" { e["step"] = json!(f.step); }
                if f.mode == "clamp" { e["min"] = json!(f.min); e["max"] = json!(f.max); }
                if !f.group.is_empty() { e["group"] = json!(f.group); }
                e
            })
            .collect()
    });
    json!({ "type": "freeze_list_result", "success": true, "entries": entries })
}

/// Writes back the pre-freeze bytes (detach / target change).
pub fn restore_frozen(mem: &impl MemIo) {
    let frozen = with_live(|l| std::mem::take(&mut l.frozen));
    for f in frozen {
        let _ = mem.write_at(f.addr, &f.before);
    }
}

pub fn watch(_relay: &Relay, mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(addr) = arg_addr(req, "address") else { return bad("watch requires 'address'") };
    let vtype = req.get("value_type").and_then(Value::as_str).unwrap_or("").to_owned();
    let cond = req.get("condition").and_then(Value::as_str).unwrap_or("any").to_owned();
    if !vtype.is_empty() && vt_width(&vtype) == 0 {
        return bad("value_type must be u8..u64, i8..i64, f32 or f64");
    }
    if !matches!(cond.as_str(), "any" | "eq" | "ne" | "gt" | "lt" | "delta") {
        return bad("condition must be any, eq, ne, gt, lt or delta");
    }
    if cond != "any" && vtype.is_empty() {
        return bad("conditions need a numeric value_type");
    }
    let size = (req.get("size").and_then(Value::as_u64).unwrap_or(4) as usize).max(vt_width(&vtype)).clamp(1, 256);
    let label = req.get("label").and_then(Value::as_str).unwrap_or("").to_owned();
    let last = read_vec(mem, addr, size).unwrap_or_default();
    let value = req.get("value").and_then(Value::as_f64).unwrap_or(0.0);
    let n = with_live(|l| {
        l.watched.retain(|w| w.addr != addr);
        l.watched.push(Watched { addr, size, label, last, vtype, cond, value, hits: 0, history: Vec::new() });
        l.watched.len()
    });
    json!({ "type": "watch_result", "success": true, "watched": n })
}

pub fn unwatch(req: &Map<String, Value>) -> Value {
    let Some(addr) = arg_addr(req, "address") else { return bad("unwatch requires 'address'") };
    let n = with_live(|l| {
        l.watched.retain(|w| w.addr != addr);
        l.watched.len()
    });
    json!({ "type": "unwatch_result", "success": true, "watched": n })
}

pub fn watch_list() -> Value {
    let entries: Vec<Value> = with_live(|l| {
        l.watched
            .iter()
            .map(|w| {
                let mut e = json!({ "address": hex_addr(w.addr), "size": w.size, "label": w.label, "last": hex_bytes(&w.last), "hits": w.hits, "history": w.history });
                if !w.vtype.is_empty() { e["value_type"] = json!(w.vtype); }
                if w.cond != "any" { e["condition"] = json!(w.cond); e["value"] = json!(w.value); }
                e
            })
            .collect()
    });
    json!({ "type": "watch_list_result", "success": true, "entries": entries })
}

// ---------------------------------------------------------------------------------------------
// Pointer scan
// ---------------------------------------------------------------------------------------------

struct ModuleSpan {
    name: String,
    base: u64,
    end: u64,
}

fn module_spans(mem: &impl MemIo) -> Vec<ModuleSpan> {
    mem.modules().unwrap_or_default().into_iter().map(|(name, base, size)| ModuleSpan { name, base, end: base + size }).collect()
}

/// Backward pointer-path search: level 0 is the target; each level finds the stored pointers whose
/// value lies within `max_offset` below the current set of addresses. A pointer that lives inside a
/// module's image is a static root and ends a path. Mirrors the agent's `pointer_scan` reply.
pub fn pointer_scan(relay: &Relay, mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(target) = arg_addr(req, "target") else { return bad("pointer_scan requires 'target'") };
    let max_depth = req.get("max_depth").and_then(Value::as_u64).unwrap_or(3).clamp(1, 5) as usize;
    let max_off = req.get("max_offset").and_then(Value::as_u64).unwrap_or(0x400).min(0x10000);
    let max_results = req.get("max_results").and_then(Value::as_u64).unwrap_or(500).clamp(1, 20000) as usize;
    let module_roots = req.get("module_only_roots").and_then(Value::as_bool).unwrap_or(true);
    let maps = mem.maps().unwrap_or_default();
    let mods = module_spans(mem);

    // 1. every aligned qword in writable memory that points into mapped memory: (value, address)
    let readable = |v: u64, maps: &[MapLine]| maps.iter().any(|m| v >= m.start && v < m.end);
    let mut ptrs: Vec<(u64, u64)> = Vec::new();
    let writable: Vec<&MapLine> = maps.iter().filter(|m| m.writable).collect();
    let total = writable.len();
    for (i, m) in writable.iter().enumerate() {
        let mut pos = m.start;
        while pos < m.end {
            let n = ((m.end - pos) as usize).min(0x100000);
            if let Some(buf) = read_vec(mem, pos, n) {
                for (k, c) in buf.as_chunks::<8>().0.iter().enumerate() {
                    let v = u64::from_le_bytes(*c);
                    if v >= 0x10000 && readable(v, &maps) {
                        ptrs.push((v, pos + 8 * k as u64));
                        if ptrs.len() >= 50_000_000 {
                            break;
                        }
                    }
                }
            }
            pos += n as u64;
        }
        relay.emit(json!({ "type": "event", "event": "progress", "job": "pointer_scan", "done": i + 1, "total": total }));
    }
    ptrs.sort_unstable();

    // 2. BFS from the target backwards
    let mut results: Vec<Value> = Vec::new();
    let mut truncated = false;
    // frontier entries: (address to reach, offsets from that address down to the target)
    let mut frontier: Vec<(u64, Vec<i64>)> = vec![(target, Vec::new())];
    let mut seen: HashSet<u64> = HashSet::new();
    'outer: for _ in 0..max_depth {
        let mut next = Vec::new();
        for (addr, offs) in &frontier {
            let lo = addr.saturating_sub(max_off);
            let start = ptrs.partition_point(|p| p.0 < lo);
            for &(value, at) in ptrs[start..].iter().take_while(|p| p.0 <= *addr) {
                let mut path = vec![(addr - value) as i64];
                path.extend_from_slice(offs);
                if let Some(m) = mods.iter().find(|m| at >= m.base && at < m.end) {
                    results.push(json!({ "module": m.name, "module_offset": at - m.base, "base": hex_addr(at), "offsets": path }));
                    if results.len() >= max_results {
                        truncated = true;
                        break 'outer;
                    }
                } else if !module_roots {
                    results.push(json!({ "module": "", "module_offset": 0, "base": hex_addr(at), "offsets": path.clone() }));
                }
                if seen.insert(at) && next.len() < 200_000 {
                    next.push((at, path));
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    results.sort_by_key(|r| r["offsets"].as_array().map(|a| a.len()).unwrap_or(0));
    json!({ "type": "pointer_scan_result", "success": true, "results": results, "truncated": truncated })
}

// ---------------------------------------------------------------------------------------------
// ELF symbols: exports
// ---------------------------------------------------------------------------------------------

/// (path, base) of a module by name (exact, then suffix match).
pub(crate) fn module_path(mem: &impl MemIo, name: &str) -> Option<(String, u64, u64)> {
    let maps = mem.maps().ok()?;
    let mods = mem.modules().ok()?;
    let (mname, base, size) = mods
        .iter()
        .find(|(n, _, _)| n == name)
        .or_else(|| mods.iter().find(|(n, _, _)| n.starts_with(name) || name.ends_with(n.as_str())))
        .cloned()?;
    let path = maps.iter().find(|m| m.path.rsplit('/').next() == Some(mname.as_str()))?.path.clone();
    Some((path, base, size))
}

pub fn resolve_export(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    use object::{Object, ObjectSymbol};
    let (Some(module), Some(name)) = (req.get("module").and_then(Value::as_str), req.get("name").and_then(Value::as_str)) else {
        return bad("resolve_export requires 'module' and 'name'");
    };
    let Some((path, base, _)) = module_path(mem, module) else { return failed(format!("module not found: {module}")) };
    let Ok(data) = std::fs::read(&path) else { return failed(format!("cannot read {path}")) };
    let Ok(file) = object::File::parse(&*data) else { return failed(format!("{path} is not an object file")) };
    let bias = crate::local::load_bias(&file, base);
    let hit = file
        .dynamic_symbols()
        .chain(file.symbols())
        .find(|s| s.name() == Ok(name) && s.is_definition() && s.address() != 0);
    match hit {
        Some(s) => json!({ "type": "resolve_export_result", "success": true, "address": hex_addr(s.address().wrapping_add(bias)), "module_base": hex_addr(base), "size": s.size() }),
        None => failed(format!("{module}!{name} not found")),
    }
}

// ---------------------------------------------------------------------------------------------
// r_debug / link_map walk
// ---------------------------------------------------------------------------------------------

const AT_PHDR: u64 = 3;
const AT_PHNUM: u64 = 5;
const AT_ENTRY: u64 = 9;
const PT_DYNAMIC: u32 = 2;
const PT_PHDR: u32 = 6;
const DT_DEBUG: u64 = 21;

pub fn read_auxv(pid: u32) -> HashMap<u64, u64> {
    let mut out = HashMap::new();
    if let Ok(b) = std::fs::read(format!("/proc/{pid}/auxv")) {
        for c in b.as_chunks::<16>().0 {
            let k = u64::from_le_bytes(c[..8].try_into().unwrap());
            let v = u64::from_le_bytes(c[8..].try_into().unwrap());
            if k == 0 {
                break;
            }
            out.insert(k, v);
        }
    }
    out
}

/// Follows AT_PHDR → PT_DYNAMIC → DT_DEBUG → r_debug.r_map → link_map list. Returns
/// (l_addr, name, l_ld) per loaded object, in load order.
pub fn walk_link_map(mem: &impl MemIo, auxv: &HashMap<u64, u64>) -> Option<Vec<(u64, String, u64)>> {
    let phdr = *auxv.get(&AT_PHDR)?;
    let phnum = *auxv.get(&AT_PHNUM)?;
    let mut bias = None;
    let mut dynamic = None;
    for i in 0..phnum.min(64) {
        // every address below is read from target memory: wrapping, never an overflow panic
        let ph = phdr.wrapping_add(i * 56);
        let ty = read_u32(mem, ph)?;
        let vaddr = read_u64(mem, ph.wrapping_add(16))?;
        match ty {
            PT_PHDR => bias = Some(phdr.wrapping_sub(vaddr)),
            PT_DYNAMIC => dynamic = Some(vaddr),
            _ => {}
        }
    }
    let dynamic = dynamic?.wrapping_add(bias.unwrap_or(0));
    let mut r_debug = 0;
    for i in 0..512u64 {
        let tag = read_u64(mem, dynamic.wrapping_add(i * 16))?;
        if tag == 0 {
            break;
        }
        if tag == DT_DEBUG {
            r_debug = read_u64(mem, dynamic.wrapping_add(i * 16 + 8))?;
            break;
        }
    }
    if r_debug == 0 {
        return None;
    }
    let mut lm = read_u64(mem, r_debug.wrapping_add(8))?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    while lm != 0 && seen.insert(lm) && out.len() < 4096 {
        let l_addr = read_u64(mem, lm)?;
        let l_name = read_u64(mem, lm.wrapping_add(8))?;
        let l_ld = read_u64(mem, lm.wrapping_add(16))?;
        let name = if l_name != 0 { read_cstr(mem, l_name, 4096).unwrap_or_default() } else { String::new() };
        out.push((l_addr, name, l_ld));
        lm = read_u64(mem, lm.wrapping_add(24))?;
    }
    Some(out)
}

pub fn link_map_walk(mem: &impl MemIo, pid: u32) -> Value {
    let auxv = read_auxv(pid);
    let maps = mem.maps().unwrap_or_default();
    let entry_of = |base: u64| -> u64 {
        // e_entry at +24 of the ELF header mapped at the module base
        match read_vec(mem, base, 64) {
            Some(h) if &h[..4] == b"\x7fELF" => {
                let e = u64::from_le_bytes(h[24..32].try_into().unwrap());
                let et = u16::from_le_bytes([h[16], h[17]]);
                if et == 3 { base.wrapping_add(e) } else { e } // ET_DYN entries are relative
            }
            _ => 0,
        }
    };
    let span = |name: &str, near: u64| -> (u64, u64) {
        let mine: Vec<&MapLine> = maps.iter().filter(|m| !name.is_empty() && m.path == name).collect();
        let lo = mine.iter().map(|m| m.start).min().unwrap_or(near);
        let hi = mine.iter().map(|m| m.end).max().unwrap_or(near);
        (lo, hi - lo)
    };
    let mut modules: Vec<Value> = Vec::new();
    let source;
    match walk_link_map(mem, &auxv) {
        Some(list) => {
            source = "link_map";
            for (i, (l_addr, name, l_ld)) in list.iter().enumerate() {
                // the main program has an empty l_name; its path comes from /proc/<pid>/exe
                let name = if name.is_empty() && i == 0 {
                    std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.display().to_string()).unwrap_or_default()
                } else {
                    name.clone()
                };
                let (base, size) = span(&name, *l_addr);
                let entry = if i == 0 { auxv.get(&AT_ENTRY).copied().unwrap_or(0) } else { entry_of(base) };
                modules.push(json!({ "base": hex_addr(base), "l_addr": hex_addr(*l_addr), "dynamic": hex_addr(*l_ld), "entry": hex_addr(entry), "size": size, "name": name }));
            }
        }
        None => {
            source = "maps";
            for (name, base, size) in mem.modules().unwrap_or_default() {
                let path = maps.iter().find(|m| m.path.ends_with(&name)).map(|m| m.path.clone()).unwrap_or(name);
                modules.push(json!({ "base": hex_addr(base), "entry": hex_addr(entry_of(base)), "size": size, "name": path }));
            }
        }
    }
    json!({ "type": "peb_walk_result", "success": true, "source": source, "count": modules.len(), "modules": modules })
}

// ---------------------------------------------------------------------------------------------
// Itanium C++ ABI type info
// ---------------------------------------------------------------------------------------------

/// Demangles an Itanium *type* name (what `std::type_info::name()` returns): `6Player`,
/// `N3foo3BarE`, `St6vectorIiSaIiEE`, `N3app5StateIJEEE`. Unknown encodings come back raw.
pub fn demangle_type(s: &str) -> String {
    let b = s.as_bytes();
    let mut i = 0;
    match parse_type(b, &mut i, 0) {
        Some(t) if i == b.len() => t,
        _ => s.to_owned(),
    }
}

fn parse_source_name(b: &[u8], i: &mut usize) -> Option<String> {
    let start = *i;
    while *i < b.len() && b[*i].is_ascii_digit() {
        *i += 1;
    }
    let n: usize = std::str::from_utf8(&b[start..*i]).ok()?.parse().ok()?;
    // the length is part of the (target-supplied) name: `18446744073709551615x` overflowed
    let name = std::str::from_utf8(b.get(*i..i.checked_add(n)?)?).ok()?.to_owned();
    *i += n;
    Some(name)
}

/// Steps over the `E` that closes a nested name, template list or literal; None when the name
/// ends first (stepping past the end made the next slice panic: `1aILN1b`).
fn eat_end(b: &[u8], i: &mut usize) -> Option<()> {
    (b.get(*i) == Some(&b'E')).then(|| *i += 1)
}

fn parse_template_args(b: &[u8], i: &mut usize, depth: usize) -> Option<String> {
    // at 'I'
    *i += 1;
    let mut args = Vec::new();
    while *i < b.len() && b[*i] != b'E' {
        if b[*i] == b'L' {
            // literal: L <type> <value> E
            *i += 1;
            let ty = parse_type(b, i, depth)?;
            let start = *i;
            while *i < b.len() && b[*i] != b'E' {
                *i += 1;
            }
            let v = std::str::from_utf8(&b[start..*i]).ok()?.replace('n', "-");
            eat_end(b, i)?;
            args.push(if ty == "bool" { if v == "1" { "true".into() } else { "false".into() } } else { v });
        } else if b[*i] == b'J' {
            *i += 1;
            let mut pack = Vec::new();
            while *i < b.len() && b[*i] != b'E' {
                pack.push(parse_type(b, i, depth)?);
            }
            eat_end(b, i)?;
            args.push(pack.join(", "));
        } else {
            args.push(parse_type(b, i, depth)?);
        }
    }
    eat_end(b, i)?;
    let joined = args.into_iter().filter(|a| !a.is_empty()).collect::<Vec<_>>().join(", ");
    Some(format!("<{joined}>"))
}

/// Deepest nesting demangled (pointers, templates, nested names). Mangled names come from target
/// memory and from symbol tables of any length: `PPPP…` a megabyte long overflowed the stack.
const MAX_TYPE_DEPTH: usize = 64;

fn parse_type(b: &[u8], i: &mut usize, depth: usize) -> Option<String> {
    if depth > MAX_TYPE_DEPTH {
        return None;
    }
    let depth = depth + 1;
    let c = *b.get(*i)?;
    let builtin = match c {
        b'v' => Some("void"), b'b' => Some("bool"), b'c' => Some("char"), b'a' => Some("signed char"),
        b'h' => Some("unsigned char"), b's' => Some("short"), b't' => Some("unsigned short"), b'i' => Some("int"),
        b'j' => Some("unsigned int"), b'l' => Some("long"), b'm' => Some("unsigned long"), b'x' => Some("long long"),
        b'y' => Some("unsigned long long"), b'f' => Some("float"), b'd' => Some("double"), b'e' => Some("long double"),
        b'w' => Some("wchar_t"), _ => None,
    };
    if let Some(t) = builtin {
        *i += 1;
        return Some(t.to_owned());
    }
    match c {
        b'P' => {
            *i += 1;
            Some(format!("{}*", parse_type(b, i, depth)?))
        }
        b'R' => {
            *i += 1;
            Some(format!("{}&", parse_type(b, i, depth)?))
        }
        b'K' => {
            *i += 1;
            Some(format!("{} const", parse_type(b, i, depth)?))
        }
        b'S' => {
            let abbr = match b.get(*i + 1) {
                Some(b't') => "std",
                Some(b'a') => "std::allocator",
                Some(b's') => "std::string",
                Some(b'i') => "std::istream",
                Some(b'o') => "std::ostream",
                _ => return None,
            };
            *i += 2;
            let mut name = if abbr == "std" { format!("std::{}", parse_source_name(b, i)?) } else { abbr.to_owned() };
            if b.get(*i) == Some(&b'I') {
                name += &parse_template_args(b, i, depth)?;
            }
            Some(name)
        }
        b'N' => {
            *i += 1;
            let mut parts: Vec<String> = Vec::new();
            while *i < b.len() && b[*i] != b'E' {
                match b[*i] {
                    b'0'..=b'9' => parts.push(parse_source_name(b, i)?),
                    b'I' => {
                        let t = parse_template_args(b, i, depth)?;
                        parts.last_mut()?.push_str(&t);
                    }
                    b'S' if b.get(*i + 1) == Some(&b't') => {
                        *i += 2;
                        parts.push("std".into());
                    }
                    b'K' | b'V' => *i += 1,
                    _ => return None,
                }
            }
            eat_end(b, i)?;
            Some(parts.join("::"))
        }
        b'0'..=b'9' => {
            let mut name = parse_source_name(b, i)?;
            if b.get(*i) == Some(&b'I') {
                name += &parse_template_args(b, i, depth)?;
            }
            Some(name)
        }
        _ => None,
    }
}

/// Name of the type_info at `ti` (its `__type_name` pointer at +8).
fn typeinfo_name(mem: &impl MemIo, ti: u64) -> Option<String> {
    let np = read_u64(mem, ti.wrapping_add(8))?;
    let raw = read_cstr(mem, np, 1024)?;
    let ok = !raw.is_empty() && raw.len() < 1024 && raw.bytes().all(|b| b.is_ascii_graphic());
    ok.then_some(raw)
}

/// Base classes of a type_info: `__si_class_type_info` has one base pointer at +16;
/// `__vmi_class_type_info` has flags at +16, a count at +20 and {base, offset_flags} pairs from +24.
fn typeinfo_bases(mem: &impl MemIo, ti: u64) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    // vmi first: small count and every entry a plausible type_info
    if let (Some(flags), Some(count)) = (read_u32(mem, ti.wrapping_add(16)), read_u32(mem, ti.wrapping_add(20))) {
        if flags < 8 && (1..=32).contains(&count) {
            let mut all = Vec::new();
            for k in 0..count as u64 {
                match read_u64(mem, ti.wrapping_add(24 + k * 16)).and_then(|b| typeinfo_name(mem, b).map(|n| (b, n))) {
                    Some(x) => all.push(x),
                    None => {
                        all.clear();
                        break;
                    }
                }
            }
            if !all.is_empty() {
                return all;
            }
        }
    }
    if let Some(b) = read_u64(mem, ti.wrapping_add(16)) {
        if let Some(n) = typeinfo_name(mem, b) {
            if b != ti {
                out.push((b, n));
            }
        }
    }
    out
}

fn resolve_object(mem: &impl MemIo, obj: u64) -> Option<Value> {
    let vptr = read_u64(mem, obj)?;
    let ti = read_u64(mem, vptr.checked_sub(8)?)?;
    let raw = typeinfo_name(mem, ti)?;
    let bases: Vec<Value> = typeinfo_bases(mem, ti)
        .into_iter()
        .map(|(a, n)| json!({ "typeinfo": hex_addr(a), "name": demangle_type(&n), "mangled": n }))
        .collect();
    Some(json!({ "success": true, "name": demangle_type(&raw), "mangled": raw, "vtable": hex_addr(vptr), "typeinfo": hex_addr(ti), "bases": bases, "abi": "itanium" }))
}

/// Class name of the vtable's first virtual slot (Itanium: the type_info sits at vtable[-1]).
pub(crate) fn itanium_vtable_name(mem: &impl MemIo, vt: u64) -> Option<String> {
    let ti = read_u64(mem, vt.checked_sub(8)?)?;
    typeinfo_name(mem, ti).map(|n| demangle_type(&n))
}

pub fn itanium_resolve(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(addr) = arg_addr(req, "address") else { return bad("rtti_resolve requires 'address'") };
    let mut r = resolve_object(mem, addr).unwrap_or_else(|| json!({ "success": false, "name": "" }));
    r["type"] = json!("rtti_resolve_result");
    r["address"] = json!(hex_addr(addr));
    r
}

pub fn itanium_resolve_batch(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let list = req.get("addresses").and_then(Value::as_array).cloned().unwrap_or_default();
    let results: Vec<Value> = list
        .iter()
        .take(4096)
        .map(|a| {
            let addr = a.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
            let mut r = addr.and_then(|x| resolve_object(mem, x)).unwrap_or_else(|| json!({ "success": false, "name": "" }));
            r["address"] = a.clone();
            r
        })
        .collect();
    json!({ "type": "rtti_resolve_batch_result", "success": true, "results": results })
}

/// Every class a module declares, from its `_ZTI*` (type_info) and `_ZTV*` (vtable) symbols.
/// The vtable symbol points at offset-to-top; virtual functions start 16 bytes in.
pub fn itanium_classes(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    use object::{Object, ObjectSymbol};
    let module = req.get("module").and_then(Value::as_str).unwrap_or("");
    let Some((path, base, size)) = (if module.is_empty() {
        crate::local::main_module(mem).and_then(|(n, _, _)| module_path(mem, &n))
    } else {
        module_path(mem, module)
    }) else {
        return failed(format!("module not found: {module}"));
    };
    let Ok(data) = std::fs::read(&path) else { return failed(format!("cannot read {path}")) };
    let Ok(file) = object::File::parse(&*data) else { return failed(format!("{path} is not an object file")) };
    let bias = crate::local::load_bias(&file, base);
    let mut classes: HashMap<String, (Option<u64>, Option<u64>)> = HashMap::new();
    for s in file.symbols().chain(file.dynamic_symbols()) {
        let (Ok(name), true) = (s.name(), s.address() != 0) else { continue };
        if let Some(t) = name.strip_prefix("_ZTI") {
            classes.entry(t.to_owned()).or_default().0 = Some(s.address().wrapping_add(bias));
        } else if let Some(t) = name.strip_prefix("_ZTV") {
            classes.entry(t.to_owned()).or_default().1 = Some(s.address().wrapping_add(bias));
        }
    }
    let mut out: Vec<Value> = classes
        .into_iter()
        .map(|(mangled, (ti, vt))| {
            let bases: Vec<String> = ti.map(|t| typeinfo_bases(mem, t).into_iter().map(|(_, n)| demangle_type(&n)).collect()).unwrap_or_default();
            let slots = vt.map(|v| {
                let mut n = 0;
                while n < 512 {
                    match read_u64(mem, v.wrapping_add(16 + n * 8)) {
                        Some(f) if f >= base && f < base.saturating_add(size) => n += 1,
                        _ => break,
                    }
                }
                n
            });
            json!({
                "name": demangle_type(&mangled), "mangled": mangled,
                "typeinfo": ti.map(hex_addr), "vtable": vt.map(|v| hex_addr(v.wrapping_add(16))),
                "slots": slots.unwrap_or(0), "bases": bases,
            })
        })
        .collect();
    out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    json!({ "type": "itanium_classes_result", "success": true, "module": path, "count": out.len(), "classes": out })
}

// ---------------------------------------------------------------------------------------------
// Module file bytes (ELF browser: section headers and symbol tables are not mapped)
// ---------------------------------------------------------------------------------------------

pub fn module_file(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let module = req.get("module").and_then(Value::as_str).unwrap_or("");
    let Some((path, base, _)) = module_path(mem, module) else { return failed(format!("module not found: {module}")) };
    let Ok(meta) = std::fs::metadata(&path) else { return failed(format!("cannot stat {path}")) };
    let off = req.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let size = req.get("size").and_then(Value::as_u64).unwrap_or(0x100000).min(0x100000);
    let data = (|| -> std::io::Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&path)?;
        f.seek(SeekFrom::Start(off))?;
        let mut buf = Vec::new();
        f.take(size).read_to_end(&mut buf)?;
        Ok(buf)
    })();
    match data {
        Ok(d) => json!({ "type": "module_file_result", "success": true, "path": path, "base": hex_addr(base), "file_size": meta.len(), "offset": off, "data": hex_bytes(&d) }),
        Err(e) => failed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Fake {
        data: Mutex<BTreeMap<u64, u8>>,
        maps: Vec<MapLine>,
    }
    impl Fake {
        fn new(maps: Vec<MapLine>) -> Self {
            Fake { data: Mutex::new(BTreeMap::new()), maps }
        }
        fn put(&self, a: u64, b: &[u8]) {
            let mut d = self.data.lock().unwrap();
            for (i, x) in b.iter().enumerate() {
                d.insert(a + i as u64, *x);
            }
        }
        fn put_u64(&self, a: u64, v: u64) {
            self.put(a, &v.to_le_bytes());
        }
    }
    impl MemIo for Fake {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.maps.iter().any(|m| addr >= m.start && addr + buf.len() as u64 <= m.end) {
                return Err(std::io::Error::other("unmapped"));
            }
            let d = self.data.lock().unwrap();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = d.get(&(addr + i as u64)).copied().unwrap_or(0);
            }
            Ok(buf.len())
        }
        fn write_at(&self, addr: u64, buf: &[u8]) -> std::io::Result<()> {
            self.put(addr, buf);
            Ok(())
        }
        fn maps(&self) -> std::io::Result<Vec<MapLine>> {
            Ok(self.maps.clone())
        }
        fn alive(&self) -> bool {
            true
        }
    }
    fn line(start: u64, end: u64, w: bool, path: &str) -> MapLine {
        MapLine { start, end, writable: w, executable: false, path: path.into() }
    }
    fn obj(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    #[test]
    fn demangles_itanium_type_names() {
        assert_eq!(demangle_type("6Player"), "Player");
        assert_eq!(demangle_type("N3foo3BarE"), "foo::Bar");
        assert_eq!(demangle_type("St9exception"), "std::exception");
        assert_eq!(demangle_type("NSt6vectorIiSaIiEEE"), "std::vector<int, std::allocator<int>>");
        assert_eq!(demangle_type("St6vectorIiSaIiEE"), "std::vector<int, std::allocator<int>>");
        assert_eq!(demangle_type("N3app5StateILi3EEE"), "app::State<3>");
        assert_eq!(demangle_type("weird$"), "weird$");
    }

    #[test]
    fn itanium_object_and_bases() {
        let mem = Fake::new(vec![line(0x1000, 0x9000, true, "/app/a.out")]);
        // names
        mem.put(0x2000, b"7Derived\0");
        mem.put(0x2100, b"4Base\0");
        // type_info for Base (plain class_type_info: vptr, name)
        mem.put_u64(0x3000, 0xdead0);
        mem.put_u64(0x3008, 0x2100);
        // type_info for Derived (__si: vptr, name, base)
        mem.put_u64(0x3100, 0xdead1);
        mem.put_u64(0x3108, 0x2000);
        mem.put_u64(0x3110, 0x3000);
        // vtable: [offset_to_top][typeinfo][fn...]; vptr points at the first fn slot
        mem.put_u64(0x4000, 0);
        mem.put_u64(0x4008, 0x3100);
        mem.put_u64(0x4010, 0x1234);
        // object
        mem.put_u64(0x5000, 0x4010);
        let r = itanium_resolve(&mem, &obj(json!({ "address": "0x5000" })));
        assert_eq!(r["success"], true, "{r}");
        assert_eq!(r["name"], "Derived");
        assert_eq!(r["bases"][0]["name"], "Base");
        let r = itanium_resolve(&mem, &obj(json!({ "address": "0x6000" })));
        assert_eq!(r["success"], false);
    }

    #[test]
    fn freeze_watch_tick() {
        let mem = Fake::new(vec![line(0x1000, 0x2000, true, "")]);
        let relay = Relay::new("t", Duration::from_secs(1));
        mem.put(0x1000, &[1, 2, 3, 4]);
        let r = freeze(&relay, &mem, &obj(json!({ "address": "0x1000", "data": "aabb", "enabled": true })));
        assert_eq!(r["frozen"], 1, "{r}");
        mem.put(0x1000, &[0, 0]);
        tick(&mem, false);
        assert_eq!(read_vec(&mem, 0x1000, 2).unwrap(), vec![0xaa, 0xbb], "ticker rewrites the frozen bytes");
        assert_eq!(freeze_list()["entries"][0]["data"], "aabb");
        freeze(&relay, &mem, &obj(json!({ "address": "0x1000", "enabled": false })));
        assert_eq!(read_vec(&mem, 0x1000, 2).unwrap(), vec![1, 2], "unfreeze restores the original bytes");

        watch(&relay, &mem, &obj(json!({ "address": "0x1010", "size": 4, "label": "hp" })));
        assert!(tick(&mem, true).is_empty());
        mem.put(0x1010, &[9]);
        let ev = tick(&mem, true);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["event"], "watch_event");
        assert_eq!(ev[0]["old"], "00000000");
        assert_eq!(ev[0]["new"], "09000000");
        assert_eq!(ev[0]["label"], "hp");
        assert!(tick(&mem, true).is_empty(), "no event without a further change");
        unwatch(&obj(json!({ "address": "0x1010" })));
        assert_eq!(watch_list()["entries"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn pointer_scan_finds_static_chain() {
        // module image 0x10000-0x11000 (static root), heap 0x20000-0x30000
        let mem = Fake::new(vec![line(0x10000, 0x11000, true, "/app/game"), line(0x20000, 0x30000, true, "")]);
        // game+0x100 -> 0x20000 ; [0x20000+0x18] -> 0x25000 ; target = 0x25000+0x40
        mem.put_u64(0x10100, 0x20000);
        mem.put_u64(0x20018, 0x25000);
        let relay = Relay::new("t", Duration::from_secs(1));
        let r = pointer_scan(&relay, &mem, &obj(json!({ "target": "0x25040", "max_depth": 3 })));
        let results = r["results"].as_array().unwrap();
        let hit = results.iter().find(|x| x["module_offset"] == 0x100).unwrap_or_else(|| panic!("{r}"));
        assert_eq!(hit["module"], "game");
        assert_eq!(hit["offsets"], json!([0x18, 0x40]));
    }

    #[test]
    fn link_map_walk_follows_r_debug() {
        let mem = Fake::new(vec![line(0x400000, 0x410000, true, "/app/main")]);
        // phdrs at 0x400040: PT_PHDR (vaddr 0x40) and PT_DYNAMIC (vaddr 0x3000)
        mem.put(0x400040, &PT_PHDR.to_le_bytes());
        mem.put_u64(0x400040 + 16, 0x40);
        mem.put(0x400040 + 56, &PT_DYNAMIC.to_le_bytes());
        mem.put_u64(0x400040 + 56 + 16, 0x3000);
        // dynamic: DT_DEBUG -> r_debug at 0x405000
        mem.put_u64(0x403000, DT_DEBUG);
        mem.put_u64(0x403008, 0x405000);
        mem.put_u64(0x405008, 0x406000);
        // two link_map nodes
        mem.put_u64(0x406000, 0);
        mem.put_u64(0x406008, 0);
        mem.put_u64(0x406018, 0x406100);
        mem.put_u64(0x406100, 0x7f0000);
        mem.put_u64(0x406108, 0x407000);
        mem.put(0x407000, b"/lib/libc.so.6\0");
        let auxv: HashMap<u64, u64> = [(AT_PHDR, 0x400040), (AT_PHNUM, 2)].into_iter().collect();
        let list = walk_link_map(&mem, &auxv).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[1], (0x7f0000, "/lib/libc.so.6".to_owned(), 0));
    }
}
