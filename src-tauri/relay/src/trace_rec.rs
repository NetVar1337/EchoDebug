//! Time-travel trace recording, storage and the `trace_*` verbs (relay-side, every backend).
//!
//! Sources:
//! - `emu` on the local backend: the Emu Debugger's Unicorn session records natively with hooks
//!   (every instruction, register deltas, every read and write with old/new bytes);
//! - `emu` with the Windows agent connected: the relay drives the agent's session one `emu_step`
//!   at a time and snapshots the memory operands with `emu_read` (slower, same trace);
//! - `ptrace` (Linux): the debugger single-steps a real thread; the memory operands of each
//!   instruction are decoded with iced-x86 and read before and after the step.
//!
//! Traces are kept in memory (the newest few) and saved to `<config>/EchoDebug/traces/<id>.edt`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::trace::{hex, hex_bytes, parse_u64, reg_index, regs_json, Loc, Meta, RawAccess, Regs, Trace, REG_NAMES, RIP};
use crate::Relay;

/// Steps recorded so far by the running recording (progress events).
pub static PROGRESS: AtomicU64 = AtomicU64::new(0);
pub static CANCEL: AtomicBool = AtomicBool::new(false);
static RECORDING: AtomicBool = AtomicBool::new(false);
/// How many traces stay decoded in memory.
const KEEP: usize = 4;

struct Store {
    loaded: VecDeque<(String, Arc<Trace>)>,
    current: Option<String>,
}

static STORE: Mutex<Store> = Mutex::new(Store { loaded: VecDeque::new(), current: None });

fn bad(detail: &str) -> Value {
    json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": detail })
}

fn failed(detail: impl std::fmt::Display) -> Value {
    json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": detail.to_string() })
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn cancelled() -> bool {
    CANCEL.load(Ordering::Relaxed)
}

// ---- limits -------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_steps: usize,
    pub until: Option<u64>,
    pub max_bytes: usize,
    pub keyframe: u32,
}

impl Limits {
    pub fn from_req(req: &Map<String, Value>) -> Limits {
        Limits {
            max_steps: req.get("max_steps").and_then(Value::as_u64).unwrap_or(10_000).clamp(1, 5_000_000) as usize,
            until: req.get("until").and_then(parse_u64).filter(|a| *a != 0),
            max_bytes: (req.get("max_mb").and_then(Value::as_u64).unwrap_or(64).clamp(1, 1024) as usize) << 20,
            keyframe: req.get("keyframe").and_then(Value::as_u64).unwrap_or(256).clamp(1, 65536) as u32,
        }
    }
}

// ---- memory operands of one instruction -----------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Planned {
    pub addr: u64,
    pub size: usize,
    pub read: bool,
    pub write: bool,
}

/// Decodes the instruction at `pc` and works out which memory it will read and write with the
/// registers `regs` (before the step). Returns the instruction length (0 = undecodable).
pub fn plan(code: &[u8], pc: u64, regs: &Regs) -> (usize, Vec<Planned>) {
    use iced_x86::{Decoder, DecoderOptions, InstructionInfoFactory, OpAccess, Register};
    let mut d = Decoder::with_ip(64, code, pc, DecoderOptions::NONE);
    let ins = d.decode();
    if ins.is_invalid() {
        return (0, Vec::new());
    }
    let mut f = InstructionInfoFactory::new();
    let info = f.info(&ins);
    let next = pc.wrapping_add(ins.len() as u64);
    let value = |r: Register| -> Option<u64> {
        match r {
            Register::ES | Register::CS | Register::SS | Register::DS => Some(0),
            Register::FS => Some(regs[18]),
            Register::GS => Some(regs[19]),
            Register::RIP => Some(next),
            Register::EIP => Some(next & 0xffff_ffff),
            _ => {
                let i = crate::trace::flow::reg_idx(r)?;
                let v = regs[i];
                Some(match r.size() {
                    1 if matches!(r, Register::AH | Register::BH | Register::CH | Register::DH) => (v >> 8) & 0xff,
                    1 => v & 0xff,
                    2 => v & 0xffff,
                    4 => v & 0xffff_ffff,
                    _ => v,
                })
            }
        }
    };
    let mut out = Vec::new();
    for u in info.used_memory() {
        let size = u.memory_size().size().min(4096);
        if size == 0 {
            continue;
        }
        let (read, write) = match u.access() {
            OpAccess::Read | OpAccess::CondRead => (true, false),
            OpAccess::Write | OpAccess::CondWrite => (false, true),
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => (true, true),
            _ => continue,
        };
        let Some(addr) = u.virtual_address(0, |r, _, _| value(r)) else { continue };
        out.push(Planned { addr, size, read, write });
    }
    (ins.len(), out)
}

// ---- generic single-stepping recorder -------------------------------------------------------------

/// A thread or session that can be stepped one instruction at a time.
pub trait Stepper {
    fn regs(&mut self) -> Result<Regs, String>;
    /// Fills `buf`; false when the memory is not readable.
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> bool;
    /// Runs one instruction. Ok(None): done, keep going. Ok(Some(why)): it ran and the recording
    /// ends after it (the function returned, …). Err(why): it did not run; the recording ends.
    fn step(&mut self) -> Result<Option<String>, String>;
}

/// Steps until a limit, recording register deltas and the instruction's memory operands.
pub fn record_steps(st: &mut dyn Stepper, mut meta: Meta, lim: &Limits) -> Result<Trace, String> {
    let init = st.regs()?;
    let mut b = crate::trace::Builder::new(Meta::default(), init, lim.keyframe);
    let mut cur = init;
    PROGRESS.store(0, Ordering::Relaxed);
    let reason: String = loop {
        if b.len() >= lim.max_steps {
            break "count".into();
        }
        if b.size_bytes() >= lim.max_bytes {
            meta.truncated = true;
            break "size limit".into();
        }
        if cancelled() {
            break "cancelled".into();
        }
        if !b.is_empty() && lim.until == Some(cur[RIP]) {
            break "until".into();
        }
        let pc = cur[RIP];
        let mut code = [0u8; 16];
        let (len, planned) = if st.read(pc, &mut code) { plan(&code, pc, &cur) } else { (0, Vec::new()) };
        let mut before: Vec<(Planned, Vec<u8>)> = Vec::new();
        for p in planned {
            let mut buf = vec![0u8; p.size];
            if st.read(p.addr, &mut buf) {
                before.push((p, buf));
            }
        }
        let end = match st.step() {
            Ok(e) => e,
            Err(e) => break e,
        };
        let after = st.regs()?;
        let mut acc = Vec::new();
        for (p, old) in before {
            if p.read {
                acc.push(RawAccess { addr: p.addr, write: false, old: old.clone(), new: Vec::new() });
            }
            if p.write {
                let mut new = vec![0u8; p.size];
                if st.read(p.addr, &mut new) {
                    acc.push(RawAccess { addr: p.addr, write: true, old, new });
                }
            }
        }
        b.step(pc, &code[..len], &after, &acc);
        PROGRESS.store(b.len() as u64, Ordering::Relaxed);
        cur = after;
        if let Some(e) = end {
            break e;
        }
    };
    meta.stop_reason = reason;
    let mut t = b.finish();
    t.meta = meta;
    Ok(t)
}

/// Drives an emulator session through relay verbs (`emu_step` / `emu_read` / `emu_state`): the
/// Windows agent's Unicorn session. Runs on a blocking thread.
struct VerbStepper {
    relay: Relay,
    rt: tokio::runtime::Handle,
    regs: Option<Regs>,
}

impl VerbStepper {
    fn call(&self, v: Value) -> Value {
        self.rt.block_on(self.relay.request(v))
    }
}

impl Stepper for VerbStepper {
    fn regs(&mut self) -> Result<Regs, String> {
        if let Some(r) = self.regs {
            return Ok(r);
        }
        let s = self.call(json!({ "type": "emu_state" }));
        if s["type"] == "error" {
            return Err(format!("emu_state: {}", s["detail"].as_str().or(s["message"].as_str()).unwrap_or("failed")));
        }
        let r = crate::trace::regs_from_json(&s["regs"]);
        self.regs = Some(r);
        Ok(r)
    }

    fn read(&mut self, addr: u64, buf: &mut [u8]) -> bool {
        let r = self.call(json!({ "type": "emu_read", "address": hex(addr), "size": buf.len() }));
        let Some(h) = r["data"].as_str() else { return false };
        let Some(bytes) = (0..h.len() / 2).map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok()).collect::<Option<Vec<u8>>>() else { return false };
        if bytes.len() < buf.len() {
            return false;
        }
        buf.copy_from_slice(&bytes[..buf.len()]);
        true
    }

    fn step(&mut self) -> Result<Option<String>, String> {
        let r = self.call(json!({ "type": "emu_step", "count": 1 }));
        if r["type"] == "error" {
            return Err(format!("emu_step: {}", r["detail"].as_str().or(r["message"].as_str()).unwrap_or("failed")));
        }
        self.regs = Some(crate::trace::regs_from_json(&r["regs"]));
        let reason = r["stop"]["reason"].as_str().unwrap_or("step");
        let ran = r["stop"]["ran"].as_u64().unwrap_or(1);
        match reason {
            "step" | "count" => Ok(None),
            "returned" if ran > 0 => Ok(Some("returned".into())),
            "watchpoint" => Ok(Some("watchpoint".into())),
            "fault" => Err(format!("fault ({})", r["stop"]["error_name"].as_str().unwrap_or("?"))),
            other if ran > 0 => Ok(Some(other.to_owned())),
            other => Err(other.to_owned()),
        }
    }
}

// ---- store and files --------------------------------------------------------------------------------

pub fn dir() -> std::path::PathBuf {
    crate::auth::config_dir().join("traces")
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn path_of(id: &str) -> std::path::PathBuf {
    dir().join(format!("{id}.edt"))
}

fn remember(id: &str, t: Arc<Trace>) {
    let mut s = STORE.lock().unwrap_or_else(|e| e.into_inner());
    s.loaded.retain(|(i, _)| i != id);
    s.loaded.push_back((id.to_owned(), t));
    while s.loaded.len() > KEEP {
        s.loaded.pop_front();
    }
    s.current = Some(id.to_owned());
}

/// Keeps a finished recording (and saves it unless `save` is false); returns its summary.
pub fn deposit(t: Trace, save: bool) -> Value {
    let id = format!("t{}", now_ms());
    let mut saved = Value::Null;
    if save {
        let _ = std::fs::create_dir_all(dir());
        let p = path_of(&id);
        saved = match std::fs::write(&p, t.encode()) {
            Ok(()) => json!(p.display().to_string()),
            Err(e) => json!({ "error": e.to_string() }),
        };
    }
    let mut s = t.summary();
    s["trace_id"] = json!(id);
    s["saved"] = saved;
    remember(&id, Arc::new(t));
    s
}

fn get(id: Option<&str>) -> Result<(String, Arc<Trace>), String> {
    let id = match id {
        Some(i) => i.to_owned(),
        None => STORE.lock().unwrap_or_else(|e| e.into_inner()).current.clone().ok_or("no trace yet: record one with trace_record (or load / import one)")?,
    };
    if let Some(t) = STORE.lock().unwrap_or_else(|e| e.into_inner()).loaded.iter().find(|(i, _)| *i == id).map(|(_, t)| t.clone()) {
        return Ok((id, t));
    }
    if !valid_id(&id) {
        return Err(format!("bad trace id '{id}'"));
    }
    let data = std::fs::read(path_of(&id)).map_err(|e| format!("trace {id}: {e}"))?;
    let t = Arc::new(Trace::decode(&data)?);
    remember(&id, t.clone());
    Ok((id, t))
}

fn list() -> Value {
    let mut out: Vec<Value> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir()) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("edt") {
                continue;
            }
            let Some(id) = p.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else { continue };
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            // the header is near the start: read a little
            let head = std::fs::File::open(&p).ok().and_then(|f| {
                use std::io::Read;
                let mut b = Vec::new();
                f.take(64 * 1024).read_to_end(&mut b).ok()?;
                Trace::peek_meta(&b).ok()
            });
            let mut v = head.unwrap_or_else(|| json!({ "error": "unreadable" }));
            v["trace_id"] = json!(id);
            v["file_size"] = json!(size);
            out.push(v);
        }
    }
    let s = STORE.lock().unwrap_or_else(|e| e.into_inner());
    for (id, t) in &s.loaded {
        if !out.iter().any(|v| v["trace_id"] == json!(id)) {
            let mut v = t.summary();
            for k in ["initial_regs", "final_regs"] {
                if let Some(m) = v.as_object_mut() {
                    m.remove(k);
                }
            }
            v["trace_id"] = json!(id);
            v["unsaved"] = json!(true);
            out.push(v);
        }
    }
    out.sort_by_key(|v| std::cmp::Reverse(v["created_ms"].as_u64().unwrap_or(0)));
    json!({ "success": true, "traces": out, "current": s.current, "dir": dir().display().to_string() })
}

// ---- queries ----------------------------------------------------------------------------------------

fn step_json(t: &Trace, i: usize, full: bool) -> Value {
    let pc = t.pc(i);
    let code = t.code_at(pc);
    let text = crate::local::disasm_one(code, pc).map(|(_, s)| s).unwrap_or_else(|| "??".into());
    let changes: Map<String, Value> = t.deltas_of(i).iter().filter(|(r, _)| *r as usize != RIP).map(|(r, v)| (REG_NAMES[*r as usize].to_owned(), json!(hex(*v)))).collect();
    let accs = t.accesses_of_step(i);
    let mut v = json!({ "step": i, "pc": hex(pc), "text": text, "changes": changes, "reads": accs.iter().filter(|a| !a.write).count(), "writes": accs.iter().filter(|a| a.write).count() });
    if full {
        v["bytes"] = json!(hex_bytes(code));
        v["accesses"] = json!(accs.iter().map(|a| if a.write {
            json!({ "kind": "write", "address": hex(a.addr), "size": a.old.len(), "old": hex_bytes(&a.old), "new": hex_bytes(&a.new) })
        } else {
            json!({ "kind": "read", "address": hex(a.addr), "size": a.old.len(), "data": hex_bytes(&a.old) })
        }).collect::<Vec<_>>());
        v["regs_before"] = regs_json(&t.regs_at(i));
    }
    v
}

pub fn query(t: &Trace, req: &Map<String, Value>) -> Result<Value, String> {
    let kind = req.get("kind").and_then(Value::as_str).ok_or("trace_query requires 'kind'")?;
    let n = t.len();
    let pos = req.get("pos").and_then(Value::as_u64).map(|p| p as usize).unwrap_or(n).min(n);
    let addr = || req.get("address").and_then(parse_u64).ok_or_else(|| format!("{kind} requires 'address'"));
    let size = req.get("size").and_then(Value::as_u64).unwrap_or(1).clamp(1, 1 << 20);
    let limit = req.get("limit").and_then(Value::as_u64).unwrap_or(500).clamp(1, 100_000) as usize;
    let reg = || {
        let r = req.get("reg").and_then(Value::as_str).ok_or_else(|| format!("{kind} requires 'reg'"))?;
        reg_index(r).ok_or_else(|| format!("unknown register '{r}' (one of {})", REG_NAMES.join(", ")))
    };
    Ok(match kind {
        "reg_at" => {
            let r = t.regs_at(pos);
            match req.get("reg").and_then(Value::as_str) {
                Some(_) => { let i = reg()?; json!({ "pos": pos, "reg": REG_NAMES[i], "value": hex(r[i]) }) }
                None => json!({ "pos": pos, "regs": regs_json(&r) }),
            }
        }
        "mem_at" => {
            let a = addr()?;
            let sz = size.min(0x10000) as usize;
            let m = t.mem_at(a, sz, pos);
            let data: String = m.iter().map(|b| b.map(|x| format!("{x:02x}")).unwrap_or_else(|| "??".into())).collect();
            json!({ "pos": pos, "address": hex(a), "size": sz, "data": data, "known": m.iter().filter(|b| b.is_some()).count() })
        }
        "last_write" => {
            let a = addr()?;
            let changed = req.get("changed_only").and_then(Value::as_bool).unwrap_or(true);
            let h = t.last_write(a, size, pos, changed);
            json!({ "pos": pos, "address": hex(a), "size": size, "write": h.map(|h| { let mut v = h.json(); v["text"] = step_json(t, h.step as usize, false)["text"].clone(); v }) })
        }
        "writes_to" => {
            let a = addr()?;
            let (w, total) = t.writes_to(a, size, limit);
            json!({ "address": hex(a), "size": size, "total": total, "writes": w.iter().map(|h| h.json()).collect::<Vec<_>>() })
        }
        "reads_of" => {
            let a = addr()?;
            let (r, total) = t.reads_of(a, size, limit);
            json!({ "address": hex(a), "size": size, "total": total, "reads": r.iter().map(|(s, pc, ad, d)| json!({ "step": s, "pc": hex(*pc), "address": hex(*ad), "data": hex_bytes(d) })).collect::<Vec<_>>() })
        }
        "executions_of" => {
            let a = addr()?;
            let (e, total) = t.executions_of(a, limit);
            json!({ "address": hex(a), "total": total, "steps": e })
        }
        "seek" => {
            let a = addr()?;
            let fwd = req.get("direction").and_then(Value::as_str).unwrap_or("forward") != "back";
            json!({ "address": hex(a), "from": pos, "step": t.seek_pc(a, pos, fwd) })
        }
        "reg_series" => {
            let i = reg()?;
            let from = req.get("from").and_then(Value::as_u64).unwrap_or(0) as usize;
            let to = req.get("to").and_then(Value::as_u64).map(|x| x as usize).unwrap_or(n);
            let max = req.get("max").and_then(Value::as_u64).unwrap_or(400).clamp(2, 20_000) as usize;
            let s = t.reg_series(i, from, to, max);
            json!({ "reg": REG_NAMES[i], "points": s.iter().map(|(p, v)| json!([p, hex(*v)])).collect::<Vec<_>>() })
        }
        "step" => {
            if pos >= n {
                return Err(format!("step {pos} is past the end ({n} steps)"));
            }
            step_json(t, pos, true)
        }
        "steps" => {
            let from = req.get("from").and_then(Value::as_u64).unwrap_or(0) as usize;
            let count = req.get("count").and_then(Value::as_u64).unwrap_or(200).clamp(1, 5000) as usize;
            json!({ "from": from, "total": n, "steps": (from.min(n)..(from + count).min(n)).map(|i| step_json(t, i, false)).collect::<Vec<_>>() })
        }
        "taint" => {
            let loc = match req.get("reg").and_then(Value::as_str) {
                Some(_) => Loc::Reg(reg()?),
                None => Loc::Mem(addr()?, size.min(64) as u16),
            };
            let hops = req.get("max_hops").and_then(Value::as_u64).unwrap_or(32).clamp(1, 512) as usize;
            json!({ "pos": pos, "hops": t.taint(pos, loc, hops) })
        }
        "touched" => {
            let r = t.touched();
            json!({ "total": r.len(), "ranges": r.iter().take(limit).map(|(a, s, rd, wr)| json!({ "address": hex(*a), "size": s, "reads": rd, "writes": wr })).collect::<Vec<_>>() })
        }
        other => return Err(format!("unknown query kind '{other}' (reg_at, mem_at, last_write, writes_to, reads_of, executions_of, seek, reg_series, step, steps, taint, touched)")),
    })
}

// ---- verbs ------------------------------------------------------------------------------------------

pub const VERBS: &[&str] = &["trace_record", "trace_cancel", "trace_status", "trace_list", "trace_info", "trace_query", "trace_delete", "trace_export", "trace_import"];

fn ext_connected(relay: &Relay) -> bool {
    relay.lock().ext.is_some()
}

pub async fn handle(relay: &Relay, req: Map<String, Value>) -> Value {
    let verb = req.get("type").and_then(Value::as_str).unwrap_or_default().to_owned();
    let mut v = match verb.as_str() {
        "trace_record" => record(relay, &req).await,
        "trace_cancel" => {
            CANCEL.store(true, Ordering::SeqCst);
            crate::local_more::CANCEL.store(true, Ordering::SeqCst);
            json!({ "success": true, "cancelling": RECORDING.load(Ordering::SeqCst) })
        }
        "trace_status" => json!({ "success": true, "recording": RECORDING.load(Ordering::SeqCst), "steps": PROGRESS.load(Ordering::Relaxed) }),
        "trace_list" => tokio::task::spawn_blocking(list).await.unwrap_or_else(failed),
        "trace_info" | "trace_query" | "trace_delete" | "trace_export" | "trace_import" => {
            let (verb2, req2) = (verb.clone(), req.clone());
            tokio::task::spawn_blocking(move || stored_verb(&verb2, &req2)).await.unwrap_or_else(failed)
        }
        _ => bad(&format!("unknown trace verb {verb}")),
    };
    if v["type"].is_null() {
        v["type"] = json!(format!("{verb}_result"));
    }
    v
}

fn stored_verb(verb: &str, req: &Map<String, Value>) -> Value {
    let id = req.get("trace").and_then(Value::as_str);
    match verb {
        "trace_info" => {
            if id.is_none() && STORE.lock().unwrap_or_else(|e| e.into_inner()).current.is_none() {
                return list();
            }
            match get(id) {
                Ok((id, t)) => {
                    let mut s = t.summary();
                    s["trace_id"] = json!(id);
                    s["success"] = json!(true);
                    s["touched"] = json!(t.touched().len());
                    s
                }
                Err(e) => failed(e),
            }
        }
        "trace_query" => match get(id) {
            Ok((id, t)) => match query(&t, req) {
                Ok(mut v) => {
                    v["trace_id"] = json!(id);
                    v["success"] = json!(true);
                    v
                }
                Err(e) => bad(&e),
            },
            Err(e) => failed(e),
        },
        "trace_delete" => {
            let Some(id) = id.filter(|i| valid_id(i)) else { return bad("trace_delete requires a valid 'trace' id") };
            let mut s = STORE.lock().unwrap_or_else(|e| e.into_inner());
            s.loaded.retain(|(i, _)| i != id);
            if s.current.as_deref() == Some(id) {
                s.current = s.loaded.back().map(|(i, _)| i.clone());
            }
            let removed = std::fs::remove_file(path_of(id)).is_ok();
            json!({ "success": true, "removed": removed })
        }
        "trace_export" => match get(id) {
            Ok((id, t)) => {
                let bin = t.encode();
                json!({ "success": true, "trace_id": id, "name": t.meta.name, "size": bin.len(), "data": crate::trace::b64_encode(&bin) })
            }
            Err(e) => failed(e),
        },
        "trace_import" => {
            let Some(data) = req.get("data").and_then(Value::as_str) else { return bad("trace_import requires base64 'data'") };
            let bin = match crate::trace::b64_decode(data) {
                Ok(b) => b,
                Err(e) => return bad(&e),
            };
            match Trace::decode(&bin) {
                Ok(mut t) => {
                    if let Some(n) = req.get("name").and_then(Value::as_str) {
                        t.meta.name = n.to_owned();
                    }
                    let mut s = deposit(t, true);
                    s["success"] = json!(true);
                    s["imported"] = json!(true);
                    s
                }
                Err(e) => failed(e),
            }
        }
        _ => bad("unknown verb"),
    }
}

async fn record(relay: &Relay, req: &Map<String, Value>) -> Value {
    if RECORDING.swap(true, Ordering::SeqCst) {
        return failed("a trace is already being recorded (trace_cancel stops it)");
    }
    CANCEL.store(false, Ordering::SeqCst);
    PROGRESS.store(0, Ordering::Relaxed);
    let lim = Limits::from_req(req);
    let source = req.get("source").and_then(Value::as_str).unwrap_or("emu").to_owned();
    // progress events while the recording runs
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();
    let ticker = {
        let relay = relay.clone();
        let max = lim.max_steps;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {
                        relay.emit(json!({ "type": "event", "event": "trace_progress", "steps": PROGRESS.load(Ordering::Relaxed), "max_steps": max }));
                    }
                }
            }
        })
    };
    let r = record_inner(relay, req, &source, &lim).await;
    let _ = done_tx.send(());
    let _ = ticker.await;
    RECORDING.store(false, Ordering::SeqCst);
    if r["type"] != "error" {
        relay.emit(json!({ "type": "event", "event": "trace_done", "trace_id": r["trace"]["trace_id"], "steps": r["trace"]["steps"], "stop_reason": r["trace"]["stop_reason"] }));
    }
    r
}

async fn record_inner(relay: &Relay, req: &Map<String, Value>, source: &str, lim: &Limits) -> Value {
    let save = req.get("save").and_then(Value::as_bool).unwrap_or(true);
    let name = req.get("name").and_then(Value::as_str).unwrap_or_default().to_owned();
    let mut fwd = req.clone();
    fwd.remove("id");
    match source {
        "emu" => {
            // optionally (re)start the session first
            if req.contains_key("start") {
                let mut s = Map::new();
                s.insert("type".into(), json!("emu_start"));
                for k in ["start", "code", "regs", "write", "stubs", "on_unmapped", "xmm"] {
                    if let Some(v) = req.get(k) {
                        s.insert(k.into(), v.clone());
                    }
                }
                let r = Box::pin(relay.request(Value::Object(s))).await;
                if r["type"] == "error" {
                    return r;
                }
            }
            if !ext_connected(relay) {
                // local Unicorn session: native hooks
                fwd.insert("type".into(), json!("emu_record"));
                fwd.insert("name".into(), json!(name));
                fwd.insert("save".into(), json!(save));
                let r = tokio::task::spawn_blocking(move || crate::local_emudbg::handle(&fwd)).await.unwrap_or_else(failed);
                return wrap(r);
            }
            // the Windows agent: step it through the relay
            let (relay2, lim2, rt) = (relay.clone(), lim.clone(), tokio::runtime::Handle::current());
            let meta = Meta { name, source: "emu-agent".into(), created_ms: now_ms(), ..Default::default() };
            let r = tokio::task::spawn_blocking(move || {
                let mut st = VerbStepper { relay: relay2, rt, regs: None };
                record_steps(&mut st, meta, &lim2).map(|t| deposit(t, save))
            })
            .await;
            match r {
                Ok(Ok(s)) => json!({ "success": true, "trace": s }),
                Ok(Err(e)) => failed(e),
                Err(e) => failed(e),
            }
        }
        "ptrace" => {
            fwd.insert("type".into(), json!("dbg_record"));
            fwd.insert("name".into(), json!(name));
            fwd.insert("save".into(), json!(save));
            let relay2 = relay.clone();
            let r = tokio::task::spawn_blocking(move || crate::local_dbg::handle(&relay2, &fwd)).await.unwrap_or_else(failed);
            wrap(r)
        }
        other => bad(&format!("unknown trace source '{other}' (emu or ptrace)")),
    }
}

/// Backend replies carry the summary under `trace`; keep the session state the backend added.
fn wrap(mut r: Value) -> Value {
    if r["type"] == "error" {
        return r;
    }
    if let Some(m) = r.as_object_mut() {
        m.remove("type");
        m.insert("success".into(), json!(true));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::NREG;

    fn regs() -> Regs {
        let mut r = [0u64; NREG];
        r[0] = 0x1000; // rax
        r[7] = 0x7000; // rsp
        r[18] = 0x9000_0000; // fs_base
        r
    }

    #[test]
    fn plans_memory_operands() {
        let r = regs();
        // mov [rax+8], ecx
        let (len, p) = plan(&[0x89, 0x48, 0x08], 0x400000, &r);
        assert_eq!((len, p), (3, vec![Planned { addr: 0x1008, size: 4, read: false, write: true }]));
        // add [rax], rbx: read and write
        let (_, p) = plan(&[0x48, 0x01, 0x18], 0x400000, &r);
        assert_eq!(p, vec![Planned { addr: 0x1000, size: 8, read: true, write: true }]);
        // push rbx writes below rsp
        let (_, p) = plan(&[0x53], 0x400000, &r);
        assert_eq!(p, vec![Planned { addr: 0x6ff8, size: 8, read: false, write: true }]);
        // mov rax, [rip+0x10] at 0x400000 (7 bytes) reads 0x400017
        let (_, p) = plan(&[0x48, 0x8b, 0x05, 0x10, 0, 0, 0], 0x400000, &r);
        assert_eq!(p, vec![Planned { addr: 0x400017, size: 8, read: true, write: false }]);
        // mov rax, fs:[0x28]
        let (_, p) = plan(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0], 0x400000, &r);
        assert_eq!(p[0].addr, 0x9000_0028);
        // lea touches no memory; nop neither
        assert!(plan(&[0x48, 0x8d, 0x40, 0x08], 0, &r).1.is_empty());
        assert_eq!(plan(&[0x90], 0, &r), (1, vec![]));
        assert_eq!(plan(&[0x0f, 0xff], 0, &r).0, 0, "invalid");
    }

    /// A tiny machine: rax += 1 and stores it at [0x100] each step.
    struct Fake {
        rax: u64,
        rip: u64,
        mem: [u8; 0x200],
    }

    impl Stepper for Fake {
        fn regs(&mut self) -> Result<Regs, String> {
            let mut r = [0u64; NREG];
            r[0] = self.rax;
            r[RIP] = self.rip;
            Ok(r)
        }
        fn read(&mut self, addr: u64, buf: &mut [u8]) -> bool {
            // code: "mov [0x100], rax" at every rip in 0x1000..
            if addr >= 0x1000 {
                let c = [0x48, 0x89, 0x04, 0x25, 0x00, 0x01, 0x00, 0x00];
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = *c.get(i).unwrap_or(&0x90);
                }
                return true;
            }
            let a = addr as usize;
            if a + buf.len() > self.mem.len() {
                return false;
            }
            buf.copy_from_slice(&self.mem[a..a + buf.len()]);
            true
        }
        fn step(&mut self) -> Result<Option<String>, String> {
            self.mem[0x100..0x108].copy_from_slice(&self.rax.to_le_bytes());
            self.rax += 1;
            self.rip += 8;
            Ok(None)
        }
    }

    #[test]
    fn stepping_recorder_records_writes_and_limits() {
        let mut f = Fake { rax: 5, rip: 0x1000, mem: [0; 0x200] };
        let lim = Limits { max_steps: 50, until: Some(0x1000 + 8 * 20), max_bytes: 1 << 20, keyframe: 8 };
        let t = record_steps(&mut f, Meta::default(), &lim).unwrap();
        assert_eq!(t.len(), 20);
        assert_eq!(t.meta.stop_reason, "until");
        assert_eq!(t.regs_at(0)[0], 5);
        assert_eq!(t.regs_at(20)[0], 25);
        // the qword at 0x100 before step 3 holds what step 2 stored (rax = 7)
        let m: Vec<u8> = t.mem_at(0x100, 8, 3).into_iter().map(|b| b.unwrap()).collect();
        assert_eq!(m, 7u64.to_le_bytes());
        assert_eq!(t.mem_at(0x100, 1, 0), vec![Some(0)]);
        let h = t.last_write(0x100, 8, 10, true).unwrap();
        assert_eq!(h.step, 9);
        let q = query(&t, &json!({ "kind": "last_write", "address": "0x100", "size": 8, "pos": 10 }).as_object().unwrap().clone()).unwrap();
        assert_eq!(q["write"]["step"], 9, "{q}");
        assert!(q["write"]["text"].as_str().unwrap().contains("mov"), "{q}");
        let lim = Limits { max_steps: 5, until: None, max_bytes: 1 << 20, keyframe: 8 };
        let t = record_steps(&mut f, Meta::default(), &lim).unwrap();
        assert_eq!((t.len(), t.meta.stop_reason.as_str()), (5, "count"));
    }

    #[test]
    fn query_kinds() {
        let mut f = Fake { rax: 0, rip: 0x1000, mem: [0; 0x200] };
        let t = record_steps(&mut f, Meta::default(), &Limits { max_steps: 30, until: None, max_bytes: 1 << 20, keyframe: 4 }).unwrap();
        let q = |v: Value| query(&t, v.as_object().unwrap()).unwrap();
        assert_eq!(q(json!({ "kind": "reg_at", "pos": 12, "reg": "rax" }))["value"], "0xc");
        assert_eq!(q(json!({ "kind": "mem_at", "pos": 12, "address": "0x100", "size": 9 }))["data"], "0b00000000000000??");
        assert_eq!(q(json!({ "kind": "writes_to", "address": "0x104", "size": 1 }))["total"], 30);
        assert_eq!(q(json!({ "kind": "executions_of", "address": "0x1008" }))["steps"], json!([1]));
        assert_eq!(q(json!({ "kind": "seek", "address": "0x1010", "pos": 0 }))["step"], 2);
        assert_eq!(q(json!({ "kind": "steps", "from": 28, "count": 10 }))["steps"].as_array().unwrap().len(), 2);
        assert_eq!(q(json!({ "kind": "step", "pos": 3 }))["accesses"][0]["kind"], "write");
        assert_eq!(q(json!({ "kind": "reg_series", "reg": "rax", "max": 4 }))["points"].as_array().unwrap().len(), 4);
        assert!(q(json!({ "kind": "taint", "address": "0x100", "size": 8, "pos": 5 }))["hops"].as_array().unwrap().len() >= 2);
        assert_eq!(q(json!({ "kind": "touched" }))["ranges"][0]["address"], "0x100");
        assert!(query(&t, json!({ "kind": "nope" }).as_object().unwrap()).is_err());
    }
}
