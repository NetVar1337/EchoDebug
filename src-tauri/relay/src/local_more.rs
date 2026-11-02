//! Local-backend counterparts of the newer agent verbs: page hashing, memory snapshots and diffs,
//! pointer maps on disk, object instances by vtable, cross-reference scanning, the write journal,
//! per-verb stats and job cancellation.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::local::{arg_addr, hex_addr, hex_bytes, MemIo};

/// Set by `cancel`, checked by long local jobs (emulation, pointer scans); cleared when one starts.
pub static CANCEL: AtomicBool = AtomicBool::new(false);

fn bad(detail: &str) -> Value {
    json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": detail })
}

fn failed(detail: impl Into<String>) -> Value {
    json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": detail.into() })
}

fn data_dir() -> std::path::PathBuf {
    crate::auth::config_dir()
}

// ---- journal ------------------------------------------------------------------------------------

pub fn journal(kind: &str, addr: u64, old: &[u8], new: &[u8]) {
    let dir = data_dir();
    let _ = std::fs::create_dir_all(&dir);
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let target = crate::local::attached_pid().map(|p| p.to_string()).unwrap_or_default();
    let line = json!({ "t": t, "kind": kind, "target": target, "address": hex_addr(addr), "old": hex_bytes(old), "new": hex_bytes(new) });
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("journal.jsonl")) {
        let _ = writeln!(f, "{line}");
    }
}

pub fn journal_verb(req: &Map<String, Value>) -> Value {
    let limit = req.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
    let path = data_dir().join("journal.jsonl");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    let entries: Vec<Value> = lines[lines.len().saturating_sub(limit)..].iter().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let clear = req.get("clear").and_then(Value::as_bool).unwrap_or(false);
    if clear {
        let _ = std::fs::remove_file(&path);
    }
    json!({ "type": "journal_result", "success": true, "entries": entries, "cleared": clear })
}

// ---- stats and cancel ---------------------------------------------------------------------------

static STATS: Mutex<Option<HashMap<String, (u64, u128)>>> = Mutex::new(None);

pub fn stat(verb: &str, t0: Instant) {
    let mut g = STATS.lock().unwrap_or_else(|e| e.into_inner());
    let e = g.get_or_insert_with(HashMap::new).entry(verb.to_owned()).or_insert((0, 0));
    e.0 += 1;
    e.1 += t0.elapsed().as_millis();
}

pub fn stats() -> Value {
    let g = STATS.lock().unwrap_or_else(|e| e.into_inner());
    let mut verbs: Vec<Value> = g.as_ref().map(|m| m.iter().map(|(k, (n, ms))| json!({ "verb": k, "calls": n, "ms": ms })).collect()).unwrap_or_default();
    verbs.sort_by(|a, b| a["verb"].as_str().cmp(&b["verb"].as_str()));
    json!({ "type": "stats_result", "success": true, "verbs": verbs, "job": "", "backend": "local" })
}

pub fn cancel() -> Value {
    CANCEL.store(true, Ordering::SeqCst);
    json!({ "type": "cancel_result", "success": true, "cancelling": true })
}

// ---- page hashes --------------------------------------------------------------------------------

/// 64-bit FNV-1a over the page's qwords, like the agent; unreadable pages hash to 0.
pub fn page_hash(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for q in b.as_chunks::<8>().0 {
        h ^= u64::from_le_bytes(*q);
        h = h.wrapping_mul(0x100000001b3);
    }
    h | 1
}

pub fn hash_pages(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(ranges) = req.get("ranges").and_then(Value::as_array) else { return bad("hash_pages requires 'ranges' ([{address, size}])") };
    let mut out = Vec::new();
    let mut total = 0u64;
    for r in ranges {
        let (Some(a), Some(n)) = (r.get("address").and_then(addr_of), r.get("size").and_then(addr_of)) else { return bad("each range needs address and size") };
        let a = a & !0xfff;
        let n = n.div_ceil(0x1000) * 0x1000;
        total += n;
        if total > 64 << 20 {
            return json!({ "type": "error", "code": 3005, "message": "limit exceeded", "detail": "at most 64 MiB per request" });
        }
        let mut packed = String::with_capacity((n / 0x1000) as usize * 16);
        let mut page = vec![0u8; 0x1000];
        let mut p = a;
        while p < a + n {
            let h = if mem.read_at(p, &mut page).map(|k| k == 0x1000).unwrap_or(false) { page_hash(&page) } else { 0 };
            packed.push_str(&format!("{h:016x}"));
            p += 0x1000;
        }
        out.push(json!({ "address": hex_addr(a), "pages": n / 0x1000, "hashes": packed }));
    }
    json!({ "type": "hash_pages_result", "success": true, "ranges": out })
}

fn addr_of(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

// ---- memory snapshots ---------------------------------------------------------------------------

struct Snap {
    base: u64,
    data: Vec<u8>,
    ok: Vec<bool>, // per 64 KiB chunk
}

static SNAPS: Mutex<Option<Vec<(String, Snap)>>> = Mutex::new(None);
const SNAP_CHUNK: u64 = 0x10000;

fn snap_read(mem: &impl MemIo, base: u64, size: u64) -> Snap {
    let mut data = vec![0u8; size as usize];
    let mut ok = Vec::new();
    let mut o = 0u64;
    while o < size {
        let n = SNAP_CHUNK.min(size - o) as usize;
        let good = mem.read_at(base + o, &mut data[o as usize..o as usize + n]).map(|k| k == n).unwrap_or(false);
        if !good {
            data[o as usize..o as usize + n].fill(0);
        }
        ok.push(good);
        o += SNAP_CHUNK;
    }
    Snap { base, data, ok }
}

fn snap_range(mem: &impl MemIo, req: &Map<String, Value>) -> Result<(u64, u64), String> {
    if let Some(m) = req.get("module").and_then(Value::as_str) {
        let mods = mem.modules().map_err(|e| e.to_string())?;
        return mods.iter().find(|(n, _, _)| n.eq_ignore_ascii_case(m)).map(|(_, b, s)| (*b, *s)).ok_or(format!("module not found: {m}"));
    }
    match (arg_addr(req, "address"), req.get("size").and_then(addr_of)) {
        (Some(a), Some(n)) => Ok((a, n)),
        _ => Err("pass address and size, or module".into()),
    }
}

pub fn mem_snapshot(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let name = req.get("name").and_then(Value::as_str).unwrap_or("default").to_owned();
    let (base, size) = match snap_range(mem, req) {
        Ok(r) => r,
        Err(e) => return bad(&e),
    };
    if size == 0 || size > 16 << 20 {
        return json!({ "type": "error", "code": 3005, "message": "limit exceeded", "detail": "a snapshot covers 1 byte .. 16 MiB" });
    }
    let snap = snap_read(mem, base, size);
    let mut g = SNAPS.lock().unwrap_or_else(|e| e.into_inner());
    let list = g.get_or_insert_with(Vec::new);
    list.retain(|(n, _)| *n != name);
    if list.len() >= 8 {
        list.remove(0);
    }
    list.push((name.clone(), snap));
    json!({ "type": "mem_snapshot_result", "success": true, "name": name, "address": hex_addr(base), "size": size })
}

pub fn mem_diff(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let name = req.get("name").and_then(Value::as_str).unwrap_or("default").to_owned();
    let max = req.get("max_ranges").and_then(Value::as_u64).unwrap_or(2000) as usize;
    let update = req.get("update").and_then(Value::as_bool).unwrap_or(false);
    let mut g = SNAPS.lock().unwrap_or_else(|e| e.into_inner());
    let Some((_, snap)) = g.get_or_insert_with(Vec::new).iter_mut().find(|(n, _)| *n == name) else { return failed(format!("no snapshot named {name}")) };
    let cur = snap_read(mem, snap.base, snap.data.len() as u64);
    let (old, new) = (&snap.data, &cur.data);
    let mut ranges = Vec::new();
    let mut changed = 0u64;
    let mut i = 0usize;
    while i < old.len() {
        let chunk_ok = snap.ok[i / SNAP_CHUNK as usize] && cur.ok[i / SNAP_CHUNK as usize];
        if old[i] == new[i] || !chunk_ok {
            i += 1;
            continue;
        }
        let mut j = i;
        // merge changes separated by up to 8 unchanged bytes
        let mut k = i + 1;
        while k < old.len() && k <= j + 8 {
            if old[k] != new[k] {
                j = k;
            }
            k += 1;
        }
        changed += (j - i + 1) as u64;
        if ranges.len() < max {
            let end = (j + 1).min(i + 32);
            ranges.push(json!({ "address": hex_addr(snap.base + i as u64), "size": j - i + 1, "old": hex_bytes(&old[i..end]), "new": hex_bytes(&new[i..end]) }));
        }
        i = j + 1;
    }
    let truncated = ranges.len() >= max;
    if update {
        *snap = cur;
    }
    json!({ "type": "mem_diff_result", "success": true, "name": name, "changed_bytes": changed, "ranges": ranges, "truncated": truncated })
}

pub fn mem_snapshot_list() -> Value {
    let g = SNAPS.lock().unwrap_or_else(|e| e.into_inner());
    let list: Vec<Value> = g.as_ref().map(|l| l.iter().map(|(n, s)| json!({ "name": n, "address": hex_addr(s.base), "size": s.data.len() })).collect()).unwrap_or_default();
    json!({ "type": "mem_snapshot_list_result", "success": true, "snapshots": list })
}

// ---- pointer maps -------------------------------------------------------------------------------

static LAST_PTR: Mutex<Option<Value>> = Mutex::new(None);

pub fn remember_pointer_scan(reply: &Value) {
    if let Some(r) = reply.get("results") {
        *LAST_PTR.lock().unwrap_or_else(|e| e.into_inner()) = Some(r.clone());
    }
}

fn ptr_file(name: &str) -> Option<std::path::PathBuf> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return None;
    }
    Some(data_dir().join("pointer-maps").join(format!("{name}.json")))
}

pub fn ptr_save(req: &Map<String, Value>) -> Value {
    let name = req.get("name").and_then(Value::as_str).unwrap_or("");
    let Some(path) = ptr_file(name) else { return bad("ptr_save needs a 'name' of letters, digits, - and _") };
    let Some(last) = LAST_PTR.lock().unwrap_or_else(|e| e.into_inner()).clone() else { return failed("run pointer_scan first") };
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if let Err(e) = std::fs::write(&path, last.to_string()) {
        return failed(e.to_string());
    }
    json!({ "type": "ptr_save_result", "success": true, "name": name, "paths": last.as_array().map(|a| a.len()).unwrap_or(0), "file": path.display().to_string() })
}

fn ptr_key(e: &Value) -> String {
    format!("{}|{}|{}", e["module"].as_str().unwrap_or(""), e["module_offset"], e["offsets"])
}

pub fn ptr_compare(req: &Map<String, Value>) -> Value {
    let Some(names) = req.get("names").and_then(Value::as_array).filter(|n| n.len() >= 2) else { return bad("ptr_compare needs 'names' (two or more saved maps; '@last' is the last scan)") };
    let mut maps: Vec<Vec<Value>> = Vec::new();
    for n in names {
        let n = n.as_str().unwrap_or("");
        let list = if n == "@last" {
            LAST_PTR.lock().unwrap_or_else(|e| e.into_inner()).clone()
        } else {
            ptr_file(n).and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str::<Value>(&t).ok())
        };
        match list.and_then(|v| v.as_array().cloned()) {
            Some(a) => maps.push(a),
            None => return failed(format!("cannot load pointer map {n}")),
        }
    }
    let mut keep: Vec<Value> = maps[0].clone();
    for other in &maps[1..] {
        let keys: HashSet<String> = other.iter().map(ptr_key).collect();
        keep.retain(|e| keys.contains(&ptr_key(e)));
    }
    json!({ "type": "ptr_compare_result", "success": true, "count": keep.len(), "common": keep })
}

// ---- instances and xrefs ------------------------------------------------------------------------

fn readable(mem: &impl MemIo, writable_only: bool, lo: u64, hi: u64) -> Vec<(u64, u64, bool)> {
    mem.maps()
        .unwrap_or_default()
        .into_iter()
        .filter(|m| m.end > lo && m.start < hi && (!writable_only || m.writable))
        .map(|m| (m.start.max(lo), m.end.min(hi), m.executable))
        .collect()
}

/// Every 8-aligned qword in writable memory that equals the vtable: the objects of that class.
pub fn find_instances(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(vt) = arg_addr(req, "vtable") else { return bad("find_instances needs 'vtable'") };
    let max = req.get("max").and_then(Value::as_u64).unwrap_or(1000).clamp(1, 100_000) as usize;
    let mut out = Vec::new();
    let needle = vt.to_le_bytes();
    'outer: for (lo, hi, _) in readable(mem, true, 0, u64::MAX) {
        let mut pos = lo;
        while pos < hi {
            let n = (hi - pos).min(0x100000) as usize;
            let mut buf = vec![0u8; n];
            if mem.read_at(pos, &mut buf).map(|k| k == n).unwrap_or(false) {
                for (i, q) in buf.as_chunks::<8>().0.iter().enumerate() {
                    if *q == needle {
                        out.push(json!(hex_addr(pos + i as u64 * 8)));
                        if out.len() >= max {
                            break 'outer;
                        }
                    }
                }
            }
            pos += n as u64;
        }
    }
    let mut probe = Map::new();
    probe.insert("address".into(), json!(hex_addr(vt)));
    let cls = crate::local_ext::itanium_vtable_name(mem, vt).unwrap_or_default();
    json!({ "type": "find_instances_result", "success": true, "vtable": hex_addr(vt), "class": cls, "count": out.len(), "instances": out, "truncated": out.len() >= max })
}

pub fn rtti_name(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(a) = arg_addr(req, "address") else { return bad("rtti_name needs 'address'") };
    let object = req.get("object").and_then(Value::as_bool).unwrap_or(false);
    let vt = if object { crate::local_ext::read_u64(mem, a).unwrap_or(0) } else { a };
    let name = crate::local_ext::itanium_vtable_name(mem, vt).unwrap_or_default();
    json!({ "type": "rtti_name_result", "success": true, "vtable": hex_addr(vt), "raw": name, "name": name })
}

/// rel32 calls/jumps and RIP-relative operands that reach `target` (verified by decoding), plus
/// absolute 8-byte pointers to it.
pub fn xref_scan(mem: &impl MemIo, req: &Map<String, Value>) -> Value {
    let Some(target) = arg_addr(req, "target") else { return bad("xref_scan needs 'target'") };
    let max = req.get("max").and_then(Value::as_u64).unwrap_or(500).clamp(1, 100_000) as usize;
    let pointers = req.get("pointers").and_then(Value::as_bool).unwrap_or(true);
    let (lo, hi) = match req.get("module").and_then(Value::as_str) {
        Some(m) => match mem.modules().ok().and_then(|ms| ms.into_iter().find(|(n, _, _)| n.eq_ignore_ascii_case(m))) {
            Some((_, b, s)) => (b, b + s),
            None => return failed(format!("module not found: {m}")),
        },
        None => (0, u64::MAX),
    };
    let mut out: Vec<Value> = Vec::new();
    let mut seen = HashSet::new();
    'outer: for (rlo, rhi, exec) in readable(mem, false, lo, hi) {
        if !exec && !pointers {
            continue;
        }
        let mut pos = rlo;
        while pos < rhi {
            let n = (rhi - pos).min(0x100000) as usize;
            let mut buf = vec![0u8; n + 16];
            let got = mem.read_at(pos, &mut buf).unwrap_or(0);
            if got < 8 {
                pos += n as u64;
                continue;
            }
            buf.truncate(got);
            for o in 0..n.min(got.saturating_sub(4)) {
                let ip = pos + o as u64;
                if exec {
                    let d = i32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]) as i64 as u64;
                    for tail in [0u64, 1, 4] {
                        if ip.wrapping_add(4 + tail).wrapping_add(d) != target {
                            continue;
                        }
                        // find the instruction this displacement belongs to
                        for back in 1..=8usize {
                            if back > o {
                                break;
                            }
                            let start = o - back;
                            if let Some((len, text)) = crate::local::disasm_one(&buf[start..], pos + start as u64) {
                                if len == back + 4 + tail as usize && seen.insert(pos + start as u64) {
                                    let kind = if text.starts_with("call") { "call" } else if text.starts_with('j') { "jump" } else { "riprel" };
                                    out.push(json!({ "address": hex_addr(pos + start as u64), "kind": kind, "text": text }));
                                    break;
                                }
                            }
                        }
                    }
                }
                if pointers && o % 8 == 0 && o + 8 <= got && u64::from_le_bytes(buf[o..o + 8].try_into().unwrap_or([0; 8])) == target && seen.insert(ip) {
                    out.push(json!({ "address": hex_addr(ip), "kind": "pointer" }));
                }
                if out.len() >= max {
                    break 'outer;
                }
            }
            pos += n as u64;
        }
    }
    json!({ "type": "xref_scan_result", "success": true, "target": hex_addr(target), "count": out.len(), "results": out, "truncated": out.len() >= max })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_names() {
        assert_ne!(page_hash(&[0u8; 4096]), page_hash(&[1u8; 4096]));
        assert!(ptr_file("good-name_1").is_some());
        assert!(ptr_file("../escape").is_none());
        let a = json!({ "module": "m", "module_offset": 16, "offsets": [8, 0] });
        let b = json!({ "module": "m", "module_offset": 16, "offsets": [8, 0], "extra": 1 });
        assert_eq!(ptr_key(&a), ptr_key(&b));
    }
}
