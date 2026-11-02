//! Relay-side monitors that work with every backend (Echo agent or the Linux local backend),
//! because they only use the ordinary `modules` and `read` verbs:
//!
//! * module monitor: polls the module list and emits `module_loaded` / `module_unloaded` events
//!   (also kept as a timeline, `module_timeline`);
//! * page monitor: hashes every 4 KiB page of watched ranges each tick and emits `page_changed`
//!   with the pages whose contents changed (self-modifying code, unpacking, patching, data churn).
//!
//! Events go to every /client and, as `notifications/message`, to MCP event streams.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::Relay;

const PAGE: u64 = 0x1000;
const CHUNK: u64 = 0x10000;
const TIMELINE_CAP: usize = 500;
/// total bytes all page monitors may watch
pub const PAGE_BUDGET: u64 = 64 << 20;

#[derive(Default)]
pub struct Monitors {
    module_task: Option<tokio::task::AbortHandle>,
    module_interval: u64,
    timeline: VecDeque<Value>,
    pages: BTreeMap<u64, PageWatch>,
}

struct PageWatch {
    size: u64,
    label: String,
    interval: u64,
    task: tokio::task::AbortHandle,
    changes: u64,
    last_change: u128,
}

impl Drop for Monitors {
    fn drop(&mut self) {
        if let Some(t) = &self.module_task {
            t.abort();
        }
        for p in self.pages.values() {
            p.task.abort();
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn hex_addr(v: u64) -> String {
    format!("0x{v:x}")
}

fn parse_addr(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::String(s) => u64::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// FNV-1a 64 of one page; unreadable pages hash to 0.
pub fn page_hash(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for x in b {
        h ^= u64::from(*x);
        h = h.wrapping_mul(0x100000001b3);
    }
    h | 1
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

/// relay.request behind a boxed future: request() dispatches to the monitors, so a direct call
/// would make the async types recursive.
fn ask(relay: &Relay, req: Map<String, Value>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Value> + Send + '_>> {
    Box::pin(relay.request(Value::Object(req)))
}

fn lock(relay: &Relay) -> std::sync::MutexGuard<'_, Monitors> {
    relay.monitors().lock().unwrap_or_else(|e| e.into_inner())
}

fn module_map(reply: &Value) -> Option<HashMap<(String, u64), u64>> {
    let list = reply.get("modules")?.as_array()?;
    Some(
        list.iter()
            .filter_map(|m| Some(((m["name"].as_str()?.to_owned(), parse_addr(m.get("base"))?), m["size"].as_u64().unwrap_or(0))))
            .collect(),
    )
}

async fn modules_now(relay: &Relay) -> Option<HashMap<(String, u64), u64>> {
    let mut req = Map::new();
    req.insert("type".into(), json!("modules"));
    let r = ask(relay, req).await;
    if r["type"] == "error" {
        return None;
    }
    module_map(&r)
}

/// Pure diff for the module monitor (and its test).
pub fn diff_modules(old: &HashMap<(String, u64), u64>, new: &HashMap<(String, u64), u64>) -> Vec<Value> {
    let mut out = Vec::new();
    let mut added: Vec<_> = new.iter().filter(|(k, _)| !old.contains_key(*k)).collect();
    added.sort_by_key(|((_, b), _)| *b);
    let mut gone: Vec<_> = old.iter().filter(|(k, _)| !new.contains_key(*k)).collect();
    gone.sort_by_key(|((_, b), _)| *b);
    for ((name, base), size) in gone {
        out.push(json!({ "type": "event", "event": "module_unloaded", "name": name, "base": hex_addr(*base), "size": size }));
    }
    for ((name, base), size) in added {
        out.push(json!({ "type": "event", "event": "module_loaded", "name": name, "base": hex_addr(*base), "size": size }));
    }
    out
}

pub async fn module_monitor(relay: &Relay, req: &Map<String, Value>) -> Value {
    let enabled = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let interval = req.get("interval_ms").and_then(Value::as_u64).unwrap_or(1000).clamp(100, 60_000);
    {
        let mut m = lock(relay);
        if let Some(t) = m.module_task.take() {
            t.abort();
        }
        if !enabled {
            return json!({ "type": "module_monitor_result", "success": true, "enabled": false });
        }
        m.module_interval = interval;
    }
    let first = modules_now(relay).await;
    let count = first.as_ref().map(|m| m.len()).unwrap_or(0);
    let r2 = relay.clone();
    let task = tokio::spawn(async move {
        let mut prev = first;
        loop {
            tokio::time::sleep(Duration::from_millis(interval)).await;
            let Some(cur) = modules_now(&r2).await else {
                prev = None; // detached: the next attach starts a fresh baseline
                continue;
            };
            if let Some(p) = &prev {
                let events = diff_modules(p, &cur);
                if !events.is_empty() {
                    let ts = now_ms();
                    {
                        let mut m = lock(&r2);
                        for e in &events {
                            let mut e = e.clone();
                            e["ts"] = json!(ts);
                            if m.timeline.len() >= TIMELINE_CAP {
                                m.timeline.pop_front();
                            }
                            m.timeline.push_back(e);
                        }
                    }
                    for mut e in events {
                        e["ts"] = json!(ts);
                        r2.emit(e);
                    }
                }
            }
            prev = Some(cur);
        }
    });
    lock(relay).module_task = Some(task.abort_handle());
    json!({ "type": "module_monitor_result", "success": true, "enabled": true, "interval_ms": interval, "modules": count })
}

pub fn module_timeline(relay: &Relay) -> Value {
    let m = lock(relay);
    json!({ "type": "module_timeline_result", "success": true, "enabled": m.module_task.is_some(), "interval_ms": m.module_interval, "entries": m.timeline.iter().cloned().collect::<Vec<_>>() })
}

/// Hashes of every page in [start, start+size): one `read` per 64 KiB chunk.
async fn hash_range(relay: &Relay, start: u64, size: u64) -> Vec<u64> {
    let mut out = Vec::with_capacity((size / PAGE) as usize);
    let mut a = start;
    while a < start + size {
        let n = CHUNK.min(start + size - a);
        let mut req = Map::new();
        req.insert("type".into(), json!("read"));
        req.insert("address".into(), json!(hex_addr(a)));
        req.insert("size".into(), json!(n));
        let r = ask(relay, req).await;
        match r["data"].as_str().and_then(hex_to_bytes).filter(|b| b.len() as u64 == n) {
            Some(b) => out.extend(b.chunks(PAGE as usize).map(page_hash)),
            None => {
                // part of the chunk is unmapped: page by page, so the readable pages still count
                let mut p = a;
                while p < a + n {
                    let mut one = Map::new();
                    one.insert("type".into(), json!("read"));
                    one.insert("address".into(), json!(hex_addr(p)));
                    one.insert("size".into(), json!(PAGE));
                    let r = ask(relay, one).await;
                    out.push(r["data"].as_str().and_then(hex_to_bytes).filter(|b| b.len() as u64 == PAGE).map(|b| page_hash(&b)).unwrap_or(0));
                    p += PAGE;
                }
            }
        }
        a += n;
    }
    out
}

pub async fn page_monitor(relay: &Relay, req: &Map<String, Value>) -> Value {
    let Some(addr) = parse_addr(req.get("address")) else {
        return json!({ "type": "error", "code": 2000, "message": "page_monitor requires 'address'" });
    };
    let start = addr & !(PAGE - 1);
    let enabled = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    if !enabled {
        let removed = lock(relay).pages.remove(&start).map(|p| p.task.abort()).is_some();
        return json!({ "type": "page_monitor_result", "success": true, "removed": removed, "watched": lock(relay).pages.len() });
    }
    let size = req.get("size").and_then(Value::as_u64).unwrap_or(PAGE).max(1);
    let size = (addr + size).div_ceil(PAGE) * PAGE - start;
    let interval = req.get("interval_ms").and_then(Value::as_u64).unwrap_or(1000).clamp(100, 60_000);
    let label = req.get("label").and_then(Value::as_str).unwrap_or_default().to_owned();
    {
        let m = lock(relay);
        let used: u64 = m.pages.iter().filter(|(k, _)| **k != start).map(|(_, p)| p.size).sum();
        if used + size > PAGE_BUDGET {
            return json!({ "type": "error", "code": 3005, "message": "limit exceeded", "detail": format!("page monitors watch at most {} MiB in total", PAGE_BUDGET >> 20) });
        }
    }
    let first = hash_range(relay, start, size).await;
    let readable = first.iter().filter(|h| **h != 0).count();
    let (r2, label2) = (relay.clone(), label.clone());
    let task = tokio::spawn(async move {
        let mut prev = first;
        loop {
            tokio::time::sleep(Duration::from_millis(interval)).await;
            let cur = hash_range(&r2, start, size).await;
            if cur.iter().all(|h| *h == 0) {
                continue; // detached or unmapped: keep the baseline
            }
            let changed: Vec<String> = cur.iter().zip(&prev).enumerate().filter(|(_, (a, b))| a != b).map(|(i, _)| hex_addr(start + i as u64 * PAGE)).collect();
            if !changed.is_empty() {
                let ts = now_ms();
                if let Some(p) = lock(&r2).pages.get_mut(&start) {
                    p.changes += changed.len() as u64;
                    p.last_change = ts;
                }
                r2.emit(json!({ "type": "event", "event": "page_changed", "address": hex_addr(start), "size": size, "label": label2, "count": changed.len(), "pages": changed.into_iter().take(256).collect::<Vec<_>>(), "ts": ts }));
            }
            prev = cur;
        }
    });
    let mut m = lock(relay);
    if let Some(old) = m.pages.insert(start, PageWatch { size, label, interval, task: task.abort_handle(), changes: 0, last_change: 0 }) {
        old.task.abort();
    }
    json!({ "type": "page_monitor_result", "success": true, "address": hex_addr(start), "size": size, "pages": size / PAGE, "readable": readable, "interval_ms": interval, "watched": m.pages.len() })
}

pub fn page_monitor_list(relay: &Relay) -> Value {
    let m = lock(relay);
    let list: Vec<Value> = m
        .pages
        .iter()
        .map(|(a, p)| json!({ "address": hex_addr(*a), "size": p.size, "label": p.label, "interval_ms": p.interval, "changes": p.changes, "last_change": p.last_change }))
        .collect();
    json!({ "type": "page_monitor_list_result", "success": true, "entries": list })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs_modules_and_hashes_pages() {
        let a: HashMap<(String, u64), u64> = [(("a.dll".into(), 0x1000), 0x100), (("b.dll".into(), 0x2000), 0x100)].into_iter().collect();
        let b: HashMap<(String, u64), u64> = [(("a.dll".into(), 0x1000), 0x100), (("c.dll".into(), 0x3000), 0x200)].into_iter().collect();
        let ev = diff_modules(&a, &b);
        assert_eq!(ev.len(), 2);
        assert_eq!((ev[0]["event"].as_str(), ev[0]["name"].as_str()), (Some("module_unloaded"), Some("b.dll")));
        assert_eq!((ev[1]["event"].as_str(), ev[1]["base"].as_str()), (Some("module_loaded"), Some("0x3000")));
        assert_ne!(page_hash(&[0; 4096]), 0, "readable pages never hash to the unreadable marker");
        assert_ne!(page_hash(&[0; 4096]), page_hash(&[1; 4096]));
    }
}
