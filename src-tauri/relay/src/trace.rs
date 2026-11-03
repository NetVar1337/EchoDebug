//! Time-travel traces: a recorded run of one thread (or emulator session), instruction by
//! instruction, and the queries that replay it.
//!
//! Model: step `i` is one executed instruction at `pc(i)`; it changed some registers (stored as
//! deltas) and touched memory (reads with the bytes read, writes with the bytes before and after).
//! Position `p` (0..=len) is the machine state *before* step `p`, so `p == len` is the final state.
//! A full register file is kept every `keyframe` steps, so `regs_at` replays at most `keyframe`
//! deltas. Memory at a position is reconstructed for every byte the trace touched: the newest
//! write before the position, else the value the first access saw.
//!
//! The on-disk format (`encode` / `decode`, extension `.edt`) is compact: varints, registers as
//! XOR deltas behind a change mask, pcs and addresses as signed deltas, the keyframes, the
//! instruction bytes per pc, and an FNV-1a checksum. See PROTOCOL.md "Time-travel traces".

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Map, Value};

pub const REG_NAMES: [&str; 20] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "fs_base", "gs_base",
];
pub const NREG: usize = REG_NAMES.len();
pub const RIP: usize = 16;
pub const RSP: usize = 7;
pub type Regs = [u64; NREG];

const MAGIC: &[u8; 8] = b"EDTRACE1";
const VERSION: u64 = 1;
/// Memory is indexed in 8-byte chunks: access ids per chunk.
const CHUNK: u64 = 8;

pub fn reg_index(name: &str) -> Option<usize> {
    REG_NAMES.iter().position(|n| n.eq_ignore_ascii_case(name.trim()))
}

pub fn regs_from_json(v: &Value) -> Regs {
    let mut r = [0u64; NREG];
    for (i, n) in REG_NAMES.iter().enumerate() {
        r[i] = v.get(*n).and_then(parse_u64).unwrap_or(0);
    }
    r
}

pub fn regs_json(r: &Regs) -> Value {
    Value::Object(REG_NAMES.iter().zip(r).map(|(n, v)| ((*n).to_owned(), json!(hex(*v)))).collect())
}

pub fn parse_u64(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => {
            let t = s.trim();
            match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16).ok(),
                None => t.parse().ok(),
            }
        }
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

pub fn hex(v: u64) -> String {
    format!("0x{v:x}")
}

pub fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One memory access as a recorder sees it. For reads `old` is the data read and `new` is empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawAccess {
    pub addr: u64,
    pub write: bool,
    pub old: Vec<u8>,
    pub new: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Acc {
    addr: u64,
    /// offset into `bytes`: `len` bytes (read data / old), then `len` more (new) for writes
    data: u32,
    len: u16,
    write: bool,
}

/// Facts about the recording. `source` is "emu" (Unicorn session), "emu-agent" (the Windows
/// agent's emulator, driven step by step) or "ptrace" (a real thread).
#[derive(Clone, Debug, Default)]
pub struct Meta {
    pub name: String,
    pub source: String,
    pub created_ms: u64,
    pub pid: Option<u32>,
    pub tid: Option<i64>,
    pub stop_reason: String,
    pub truncated: bool,
}

impl Meta {
    fn to_json(&self) -> Value {
        json!({ "name": self.name, "source": self.source, "created_ms": self.created_ms, "pid": self.pid, "tid": self.tid, "stop_reason": self.stop_reason, "truncated": self.truncated })
    }
    fn from_json(v: &Value) -> Meta {
        Meta {
            name: v["name"].as_str().unwrap_or_default().to_owned(),
            source: v["source"].as_str().unwrap_or_default().to_owned(),
            created_ms: v["created_ms"].as_u64().unwrap_or(0),
            pid: v["pid"].as_u64().map(|p| p as u32),
            tid: v["tid"].as_i64(),
            stop_reason: v["stop_reason"].as_str().unwrap_or_default().to_owned(),
            truncated: v["truncated"].as_bool().unwrap_or(false),
        }
    }
}

pub struct Trace {
    pub meta: Meta,
    pub keyframe: u32,
    pcs: Vec<u64>,
    /// deltas[delta_off[i]..delta_off[i + 1]]: registers step i changed (index, new value)
    delta_off: Vec<u32>,
    deltas: Vec<(u8, u64)>,
    acc_off: Vec<u32>,
    accs: Vec<Acc>,
    bytes: Vec<u8>,
    /// instruction bytes per pc (first seen)
    code: BTreeMap<u64, Vec<u8>>,
    /// keyframes[j] = registers before step j * keyframe
    keyframes: Vec<Regs>,
    last: Regs,
    /// chunk (addr / 8) -> access ids, ascending
    index: HashMap<u64, Vec<u32>>,
}

/// One write found by a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriteHit {
    pub step: u32,
    pub pc: u64,
    pub addr: u64,
    pub old: Vec<u8>,
    pub new: Vec<u8>,
}

impl WriteHit {
    pub fn json(&self) -> Value {
        json!({ "step": self.step, "pc": hex(self.pc), "address": hex(self.addr), "size": self.old.len(), "old": hex_bytes(&self.old), "new": hex_bytes(&self.new) })
    }
}

/// One read found by a query: (step, pc, address, bytes read).
pub type ReadHit = (u32, u64, u64, Vec<u8>);

/// Builds a trace step by step (the recorders feed it).
pub struct Builder {
    t: Trace,
    prev: Regs,
}

impl Builder {
    pub fn new(meta: Meta, init: Regs, keyframe: u32) -> Builder {
        let k = keyframe.clamp(1, 1 << 20);
        Builder {
            t: Trace { meta, keyframe: k, pcs: Vec::new(), delta_off: vec![0], deltas: Vec::new(), acc_off: vec![0], accs: Vec::new(), bytes: Vec::new(), code: BTreeMap::new(), keyframes: Vec::new(), last: init, index: HashMap::new() },
            prev: init,
        }
    }

    pub fn len(&self) -> usize {
        self.t.pcs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.t.pcs.is_empty()
    }

    pub fn has_code(&self, pc: u64) -> bool {
        self.t.code.contains_key(&pc)
    }

    /// Approximate memory held, in bytes (the recorders' size bound).
    pub fn size_bytes(&self) -> usize {
        self.t.pcs.len() * 16 + self.t.deltas.len() * 16 + self.t.accs.len() * 16 + self.t.bytes.len() + self.t.keyframes.len() * NREG * 8 + self.t.code.len() * 40
    }

    /// Step `pc` (bytes `code`, may be empty when already known) left the registers at `after`.
    pub fn step(&mut self, pc: u64, code: &[u8], after: &Regs, accesses: &[RawAccess]) {
        let i = self.t.pcs.len() as u32;
        if i.is_multiple_of(self.t.keyframe) {
            self.t.keyframes.push(self.prev);
        }
        self.t.pcs.push(pc);
        if !code.is_empty() {
            self.t.code.entry(pc).or_insert_with(|| code[..code.len().min(15)].to_vec());
        }
        for (r, (a, b)) in self.prev.iter().zip(after).enumerate() {
            if a != b {
                self.t.deltas.push((r as u8, *b));
            }
        }
        self.t.delta_off.push(self.t.deltas.len() as u32);
        for a in accesses {
            let len = a.old.len().min(u16::MAX as usize);
            if len == 0 {
                continue;
            }
            let data = self.t.bytes.len() as u32;
            self.t.bytes.extend_from_slice(&a.old[..len]);
            if a.write {
                let mut n = a.new.clone();
                n.resize(len, 0);
                self.t.bytes.extend_from_slice(&n);
            }
            self.t.accs.push(Acc { addr: a.addr, data, len: len as u16, write: a.write });
        }
        self.t.acc_off.push(self.t.accs.len() as u32);
        self.prev = *after;
        self.t.last = *after;
    }

    pub fn finish(mut self) -> Trace {
        if self.t.keyframes.is_empty() {
            self.t.keyframes.push(self.prev);
        }
        self.t.build_index();
        self.t
    }
}

/// A place a value can live, for dataflow queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Loc {
    Reg(usize),
    Mem(u64, u16),
}

impl Loc {
    fn json(&self) -> Value {
        match self {
            Loc::Reg(r) => json!({ "kind": "reg", "reg": REG_NAMES[*r] }),
            Loc::Mem(a, n) => json!({ "kind": "mem", "address": hex(*a), "size": n }),
        }
    }
}

impl Trace {
    pub fn len(&self) -> usize {
        self.pcs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pcs.is_empty()
    }

    pub fn pc(&self, i: usize) -> u64 {
        self.pcs[i]
    }

    pub fn code_at(&self, pc: u64) -> &[u8] {
        self.code.get(&pc).map(Vec::as_slice).unwrap_or(&[])
    }

    fn build_index(&mut self) {
        let mut idx: HashMap<u64, Vec<u32>> = HashMap::new();
        for (i, a) in self.accs.iter().enumerate() {
            let first = a.addr / CHUNK;
            let last = (a.addr.saturating_add(a.len as u64 - 1)) / CHUNK;
            for c in first..=last {
                idx.entry(c).or_default().push(i as u32);
            }
        }
        self.index = idx;
    }

    /// Step that owns access `a` (binary search in the offsets).
    fn step_of_acc(&self, a: u32) -> u32 {
        (self.acc_off.partition_point(|&o| o <= a) - 1) as u32
    }

    fn acc_old(&self, a: &Acc) -> &[u8] {
        &self.bytes[a.data as usize..a.data as usize + a.len as usize]
    }

    fn acc_new(&self, a: &Acc) -> &[u8] {
        if a.write {
            &self.bytes[a.data as usize + a.len as usize..a.data as usize + 2 * a.len as usize]
        } else {
            self.acc_old(a)
        }
    }

    pub fn deltas_of(&self, i: usize) -> &[(u8, u64)] {
        &self.deltas[self.delta_off[i] as usize..self.delta_off[i + 1] as usize]
    }

    /// Registers before step `pos` (`pos == len()`: after the last step).
    pub fn regs_at(&self, pos: usize) -> Regs {
        let pos = pos.min(self.len());
        let k = self.keyframe as usize;
        let kf = (pos / k).min(self.keyframes.len() - 1);
        let mut r = self.keyframes[kf];
        for i in kf * k..pos {
            for (reg, v) in self.deltas_of(i) {
                r[*reg as usize] = *v;
            }
        }
        r
    }

    pub fn final_regs(&self) -> Regs {
        self.last
    }

    /// The value of one register at up to `max` evenly spaced positions in from..=to, plus every
    /// position where it changed when that fits.
    pub fn reg_series(&self, reg: usize, from: usize, to: usize, max: usize) -> Vec<(usize, u64)> {
        let to = to.min(self.len());
        let from = from.min(to);
        let mut v = self.regs_at(from)[reg];
        let mut changes = vec![(from, v)];
        for i in from..to {
            if let Some((_, nv)) = self.deltas_of(i).iter().find(|(r, _)| *r as usize == reg) {
                v = *nv;
                changes.push((i + 1, v));
            }
        }
        if changes.len() <= max.max(2) {
            if changes.last().map(|c| c.0) != Some(to) {
                changes.push((to, v));
            }
            return changes;
        }
        // too many changes: sample the step function
        let max = max.max(2);
        let mut out = Vec::with_capacity(max);
        let mut j = 0;
        for s in 0..max {
            let p = from + (to - from) * s / (max - 1);
            while j + 1 < changes.len() && changes[j + 1].0 <= p {
                j += 1;
            }
            out.push((p, changes[j].1));
        }
        out
    }

    /// Accesses touching byte `b`, as access ids in step order.
    fn accesses_at(&self, b: u64) -> impl Iterator<Item = u32> + '_ {
        self.index.get(&(b / CHUNK)).into_iter().flatten().copied().filter(move |&i| {
            let a = &self.accs[i as usize];
            b >= a.addr && b < a.addr + a.len as u64
        })
    }

    /// Memory before step `pos`; None for bytes the trace never touched.
    pub fn mem_at(&self, addr: u64, len: usize, pos: usize) -> Vec<Option<u8>> {
        let limit = self.acc_off[pos.min(self.len())];
        (0..len as u64)
            .map(|o| {
                let b = addr.wrapping_add(o);
                let mut first: Option<u32> = None;
                let mut last_write: Option<u32> = None;
                for i in self.accesses_at(b) {
                    if first.is_none() {
                        first = Some(i);
                    }
                    if i < limit && self.accs[i as usize].write {
                        last_write = Some(i);
                    }
                }
                if let Some(w) = last_write {
                    let a = &self.accs[w as usize];
                    return Some(self.acc_new(a)[(b - a.addr) as usize]);
                }
                first.map(|f| {
                    let a = &self.accs[f as usize];
                    self.acc_old(a)[(b - a.addr) as usize]
                })
            })
            .collect()
    }

    fn write_hit(&self, i: u32) -> WriteHit {
        let a = &self.accs[i as usize];
        let step = self.step_of_acc(i);
        WriteHit { step, pc: self.pcs[step as usize], addr: a.addr, old: self.acc_old(a).to_vec(), new: self.acc_new(a).to_vec() }
    }

    fn writes_overlapping(&self, addr: u64, len: u64) -> Vec<u32> {
        let end = addr.saturating_add(len.max(1));
        let mut ids: Vec<u32> = (addr / CHUNK..=(end - 1) / CHUNK)
            .take(1 << 16)
            .filter_map(|c| self.index.get(&c))
            .flatten()
            .copied()
            .filter(|&i| {
                let a = &self.accs[i as usize];
                a.write && a.addr < end && a.addr + a.len as u64 > addr
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// The newest write before `pos` to any byte of addr..addr+len. With `changed_only`, writes
    /// that stored the bytes already there (over the queried range) are skipped.
    pub fn last_write(&self, addr: u64, len: u64, pos: usize, changed_only: bool) -> Option<WriteHit> {
        let limit = self.acc_off[pos.min(self.len())];
        self.writes_overlapping(addr, len).into_iter().rev().filter(|&i| i < limit).map(|i| self.write_hit(i)).find(|h| {
            if !changed_only {
                return true;
            }
            let lo = addr.max(h.addr);
            let hi = (addr + len.max(1)).min(h.addr + h.old.len() as u64);
            (lo..hi).any(|b| h.old[(b - h.addr) as usize] != h.new[(b - h.addr) as usize])
        })
    }

    pub fn writes_to(&self, addr: u64, len: u64, limit: usize) -> (Vec<WriteHit>, usize) {
        let ids = self.writes_overlapping(addr, len);
        let n = ids.len();
        (ids.into_iter().take(limit).map(|i| self.write_hit(i)).collect(), n)
    }

    /// Steps that read any byte of addr..addr+len.
    pub fn reads_of(&self, addr: u64, len: u64, limit: usize) -> (Vec<ReadHit>, usize) {
        let end = addr.saturating_add(len.max(1));
        let mut ids: Vec<u32> = (addr / CHUNK..=(end - 1) / CHUNK).take(1 << 16).filter_map(|c| self.index.get(&c)).flatten().copied()
            .filter(|&i| { let a = &self.accs[i as usize]; !a.write && a.addr < end && a.addr + a.len as u64 > addr }).collect();
        ids.sort_unstable();
        ids.dedup();
        let n = ids.len();
        (ids.into_iter().take(limit).map(|i| { let a = &self.accs[i as usize]; let s = self.step_of_acc(i); (s, self.pcs[s as usize], a.addr, self.acc_old(a).to_vec()) }).collect(), n)
    }

    pub fn executions_of(&self, pc: u64, limit: usize) -> (Vec<usize>, usize) {
        let all: Vec<usize> = self.pcs.iter().enumerate().filter(|(_, p)| **p == pc).map(|(i, _)| i).collect();
        let n = all.len();
        (all.into_iter().take(limit).collect(), n)
    }

    /// The next (forward) or previous step that executes `pc`, strictly after / before `from`.
    pub fn seek_pc(&self, pc: u64, from: usize, forward: bool) -> Option<usize> {
        if forward {
            self.pcs.iter().enumerate().skip(from + 1).find(|(_, p)| **p == pc).map(|(i, _)| i)
        } else {
            self.pcs[..from.min(self.len())].iter().rposition(|p| *p == pc)
        }
    }

    pub fn accesses_of_step(&self, i: usize) -> Vec<RawAccess> {
        self.accs[self.acc_off[i] as usize..self.acc_off[i + 1] as usize]
            .iter()
            .map(|a| RawAccess { addr: a.addr, write: a.write, old: self.acc_old(a).to_vec(), new: if a.write { self.acc_new(a).to_vec() } else { Vec::new() } })
            .collect()
    }

    /// Memory ranges the trace touched, merged (address, size, reads, writes).
    pub fn touched(&self) -> Vec<(u64, u64, u32, u32)> {
        let mut v: Vec<(u64, u64, bool)> = self.accs.iter().map(|a| (a.addr, a.addr + a.len as u64, a.write)).collect();
        v.sort_unstable_by_key(|x| x.0);
        let mut out: Vec<(u64, u64, u32, u32)> = Vec::new();
        for (lo, hi, w) in v {
            match out.last_mut() {
                Some(l) if lo <= l.0 + l.1 => {
                    l.1 = l.1.max(hi - l.0);
                    if w { l.3 += 1 } else { l.2 += 1 }
                }
                _ => out.push((lo, hi - lo, u32::from(!w), u32::from(w))),
            }
        }
        out
    }

    pub fn unique_pcs(&self) -> usize {
        self.pcs.iter().collect::<HashSet<_>>().len()
    }

    pub fn size_bytes(&self) -> usize {
        self.pcs.len() * 16 + self.deltas.len() * 16 + self.accs.len() * 16 + self.bytes.len() + self.keyframes.len() * NREG * 8 + self.code.len() * 40
    }

    pub fn summary(&self) -> Value {
        let mut m = match self.meta.to_json() { Value::Object(m) => m, _ => Map::new() };
        m.insert("steps".into(), json!(self.len()));
        m.insert("keyframe".into(), json!(self.keyframe));
        m.insert("keyframes".into(), json!(self.keyframes.len()));
        m.insert("unique_pcs".into(), json!(self.unique_pcs()));
        m.insert("accesses".into(), json!(self.accs.len()));
        m.insert("writes".into(), json!(self.accs.iter().filter(|a| a.write).count()));
        m.insert("memory_bytes".into(), json!(self.size_bytes()));
        m.insert("first_pc".into(), json!(self.pcs.first().map(|p| hex(*p))));
        m.insert("initial_regs".into(), regs_json(&self.keyframes[0]));
        m.insert("final_regs".into(), regs_json(&self.last));
        Value::Object(m)
    }

    // ---- encoding ---------------------------------------------------------------------------

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(self.size_bytes() / 2 + 64);
        o.extend_from_slice(MAGIC);
        put(&mut o, VERSION);
        let mut meta = self.meta.to_json();
        meta["steps"] = json!(self.len());
        meta["keyframe"] = json!(self.keyframe);
        meta["regs"] = json!(REG_NAMES);
        let mj = meta.to_string().into_bytes();
        put(&mut o, mj.len() as u64);
        o.extend_from_slice(&mj);
        let init = self.keyframes[0];
        for v in init {
            o.extend_from_slice(&v.to_le_bytes());
        }
        put(&mut o, self.len() as u64);
        let mut prev = init;
        let mut prev_pc = init[RIP];
        let mut prev_addr = 0u64;
        for i in 0..self.len() {
            put_i(&mut o, self.pcs[i].wrapping_sub(prev_pc) as i64);
            prev_pc = self.pcs[i];
            let d = self.deltas_of(i);
            let mask = d.iter().fold(0u64, |m, (r, _)| m | 1 << r);
            put(&mut o, mask);
            for (r, v) in d {
                put(&mut o, v ^ prev[*r as usize]);
                prev[*r as usize] = *v;
            }
            let accs = &self.accs[self.acc_off[i] as usize..self.acc_off[i + 1] as usize];
            put(&mut o, accs.len() as u64);
            for a in accs {
                put(&mut o, (a.len as u64) << 1 | u64::from(a.write));
                put_i(&mut o, a.addr.wrapping_sub(prev_addr) as i64);
                prev_addr = a.addr;
                let n = a.len as usize * if a.write { 2 } else { 1 };
                o.extend_from_slice(&self.bytes[a.data as usize..a.data as usize + n]);
            }
        }
        put(&mut o, self.code.len() as u64);
        let mut prev_pc = 0u64;
        for (pc, b) in &self.code {
            put(&mut o, pc - prev_pc);
            prev_pc = *pc;
            o.push(b.len() as u8);
            o.extend_from_slice(b);
        }
        put(&mut o, self.keyframes.len() as u64);
        let mut prev = [0u64; NREG];
        for k in &self.keyframes {
            for (r, v) in k.iter().enumerate() {
                put(&mut o, v ^ prev[r]);
            }
            prev = *k;
        }
        let sum = fnv(&o);
        o.extend_from_slice(&sum.to_le_bytes());
        o
    }

    /// Meta of an encoded trace without decoding the steps (trace lists).
    pub fn peek_meta(data: &[u8]) -> Result<Value, String> {
        let mut r = Reader { b: data, i: 0 };
        if r.take(8)? != MAGIC {
            return Err("not an EchoDebug trace (bad magic)".into());
        }
        let ver = r.get()?;
        if ver != VERSION {
            return Err(format!("unsupported trace version {ver}"));
        }
        let n = r.get()? as usize;
        serde_json::from_slice(r.take(n)?).map_err(|e| format!("bad trace header: {e}"))
    }

    pub fn decode(data: &[u8]) -> Result<Trace, String> {
        if data.len() < 16 {
            return Err("trace file too short".into());
        }
        let (body, sum) = data.split_at(data.len() - 8);
        if fnv(body).to_le_bytes() != sum {
            return Err("trace checksum mismatch (file damaged)".into());
        }
        let meta_v = Trace::peek_meta(body)?;
        let mut r = Reader { b: body, i: 0 };
        r.take(8)?;
        r.get()?;
        let n = r.get()? as usize;
        r.take(n)?;
        if meta_v["regs"].as_array().map(|a| a.len()) != Some(NREG) {
            return Err("trace register set does not match".into());
        }
        let mut init = [0u64; NREG];
        for v in init.iter_mut() {
            *v = u64::from_le_bytes(r.take(8)?.try_into().map_err(|_| "short")?);
        }
        let keyframe = meta_v["keyframe"].as_u64().unwrap_or(256) as u32;
        let mut b = Builder::new(Meta::from_json(&meta_v), init, keyframe);
        let steps = r.get()? as usize;
        let mut prev = init;
        let mut prev_pc = init[RIP];
        let mut prev_addr = 0u64;
        let mut accs = Vec::new();
        for _ in 0..steps {
            let pc = prev_pc.wrapping_add(r.get_i()? as u64);
            prev_pc = pc;
            let mask = r.get()?;
            if mask >> NREG != 0 {
                return Err("bad register mask".into());
            }
            let mut after = prev;
            for reg in 0..NREG {
                if mask & 1 << reg != 0 {
                    after[reg] = prev[reg] ^ r.get()?;
                }
            }
            accs.clear();
            let na = r.get()? as usize;
            for _ in 0..na {
                let f = r.get()?;
                let len = (f >> 1) as usize;
                let write = f & 1 == 1;
                let addr = prev_addr.wrapping_add(r.get_i()? as u64);
                prev_addr = addr;
                let old = r.take(len)?.to_vec();
                let new = if write { r.take(len)?.to_vec() } else { Vec::new() };
                accs.push(RawAccess { addr, write, old, new });
            }
            b.step(pc, &[], &after, &accs);
            prev = after;
        }
        let nc = r.get()? as usize;
        let mut pc = 0u64;
        for _ in 0..nc {
            pc = pc.wrapping_add(r.get()?);
            let l = r.take(1)?[0] as usize;
            b.t.code.insert(pc, r.take(l)?.to_vec());
        }
        let nk = r.get()? as usize;
        let mut kprev = [0u64; NREG];
        // every keyframe takes at least NREG bytes of the file, so a count read from the file
        // cannot size the allocation (2^63 was a capacity-overflow panic, in release too)
        let mut stored = Vec::with_capacity(nk.min(r.b.len() / NREG));
        for _ in 0..nk {
            let mut k = [0u64; NREG];
            for (reg, v) in k.iter_mut().enumerate() {
                *v = kprev[reg] ^ r.get()?;
            }
            kprev = k;
            stored.push(k);
        }
        let t = b.finish();
        if stored != t.keyframes {
            return Err("trace keyframes do not match the steps (file damaged)".into());
        }
        Ok(t)
    }

    // ---- dataflow ("where did this value come from?") ----------------------------------------

    /// Walks back from `loc` as it is before `pos` through the instructions that produced it.
    /// Returns hops `{id, parent, step, pc, text, loc, value, kind, sources}`; `kind` is `mov`,
    /// `arith`, `const` (an immediate or a self-clearing idiom), `initial` (already there when
    /// the trace started) or `unmodeled` (an instruction the walk does not model).
    pub fn taint(&self, pos: usize, loc: Loc, max_hops: usize) -> Vec<Value> {
        let mut out = Vec::new();
        let mut queue: std::collections::VecDeque<(Loc, usize, Option<usize>)> = [(loc, pos.min(self.len()), None)].into();
        let mut seen: HashSet<(Loc, usize)> = HashSet::new();
        let mut infos: HashMap<u64, Option<flow::Info>> = HashMap::new();
        while let Some((loc, before, parent)) = queue.pop_front() {
            if out.len() >= max_hops.max(1) {
                break;
            }
            let id = out.len();
            let def = match loc {
                Loc::Mem(a, n) => self.last_write(a, n as u64, before, false).map(|h| h.step as usize),
                Loc::Reg(r) => (0..before).rev().take(2_000_000).find(|&s| {
                    let pc = self.pcs[s];
                    let info = infos.entry(pc).or_insert_with(|| flow::analyze(self.code_at(pc), pc));
                    match info { Some(i) => i.writes.contains(&r), None => self.deltas_of(s).iter().any(|(x, _)| *x as usize == r) }
                }),
            };
            let value = match loc {
                Loc::Reg(r) => hex(self.regs_at(before)[r]),
                Loc::Mem(a, n) => self.mem_at(a, n as usize, before).iter().map(|b| b.map(|x| format!("{x:02x}")).unwrap_or_else(|| "??".into())).collect(),
            };
            let Some(s) = def else {
                out.push(json!({ "id": id, "parent": parent, "loc": loc.json(), "value": value, "kind": "initial", "step": null }));
                continue;
            };
            if !seen.insert((loc, s)) {
                continue;
            }
            let pc = self.pcs[s];
            let code = self.code_at(pc);
            let text = crate::local::disasm_one(code, pc).map(|(_, t)| t).unwrap_or_else(|| "??".into());
            let info = infos.entry(pc).or_insert_with(|| flow::analyze(code, pc)).clone();
            let reads: Vec<Loc> = self.accesses_of_step(s).iter().filter(|a| !a.write).map(|a| Loc::Mem(a.addr, a.old.len() as u16)).collect();
            let (kind, sources): (&str, Vec<Loc>) = match &info {
                None => ("unmodeled", Vec::new()),
                Some(i) if i.constant => ("const", Vec::new()),
                Some(i) if !i.modeled => ("unmodeled", Vec::new()),
                Some(i) => {
                    let mut src: Vec<Loc> = i.data_regs.iter().map(|r| Loc::Reg(*r)).collect();
                    if i.reads_mem {
                        src.extend(reads.iter().copied());
                    }
                    (if i.mov { "mov" } else { "arith" }, src)
                }
            };
            out.push(json!({ "id": id, "parent": parent, "step": s, "pc": hex(pc), "text": text, "loc": loc.json(), "value": value, "kind": kind, "sources": sources.iter().map(Loc::json).collect::<Vec<_>>() }));
            for src in sources {
                queue.push_back((src, s, Some(id)));
            }
        }
        out
    }
}

/// Instruction facts for the dataflow walk (iced-x86).
pub mod flow {
    use iced_x86::{Decoder, DecoderOptions, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

    #[derive(Clone, Debug)]
    pub struct Info {
        /// full registers written (trace indices)
        pub writes: Vec<usize>,
        /// registers whose *values* flow into the result (not address registers)
        pub data_regs: Vec<usize>,
        pub reads_mem: bool,
        pub mov: bool,
        pub constant: bool,
        pub modeled: bool,
    }

    pub fn reg_idx(r: Register) -> Option<usize> {
        let f = r.full_register();
        let n = match f {
            Register::RAX => 0, Register::RBX => 1, Register::RCX => 2, Register::RDX => 3,
            Register::RSI => 4, Register::RDI => 5, Register::RBP => 6, Register::RSP => 7,
            Register::R8 => 8, Register::R9 => 9, Register::R10 => 10, Register::R11 => 11,
            Register::R12 => 12, Register::R13 => 13, Register::R14 => 14, Register::R15 => 15,
            Register::RIP => 16,
            _ => return None,
        };
        Some(n)
    }

    pub fn analyze(code: &[u8], pc: u64) -> Option<Info> {
        if code.is_empty() {
            return None;
        }
        let mut d = Decoder::with_ip(64, code, pc, DecoderOptions::NONE);
        let ins = d.decode();
        if ins.is_invalid() {
            return None;
        }
        let mut f = InstructionInfoFactory::new();
        let info = f.info(&ins);
        let mut writes = Vec::new();
        let mut reads = Vec::new();
        for u in info.used_registers() {
            let Some(i) = reg_idx(u.register()) else { continue };
            match u.access() {
                OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    writes.push(i);
                    if matches!(u.access(), OpAccess::ReadWrite | OpAccess::ReadCondWrite) {
                        reads.push(i);
                    }
                }
                OpAccess::Read | OpAccess::CondRead => reads.push(i),
                _ => {}
            }
        }
        writes.sort_unstable();
        writes.dedup();
        let m = ins.mnemonic();
        let lea = m == Mnemonic::Lea;
        // address registers carry no data, except for lea where the address is the result
        let mut addr_regs: Vec<usize> = Vec::new();
        for op in 0..ins.op_count() {
            if ins.op_kind(op) == OpKind::Memory && !lea {
                addr_regs.extend(reg_idx(ins.memory_base()));
                addr_regs.extend(reg_idx(ins.memory_index()));
            }
        }
        // a register that is an explicit operand stays a data source even if it also addresses
        let mut explicit: Vec<usize> = Vec::new();
        for op in 0..ins.op_count() {
            if ins.op_kind(op) == OpKind::Register {
                explicit.extend(reg_idx(ins.op_register(op)));
            }
        }
        let stack = matches!(m, Mnemonic::Push | Mnemonic::Pop | Mnemonic::Call | Mnemonic::Ret);
        let mov = matches!(m, Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Movd | Mnemonic::Movq
            | Mnemonic::Movaps | Mnemonic::Movups | Mnemonic::Movdqa | Mnemonic::Movdqu | Mnemonic::Push | Mnemonic::Pop
            | Mnemonic::Xchg | Mnemonic::Lea | Mnemonic::Movsb | Mnemonic::Movsw | Mnemonic::Movsd | Mnemonic::Movsq | Mnemonic::Stosb | Mnemonic::Stosw | Mnemonic::Stosd | Mnemonic::Stosq | Mnemonic::Lodsb | Mnemonic::Lodsw | Mnemonic::Lodsd | Mnemonic::Lodsq)
            || format!("{m:?}").starts_with("Cmov");
        let arith = matches!(m, Mnemonic::Add | Mnemonic::Sub | Mnemonic::Adc | Mnemonic::Sbb | Mnemonic::And | Mnemonic::Or | Mnemonic::Xor
            | Mnemonic::Inc | Mnemonic::Dec | Mnemonic::Neg | Mnemonic::Not | Mnemonic::Imul | Mnemonic::Mul | Mnemonic::Shl | Mnemonic::Shr
            | Mnemonic::Sar | Mnemonic::Rol | Mnemonic::Ror | Mnemonic::Bswap | Mnemonic::Xadd | Mnemonic::Shld | Mnemonic::Shrd | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc);
        // xor/sub r, r → 0 regardless of the input
        let self_clear = matches!(m, Mnemonic::Xor | Mnemonic::Sub | Mnemonic::Pxor | Mnemonic::Xorps)
            && ins.op_count() == 2 && ins.op_kind(0) == OpKind::Register && ins.op_kind(1) == OpKind::Register && ins.op_register(0) == ins.op_register(1);
        let mut data_regs: Vec<usize> = reads.into_iter()
            .filter(|r| *r != super::RIP)
            .filter(|r| !(stack && *r == super::RSP) || explicit.contains(r))
            .filter(|r| !addr_regs.contains(r) || explicit.contains(r))
            .collect();
        // a plain mov does not read its destination
        if mov && !lea && m != Mnemonic::Xchg && ins.op_count() >= 1 && ins.op_kind(0) == OpKind::Register {
            if let Some(dst) = reg_idx(ins.op_register(0)) {
                if !(ins.op_count() >= 2 && ins.op_kind(1) == OpKind::Register && reg_idx(ins.op_register(1)) == Some(dst)) && !format!("{m:?}").starts_with("Cmov") {
                    data_regs.retain(|r| *r != dst);
                }
            }
        }
        data_regs.sort_unstable();
        data_regs.dedup();
        let reads_mem = info.used_memory().iter().any(|u| matches!(u.access(), OpAccess::Read | OpAccess::ReadWrite | OpAccess::CondRead | OpAccess::ReadCondWrite)) && !lea;
        let has_imm_only = (mov || arith) && data_regs.is_empty() && !reads_mem;
        Some(Info { writes, data_regs, reads_mem, mov: mov && !arith, constant: self_clear || (has_imm_only && !matches!(m, Mnemonic::Pop)), modeled: mov || arith || self_clear })
    }
}

// ---- varints ----------------------------------------------------------------------------------

fn put(o: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        o.push((v as u8) | 0x80);
        v >>= 7;
    }
    o.push(v as u8);
}

fn put_i(o: &mut Vec<u8>, v: i64) {
    put(o, ((v << 1) ^ (v >> 63)) as u64);
}

fn fnv(b: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for x in b {
        h ^= *x as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        // `n` comes from the file: `i + n` must not overflow (it wrapped past this check in release)
        if self.i.checked_add(n).is_none_or(|e| e > self.b.len()) {
            return Err("trace file truncated".into());
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn get(&mut self) -> Result<u64, String> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *self.b.get(self.i).ok_or("trace file truncated")?;
            self.i += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("bad varint".into())
    }
    fn get_i(&mut self) -> Result<i64, String> {
        let u = self.get()?;
        Ok((u >> 1) as i64 ^ -((u & 1) as i64))
    }
}

// ---- base64 (export / import over the wire) ---------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            if k <= c.len() {
                s.push(B64[(n >> (18 - 6 * k) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut bits = 0;
    for ch in s.bytes() {
        if ch == b'=' || ch.is_ascii_whitespace() {
            continue;
        }
        let v = B64.iter().position(|c| *c == ch).ok_or("bad base64")? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs(rip: u64, rax: u64) -> Regs {
        let mut r = [0u64; NREG];
        r[RIP] = rip;
        r[0] = rax;
        r
    }

    /// 1000 steps: rax counts up, every step writes rax's low byte to 0x1000 + (i % 16),
    /// step 500 reads 0x2000.
    fn sample(k: u32) -> Trace {
        let mut b = Builder::new(Meta { name: "t".into(), source: "test".into(), ..Default::default() }, regs(0x400000, 0), k);
        for i in 0..1000u64 {
            let pc = 0x400000 + (i % 4) * 4;
            let after = regs(0x400000 + ((i + 1) % 4) * 4, i + 1);
            let a = 0x1000 + (i % 16);
            let old = if i < 16 { 0xaa } else { (i - 16 + 1) as u8 };
            let mut acc = vec![RawAccess { addr: a, write: true, old: vec![old], new: vec![(i + 1) as u8] }];
            if i == 500 {
                acc.push(RawAccess { addr: 0x2000, write: false, old: vec![1, 2, 3, 4], new: vec![] });
            }
            b.step(pc, &[0x90], &after, &acc);
        }
        b.finish()
    }

    #[test]
    fn keyframe_seeking_matches_linear_replay() {
        for k in [1, 7, 64, 256, 5000] {
            let t = sample(k);
            assert_eq!(t.len(), 1000);
            assert_eq!(t.keyframes.len(), 1000usize.div_ceil(k as usize));
            for pos in [0, 1, 6, 7, 8, 63, 64, 65, 500, 999, 1000] {
                let r = t.regs_at(pos);
                assert_eq!(r[0], pos as u64, "k={k} pos={pos}");
                assert_eq!(r[RIP], 0x400000 + (pos as u64 % 4) * 4);
            }
            assert_eq!(t.final_regs()[0], 1000);
        }
    }

    #[test]
    fn memory_reconstruction() {
        let t = sample(64);
        // before anything: the first write's old value
        assert_eq!(t.mem_at(0x1000, 2, 0), vec![Some(0xaa), Some(0xaa)]);
        // after step 0 wrote 1 to 0x1000
        assert_eq!(t.mem_at(0x1000, 1, 1), vec![Some(1)]);
        // position 20: 0x1000..0x1003 last written at steps 16..19 (values 17..20), 0x1004 at step 4 (5)
        assert_eq!(t.mem_at(0x1000, 5, 20), vec![Some(17), Some(18), Some(19), Some(20), Some(5)]);
        // a read-only byte keeps what was read; an untouched byte is unknown
        assert_eq!(t.mem_at(0x2000, 5, 0), vec![Some(1), Some(2), Some(3), Some(4), None]);
        assert_eq!(t.mem_at(0x2000, 1, 1000), vec![Some(1)]);
    }

    #[test]
    fn last_write_and_lists() {
        let t = sample(64);
        let h = t.last_write(0x1003, 1, 100, true).unwrap();
        assert_eq!((h.step, h.new.clone()), (99, vec![100]));
        assert_eq!(t.last_write(0x1003, 1, 3, true), None, "nothing wrote 0x1003 before step 3");
        let h = t.last_write(0x1000, 16, 1000, true).unwrap();
        assert_eq!(h.step, 999);
        let (w, n) = t.writes_to(0x1000, 1, 3);
        assert_eq!((n, w.len(), w[1].step), (63, 3, 16));
        let (e, n) = t.executions_of(0x400004, 2);
        assert_eq!((n, e), (250, vec![1, 5]));
        assert_eq!(t.seek_pc(0x400004, 5, true), Some(9));
        assert_eq!(t.seek_pc(0x400004, 5, false), Some(1));
        assert_eq!(t.seek_pc(0x400004, 1, false), None);
        let (r, n) = t.reads_of(0x2002, 1, 10);
        assert_eq!((n, r[0].0), (1, 500));
        // an unchanged write is skipped by the "changed" query
        let mut b = Builder::new(Meta::default(), regs(0, 0), 16);
        b.step(0, &[], &regs(1, 0), &[RawAccess { addr: 8, write: true, old: vec![0], new: vec![5] }]);
        b.step(1, &[], &regs(2, 0), &[RawAccess { addr: 8, write: true, old: vec![5], new: vec![5] }]);
        let t2 = b.finish();
        assert_eq!(t2.last_write(8, 1, 2, true).unwrap().step, 0);
        assert_eq!(t2.last_write(8, 1, 2, false).unwrap().step, 1);
        assert_eq!(t.touched()[0], (0x1000, 16, 0, 1000));
    }

    #[test]
    fn series_is_a_step_function() {
        let t = sample(64);
        let s = t.reg_series(0, 0, 1000, 2000);
        assert_eq!(s.len(), 1001);
        let s = t.reg_series(0, 100, 200, 11);
        assert_eq!(s.len(), 11);
        assert_eq!(s[0], (100, 100));
        assert_eq!(s[10], (200, 200));
    }

    #[test]
    fn export_import_round_trip() {
        let t = sample(32);
        let bin = t.encode();
        let u = Trace::decode(&bin).unwrap();
        assert_eq!(u.len(), t.len());
        assert_eq!(u.keyframes, t.keyframes);
        assert_eq!(u.meta.name, "t");
        for pos in [0, 33, 500, 1000] {
            assert_eq!(u.regs_at(pos), t.regs_at(pos));
            assert_eq!(u.mem_at(0x1000, 16, pos), t.mem_at(0x1000, 16, pos));
        }
        assert_eq!(u.code_at(0x400000), &[0x90]);
        assert_eq!(Trace::peek_meta(&bin).unwrap()["steps"], 1000);
        // compact: far below the in-memory form
        assert!(bin.len() < t.size_bytes() / 2, "{} vs {}", bin.len(), t.size_bytes());
        let mut bad = bin.clone();
        bad[40] ^= 1;
        assert!(Trace::decode(&bad).is_err());
        assert!(Trace::decode(b"nope").is_err());
        let s = b64_encode(&bin);
        assert_eq!(b64_decode(&s).unwrap(), bin);
        assert_eq!(b64_encode(b"ab"), "YWI=");
    }

    #[test]
    fn taint_walks_back_through_movs_and_arith() {
        // 0: mov eax, 5          rax = 5
        // 1: mov [0x500000], rax (store)
        // 2: mov rcx, [0x500000] rcx = 5
        // 3: add rcx, rdx        rcx = 5 + 7
        // 4: xor rbx, rbx
        let mut b = Builder::new(Meta::default(), { let mut r = regs(0x1000, 0); r[3] = 7; r }, 2);
        let mut r = b.prev;
        let code0 = [0xb8, 5, 0, 0, 0];
        r[0] = 5; r[RIP] = 0x1005;
        b.step(0x1000, &code0, &r, &[]);
        let code1 = [0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00];
        r[RIP] = 0x100d;
        b.step(0x1005, &code1, &r, &[RawAccess { addr: 0x500000, write: true, old: vec![0; 8], new: 5u64.to_le_bytes().to_vec() }]);
        let code2 = [0x48, 0x8b, 0x0c, 0x25, 0x00, 0x00, 0x50, 0x00];
        r[2] = 5; r[RIP] = 0x1015;
        b.step(0x100d, &code2, &r, &[RawAccess { addr: 0x500000, write: false, old: 5u64.to_le_bytes().to_vec(), new: vec![] }]);
        let code3 = [0x48, 0x01, 0xd1];
        r[2] = 12; r[RIP] = 0x1018;
        b.step(0x1015, &code3, &r, &[]);
        let code4 = [0x48, 0x31, 0xdb];
        r[RIP] = 0x101b;
        b.step(0x1018, &code4, &r, &[]);
        let t = b.finish();
        let hops = t.taint(t.len(), Loc::Reg(2), 16);
        let kinds: Vec<(&str, Value)> = hops.iter().map(|h| (h["kind"].as_str().unwrap(), h["step"].clone())).collect();
        // rcx ← add (step 3) ← {rcx ← mov [mem] (step 2), rdx initial}; mem ← store (1) ← rax ← mov eax,5 (0, const)
        assert_eq!(kinds[0], ("arith", json!(3)), "{hops:?}");
        assert!(kinds.contains(&("mov", json!(2))), "{hops:?}");
        assert!(kinds.contains(&("initial", Value::Null)), "rdx was there before: {hops:?}");
        assert!(kinds.contains(&("mov", json!(1))), "{hops:?}");
        assert!(kinds.contains(&("const", json!(0))), "{hops:?}");
        assert_eq!(hops[0]["value"], "0xc");
        // xor rbx, rbx is a constant even though rbx is "read"
        let h = t.taint(t.len(), Loc::Reg(1), 4);
        assert_eq!(h[0]["kind"], "const", "{h:?}");
        // the memory source of step 2 is the stored qword
        let m = t.taint(3, Loc::Mem(0x500000, 8), 4);
        assert_eq!((m[0]["step"].clone(), m[0]["value"].clone()), (json!(1), json!("0500000000000000")));
    }
}
