//! A ptrace debugger for the local Linux backend: software breakpoints (int3), hardware
//! breakpoints/watchpoints (DR0-DR3), single-step, continue, register read/write.
//!
//! Linux ties a tracee to the *thread* that attached it, so one dedicated debugger thread owns
//! every ptrace call; verbs talk to it over a channel. All threads of the process are seized
//! (`PTRACE_SEIZE` + `TRACECLONE`), so a breakpoint hit in any thread is caught instead of killing
//! the process. All-stop model: when one thread stops for an event, every thread is interrupted.
//!
//! Verbs (`dbg_*`, ext routing): `dbg_attach`, `dbg_detach`, `dbg_status`, `dbg_break`
//! {address, enabled}, `dbg_hwbreak` {slot 0-3, address, kind exec|write|rw, len 1|2|4|8,
//! enabled}, `dbg_continue`, `dbg_step` {tid?}, `dbg_pause`, `dbg_regs` {tid?}, `dbg_set_regs`
//! {tid?, regs}, `dbg_all_regs` (every thread). Stops broadcast `{type:"event", event:"dbg_stop", reason, tid, address, regs}`;
//! process exit broadcasts `dbg_exit`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::Relay;

/// Original bytes under the debugger's int3s: reads and disassembly show these instead of 0xCC.
static SHADOW: Mutex<BTreeMap<u64, u8>> = Mutex::new(BTreeMap::new());

/// Replaces planted breakpoint bytes in `buf` (read from `addr`) with the original bytes.
pub fn unshadow(addr: u64, buf: &mut [u8]) {
    let g = SHADOW.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_empty() {
        return;
    }
    for (a, b) in g.range(addr..addr.saturating_add(buf.len() as u64)) {
        buf[(a - addr) as usize] = *b;
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn shadow_set(addr: u64, orig: Option<u8>) {
    let mut g = SHADOW.lock().unwrap_or_else(|e| e.into_inner());
    match orig {
        Some(b) => g.insert(addr, b),
        None => g.remove(&addr),
    };
}

#[cfg(not(target_os = "linux"))]
pub fn handle(_relay: &Relay, _req: &Map<String, Value>) -> Value {
    json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": "the ptrace debugger exists on Linux only" })
}

#[cfg(not(target_os = "linux"))]
pub fn detach_all() {}

/// Is a ptrace debug session attached? (Its threads cannot be seized a second time.)
#[cfg(not(target_os = "linux"))]
pub fn active() -> bool {
    false
}

#[cfg(target_os = "linux")]
pub use imp::{active, detach_all, handle};

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::collections::HashMap;
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use nix::sys::ptrace::{self, Options};
    use nix::sys::signal::Signal;
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;

    use crate::local::{arg_addr, hex_addr, MemIo, ProcIo};

    /// offsetof(struct user, u_debugreg) on x86-64
    const DR_OFFSET: usize = 848;
    const EVENT_STOP: i32 = 128; // PTRACE_EVENT_STOP

    type Cmd = (Map<String, Value>, Sender<Value>);

    struct Session {
        tx: Sender<Cmd>,
    }

    static SESSION: Mutex<Option<Session>> = Mutex::new(None);

    fn bad(detail: &str) -> Value {
        json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": detail })
    }
    fn failed(detail: impl std::fmt::Display) -> Value {
        json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": detail.to_string() })
    }

    pub fn handle(relay: &Relay, req: &Map<String, Value>) -> Value {
        let verb = req.get("type").and_then(Value::as_str).unwrap_or_default().to_owned();
        if verb == "dbg_attach" {
            let pid = req.get("pid").and_then(Value::as_u64).map(|p| p as u32).or_else(crate::local::attached_pid);
            let Some(pid) = pid else { return failed("attach to a process first (Targets), or pass 'pid'") };
            if SESSION.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                return failed("a debug session is already active; dbg_detach first");
            }
            let (tx, rx) = mpsc::channel::<Cmd>();
            let (ready_tx, ready_rx) = mpsc::channel::<Result<Vec<i32>, String>>();
            let relay = relay.clone();
            std::thread::Builder::new()
                .name("echodebug-ptrace".into())
                .spawn(move || run(pid, rx, ready_tx, relay))
                .expect("spawn debugger thread");
            return match ready_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(Ok(tids)) => {
                    *SESSION.lock().unwrap_or_else(|e| e.into_inner()) = Some(Session { tx });
                    json!({ "type": "dbg_attach_result", "success": true, "pid": pid, "threads": tids, "state": "stopped" })
                }
                Ok(Err(e)) => failed(e),
                Err(_) => failed("debugger thread did not start"),
            };
        }
        let tx = {
            let g = SESSION.lock().unwrap_or_else(|e| e.into_inner());
            match g.as_ref() {
                Some(s) => s.tx.clone(),
                None if verb == "dbg_status" => return json!({ "type": "dbg_status_result", "success": true, "active": false }),
                None => return failed("no debug session; call dbg_attach first"),
            }
        };
        let (rtx, rrx) = mpsc::channel();
        if tx.send((req.clone(), rtx)).is_err() {
            *SESSION.lock().unwrap_or_else(|e| e.into_inner()) = None;
            return failed("debug session ended");
        }
        // a trace recording single-steps for as long as its limits allow
        let wait = if verb == "dbg_record" { Duration::from_secs(4 * 3600) } else { Duration::from_secs(15) };
        let reply = rrx.recv_timeout(wait).unwrap_or_else(|_| failed("debugger did not answer"));
        if verb == "dbg_detach" {
            *SESSION.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
        reply
    }

    pub fn active() -> bool {
        SESSION.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Detach (restoring breakpoints) when the local backend detaches from its target.
    pub fn detach_all() {
        let tx = SESSION.lock().unwrap_or_else(|e| e.into_inner()).take().map(|s| s.tx);
        if let Some(tx) = tx {
            let (rtx, rrx) = mpsc::channel();
            let mut m = Map::new();
            m.insert("type".into(), json!("dbg_detach"));
            if tx.send((m, rtx)).is_ok() {
                let _ = rrx.recv_timeout(Duration::from_secs(5));
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum TState {
        Running,
        Stopped,
    }

    struct Dbg {
        pid: u32,
        mem: ProcIo,
        threads: BTreeMap<i32, TState>,
        /// pending signal to deliver on resume, per thread
        signals: HashMap<i32, Signal>,
        /// address -> original byte
        bps: BTreeMap<u64, u8>,
        /// slot -> (address, kind, len)
        hw: [Option<(u64, String, u8)>; 4],
        running: bool,
        focus: i32,
        last: Value,
        relay: Relay,
    }

    fn tids_of(pid: u32) -> Vec<i32> {
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .map(|d| d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect())
            .unwrap_or_default()
    }

    fn wait_stop(tid: i32, timeout: Duration) -> Result<WaitStatus, String> {
        let t0 = Instant::now();
        loop {
            match waitpid(Pid::from_raw(tid), Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {}
                Ok(s) => return Ok(s),
                Err(e) => return Err(format!("waitpid {tid}: {e}")),
            }
            if t0.elapsed() > timeout {
                return Err(format!("thread {tid} did not stop"));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn regs_json(tid: i32) -> Value {
        match ptrace::getregs(Pid::from_raw(tid)) {
            Ok(r) => json!({
                "rax": hex_addr(r.rax), "rbx": hex_addr(r.rbx), "rcx": hex_addr(r.rcx), "rdx": hex_addr(r.rdx),
                "rsi": hex_addr(r.rsi), "rdi": hex_addr(r.rdi), "rbp": hex_addr(r.rbp), "rsp": hex_addr(r.rsp),
                "r8": hex_addr(r.r8), "r9": hex_addr(r.r9), "r10": hex_addr(r.r10), "r11": hex_addr(r.r11),
                "r12": hex_addr(r.r12), "r13": hex_addr(r.r13), "r14": hex_addr(r.r14), "r15": hex_addr(r.r15),
                "rip": hex_addr(r.rip), "eflags": hex_addr(r.eflags), "fs_base": hex_addr(r.fs_base), "gs_base": hex_addr(r.gs_base),
            }),
            Err(e) => json!({ "error": e.to_string() }),
        }
    }

    fn rip(tid: i32) -> u64 {
        ptrace::getregs(Pid::from_raw(tid)).map(|r| r.rip).unwrap_or(0)
    }

    fn set_rip(tid: i32, v: u64) {
        if let Ok(mut r) = ptrace::getregs(Pid::from_raw(tid)) {
            r.rip = v;
            let _ = ptrace::setregs(Pid::from_raw(tid), r);
        }
    }

    impl Dbg {
        fn attach_all(&mut self) -> Result<Vec<i32>, String> {
            let opts = Options::PTRACE_O_TRACECLONE | Options::PTRACE_O_TRACEEXIT;
            let mut attached = Vec::new();
            // threads can appear while we attach: loop until the set is stable
            for _ in 0..8 {
                let mut new = false;
                for tid in tids_of(self.pid) {
                    if self.threads.contains_key(&tid) {
                        continue;
                    }
                    ptrace::seize(Pid::from_raw(tid), opts).map_err(|e| format!("PTRACE_SEIZE {tid}: {e} (same user, or kernel.yama.ptrace_scope=0)"))?;
                    let _ = ptrace::interrupt(Pid::from_raw(tid));
                    wait_stop(tid, Duration::from_secs(3))?;
                    self.threads.insert(tid, TState::Stopped);
                    attached.push(tid);
                    new = true;
                }
                if !new {
                    break;
                }
            }
            if self.threads.is_empty() {
                return Err(format!("process {} has no threads", self.pid));
            }
            self.focus = self.pid as i32;
            Ok(attached)
        }

        fn stop_all(&mut self, except: i32) {
            let running: Vec<i32> = self.threads.iter().filter(|(t, s)| **t != except && **s == TState::Running).map(|(t, _)| *t).collect();
            for tid in &running {
                let _ = ptrace::interrupt(Pid::from_raw(*tid));
            }
            for tid in running {
                match wait_stop(tid, Duration::from_secs(2)) {
                    Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) | Err(_) => {
                        self.threads.remove(&tid);
                    }
                    Ok(WaitStatus::Stopped(_, sig)) if sig != Signal::SIGTRAP && sig != Signal::SIGSTOP => {
                        self.signals.insert(tid, sig);
                        self.threads.insert(tid, TState::Stopped);
                    }
                    Ok(_) => {
                        self.threads.insert(tid, TState::Stopped);
                    }
                }
            }
            self.running = false;
        }

        fn write_byte(&self, addr: u64, b: u8) -> Result<(), String> {
            self.mem.write_at(addr, &[b]).map_err(|e| format!("{addr:#x}: {e}"))
        }

        /// Steps one thread over a breakpoint that sits at its rip, if any.
        fn step_over_bp(&mut self, tid: i32) -> Result<(), String> {
            let at = rip(tid);
            let Some(orig) = self.bps.get(&at).copied() else { return Ok(()) };
            self.write_byte(at, orig)?;
            let sig = self.signals.remove(&tid);
            ptrace::step(Pid::from_raw(tid), sig).map_err(|e| e.to_string())?;
            let st = wait_stop(tid, Duration::from_secs(3));
            self.write_byte(at, 0xcc)?;
            match st {
                Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => {
                    self.threads.remove(&tid);
                }
                Ok(_) => {}
                Err(e) => return Err(e),
            }
            Ok(())
        }

        fn resume_all(&mut self) -> Result<(), String> {
            let tids: Vec<i32> = self.threads.keys().copied().collect();
            for tid in &tids {
                self.step_over_bp(*tid)?;
            }
            for tid in tids {
                if !self.threads.contains_key(&tid) {
                    continue;
                }
                let sig = self.signals.remove(&tid);
                if ptrace::cont(Pid::from_raw(tid), sig).is_ok() {
                    self.threads.insert(tid, TState::Running);
                }
            }
            self.running = true;
            Ok(())
        }

        fn dr7(&self) -> u64 {
            let mut v = 0u64;
            for (i, slot) in self.hw.iter().enumerate() {
                if let Some((_, kind, len)) = slot {
                    let rw = match kind.as_str() {
                        "write" => 0b01,
                        "rw" => 0b11,
                        _ => 0b00,
                    };
                    let ln = if kind == "exec" { 0 } else { match len { 2 => 0b01, 8 => 0b10, 4 => 0b11, _ => 0b00 } };
                    v |= 1 << (i * 2);
                    v |= (rw | (ln << 2)) << (16 + i * 4);
                }
            }
            v
        }

        fn apply_hw(&self) -> Result<(), String> {
            let dr7 = self.dr7();
            for tid in self.threads.keys() {
                let p = Pid::from_raw(*tid);
                // DR7 off first so a half-written slot never fires
                let _ = ptrace::write_user(p, (DR_OFFSET + 7 * 8) as _, 0);
                for (i, slot) in self.hw.iter().enumerate() {
                    let a = slot.as_ref().map(|s| s.0).unwrap_or(0);
                    ptrace::write_user(p, (DR_OFFSET + i * 8) as _, a as i64).map_err(|e| format!("DR{i} on {tid}: {e}"))?;
                }
                ptrace::write_user(p, (DR_OFFSET + 7 * 8) as _, dr7 as i64).map_err(|e| format!("DR7 on {tid}: {e}"))?;
            }
            Ok(())
        }

        fn stop_event(&mut self, tid: i32, reason: &str, extra: Value) -> Value {
            let mut ev = json!({ "type": "event", "event": "dbg_stop", "reason": reason, "tid": tid, "address": hex_addr(rip(tid)), "regs": regs_json(tid) });
            if let (Value::Object(e), Value::Object(x)) = (&mut ev, extra) {
                e.extend(x);
            }
            self.focus = tid;
            self.last = ev.clone();
            ev
        }

        /// Non-blocking: reaps one wait status while running; returns an event to broadcast.
        fn poll(&mut self) -> Option<Value> {
            if !self.running {
                return None;
            }
            let st = waitpid(None::<Pid>, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)).ok()?;
            match st {
                WaitStatus::StillAlive => None,
                WaitStatus::Exited(p, code) => {
                    self.threads.remove(&p.as_raw());
                    if self.threads.is_empty() || p.as_raw() == self.pid as i32 {
                        self.threads.clear();
                        self.running = false;
                        return Some(json!({ "type": "event", "event": "dbg_exit", "pid": self.pid, "code": code }));
                    }
                    None
                }
                WaitStatus::Signaled(p, sig, _) => {
                    self.threads.remove(&p.as_raw());
                    if self.threads.is_empty() || p.as_raw() == self.pid as i32 {
                        self.threads.clear();
                        self.running = false;
                        return Some(json!({ "type": "event", "event": "dbg_exit", "pid": self.pid, "signal": sig.as_str() }));
                    }
                    None
                }
                WaitStatus::PtraceEvent(p, _, ev) if ev == libc_clone() => {
                    // new thread: auto-attached and stopped; keep it running with the rest
                    if let Ok(new) = ptrace::getevent(p) {
                        let nt = new as i32;
                        let _ = wait_stop(nt, Duration::from_millis(500));
                        let _ = self.apply_hw_one(nt);
                        let _ = ptrace::cont(Pid::from_raw(nt), None);
                        self.threads.insert(nt, TState::Running);
                    }
                    let _ = ptrace::cont(p, None);
                    None
                }
                WaitStatus::PtraceEvent(p, _, ev) if ev == EVENT_STOP => {
                    // group-stop / stray interrupt: keep going
                    let _ = ptrace::cont(p, None);
                    None
                }
                WaitStatus::PtraceEvent(p, _, _) => {
                    let _ = ptrace::cont(p, None);
                    None
                }
                WaitStatus::Stopped(p, sig) => {
                    let tid = p.as_raw();
                    self.threads.insert(tid, TState::Stopped);
                    self.stop_all(tid);
                    if sig == Signal::SIGTRAP {
                        let at = rip(tid);
                        if self.bps.contains_key(&(at.wrapping_sub(1))) {
                            set_rip(tid, at - 1);
                            return Some(self.stop_event(tid, "breakpoint", json!({})));
                        }
                        let dr6 = ptrace::read_user(p, (DR_OFFSET + 6 * 8) as _).unwrap_or(0) as u64;
                        if let Some(slot) = (0..4).find(|i| dr6 & (1 << i) != 0) {
                            let _ = ptrace::write_user(p, (DR_OFFSET + 6 * 8) as _, 0);
                            let hit = self.hw[slot].as_ref().map(|h| hex_addr(h.0));
                            return Some(self.stop_event(tid, "hardware", json!({ "slot": slot, "watch": hit })));
                        }
                        return Some(self.stop_event(tid, "trap", json!({})));
                    }
                    self.signals.insert(tid, sig);
                    Some(self.stop_event(tid, "signal", json!({ "signal": sig.as_str() })))
                }
                _ => None,
            }
        }

        fn apply_hw_one(&self, tid: i32) -> Result<(), String> {
            let p = Pid::from_raw(tid);
            for (i, slot) in self.hw.iter().enumerate() {
                let a = slot.as_ref().map(|s| s.0).unwrap_or(0);
                ptrace::write_user(p, (DR_OFFSET + i * 8) as _, a as i64).map_err(|e| e.to_string())?;
            }
            ptrace::write_user(p, (DR_OFFSET + 7 * 8) as _, self.dr7() as i64).map_err(|e| e.to_string())
        }

        fn need_stopped(&mut self) {
            if self.running {
                self.stop_all(0);
            }
        }

        fn tid_arg(&self, req: &Map<String, Value>) -> i32 {
            req.get("tid").and_then(Value::as_i64).map(|t| t as i32).filter(|t| self.threads.contains_key(t)).unwrap_or(self.focus)
        }

        fn status(&self) -> Value {
            let threads: Vec<Value> = self.threads.iter().map(|(t, s)| json!({ "tid": t, "state": format!("{s:?}").to_lowercase() })).collect();
            let bps: Vec<Value> = self.bps.keys().map(|a| json!(hex_addr(*a))).collect();
            let hw: Vec<Value> = self.hw.iter().enumerate().map(|(i, h)| match h {
                Some((a, k, l)) => json!({ "slot": i, "address": hex_addr(*a), "kind": k, "len": l }),
                None => json!({ "slot": i, "address": null }),
            }).collect();
            json!({ "type": "dbg_status_result", "success": true, "active": true, "pid": self.pid, "state": if self.running { "running" } else { "stopped" },
                "focus": self.focus, "threads": threads, "breakpoints": bps, "hardware": hw, "last": self.last })
        }

        fn detach(&mut self) {
            self.need_stopped();
            for (a, b) in std::mem::take(&mut self.bps) {
                shadow_set(a, None);
                let _ = self.write_byte(a, b);
            }
            self.hw = [None, None, None, None];
            let _ = self.apply_hw();
            for (tid, _) in std::mem::take(&mut self.threads) {
                let sig = self.signals.remove(&tid);
                let _ = ptrace::detach(Pid::from_raw(tid), sig);
            }
        }

        fn command(&mut self, req: &Map<String, Value>) -> Value {
            let verb = req.get("type").and_then(Value::as_str).unwrap_or_default();
            match verb {
                "dbg_status" => self.status(),
                "dbg_pause" => {
                    self.need_stopped();
                    let tid = self.focus;
                    let ev = self.stop_event(tid, "pause", json!({}));
                    self.relay.emit(ev);
                    self.status()
                }
                "dbg_continue" => match self.resume_all() {
                    Ok(()) => json!({ "type": "dbg_continue_result", "success": true, "state": "running" }),
                    Err(e) => failed(e),
                },
                "dbg_step" => {
                    self.need_stopped();
                    let tid = self.tid_arg(req);
                    let at = rip(tid);
                    let result = if let Some(orig) = self.bps.get(&at).copied() {
                        let _ = self.write_byte(at, orig);
                        let r = ptrace::step(Pid::from_raw(tid), self.signals.remove(&tid)).map_err(|e| e.to_string()).and_then(|_| wait_stop(tid, Duration::from_secs(3)));
                        let _ = self.write_byte(at, 0xcc);
                        r
                    } else {
                        ptrace::step(Pid::from_raw(tid), self.signals.remove(&tid)).map_err(|e| e.to_string()).and_then(|_| wait_stop(tid, Duration::from_secs(3)))
                    };
                    match result {
                        Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => {
                            self.threads.remove(&tid);
                            failed("thread exited during the step")
                        }
                        // A thread parked in a system call only completes the step when the call
                        // returns; pull it back into a stop instead of hanging the session.
                        Err(e) if e.contains("did not stop") => {
                            let _ = ptrace::interrupt(Pid::from_raw(tid));
                            let _ = wait_stop(tid, Duration::from_secs(2));
                            failed(format!("thread {tid} is blocked in a system call at {}; the step completes when the call returns (set a breakpoint after it and continue)", hex_addr(at)))
                        }
                        Ok(_) => {
                            let ev = self.stop_event(tid, "step", json!({ "from": hex_addr(at) }));
                            self.relay.emit(ev.clone());
                            json!({ "type": "dbg_step_result", "success": true, "tid": tid, "from": hex_addr(at), "address": ev["address"], "regs": ev["regs"] })
                        }
                        Err(e) => failed(e),
                    }
                }
                "dbg_regs" => {
                    let was_running = self.running;
                    self.need_stopped();
                    let tid = self.tid_arg(req);
                    let r = json!({ "type": "dbg_regs_result", "success": true, "tid": tid, "regs": regs_json(tid) });
                    if was_running {
                        let _ = self.resume_all();
                    }
                    r
                }
                "dbg_set_regs" => {
                    self.need_stopped();
                    let tid = self.tid_arg(req);
                    let Some(Value::Object(set)) = req.get("regs") else { return bad("dbg_set_regs requires 'regs'") };
                    let Ok(mut r) = ptrace::getregs(Pid::from_raw(tid)) else { return failed("cannot read registers") };
                    for (k, v) in set {
                        let Some(val) = v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()).or_else(|| v.as_u64()) else { continue };
                        match k.as_str() {
                            "rax" => r.rax = val, "rbx" => r.rbx = val, "rcx" => r.rcx = val, "rdx" => r.rdx = val,
                            "rsi" => r.rsi = val, "rdi" => r.rdi = val, "rbp" => r.rbp = val, "rsp" => r.rsp = val,
                            "r8" => r.r8 = val, "r9" => r.r9 = val, "r10" => r.r10 = val, "r11" => r.r11 = val,
                            "r12" => r.r12 = val, "r13" => r.r13 = val, "r14" => r.r14 = val, "r15" => r.r15 = val,
                            "rip" => r.rip = val, "eflags" => r.eflags = val,
                            _ => {}
                        }
                    }
                    match ptrace::setregs(Pid::from_raw(tid), r) {
                        Ok(()) => json!({ "type": "dbg_set_regs_result", "success": true, "tid": tid, "regs": regs_json(tid) }),
                        Err(e) => failed(e),
                    }
                }
                "dbg_break" => {
                    let Some(addr) = arg_addr(req, "address") else { return bad("dbg_break requires 'address'") };
                    let enabled = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                    if enabled {
                        if !self.bps.contains_key(&addr) {
                            let mut b = [0u8; 1];
                            if self.mem.read_at(addr, &mut b).map(|n| n != 1).unwrap_or(true) {
                                return failed(format!("{addr:#x} is not readable"));
                            }
                            if let Err(e) = self.write_byte(addr, 0xcc) {
                                return failed(e);
                            }
                            self.bps.insert(addr, b[0]);
                            shadow_set(addr, Some(b[0]));
                        }
                    } else if let Some(orig) = self.bps.remove(&addr) {
                        shadow_set(addr, None);
                        if let Err(e) = self.write_byte(addr, orig) {
                            return failed(e);
                        }
                    }
                    json!({ "type": "dbg_break_result", "success": true, "breakpoints": self.bps.keys().map(|a| hex_addr(*a)).collect::<Vec<_>>() })
                }
                "dbg_hwbreak" => {
                    let slot = req.get("slot").and_then(Value::as_u64).unwrap_or(0) as usize;
                    if slot > 3 {
                        return bad("slot must be 0-3");
                    }
                    let enabled = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                    if enabled {
                        let Some(addr) = arg_addr(req, "address") else { return bad("dbg_hwbreak requires 'address'") };
                        let kind = req.get("kind").and_then(Value::as_str).unwrap_or("exec").to_owned();
                        if !matches!(kind.as_str(), "exec" | "write" | "rw") {
                            return bad("kind must be exec, write or rw");
                        }
                        let len = req.get("len").and_then(Value::as_u64).unwrap_or(1) as u8;
                        if kind != "exec" && (!matches!(len, 1 | 2 | 4 | 8) || addr % len as u64 != 0) {
                            return bad("len must be 1, 2, 4 or 8 and the address aligned to it");
                        }
                        self.hw[slot] = Some((addr, kind, len));
                    } else {
                        self.hw[slot] = None;
                    }
                    let was_running = self.running;
                    self.need_stopped();
                    let r = self.apply_hw();
                    if was_running {
                        let _ = self.resume_all();
                    }
                    match r {
                        Ok(()) => {
                            let mut s = self.status();
                            s["type"] = json!("dbg_hwbreak_result");
                            s
                        }
                        Err(e) => failed(e),
                    }
                }
                "dbg_record" => {
                    self.need_stopped();
                    let tid = self.tid_arg(req);
                    let lim = crate::trace_rec::Limits::from_req(req);
                    let meta = crate::trace::Meta {
                        name: req.get("name").and_then(Value::as_str).unwrap_or_default().to_owned(),
                        source: "ptrace".into(),
                        created_ms: crate::trace_rec::now_ms(),
                        pid: Some(self.pid),
                        tid: Some(tid as i64),
                        ..Default::default()
                    };
                    let save = req.get("save").and_then(Value::as_bool).unwrap_or(true);
                    let r = crate::trace_rec::record_steps(&mut Stepping { d: self, tid }, meta, &lim);
                    let ev = self.stop_event(tid, "step", json!({ "trace": true }));
                    self.relay.emit(ev.clone());
                    match r {
                        Ok(t) => json!({ "type": "dbg_record_result", "success": true, "tid": tid, "address": ev["address"], "regs": ev["regs"], "trace": crate::trace_rec::deposit(t, save) }),
                        Err(e) => failed(e),
                    }
                }
                // every thread's registers at once (the Threads view while a session is active)
                "dbg_all_regs" => {
                    let was_running = self.running;
                    self.need_stopped();
                    let threads: Vec<Value> = self.threads.keys().map(|t| json!({ "tid": t, "regs": regs_json(*t) })).collect();
                    if was_running {
                        let _ = self.resume_all();
                    }
                    json!({ "type": "dbg_all_regs_result", "success": true, "threads": threads, "was_running": was_running })
                }
                "dbg_detach" => {
                    self.detach();
                    json!({ "type": "dbg_detach_result", "success": true })
                }
                other => json!({ "type": "error", "code": 3000, "message": "unknown verb", "detail": other }),
            }
        }
    }

    /// One thread single-stepped for a trace recording (breakpoints are stepped over, their
    /// bytes hidden from the reads).
    struct Stepping<'a> {
        d: &'a mut Dbg,
        tid: i32,
    }

    impl crate::trace_rec::Stepper for Stepping<'_> {
        fn regs(&mut self) -> Result<crate::trace::Regs, String> {
            let r = ptrace::getregs(Pid::from_raw(self.tid)).map_err(|e| format!("registers of {}: {e}", self.tid))?;
            Ok([r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.rip, r.eflags, r.fs_base, r.gs_base])
        }

        fn read(&mut self, addr: u64, buf: &mut [u8]) -> bool {
            if !matches!(self.d.mem.read_at(addr, buf), Ok(n) if n == buf.len()) {
                return false;
            }
            unshadow(addr, buf);
            true
        }

        fn step(&mut self) -> Result<Option<String>, String> {
            let tid = self.tid;
            let at = rip(tid);
            let orig = self.d.bps.get(&at).copied();
            if let Some(o) = orig {
                self.d.write_byte(at, o)?;
            }
            let r = ptrace::step(Pid::from_raw(tid), self.d.signals.remove(&tid)).map_err(|e| e.to_string()).and_then(|_| wait_stop(tid, Duration::from_secs(3)));
            if orig.is_some() {
                let _ = self.d.write_byte(at, 0xcc);
            }
            match r {
                Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => Ok(None),
                Ok(WaitStatus::Stopped(_, sig)) => {
                    self.d.signals.insert(tid, sig);
                    Err(format!("signal {}", sig.as_str()))
                }
                Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => {
                    self.d.threads.remove(&tid);
                    Err("thread exited".into())
                }
                Ok(WaitStatus::PtraceEvent(..)) => Ok(Some("ptrace event (clone/exec/exit)".into())),
                Ok(_) => Ok(None),
                Err(e) if e.contains("did not stop") => {
                    let _ = ptrace::interrupt(Pid::from_raw(tid));
                    let _ = wait_stop(tid, Duration::from_secs(2));
                    Err(format!("blocked in a system call at {}", hex_addr(at)))
                }
                Err(e) => Err(e),
            }
        }
    }

    fn libc_clone() -> i32 {
        3 // PTRACE_EVENT_CLONE
    }

    fn run(pid: u32, rx: Receiver<Cmd>, ready: Sender<Result<Vec<i32>, String>>, relay: Relay) {
        let mem = match ProcIo::open(pid) {
            Ok(m) => m,
            Err(e) => {
                let _ = ready.send(Err(e.to_string()));
                return;
            }
        };
        let mut d = Dbg { pid, mem, threads: BTreeMap::new(), signals: HashMap::new(), bps: BTreeMap::new(), hw: [None, None, None, None], running: false, focus: pid as i32, last: Value::Null, relay };
        match d.attach_all() {
            Ok(t) => {
                let _ = ready.send(Ok(t));
            }
            Err(e) => {
                d.detach();
                let _ = ready.send(Err(e));
                return;
            }
        }
        loop {
            match rx.recv_timeout(Duration::from_millis(if d.running { 2 } else { 50 })) {
                Ok((req, reply)) => {
                    let detach = req.get("type").and_then(Value::as_str) == Some("dbg_detach");
                    let r = d.command(&req);
                    let _ = reply.send(r);
                    if detach {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    d.detach();
                    return;
                }
            }
            while let Some(ev) = d.poll() {
                let exit = ev["event"] == "dbg_exit";
                d.relay.emit(ev);
                if exit {
                    *SESSION.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    return;
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::local::MemIo;

        /// A real child process: attach, read registers, single-step, plant and remove an int3,
        /// set a hardware watchpoint, continue, detach. Skipped when ptrace is not permitted.
        #[test]
        fn ptrace_session_on_a_child() {
            // busy in user space, so a single-step completes immediately (a thread blocked in a
            // syscall such as nanosleep only finishes the step when the call returns)
            let mut child = std::process::Command::new("sh").args(["-c", "while :; do :; done"]).spawn().expect("spawn sh");
            let pid = child.id();
            let relay = Relay::new("t", Duration::from_secs(1));
            let mut req = Map::new();
            req.insert("type".into(), json!("dbg_attach"));
            req.insert("pid".into(), json!(pid));
            let r = handle(&relay, &req);
            if r["type"] == "error" {
                eprintln!("ptrace not permitted here, skipping: {r}");
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            assert_eq!(r["state"], "stopped", "{r}");
            let call = |v: Value| {
                let Value::Object(m) = v else { unreachable!() };
                handle(&relay, &m)
            };
            let regs = call(json!({ "type": "dbg_regs" }));
            let rip0 = regs["regs"]["rip"].as_str().unwrap().to_owned();
            assert!(rip0.starts_with("0x"), "{regs}");
            let st = call(json!({ "type": "dbg_step" }));
            assert_eq!(st["success"], true, "{st}");

            // breakpoint on a mapped code byte: memory shows 0xcc, removal restores it
            let mem = ProcIo::open(pid).unwrap();
            let at = u64::from_str_radix(st["address"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            let mut orig = [0u8; 1];
            mem.read_at(at, &mut orig).unwrap();
            let b = call(json!({ "type": "dbg_break", "address": hex_addr(at) }));
            assert_eq!(b["breakpoints"][0], hex_addr(at), "{b}");
            let mut now = [0u8; 1];
            mem.read_at(at, &mut now).unwrap();
            assert_eq!(now[0], 0xcc);
            call(json!({ "type": "dbg_break", "address": hex_addr(at), "enabled": false }));
            mem.read_at(at, &mut now).unwrap();
            assert_eq!(now[0], orig[0]);

            let hw = call(json!({ "type": "dbg_hwbreak", "slot": 1, "address": "0x1000", "kind": "write", "len": 8 }));
            assert_eq!(hw["hardware"][1]["kind"], "write", "{hw}");
            let c = call(json!({ "type": "dbg_continue" }));
            assert_eq!(c["state"], "running", "{c}");
            let s = call(json!({ "type": "dbg_status" }));
            assert_eq!(s["state"], "running");
            let d = call(json!({ "type": "dbg_detach" }));
            assert_eq!(d["success"], true);
            assert_eq!(call(json!({ "type": "dbg_status" }))["active"], false);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
