//! A ptrace debugger for the local Linux backend: software breakpoints (int3), hardware
//! breakpoints/watchpoints (DR0-DR3), single-step, continue, register read/write, plus the access
//! finder (`dbg_trace_*`) and the API call monitor (`dbg_api_*`) from `dbg_core`.
//!
//! Linux ties a tracee to the *thread* that attached it, so one dedicated debugger thread owns
//! every ptrace call; verbs talk to it over a channel. All threads of the process are seized
//! (`PTRACE_SEIZE` + `TRACECLONE`), so a breakpoint hit in any thread is caught instead of killing
//! the process. All-stop model: when one thread stops for an event, every thread is interrupted —
//! except for access-finder and API-monitor traps, which are recorded and resumed on the one
//! thread that hit them so the process keeps running.
//!
//! Verbs (`dbg_*`, ext routing): `dbg_attach`, `dbg_detach`, `dbg_status`, `dbg_break`
//! {address, enabled}, `dbg_hwbreak` {slot 0-3, address, kind exec|write|rw, len 1|2|4|8,
//! enabled}, `dbg_continue`, `dbg_step` {tid?}, `dbg_pause`, `dbg_regs` {tid?}, `dbg_set_regs`
//! {tid?, regs}, `dbg_all_regs` (every thread), `dbg_disasm`, `dbg_trace_start|stop|results`,
//! `dbg_api_start|stop|log|clear|signatures`, `dbg_record` (a time-travel trace: single-steps one
//! thread, for `trace_record` with source ptrace). Stops broadcast `{type:"event", event:"dbg_stop",
//! reason, tid, address, regs}`; process exit broadcasts `dbg_exit`; a newly found accessor
//! broadcasts `dbg_access`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::Relay;

/// Original bytes under the debugger's int3s: reads and disassembly show these instead of 0xCC.
/// Shared by the ptrace and the Win32 debugger (only one of them exists per build).
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

/// True while any int3 is planted.
pub fn shadowing() -> bool {
    !SHADOW.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
}

/// Hides planted bytes in a `read` / `read_batch` reply that came from another backend (the Echo
/// agent reading a process the Win32 debugger has breakpoints in).
pub fn unshadow_reply(reply: &mut Value) {
    fn fix(v: &mut Value) {
        let (Some(a), Some(d)) = (v["address"].as_str(), v["data"].as_str()) else { return };
        let Ok(addr) = u64::from_str_radix(a.trim_start_matches("0x"), 16) else { return };
        let Some(mut bytes) = (0..d.len() / 2).map(|i| u8::from_str_radix(d.get(i * 2..i * 2 + 2)?, 16).ok()).collect::<Option<Vec<u8>>>() else { return };
        unshadow(addr, &mut bytes);
        v["data"] = json!(bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
    if !shadowing() {
        return;
    }
    fix(reply);
    if let Some(rs) = reply.get_mut("results").and_then(Value::as_array_mut) {
        rs.iter_mut().for_each(fix);
    }
}

#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
pub(crate) fn shadow_set(addr: u64, orig: Option<u8>) {
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

/// Is a ptrace debug session attached to `pid`? (Its threads cannot be seized a second time.)
#[cfg(not(target_os = "linux"))]
pub fn active_on(_pid: u32) -> bool {
    false
}

#[cfg(target_os = "linux")]
pub use imp::handle;

#[cfg(target_os = "linux")]
pub fn detach_all() {
    crate::dbg_core::detach_all();
}

/// Is a ptrace debug session attached to `pid`? (Its threads cannot be seized a second time.)
#[cfg(target_os = "linux")]
pub fn active_on(pid: u32) -> bool {
    crate::dbg_core::session_pid() == Some(pid)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::mpsc::{Receiver, RecvTimeoutError};
    use std::time::{Duration, Instant};

    use nix::sys::ptrace::{self, Options};
    use nix::sys::signal::Signal;
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;

    use crate::dbg_core::{self as core, bad, failed, with_mon, Abi, Backend, Cmd, Gprs, Hook, HwSlot};
    use crate::local::{arg_addr, hex_addr, MemIo, ProcIo};

    /// offsetof(struct user, u_debugreg) on x86-64
    const DR_OFFSET: usize = 848;
    const EVENT_STOP: i32 = 128; // PTRACE_EVENT_STOP
    const EVENT_CLONE: i32 = 3; // PTRACE_EVENT_CLONE
    const ABI: Abi = Abi::SysV;

    static BACKEND: Backend = Backend { name: "ptrace", abi: ABI, spawn: run, disasm };

    pub fn handle(relay: &Relay, req: &Map<String, Value>) -> Value {
        core::handle(relay, req, crate::local::attached_pid(), &BACKEND)
    }

    fn disasm(pid: u32, req: &Map<String, Value>) -> Value {
        match ProcIo::open(pid) {
            Ok(m) => crate::local::native_disassemble(&m, req),
            Err(e) => failed(e),
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
        /// every planted int3: address -> original byte
        planted: BTreeMap<u64, u8>,
        /// the user's breakpoints (a subset of `planted`)
        user: BTreeSet<u64>,
        /// int3s removed during the session: a thread may still report a trap on one
        retired: BTreeSet<u64>,
        /// slot -> (address, kind, len)
        hw: [HwSlot; 4],
        /// slots that belong to an access-finder trace
        trace: [bool; 4],
        running: bool,
        focus: i32,
        last: Value,
        relay: Relay,
        /// started by the access finder / API monitor: detach when they stop
        auto: bool,
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

    fn gprs(tid: i32) -> Option<Gprs> {
        let r = ptrace::getregs(Pid::from_raw(tid)).ok()?;
        Some(Gprs {
            rax: r.rax, rbx: r.rbx, rcx: r.rcx, rdx: r.rdx, rsi: r.rsi, rdi: r.rdi, rbp: r.rbp, rsp: r.rsp,
            r8: r.r8, r9: r.r9, r10: r.r10, r11: r.r11, r12: r.r12, r13: r.r13, r14: r.r14, r15: r.r15,
            rip: r.rip, eflags: r.eflags, fs_base: r.fs_base, gs_base: r.gs_base,
        })
    }

    fn regs_json(tid: i32) -> Value {
        match ptrace::getregs(Pid::from_raw(tid)) {
            Ok(_) => gprs(tid).map(|g| g.to_json()).unwrap_or(Value::Null),
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

    fn dr6(tid: i32) -> u64 {
        ptrace::read_user(Pid::from_raw(tid), (DR_OFFSET + 6 * 8) as _).unwrap_or(0) as u64
    }

    impl Dbg {
        fn attach_all(&mut self) -> Result<Vec<u64>, String> {
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
                    attached.push(tid as u64);
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

        fn read(&self, addr: u64, buf: &mut [u8]) -> usize {
            let n = self.mem.read_at(addr, buf).unwrap_or(0);
            unshadow(addr, &mut buf[..n]);
            n
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
                    Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
                        // it hit an int3 or a watchpoint on the way: rewind onto the int3 (it
                        // traps again after the resume) and keep the watchpoint hit
                        if let Some(ev) = self.take_trace_hit(tid) {
                            if let Some(ev) = ev { self.relay.emit(ev); }
                        } else {
                            let at = rip(tid).wrapping_sub(1);
                            if self.planted.contains_key(&at) || self.retired.contains(&at) {
                                set_rip(tid, at);
                            }
                        }
                        self.threads.insert(tid, TState::Stopped);
                    }
                    Ok(WaitStatus::Stopped(_, sig)) if sig != Signal::SIGSTOP => {
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

        /// Whether an int3 at `addr` is still wanted (user breakpoint, API entry or return site).
        fn needed(&self, addr: u64) -> bool {
            self.user.contains(&addr) || with_mon(ABI, |m| m.api.is_site(addr))
        }

        fn plant(&mut self, addr: u64) -> Result<(), String> {
            if self.planted.contains_key(&addr) {
                return Ok(());
            }
            let mut b = [0u8; 1];
            if self.mem.read_at(addr, &mut b).map(|n| n != 1).unwrap_or(true) {
                return Err(format!("{addr:#x} is not readable"));
            }
            self.write_byte(addr, 0xcc)?;
            self.planted.insert(addr, b[0]);
            self.retired.remove(&addr);
            shadow_set(addr, Some(b[0]));
            Ok(())
        }

        fn unplant(&mut self, addr: u64) -> Result<(), String> {
            if let Some(orig) = self.planted.remove(&addr) {
                shadow_set(addr, None);
                self.retired.insert(addr);
                self.write_byte(addr, orig)?;
            }
            Ok(())
        }

        fn unplant_if_unused(&mut self, addr: u64) {
            if !self.needed(addr) {
                let _ = self.unplant(addr);
            }
        }

        /// Steps one thread over a user breakpoint that sits at its rip, if any. A thread parked on
        /// an API-monitor int3 is not stepped: it traps again after the resume and gets logged.
        fn step_over_bp(&mut self, tid: i32) -> Result<(), String> {
            let at = rip(tid);
            if !self.user.contains(&at) {
                return Ok(());
            }
            let Some(orig) = self.planted.get(&at).copied() else { return Ok(()) };
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

        fn apply_hw(&self) -> Result<(), String> {
            let dr7 = core::dr7(&self.hw);
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

        fn apply_hw_one(&self, tid: i32) -> Result<(), String> {
            let p = Pid::from_raw(tid);
            for (i, slot) in self.hw.iter().enumerate() {
                let a = slot.as_ref().map(|s| s.0).unwrap_or(0);
                ptrace::write_user(p, (DR_OFFSET + i * 8) as _, a as i64).map_err(|e| e.to_string())?;
            }
            ptrace::write_user(p, (DR_OFFSET + 7 * 8) as _, core::dr7(&self.hw) as i64).map_err(|e| e.to_string())
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

        /// A data-watchpoint trap on an access-finder slot: record it and clear DR6.
        fn take_trace_hit(&mut self, tid: i32) -> Option<Option<Value>> {
            let d6 = dr6(tid);
            let slot = (0..4).find(|i| d6 & (1 << i) != 0 && self.trace[*i])?;
            let _ = ptrace::write_user(Pid::from_raw(tid), (DR_OFFSET + 6 * 8) as _, 0);
            let Some(regs) = gprs(tid) else { return Some(None) };
            let mut before = [0u8; 16];
            let mut n = self.read(regs.rip.wrapping_sub(16), &mut before);
            if n != 16 {
                // the code page before rip may be unmapped: take what this page has
                let k = (regs.rip & 0xfff).min(16) as usize;
                let mut tail = [0u8; 16];
                n = self.read(regs.rip - k as u64, &mut tail[..k]);
                before = [0u8; 16];
                before[16 - n..].copy_from_slice(&tail[..n]);
            }
            let have = &before[16 - n..];
            Some(with_mon(ABI, |m| m.traces[slot].as_mut().and_then(|t| t.record(have, regs.rip, &regs, tid as u64))))
        }

        /// Traps the access finder and the API monitor handle without stopping the process.
        /// `Some(event?)` when handled (the thread is running again).
        fn fast_trap(&mut self, tid: i32) -> Option<Option<Value>> {
            let p = Pid::from_raw(tid);
            if let Some(ev) = self.take_trace_hit(tid) {
                let _ = ptrace::cont(p, None);
                return Some(ev);
            }
            if dr6(tid) & 0xf != 0 {
                return None; // a user hardware breakpoint
            }
            let at = rip(tid).wrapping_sub(1);
            if self.planted.contains_key(&at) && !self.user.contains(&at) {
                set_rip(tid, at);
                let regs = gprs(tid)?;
                let ret_site = {
                    let read = |a: u64, b: &mut [u8]| self.read(a, b);
                    with_mon(ABI, |m| {
                        if m.api.on_return(at, tid as u64, &regs, &read) || !m.api.hooks.contains_key(&at) {
                            None
                        } else {
                            m.api.on_entry(at, tid as u64, &regs, &read)
                        }
                    })
                };
                if let Some(site) = ret_site {
                    let _ = self.plant(site);
                }
                let mut ev = None;
                if self.needed(at) {
                    if let Some(orig) = self.planted.get(&at).copied() {
                        let _ = self.write_byte(at, orig);
                        if ptrace::step(p, None).is_ok() {
                            if let Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) = wait_stop(tid, Duration::from_secs(3)) {
                                self.threads.remove(&tid);
                            }
                        }
                        let _ = self.write_byte(at, 0xcc);
                        ev = self.take_trace_hit(tid).flatten();
                    }
                } else {
                    let _ = self.unplant(at);
                }
                if self.threads.contains_key(&tid) {
                    let _ = ptrace::cont(p, None);
                }
                return Some(ev);
            }
            if self.retired.contains(&at) && !self.planted.contains_key(&at) {
                // an int3 removed while this thread was already trapping on it
                set_rip(tid, at);
                let _ = ptrace::cont(p, None);
                return Some(None);
            }
            None
        }

        /// Non-blocking: reaps one wait status while running; returns an event to broadcast.
        /// `Err(())` when nothing is pending.
        fn poll(&mut self) -> Result<Option<Value>, ()> {
            if !self.running {
                return Err(());
            }
            let st = waitpid(None::<Pid>, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)).map_err(|_| ())?;
            Ok(match st {
                WaitStatus::StillAlive => return Err(()),
                WaitStatus::Exited(p, code) => {
                    self.threads.remove(&p.as_raw());
                    if self.threads.is_empty() || p.as_raw() == self.pid as i32 {
                        self.threads.clear();
                        self.running = false;
                        return Ok(Some(json!({ "type": "event", "event": "dbg_exit", "pid": self.pid, "code": code })));
                    }
                    None
                }
                WaitStatus::Signaled(p, sig, _) => {
                    self.threads.remove(&p.as_raw());
                    if self.threads.is_empty() || p.as_raw() == self.pid as i32 {
                        self.threads.clear();
                        self.running = false;
                        return Ok(Some(json!({ "type": "event", "event": "dbg_exit", "pid": self.pid, "signal": sig.as_str() })));
                    }
                    None
                }
                WaitStatus::PtraceEvent(p, _, ev) if ev == EVENT_CLONE => {
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
                    if sig == Signal::SIGTRAP {
                        if let Some(ev) = self.fast_trap(tid) {
                            return Ok(ev);
                        }
                    }
                    self.threads.insert(tid, TState::Stopped);
                    self.stop_all(tid);
                    if sig == Signal::SIGTRAP {
                        let at = rip(tid).wrapping_sub(1);
                        if self.planted.contains_key(&at) {
                            set_rip(tid, at);
                            // a user breakpoint on a monitored function still logs the call
                            if let Some(regs) = gprs(tid) {
                                let read = |a: u64, b: &mut [u8]| self.read(a, b);
                                let site = with_mon(ABI, |m| m.api.on_entry(at, tid as u64, &regs, &read));
                                if let Some(s) = site {
                                    let _ = self.plant(s);
                                }
                            }
                            return Ok(Some(self.stop_event(tid, "breakpoint", json!({}))));
                        }
                        let d6 = dr6(tid);
                        if let Some(slot) = (0..4).find(|i| d6 & (1 << i) != 0) {
                            let _ = ptrace::write_user(p, (DR_OFFSET + 6 * 8) as _, 0);
                            let hit = self.hw[slot].as_ref().map(|h| hex_addr(h.0));
                            return Ok(Some(self.stop_event(tid, "hardware", json!({ "slot": slot, "watch": hit }))));
                        }
                        return Ok(Some(self.stop_event(tid, "trap", json!({}))));
                    }
                    self.signals.insert(tid, sig);
                    Some(self.stop_event(tid, "signal", json!({ "signal": sig.as_str() })))
                }
                _ => None,
            })
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
            let threads: Vec<Value> = self.threads.iter().map(|(t, s)| {
                let mut v = json!({ "tid": t, "state": format!("{s:?}").to_lowercase() });
                if *s == TState::Stopped {
                    v["rip"] = json!(hex_addr(rip(*t)));
                }
                v
            }).collect();
            let bps: Vec<Value> = self.user.iter().map(|a| json!(hex_addr(*a))).collect();
            let hw: Vec<Value> = self.hw.iter().enumerate().map(|(i, h)| match h {
                Some((a, k, l)) => json!({ "slot": i, "address": hex_addr(*a), "kind": k, "len": l, "trace": self.trace[i] }),
                None => json!({ "slot": i, "address": null }),
            }).collect();
            let api = with_mon(ABI, |m| m.api.hooks.len());
            json!({ "type": "dbg_status_result", "success": true, "active": true, "backend": "ptrace", "pid": self.pid, "state": if self.running { "running" } else { "stopped" },
                "focus": self.focus, "threads": threads, "breakpoints": bps, "hardware": hw, "last": self.last, "auto": self.auto,
                "api_hooks": api, "traces": core::traces_json(ABI) })
        }

        fn nothing_left(&self) -> bool {
            self.user.is_empty() && self.hw.iter().all(Option::is_none) && with_mon(ABI, |m| m.api.hooks.is_empty())
        }

        fn detach(&mut self) {
            self.need_stopped();
            with_mon(ABI, |m| {
                m.api.stop();
                m.traces.iter_mut().flatten().for_each(|t| t.active = false);
            });
            self.user.clear();
            for (a, b) in std::mem::take(&mut self.planted) {
                shadow_set(a, None);
                let _ = self.write_byte(a, b);
            }
            self.hw = [None, None, None, None];
            self.trace = [false; 4];
            let _ = self.apply_hw();
            for (tid, _) in std::mem::take(&mut self.threads) {
                let sig = self.signals.remove(&tid);
                let _ = ptrace::detach(Pid::from_raw(tid), sig);
            }
        }

        /// After a monitor stopped: an auto-started session detaches when nothing is left.
        fn finish(&mut self, mut reply: Value, was_running: bool) -> Value {
            if self.auto && self.nothing_left() {
                self.detach();
                reply["detached"] = json!(true);
            } else if was_running {
                let _ = self.resume_all();
            }
            reply
        }

        fn resolve(&self, spec: &str) -> Result<u64, String> {
            let (module, name) = match spec.split_once('!') {
                Some((m, n)) => (m.trim(), n.trim()),
                None => ("", spec.trim()),
            };
            if let Some(h) = name.strip_prefix("0x") {
                return u64::from_str_radix(h, 16).map_err(|_| format!("bad address {name}"));
            }
            let try_mod = |m: &str| {
                let mut r = Map::new();
                r.insert("module".into(), json!(m));
                r.insert("name".into(), json!(name));
                let v = crate::local_ext::resolve_export(&self.mem, &r);
                v.as_object().filter(|_| v["success"] == true).and_then(|o| arg_addr(o, "address"))
            };
            if !module.is_empty() {
                return try_mod(module).ok_or_else(|| format!("{spec}: not exported by {module}"));
            }
            let mods = self.mem.modules().map_err(|e| e.to_string())?;
            mods.iter().find_map(|(m, _, _)| try_mod(m)).ok_or_else(|| format!("{spec}: no loaded module exports it"))
        }

        fn command(&mut self, req: &Map<String, Value>) -> Value {
            let verb = req.get("type").and_then(Value::as_str).unwrap_or_default();
            let auto = req.get("auto") == Some(&json!(true));
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
                    let result = if let Some(orig) = self.planted.get(&at).copied() {
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
                            if let Some(Some(ev)) = self.take_trace_hit(tid) {
                                self.relay.emit(ev);
                            }
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
                    let Some(mut g) = gprs(tid) else { return failed("cannot read registers") };
                    g.apply(set);
                    (r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp) = (g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.rbp, g.rsp);
                    (r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15) = (g.r8, g.r9, g.r10, g.r11, g.r12, g.r13, g.r14, g.r15);
                    (r.rip, r.eflags) = (g.rip, g.eflags);
                    match ptrace::setregs(Pid::from_raw(tid), r) {
                        Ok(()) => json!({ "type": "dbg_set_regs_result", "success": true, "tid": tid, "regs": regs_json(tid) }),
                        Err(e) => failed(e),
                    }
                }
                "dbg_break" => {
                    let Some(addr) = arg_addr(req, "address") else { return bad("dbg_break requires 'address'") };
                    let enabled = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                    if enabled {
                        if let Err(e) = core::check_code(&self.mem, addr).and_then(|()| self.plant(addr)) {
                            return failed(e);
                        }
                        self.user.insert(addr);
                    } else if self.user.remove(&addr) && !self.needed(addr) {
                        if let Err(e) = self.unplant(addr) {
                            return failed(e);
                        }
                    }
                    json!({ "type": "dbg_break_result", "success": true, "breakpoints": self.user.iter().map(|a| hex_addr(*a)).collect::<Vec<_>>() })
                }
                "dbg_hwbreak" => {
                    let (slot, val) = match core::parse_hwbreak(req) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if self.trace[slot] {
                        return failed(format!("DR{slot} is used by an access-finder trace; stop it first"));
                    }
                    if let Some((a, kind, _)) = &val {
                        if kind == "exec" {
                            if let Err(e) = core::check_code(&self.mem, *a) {
                                return failed(e);
                            }
                        }
                    }
                    self.hw[slot] = val;
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
                "dbg_trace_start" => {
                    let t = match core::parse_trace(req, &self.hw) {
                        Ok(t) => t,
                        Err(e) => return e,
                    };
                    if self.hw[t.slot].is_some() && !self.trace[t.slot] {
                        return failed(format!("DR{} holds a hardware breakpoint; pick another slot", t.slot));
                    }
                    let slot = t.slot;
                    self.hw[slot] = Some(t.hw());
                    self.trace[slot] = true;
                    let reply = json!({ "type": "dbg_trace_start_result", "success": true, "slot": slot, "address": hex_addr(t.address), "size": t.size, "kind": t.kind,
                        "watch": { "address": hex_addr(t.watch.0), "len": t.watch.1 }, "auto": auto || self.auto });
                    with_mon(ABI, |m| m.traces[slot] = Some(t));
                    let was_running = self.running;
                    self.need_stopped();
                    if let Err(e) = self.apply_hw() {
                        self.hw[slot] = None;
                        self.trace[slot] = false;
                        with_mon(ABI, |m| m.traces[slot] = None);
                        return self.finish(failed(e), was_running);
                    }
                    if auto {
                        self.auto = true;
                    }
                    if was_running || auto {
                        let _ = self.resume_all();
                    }
                    reply
                }
                "dbg_trace_stop" => {
                    let only = req.get("slot").and_then(Value::as_u64).map(|s| s as usize);
                    let was_running = self.running;
                    self.need_stopped();
                    for i in 0..4 {
                        if self.trace[i] && only.is_none_or(|s| s == i) {
                            self.trace[i] = false;
                            self.hw[i] = None;
                            with_mon(ABI, |m| if let Some(t) = m.traces[i].as_mut() { t.active = false });
                        }
                    }
                    let r = self.apply_hw();
                    let reply = match r {
                        Ok(()) => json!({ "type": "dbg_trace_stop_result", "success": true, "traces": core::traces_json(ABI) }),
                        Err(e) => failed(e),
                    };
                    self.finish(reply, was_running)
                }
                "dbg_api_start" => {
                    let specs = match core::parse_api_functions(req) {
                        Ok(s) => s,
                        Err(e) => return e,
                    };
                    let was_running = self.running;
                    self.need_stopped();
                    let mut added = Vec::new();
                    let mut unresolved = Vec::new();
                    for (spec, addr) in specs {
                        let addr = match addr.map(Ok).unwrap_or_else(|| self.resolve(&spec)) {
                            Ok(a) => a,
                            Err(e) => {
                                unresolved.push(json!({ "name": spec, "error": e }));
                                continue;
                            }
                        };
                        if let Err(e) = core::check_code(&self.mem, addr).and_then(|()| self.plant(addr)) {
                            unresolved.push(json!({ "name": spec, "error": e }));
                            continue;
                        }
                        with_mon(ABI, |m| {
                            m.api.hooks.insert(addr, Hook { name: spec.clone(), hits: 0 });
                            m.api.active = true;
                        });
                        added.push(json!({ "name": spec, "address": hex_addr(addr) }));
                    }
                    if added.is_empty() {
                        let e = failed(format!("no function could be hooked: {}", Value::Array(unresolved)));
                        return if auto { self.auto = true; self.finish(e, false) } else { self.finish(e, was_running) };
                    }
                    if auto {
                        self.auto = true;
                    }
                    if was_running || auto {
                        let _ = self.resume_all();
                    }
                    json!({ "type": "dbg_api_start_result", "success": true, "hooked": added, "unresolved": unresolved, "hooks": with_mon(ABI, |m| m.api.hooks_json()), "auto": self.auto })
                }
                "dbg_api_stop" => {
                    let was_running = self.running;
                    self.need_stopped();
                    let sites: Vec<u64> = with_mon(ABI, |m| {
                        let mut s: Vec<u64> = m.api.hooks.keys().copied().collect();
                        s.extend(m.api.return_sites());
                        m.api.stop();
                        s
                    });
                    for a in sites {
                        self.unplant_if_unused(a);
                    }
                    let total = with_mon(ABI, |m| m.api.log_json(u64::MAX, 1, "")["total"].clone());
                    self.finish(json!({ "type": "dbg_api_stop_result", "success": true, "calls": total }), was_running)
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
            let orig = self.d.planted.get(&at).copied();
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

    fn run(pid: u32, rx: Receiver<Cmd>, ready: core::Ready, relay: Relay) {
        let mem = match ProcIo::open(pid) {
            Ok(m) => m,
            Err(e) => {
                let _ = ready.send(Err(e.to_string()));
                return;
            }
        };
        if let Err(e) = core::check_process(&mem, crate::local::main_module(&mem)) {
            let _ = ready.send(Err(e));
            return;
        }
        let mut d = Dbg {
            pid, mem, threads: BTreeMap::new(), signals: HashMap::new(), planted: BTreeMap::new(), user: BTreeSet::new(), retired: BTreeSet::new(),
            hw: [None, None, None, None], trace: [false; 4], running: false, focus: pid as i32, last: Value::Null, relay, auto: false,
        };
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
                    let r = d.command(&req);
                    let end = core::ends_session(&req, &r);
                    let _ = reply.send(r);
                    if end {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    d.detach();
                    return;
                }
            }
            // drain what is pending, but come back to the command channel regularly
            for _ in 0..256 {
                match d.poll() {
                    Err(()) => break,
                    Ok(None) => {}
                    Ok(Some(ev)) => {
                        let exit = ev["event"] == "dbg_exit";
                        d.relay.emit(ev);
                        if exit {
                            with_mon(ABI, |m| {
                                m.api.stop();
                                m.traces.iter_mut().flatten().for_each(|t| t.active = false);
                            });
                            for a in std::mem::take(&mut d.planted).into_keys() {
                                shadow_set(a, None);
                            }
                            core::end_session();
                            return;
                        }
                    }
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
            // dbg_disasm hides it
            let d = call(json!({ "type": "dbg_disasm", "address": hex_addr(at), "size": 16 }));
            assert_eq!(d["type"], "dbg_disasm_result", "{d}");
            assert_ne!(d["results"][0]["bytes"].as_str().unwrap().get(..2), Some("cc"), "{d}");
            call(json!({ "type": "dbg_break", "address": hex_addr(at), "enabled": false }));
            mem.read_at(at, &mut now).unwrap();
            assert_eq!(now[0], orig[0]);

            let hw = call(json!({ "type": "dbg_hwbreak", "slot": 1, "address": "0x1000", "kind": "write", "len": 8 }));
            assert_eq!(hw["hardware"][1]["kind"], "write", "{hw}");
            let c = call(json!({ "type": "dbg_continue" }));
            assert_eq!(c["state"], "running", "{c}");
            let s = call(json!({ "type": "dbg_status" }));
            assert_eq!(s["state"], "running");
            assert!(s["threads"][0]["tid"].as_i64().is_some(), "{s}");
            let d = call(json!({ "type": "dbg_detach" }));
            assert_eq!(d["success"], true);
            assert_eq!(call(json!({ "type": "dbg_status" }))["active"], false);
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
