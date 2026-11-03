//! Native Windows debugger (Win32 debug API) for a local x64 process: the same `dbg_*` verbs,
//! replies and events as the ptrace debugger in `local_dbg.rs`, so the Debugger view, the access
//! finder and the API monitor work on both OSes.
//!
//! It is a separate, optional backend: Windows targets normally reach the relay through the Echo
//! agent, which has no debugger API. The user picks this one in the Debugger view for a process
//! on this machine (by default the one Echo is attached to). `ECHODEBUG_NATIVE_DEBUGGER=0` turns
//! it off. Unlike Echo's memory access it is visible to the target (IsDebuggerPresent, the debug
//! port), and it attaches with `DebugActiveProcess` like any user-mode debugger.
//!
//! One thread owns the debug session (the Win32 debug object belongs to the thread that called
//! `DebugActiveProcess`): it runs `WaitForDebugEvent` / `ContinueDebugEvent` and serves the verbs
//! sent over the channel. While a debug event is held, every thread of the target is frozen
//! (all-stop). Breakpoints: int3 written with `WriteProcessMemory` (original bytes hidden from
//! reads like on Linux), stepped over with the trap flag while the other threads are suspended;
//! hardware breakpoints in DR0-DR3 of every thread (new threads get them on CREATE_THREAD).
//! Detach restores every byte and debug register, drains late breakpoint events and calls
//! `DebugActiveProcessStop` with kill-on-exit off, so the target keeps running.

use serde_json::{Map, Value};

use crate::Relay;

/// Whether `dbg_*` verbs go to the native Windows debugger (Windows builds, unless
/// `ECHODEBUG_NATIVE_DEBUGGER=0`).
pub fn enabled() -> bool {
    cfg!(windows) && std::env::var("ECHODEBUG_NATIVE_DEBUGGER").map(|v| v != "0").unwrap_or(true)
}

/// True when this debugger has int3s planted in `target` (the process another backend reads).
pub fn shadows(target: Option<u32>) -> bool {
    enabled() && target.is_some() && crate::dbg_core::session_pid() == target && crate::local_dbg::shadowing()
}

#[cfg(not(windows))]
pub fn handle(_relay: &Relay, _req: &Map<String, Value>, _target: Option<u32>) -> Value {
    crate::dbg_core::failed("the native Windows debugger exists in Windows builds only")
}

/// Disassembly of the debuggee with planted bytes hidden (replaces an Echo reply that shows them).
#[cfg(not(windows))]
pub fn redisasm(_req: &Map<String, Value>) -> Option<Value> {
    None
}

#[cfg(windows)]
pub use imp::{handle, redisasm};

#[cfg(windows)]
mod imp {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use serde_json::json;
    use std::ffi::c_void;
    use std::io;
    use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, NTSTATUS,
        STATUS_WX86_BREAKPOINT,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::{
        ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugBreakProcess, DebugSetProcessKillOnExit, FlushInstructionCache,
        GetThreadContext, ReadProcessMemory, SetThreadContext, WaitForDebugEvent, WriteProcessMemory, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
        CONTEXT_FULL_AMD64, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
        EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32};
    use windows_sys::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
    use windows_sys::Win32::System::Threading::{
        IsWow64Process, OpenProcess, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    use crate::dbg_core::{self as core, arg_addr, bad, failed, hex, with_mon, Abi, Backend, Cmd, Export, Gprs, Hook, HwSlot};
    use crate::local::{MapLine, MemIo};
    use crate::local_dbg::{shadow_set, unshadow};

    const ABI: Abi = Abi::Win64;
    const TF: u32 = 0x100;
    const CTX_FLAGS: u32 = CONTEXT_FULL_AMD64 | CONTEXT_DEBUG_REGISTERS_AMD64;
    /// first-chance exceptions that are routine (C++ throw, thread naming, OutputDebugString
    /// variants, RPC): reported as `dbg_exception` without stopping
    const ROUTINE: &[u32] = &[0xE06D_7363, 0x406D_1388, 0x4001_0006, 0x4001_000A, 0x0000_06BA, 0x0000_071A];

    static BACKEND: Backend = Backend { name: "windows", abi: ABI, spawn: run, disasm };

    pub fn handle(relay: &Relay, req: &Map<String, Value>, target: Option<u32>) -> Value {
        core::handle(relay, req, target, &BACKEND)
    }

    fn disasm(pid: u32, req: &Map<String, Value>) -> Value {
        match WinIo::open(pid) {
            Ok(m) => crate::local::native_disassemble(&m, req),
            Err(e) => failed(e),
        }
    }

    pub fn redisasm(req: &Map<String, Value>) -> Option<Value> {
        let pid = core::session_pid()?;
        let v = disasm(pid, req);
        (v["type"] == "disassemble_result").then_some(v)
    }

    // ---- process memory -------------------------------------------------------------------------

    /// A process handle with VM read/write rights (owned; closed on drop).
    pub struct WinIo {
        h: HANDLE,
        pid: u32,
    }

    // SAFETY: a process handle is a kernel object reference, usable from any thread.
    unsafe impl Send for WinIo {}
    unsafe impl Sync for WinIo {}

    impl WinIo {
        pub fn open(pid: u32) -> io::Result<WinIo> {
            // SAFETY: plain Win32 call; a null handle is checked below.
            let h = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, 0, pid) };
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(WinIo { h, pid })
        }

        fn rpm(&self, addr: u64, buf: &mut [u8]) -> usize {
            let mut n = 0usize;
            // SAFETY: the buffer is valid for buf.len() bytes; n receives the count.
            let ok = unsafe { ReadProcessMemory(self.h, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut n) };
            if ok == 0 { 0 } else { n }
        }

        fn wow64(&self) -> bool {
            let mut w = 0;
            // SAFETY: w is a valid out pointer.
            unsafe { IsWow64Process(self.h, &mut w) != 0 && w != 0 }
        }
    }

    impl Drop for WinIo {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by WinIo::open and is closed once.
            unsafe { CloseHandle(self.h) };
        }
    }

    impl MemIo for WinIo {
        fn read_at(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let n = self.rpm(addr, buf);
            if n == buf.len() {
                return Ok(n);
            }
            // ReadProcessMemory fails as a whole across an unmapped page: read page by page
            let mut done = 0usize;
            while done < buf.len() {
                let a = addr + done as u64;
                let chunk = (buf.len() - done).min(0x1000 - (a & 0xfff) as usize);
                let n = self.rpm(a, &mut buf[done..done + chunk]);
                if n == 0 {
                    break;
                }
                done += n;
            }
            if done == 0 { Err(io::Error::last_os_error()) } else { Ok(done) }
        }

        fn write_at(&self, addr: u64, buf: &[u8]) -> io::Result<()> {
            let write = || {
                let mut n = 0usize;
                // SAFETY: the buffer is valid for buf.len() bytes.
                unsafe { WriteProcessMemory(self.h, addr as *const c_void, buf.as_ptr() as *const c_void, buf.len(), &mut n) != 0 && n == buf.len() }
            };
            let mut ok = write();
            if !ok {
                // code pages are not writable: lift the protection for the write
                let mut old: PAGE_PROTECTION_FLAGS = 0;
                // SAFETY: old is a valid out pointer; the range is the one being written.
                if unsafe { VirtualProtectEx(self.h, addr as *const c_void, buf.len(), PAGE_EXECUTE_READWRITE, &mut old) } != 0 {
                    ok = write();
                    let mut tmp: PAGE_PROTECTION_FLAGS = 0;
                    // SAFETY: as above, restoring the previous protection.
                    unsafe { VirtualProtectEx(self.h, addr as *const c_void, buf.len(), old, &mut tmp) };
                }
            }
            // SAFETY: flushes the instruction cache for the written range.
            unsafe { FlushInstructionCache(self.h, addr as *const c_void, buf.len()) };
            if ok { Ok(()) } else { Err(io::Error::last_os_error()) }
        }

        fn maps(&self) -> io::Result<Vec<MapLine>> {
            Ok(Vec::new())
        }

        fn modules(&self) -> io::Result<Vec<(String, u64, u64)>> {
            for _ in 0..5 {
                // SAFETY: plain Win32 call; the handle is checked and closed below.
                let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) };
                if snap.is_null() || snap as isize == -1 {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                let mut out = Vec::new();
                // SAFETY: zeroed MODULEENTRY32W with dwSize set, as the API requires.
                let mut me: MODULEENTRY32W = unsafe { std::mem::zeroed() };
                me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
                // SAFETY: snap is a valid snapshot handle, me a valid entry.
                let mut ok = unsafe { Module32FirstW(snap, &mut me) } != 0;
                while ok {
                    let end = me.szModule.iter().position(|c| *c == 0).unwrap_or(me.szModule.len());
                    out.push((String::from_utf16_lossy(&me.szModule[..end]), me.modBaseAddr as u64, me.modBaseSize as u64));
                    // SAFETY: as above.
                    ok = unsafe { Module32NextW(snap, &mut me) } != 0;
                }
                // SAFETY: closes the snapshot handle once.
                unsafe { CloseHandle(snap) };
                return Ok(out);
            }
            Err(io::Error::last_os_error())
        }

        fn alive(&self) -> bool {
            true
        }
    }

    // ---- thread contexts ------------------------------------------------------------------------

    /// CONTEXT must be 16-byte aligned for Get/SetThreadContext.
    #[repr(C, align(16))]
    struct Ctx(CONTEXT);

    fn get_ctx(h: HANDLE) -> Option<Box<Ctx>> {
        // SAFETY: CONTEXT is plain data; zeroed is a valid initial value.
        let mut c: Box<Ctx> = Box::new(Ctx(unsafe { std::mem::zeroed() }));
        c.0.ContextFlags = CTX_FLAGS;
        // SAFETY: h is a thread handle from a debug event; c is aligned and writable.
        (unsafe { GetThreadContext(h, &mut c.0) } != 0).then_some(c)
    }

    fn set_ctx(h: HANDLE, c: &Ctx) -> bool {
        // SAFETY: as get_ctx.
        unsafe { SetThreadContext(h, &c.0) != 0 }
    }

    fn gprs_of(c: &CONTEXT) -> Gprs {
        Gprs {
            rax: c.Rax, rbx: c.Rbx, rcx: c.Rcx, rdx: c.Rdx, rsi: c.Rsi, rdi: c.Rdi, rbp: c.Rbp, rsp: c.Rsp,
            r8: c.R8, r9: c.R9, r10: c.R10, r11: c.R11, r12: c.R12, r13: c.R13, r14: c.R14, r15: c.R15,
            rip: c.Rip, eflags: c.EFlags as u64, fs_base: 0, gs_base: 0,
        }
    }

    fn put_gprs(c: &mut CONTEXT, g: &Gprs) {
        (c.Rax, c.Rbx, c.Rcx, c.Rdx, c.Rsi, c.Rdi, c.Rbp, c.Rsp) = (g.rax, g.rbx, g.rcx, g.rdx, g.rsi, g.rdi, g.rbp, g.rsp);
        (c.R8, c.R9, c.R10, c.R11, c.R12, c.R13, c.R14, c.R15) = (g.r8, g.r9, g.r10, g.r11, g.r12, g.r13, g.r14, g.r15);
        c.Rip = g.rip;
        c.EFlags = g.eflags as u32;
    }

    fn exception_text(code: u32, info: &[usize]) -> String {
        match code {
            0xC000_0005 => {
                let what = match info.first() { Some(0) => "read", Some(1) => "write", Some(8) => "execute", _ => "access" };
                format!("access violation ({what} at {})", hex(info.get(1).copied().unwrap_or(0) as u64))
            }
            0x8000_0003 => "breakpoint".into(),
            0x8000_0004 => "single step".into(),
            0x8000_0001 => "guard page".into(),
            0xC000_001D => "illegal instruction".into(),
            0xC000_0094 => "integer divide by zero".into(),
            0xC000_0095 => "integer overflow".into(),
            0xC000_00FD => "stack overflow".into(),
            0xC000_0096 => "privileged instruction".into(),
            0xC000_0409 => "stack buffer overrun (fast fail)".into(),
            0xC000_0374 => "heap corruption".into(),
            0xE06D_7363 => "C++ exception".into(),
            0x406D_1388 => "thread name".into(),
            0x4001_0006 | 0x4001_000A => "debug print".into(),
            _ => "exception".into(),
        }
    }

    // ---- the debugger ---------------------------------------------------------------------------

    /// Why a thread single-steps: re-plant an int3, or re-enable its hardware breakpoints.
    #[derive(Clone, Copy, Debug)]
    enum Rearm {
        Int3(u64),
        Hw,
    }

    struct Held {
        tid: u32,
        status: NTSTATUS,
    }

    enum Next {
        /// continue with this status; maybe broadcast an event
        Go(NTSTATUS, Option<Value>),
        /// keep the event (all threads frozen); broadcast the stop event unless it is null
        Hold(NTSTATUS, Value),
        Exit(Value),
    }

    struct Dbg {
        pid: u32,
        io: WinIo,
        /// the debug event's process handle (full access; owned by the system)
        hproc: HANDLE,
        threads: BTreeMap<u32, HANDLE>,
        main_tid: u32,
        planted: BTreeMap<u64, u8>,
        user: BTreeSet<u64>,
        retired: BTreeSet<u64>,
        hw: [HwSlot; 4],
        trace: [bool; 4],
        held: Option<Held>,
        focus: u32,
        last: Value,
        relay: Relay,
        auto: bool,
        rearm: HashMap<u32, Rearm>,
        /// dbg_step in progress: (thread, from)
        user_step: Option<(u32, u64)>,
        /// threads suspended while one thread steps over a breakpoint
        suspended: Vec<u32>,
        /// threads stopped on an execute hardware breakpoint (step past it with the DR off)
        hw_stopped: BTreeSet<u32>,
        /// DebugBreakProcess break-ins still to come, and whether one should stop (and quietly)
        breakins: u32,
        pause_wanted: bool,
        pause_silent: bool,
        attach_done: bool,
        exited: bool,
    }

    // SAFETY: the handles are only used from the debugger thread that owns this value.
    unsafe impl Send for Dbg {}

    fn wait_event(ms: u32) -> Option<DEBUG_EVENT> {
        // SAFETY: DEBUG_EVENT is plain data, filled by the call.
        let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        // SAFETY: ev is a valid out pointer.
        (unsafe { WaitForDebugEvent(&mut ev, ms) } != 0).then_some(ev)
    }

    fn cont(pid: u32, tid: u32, status: NTSTATUS) {
        // SAFETY: continues the event this debugger received.
        unsafe { ContinueDebugEvent(pid, tid, status) };
    }

    fn close_file(h: HANDLE) {
        if !h.is_null() {
            // SAFETY: file handles in CREATE_PROCESS / LOAD_DLL events belong to the debugger.
            unsafe { CloseHandle(h) };
        }
    }

    impl Dbg {
        fn read(&self, addr: u64, buf: &mut [u8]) -> usize {
            let n = self.io.read_at(addr, buf).unwrap_or(0);
            unshadow(addr, &mut buf[..n]);
            n
        }

        fn write_byte(&self, addr: u64, b: u8) -> Result<(), String> {
            self.io.write_at(addr, &[b]).map_err(|e| format!("{}: {e}", hex(addr)))
        }

        fn needed(&self, addr: u64) -> bool {
            self.user.contains(&addr) || with_mon(ABI, |m| m.api.is_site(addr))
        }

        fn plant(&mut self, addr: u64) -> Result<(), String> {
            if self.planted.contains_key(&addr) {
                return Ok(());
            }
            let mut b = [0u8; 1];
            if self.io.read_at(addr, &mut b).map(|n| n != 1).unwrap_or(true) {
                return Err(format!("{} is not readable", hex(addr)));
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
                // a thread stepping over it already sees the original byte
                self.write_byte(addr, orig)?;
            }
            Ok(())
        }

        fn unplant_if_unused(&mut self, addr: u64) {
            if !self.needed(addr) {
                let _ = self.unplant(addr);
            }
        }

        fn th(&self, tid: u32) -> Option<HANDLE> {
            self.threads.get(&tid).copied()
        }

        fn regs(&self, tid: u32) -> Option<Gprs> {
            get_ctx(self.th(tid)?).map(|c| gprs_of(&c.0))
        }

        fn regs_json(&self, tid: u32) -> Value {
            self.regs(tid).map(|g| g.to_json()).unwrap_or_else(|| json!({ "error": format!("cannot read the context of thread {tid}") }))
        }

        fn set_rip(&self, tid: u32, rip: u64) {
            if let Some(h) = self.th(tid) {
                if let Some(mut c) = get_ctx(h) {
                    c.0.Rip = rip;
                    set_ctx(h, &c);
                }
            }
        }

        fn apply_hw_one(&self, h: HANDLE) -> Result<(), String> {
            let mut c = get_ctx(h).ok_or("GetThreadContext failed")?;
            let a = |i: usize| self.hw[i].as_ref().map(|s| s.0).unwrap_or(0);
            (c.0.Dr0, c.0.Dr1, c.0.Dr2, c.0.Dr3) = (a(0), a(1), a(2), a(3));
            c.0.Dr7 = core::dr7(&self.hw);
            if set_ctx(h, &c) { Ok(()) } else { Err("SetThreadContext failed".into()) }
        }

        fn apply_hw(&self) -> Result<(), String> {
            for (tid, h) in &self.threads {
                self.apply_hw_one(*h).map_err(|e| format!("thread {tid}: {e}"))?;
            }
            Ok(())
        }

        fn suspend_others(&mut self, tid: u32) {
            for (t, h) in &self.threads {
                // SAFETY: thread handles from debug events carry THREAD_SUSPEND_RESUME.
                if *t != tid && unsafe { SuspendThread(*h) } != u32::MAX {
                    self.suspended.push(*t);
                }
            }
        }

        fn resume_suspended(&mut self) {
            for t in std::mem::take(&mut self.suspended) {
                if let Some(h) = self.th(t) {
                    // SAFETY: as suspend_others.
                    unsafe { ResumeThread(h) };
                }
            }
        }

        fn stop_event(&mut self, tid: u32, reason: &str, extra: Value) -> Value {
            let regs = self.regs(tid).unwrap_or_default();
            let mut ev = json!({ "type": "event", "event": "dbg_stop", "reason": reason, "tid": tid, "address": hex(regs.rip), "regs": regs.to_json() });
            if let (Value::Object(e), Value::Object(x)) = (&mut ev, extra) {
                e.extend(x);
            }
            self.focus = tid;
            self.last = ev.clone();
            ev
        }

        fn take_trace_hit(&mut self, tid: u32, c: &mut Ctx) -> Option<Value> {
            let slot = (0..4).find(|i| c.0.Dr6 & (1 << i) != 0 && self.trace[*i])?;
            let regs = gprs_of(&c.0);
            let mut before = [0u8; 16];
            let mut n = self.read(regs.rip.wrapping_sub(16), &mut before);
            if n != 16 {
                let k = (regs.rip & 0xfff).min(16) as usize;
                let mut tail = [0u8; 16];
                n = self.read(regs.rip - k as u64, &mut tail[..k]);
                before = [0u8; 16];
                before[16 - n..].copy_from_slice(&tail[..n]);
            }
            let have = &before[16 - n..];
            with_mon(ABI, |m| m.traces[slot].as_mut().and_then(|t| t.record(have, regs.rip, &regs, tid as u64)))
        }

        /// One of our int3s was hit by `tid`.
        fn on_int3(&mut self, tid: u32, addr: u64) -> Next {
            let Some(h) = self.th(tid) else { return Next::Go(DBG_CONTINUE, None) };
            let Some(mut c) = get_ctx(h) else { return Next::Go(DBG_CONTINUE, None) };
            c.0.Rip = addr;
            let regs = gprs_of(&c.0);
            let user = self.user.contains(&addr);
            let ret_site = {
                let read = |a: u64, b: &mut [u8]| self.read(a, b);
                with_mon(ABI, |m| {
                    if (!user && m.api.on_return(addr, tid as u64, &regs, &read)) || !m.api.hooks.contains_key(&addr) {
                        None
                    } else {
                        m.api.on_entry(addr, tid as u64, &regs, &read)
                    }
                })
            };
            if let Some(site) = ret_site {
                let _ = self.plant(site);
            }
            if user {
                set_ctx(h, &c);
                let ev = self.stop_event(tid, "breakpoint", json!({}));
                return Next::Hold(DBG_CONTINUE, ev);
            }
            // API monitor: log and run on (other threads keep running; one passing the
            // function during the single step is not logged)
            if self.needed(addr) {
                if let Some(orig) = self.planted.get(&addr).copied() {
                    let _ = self.write_byte(addr, orig);
                    c.0.EFlags |= TF;
                    self.rearm.insert(tid, Rearm::Int3(addr));
                }
            } else {
                let _ = self.unplant(addr);
            }
            set_ctx(h, &c);
            Next::Go(DBG_CONTINUE, None)
        }

        fn on_single_step(&mut self, tid: u32) -> Next {
            let Some(h) = self.th(tid) else { return Next::Go(DBG_CONTINUE, None) };
            let Some(mut c) = get_ctx(h) else { return Next::Go(DBG_CONTINUE, None) };
            let trace_ev = self.take_trace_hit(tid, &mut c);
            let dr6 = c.0.Dr6;
            c.0.Dr6 = 0;
            let rearmed = self.rearm.remove(&tid);
            match rearmed {
                Some(Rearm::Int3(a)) if self.planted.contains_key(&a) => {
                    let _ = self.write_byte(a, 0xcc);
                }
                Some(Rearm::Hw) => {
                    let a = |i: usize| self.hw[i].as_ref().map(|s| s.0).unwrap_or(0);
                    (c.0.Dr0, c.0.Dr1, c.0.Dr2, c.0.Dr3) = (a(0), a(1), a(2), a(3));
                    c.0.Dr7 = core::dr7(&self.hw);
                }
                _ => {}
            }
            if rearmed.is_some() || self.user_step.is_some_and(|s| s.0 == tid) {
                c.0.EFlags &= !TF;
            }
            set_ctx(h, &c);
            if let Some((t, from)) = self.user_step {
                if t == tid {
                    self.user_step = None;
                    self.resume_suspended();
                    if let Some(ev) = trace_ev {
                        self.relay.emit(ev);
                    }
                    let ev = self.stop_event(tid, "step", json!({ "from": hex(from) }));
                    return Next::Hold(DBG_CONTINUE, ev);
                }
            }
            if rearmed.is_some() {
                self.resume_suspended();
                return Next::Go(DBG_CONTINUE, trace_ev);
            }
            if trace_ev.is_some() || (dr6 & 0xf != 0 && (0..4).all(|i| dr6 & (1 << i) == 0 || self.trace[i])) {
                return Next::Go(DBG_CONTINUE, trace_ev);
            }
            if let Some(slot) = (0..4).find(|i| dr6 & (1 << i) != 0) {
                if self.hw[slot].as_ref().is_some_and(|s| s.1 == "exec") {
                    self.hw_stopped.insert(tid);
                }
                let watch = self.hw[slot].as_ref().map(|s| hex(s.0));
                let ev = self.stop_event(tid, "hardware", json!({ "slot": slot, "watch": watch }));
                return Next::Hold(DBG_CONTINUE, ev);
            }
            // the program set the trap flag itself
            let ev = self.stop_event(tid, "exception", json!({ "code": "0x80000004", "first_chance": true, "description": "single step" }));
            Next::Hold(DBG_EXCEPTION_NOT_HANDLED, ev)
        }

        fn on_event(&mut self, ev: &DEBUG_EVENT) -> Next {
            let tid = ev.dwThreadId;
            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    // SAFETY: the union member matching the event code.
                    let info = unsafe { ev.u.CreateProcessInfo };
                    close_file(info.hFile);
                    self.hproc = info.hProcess;
                    self.threads.insert(tid, info.hThread);
                    self.main_tid = tid;
                    self.focus = tid;
                    let _ = self.apply_hw_one(info.hThread);
                    Next::Go(DBG_CONTINUE, None)
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    // SAFETY: as above.
                    let info = unsafe { ev.u.CreateThread };
                    self.threads.insert(tid, info.hThread);
                    let _ = self.apply_hw_one(info.hThread);
                    Next::Go(DBG_CONTINUE, None)
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    self.threads.remove(&tid);
                    self.rearm.remove(&tid);
                    self.hw_stopped.remove(&tid);
                    self.suspended.retain(|t| *t != tid);
                    Next::Go(DBG_CONTINUE, None)
                }
                LOAD_DLL_DEBUG_EVENT => {
                    // SAFETY: as above.
                    close_file(unsafe { ev.u.LoadDll }.hFile);
                    Next::Go(DBG_CONTINUE, None)
                }
                OUTPUT_DEBUG_STRING_EVENT => {
                    // SAFETY: as above.
                    let info = unsafe { ev.u.DebugString };
                    let len = (info.nDebugStringLength as usize).min(4096);
                    let text = if info.fUnicode != 0 {
                        let mut b = vec![0u8; len * 2];
                        let n = self.read(info.lpDebugStringData as u64, &mut b) / 2;
                        let u: Vec<u16> = b[..n * 2].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                        String::from_utf16_lossy(&u)
                    } else {
                        let mut b = vec![0u8; len];
                        let n = self.read(info.lpDebugStringData as u64, &mut b);
                        String::from_utf8_lossy(&b[..n]).into_owned()
                    };
                    let text = text.trim_end_matches(['\0', '\n', '\r']).to_owned();
                    Next::Go(DBG_CONTINUE, Some(json!({ "type": "event", "event": "dbg_output", "tid": tid, "text": text })))
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    // SAFETY: as above.
                    let code = unsafe { ev.u.ExitProcess }.dwExitCode;
                    Next::Exit(json!({ "type": "event", "event": "dbg_exit", "pid": self.pid, "code": code }))
                }
                EXCEPTION_DEBUG_EVENT => {
                    // SAFETY: as above.
                    let info = unsafe { ev.u.Exception };
                    let rec = info.ExceptionRecord;
                    let code = rec.ExceptionCode;
                    let addr = rec.ExceptionAddress as u64;
                    let first = info.dwFirstChance != 0;
                    if code == EXCEPTION_BREAKPOINT {
                        if !self.attach_done {
                            // the break-in DebugActiveProcess injects: the session starts stopped
                            self.attach_done = true;
                            self.focus = self.main_tid;
                            return Next::Hold(DBG_CONTINUE, Value::Null);
                        }
                        if self.planted.contains_key(&addr) {
                            return self.on_int3(tid, addr);
                        }
                        if self.retired.contains(&addr) {
                            // trapped on an int3 removed meanwhile: re-run the original instruction
                            self.set_rip(tid, addr);
                            return Next::Go(DBG_CONTINUE, None);
                        }
                        if self.breakins > 0 {
                            self.breakins -= 1;
                            if !self.pause_wanted {
                                return Next::Go(DBG_CONTINUE, None);
                            }
                            self.pause_wanted = false;
                            if self.pause_silent {
                                return Next::Hold(DBG_CONTINUE, Value::Null);
                            }
                            let shown = if self.threads.contains_key(&self.focus) && self.focus != tid { self.focus } else { self.main_tid };
                            let shown = if self.threads.contains_key(&shown) { shown } else { tid };
                            let ev = self.stop_event(shown, "pause", json!({ "break_tid": tid }));
                            return Next::Hold(DBG_CONTINUE, ev);
                        }
                    }
                    if code == EXCEPTION_SINGLE_STEP {
                        return self.on_single_step(tid);
                    }
                    if code == STATUS_WX86_BREAKPOINT {
                        return Next::Go(DBG_CONTINUE, None);
                    }
                    let ucode = code as u32;
                    let n = (rec.NumberParameters as usize).min(rec.ExceptionInformation.len());
                    let params = &rec.ExceptionInformation[..n];
                    let extra = json!({
                        "code": format!("0x{ucode:08x}"), "first_chance": first, "description": exception_text(ucode, params),
                        "exception_address": hex(addr), "parameters": params.iter().map(|p| hex(*p as u64)).collect::<Vec<_>>(),
                    });
                    if first && ROUTINE.contains(&ucode) {
                        let mut ev = json!({ "type": "event", "event": "dbg_exception", "tid": tid });
                        if let (Value::Object(e), Value::Object(x)) = (&mut ev, extra) {
                            e.extend(x);
                        }
                        return Next::Go(DBG_EXCEPTION_NOT_HANDLED, Some(ev));
                    }
                    let ev = self.stop_event(tid, "exception", extra);
                    Next::Hold(DBG_EXCEPTION_NOT_HANDLED, ev)
                }
                _ => Next::Go(DBG_CONTINUE, None),
            }
        }

        /// Handles one event; returns what to broadcast.
        fn dispatch(&mut self, ev: DEBUG_EVENT) -> Option<Value> {
            match self.on_event(&ev) {
                Next::Go(st, e) => {
                    cont(ev.dwProcessId, ev.dwThreadId, st);
                    e
                }
                Next::Hold(st, e) => {
                    self.held = Some(Held { tid: ev.dwThreadId, status: st });
                    (!e.is_null()).then_some(e)
                }
                Next::Exit(e) => {
                    cont(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                    self.exited = true;
                    Some(e)
                }
            }
        }

        /// Runs the event loop until an event is held (or the process exits / time runs out).
        fn pump_until_held(&mut self, timeout: Duration) -> bool {
            let t0 = Instant::now();
            while self.held.is_none() && !self.exited && t0.elapsed() < timeout {
                if let Some(ev) = wait_event(20) {
                    if let Some(e) = self.dispatch(ev) {
                        self.relay.emit(e);
                    }
                }
            }
            self.held.is_some()
        }

        fn break_in(&mut self, silent: bool) -> bool {
            self.pause_wanted = true;
            self.pause_silent = silent;
            self.breakins += 1;
            // SAFETY: hproc is the debuggee's handle from CREATE_PROCESS_DEBUG_EVENT.
            if unsafe { DebugBreakProcess(self.hproc) } == 0 {
                self.breakins -= 1;
                self.pause_wanted = false;
                return false;
            }
            self.pump_until_held(Duration::from_secs(5))
        }

        fn need_stopped(&mut self) -> bool {
            self.held.is_some() || self.break_in(true)
        }

        fn running(&self) -> bool {
            self.held.is_none()
        }

        /// Continues the held event. A thread on a user int3 or an execute hardware breakpoint
        /// first single-steps past it with the other threads suspended.
        fn resume(&mut self) {
            let Some(held) = self.held.take() else { return };
            let tid = held.tid;
            if let Some(h) = self.th(tid) {
                if let Some(mut c) = get_ctx(h) {
                    let rip = c.0.Rip;
                    let mut step = false;
                    if self.user.contains(&rip) {
                        if let Some(orig) = self.planted.get(&rip).copied() {
                            let _ = self.write_byte(rip, orig);
                            self.rearm.insert(tid, Rearm::Int3(rip));
                            step = true;
                        }
                    } else if self.hw_stopped.remove(&tid) {
                        c.0.Dr7 = 0;
                        self.rearm.insert(tid, Rearm::Hw);
                        step = true;
                    }
                    if step {
                        c.0.EFlags |= TF;
                        set_ctx(h, &c);
                        self.suspend_others(tid);
                    }
                }
            }
            cont(self.pid, tid, held.status);
        }

        fn tid_arg(&self, req: &Map<String, Value>) -> u32 {
            req.get("tid").and_then(Value::as_u64).map(|t| t as u32).filter(|t| self.threads.contains_key(t)).unwrap_or(if self.threads.contains_key(&self.focus) { self.focus } else { self.main_tid })
        }

        fn status(&self) -> Value {
            let stopped = self.held.is_some();
            let threads: Vec<Value> = self.threads.keys().map(|t| {
                let mut v = json!({ "tid": t, "state": if stopped { "stopped" } else { "running" } });
                if stopped {
                    if let Some(g) = self.regs(*t) {
                        v["rip"] = json!(hex(g.rip));
                    }
                }
                v
            }).collect();
            let hw: Vec<Value> = self.hw.iter().enumerate().map(|(i, h)| match h {
                Some((a, k, l)) => json!({ "slot": i, "address": hex(*a), "kind": k, "len": l, "trace": self.trace[i] }),
                None => json!({ "slot": i, "address": null }),
            }).collect();
            json!({ "type": "dbg_status_result", "success": true, "active": true, "backend": "windows", "pid": self.pid,
                "state": if stopped { "stopped" } else { "running" }, "focus": self.focus, "threads": threads,
                "breakpoints": self.user.iter().map(|a| hex(*a)).collect::<Vec<_>>(), "hardware": hw, "last": self.last,
                "auto": self.auto, "api_hooks": with_mon(ABI, |m| m.api.hooks.len()), "traces": core::traces_json(ABI) })
        }

        fn nothing_left(&self) -> bool {
            self.user.is_empty() && self.hw.iter().all(Option::is_none) && with_mon(ABI, |m| m.api.hooks.is_empty())
        }

        fn detach(&mut self) {
            if !self.exited {
                self.need_stopped();
            }
            with_mon(ABI, |m| {
                m.api.stop();
                m.traces.iter_mut().flatten().for_each(|t| t.active = false);
            });
            self.user.clear();
            for (a, b) in std::mem::take(&mut self.planted) {
                shadow_set(a, None);
                self.retired.insert(a);
                let _ = self.write_byte(a, b);
            }
            self.hw = [None, None, None, None];
            self.trace = [false; 4];
            let _ = self.apply_hw();
            for h in self.threads.values() {
                if let Some(mut c) = get_ctx(*h) {
                    if c.0.EFlags & TF != 0 {
                        c.0.EFlags &= !TF;
                        set_ctx(*h, &c);
                    }
                }
            }
            self.resume_suspended();
            self.rearm.clear();
            self.user_step = None;
            if self.exited {
                return;
            }
            if let Some(h) = self.held.take() {
                cont(self.pid, h.tid, h.status);
            }
            // late events: threads that trapped on an int3 just removed, a break-in still queued
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_millis(250) {
                let Some(ev) = wait_event(25) else { continue };
                let mut st = DBG_CONTINUE;
                match ev.dwDebugEventCode {
                    EXCEPTION_DEBUG_EVENT => {
                        // SAFETY: the union member matching the event code.
                        let info = unsafe { ev.u.Exception };
                        let code = info.ExceptionRecord.ExceptionCode;
                        let addr = info.ExceptionRecord.ExceptionAddress as u64;
                        if code == EXCEPTION_BREAKPOINT && self.retired.contains(&addr) {
                            self.set_rip(ev.dwThreadId, addr);
                        } else if code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP {
                            st = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    }
                    CREATE_PROCESS_DEBUG_EVENT => close_file(unsafe { ev.u.CreateProcessInfo }.hFile),
                    LOAD_DLL_DEBUG_EVENT => close_file(unsafe { ev.u.LoadDll }.hFile),
                    _ => {}
                }
                cont(ev.dwProcessId, ev.dwThreadId, st);
                if ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                    self.exited = true;
                    return;
                }
            }
            // SAFETY: detaches the debugger this thread attached.
            unsafe { DebugActiveProcessStop(self.pid) };
        }

        fn finish(&mut self, mut reply: Value, was_running: bool) -> Value {
            if self.auto && self.nothing_left() {
                self.detach();
                reply["detached"] = json!(true);
            } else if was_running {
                self.resume();
            }
            reply
        }

        fn resolve_in(&self, mods: &[(String, u64, u64)], module: &str, name: &str, depth: u8) -> Result<u64, String> {
            let want = module.to_lowercase();
            let want_dll = if want.contains('.') { want.clone() } else { format!("{want}.dll") };
            let read = |a: u64, b: &mut [u8]| self.read(a, b);
            let candidates: Vec<&(String, u64, u64)> = if module.is_empty() {
                mods.iter().collect()
            } else {
                mods.iter().filter(|(n, _, _)| { let n = n.to_lowercase(); n == want || n == want_dll }).collect()
            };
            if candidates.is_empty() {
                return Err(format!("module {module} is not loaded"));
            }
            for (_, base, _) in candidates {
                match core::pe_export(&read, *base, name) {
                    Ok(Export::At(a)) => return Ok(a),
                    Ok(Export::Forward(f)) if depth < 3 => {
                        if let Some((dll, func)) = f.split_once('.') {
                            return self.resolve_in(mods, dll, func, depth + 1).map_err(|e| format!("forwarded to {f}: {e}"));
                        }
                    }
                    Ok(Export::Forward(f)) => return Err(format!("forwarder chain too long ({f})")),
                    Err(e) if !module.is_empty() => return Err(e),
                    Err(_) => {}
                }
            }
            Err(format!("{name}: no loaded module exports it"))
        }

        fn resolve(&self, spec: &str) -> Result<u64, String> {
            let (module, name) = match spec.split_once('!') {
                Some((m, n)) => (m.trim(), n.trim()),
                None => ("", spec.trim()),
            };
            if let Some(h) = name.strip_prefix("0x") {
                return u64::from_str_radix(h, 16).map_err(|_| format!("bad address {name}"));
            }
            let mods = self.io.modules().map_err(|e| format!("cannot list modules: {e}"))?;
            self.resolve_in(&mods, module, name, 0).map_err(|e| format!("{spec}: {e}"))
        }

        /// A dbg_step that did not complete: clear the trap flag, put the breakpoint back.
        fn undo_step(&mut self, tid: u32, h: HANDLE) {
            self.user_step = None;
            if let Some(mut c) = get_ctx(h) {
                c.0.EFlags &= !TF;
                set_ctx(h, &c);
            }
            match self.rearm.remove(&tid) {
                Some(Rearm::Int3(a)) if self.planted.contains_key(&a) => {
                    let _ = self.write_byte(a, 0xcc);
                }
                Some(Rearm::Hw) => {
                    let _ = self.apply_hw_one(h);
                }
                _ => {}
            }
            self.resume_suspended();
        }

        fn command(&mut self, req: &Map<String, Value>) -> Value {
            let verb = req.get("type").and_then(Value::as_str).unwrap_or_default();
            let auto = req.get("auto") == Some(&json!(true));
            match verb {
                "dbg_status" => self.status(),
                "dbg_pause" => {
                    if self.held.is_some() {
                        let tid = self.tid_arg(req);
                        let ev = self.stop_event(tid, "pause", json!({}));
                        self.relay.emit(ev);
                    } else if !self.break_in(false) {
                        return failed("DebugBreakProcess did not stop the process");
                    }
                    self.status()
                }
                "dbg_continue" => {
                    self.resume();
                    json!({ "type": "dbg_continue_result", "success": true, "state": "running" })
                }
                "dbg_step" => {
                    if !self.need_stopped() {
                        return failed("cannot stop the process");
                    }
                    let tid = self.tid_arg(req);
                    let Some(h) = self.th(tid) else { return failed(format!("no thread {tid}")) };
                    let Some(mut c) = get_ctx(h) else { return failed("GetThreadContext failed") };
                    let from = c.0.Rip;
                    if let Some(orig) = self.planted.get(&from).copied() {
                        let _ = self.write_byte(from, orig);
                        self.rearm.insert(tid, Rearm::Int3(from));
                    } else if self.hw_stopped.remove(&tid) {
                        c.0.Dr7 = 0;
                        self.rearm.insert(tid, Rearm::Hw);
                    }
                    c.0.EFlags |= TF;
                    set_ctx(h, &c);
                    self.user_step = Some((tid, from));
                    self.suspend_others(tid);
                    if let Some(held) = self.held.take() {
                        cont(self.pid, held.tid, held.status);
                    }
                    // the stop (step, or whatever interrupted it) is broadcast by the pump
                    let stopped = self.pump_until_held(Duration::from_secs(3));
                    if self.exited {
                        return failed("the process exited during the step");
                    }
                    let completed = stopped && self.user_step.is_none();
                    if !stopped {
                        // the thread sits in a system call: stop the process again
                        self.break_in(true);
                    }
                    if completed || stopped {
                        let ev = self.last.clone();
                        if !completed {
                            self.undo_step(tid, h);
                        }
                        return json!({ "type": "dbg_step_result", "success": true, "tid": ev["tid"], "from": hex(from), "address": ev["address"], "regs": ev["regs"], "reason": ev["reason"] });
                    }
                    self.undo_step(tid, h);
                    failed(format!("thread {tid} is blocked in a system call at {}; the step completes when the call returns (set a breakpoint after it and continue)", hex(from)))
                }
                "dbg_regs" => {
                    let was_running = self.running();
                    self.need_stopped();
                    let tid = self.tid_arg(req);
                    let r = json!({ "type": "dbg_regs_result", "success": true, "tid": tid, "regs": self.regs_json(tid) });
                    if was_running {
                        self.resume();
                    }
                    r
                }
                // every thread's registers at once (like the ptrace debugger's)
                "dbg_all_regs" => {
                    let was_running = self.running();
                    if !self.need_stopped() {
                        return failed("cannot stop the process");
                    }
                    let threads: Vec<Value> = self.threads.keys().map(|t| json!({ "tid": t, "regs": self.regs_json(*t) })).collect();
                    if was_running {
                        self.resume();
                    }
                    json!({ "type": "dbg_all_regs_result", "success": true, "threads": threads, "was_running": was_running })
                }
                "dbg_set_regs" => {
                    if !self.need_stopped() {
                        return failed("cannot stop the process");
                    }
                    let tid = self.tid_arg(req);
                    let Some(Value::Object(set)) = req.get("regs") else { return bad("dbg_set_regs requires 'regs'") };
                    let Some(h) = self.th(tid) else { return failed(format!("no thread {tid}")) };
                    let Some(mut c) = get_ctx(h) else { return failed("GetThreadContext failed") };
                    let mut g = gprs_of(&c.0);
                    g.apply(set);
                    put_gprs(&mut c.0, &g);
                    if !set_ctx(h, &c) {
                        // SAFETY: reads the calling thread's last error.
                        return failed(format!("SetThreadContext failed: error {}", unsafe { GetLastError() }));
                    }
                    json!({ "type": "dbg_set_regs_result", "success": true, "tid": tid, "regs": self.regs_json(tid) })
                }
                "dbg_break" => {
                    let Some(addr) = arg_addr(req, "address") else { return bad("dbg_break requires 'address'") };
                    let enabled = req.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                    if enabled {
                        if let Err(e) = self.plant(addr) {
                            return failed(e);
                        }
                        self.user.insert(addr);
                    } else if self.user.remove(&addr) && !self.needed(addr) {
                        if let Err(e) = self.unplant(addr) {
                            return failed(e);
                        }
                    }
                    json!({ "type": "dbg_break_result", "success": true, "breakpoints": self.user.iter().map(|a| hex(*a)).collect::<Vec<_>>() })
                }
                "dbg_hwbreak" => {
                    let (slot, val) = match core::parse_hwbreak(req) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                    if self.trace[slot] {
                        return failed(format!("DR{slot} is used by an access-finder trace; stop it first"));
                    }
                    self.hw[slot] = val;
                    let was_running = self.running();
                    self.need_stopped();
                    let r = self.apply_hw();
                    if was_running {
                        self.resume();
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
                    let reply = json!({ "type": "dbg_trace_start_result", "success": true, "slot": slot, "address": hex(t.address), "size": t.size, "kind": t.kind,
                        "watch": { "address": hex(t.watch.0), "len": t.watch.1 }, "auto": auto || self.auto });
                    with_mon(ABI, |m| m.traces[slot] = Some(t));
                    let was_running = self.running();
                    self.need_stopped();
                    if let Err(e) = self.apply_hw() {
                        self.hw[slot] = None;
                        self.trace[slot] = false;
                        with_mon(ABI, |m| m.traces[slot] = None);
                        if auto {
                            self.auto = true;
                        }
                        return self.finish(failed(e), was_running);
                    }
                    if auto {
                        self.auto = true;
                    }
                    if was_running || auto {
                        self.resume();
                    }
                    reply
                }
                "dbg_trace_stop" => {
                    let only = req.get("slot").and_then(Value::as_u64).map(|s| s as usize);
                    let was_running = self.running();
                    self.need_stopped();
                    for i in 0..4 {
                        if self.trace[i] && only.is_none_or(|s| s == i) {
                            self.trace[i] = false;
                            self.hw[i] = None;
                            with_mon(ABI, |m| if let Some(t) = m.traces[i].as_mut() { t.active = false });
                        }
                    }
                    let reply = match self.apply_hw() {
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
                    let was_running = self.running();
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
                        if let Err(e) = self.plant(addr) {
                            unresolved.push(json!({ "name": spec, "error": e }));
                            continue;
                        }
                        with_mon(ABI, |m| {
                            m.api.hooks.insert(addr, Hook { name: spec.clone(), hits: 0 });
                            m.api.active = true;
                        });
                        added.push(json!({ "name": spec, "address": hex(addr) }));
                    }
                    if auto {
                        self.auto = true;
                    }
                    if added.is_empty() {
                        let e = failed(format!("no function could be hooked: {}", Value::Array(unresolved)));
                        return self.finish(e, was_running);
                    }
                    if was_running || auto {
                        self.resume();
                    }
                    json!({ "type": "dbg_api_start_result", "success": true, "hooked": added, "unresolved": unresolved, "hooks": with_mon(ABI, |m| m.api.hooks_json()), "auto": self.auto })
                }
                "dbg_api_stop" => {
                    let was_running = self.running();
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
                "dbg_detach" => {
                    self.detach();
                    json!({ "type": "dbg_detach_result", "success": true })
                }
                other => json!({ "type": "error", "code": 3000, "message": "unknown verb", "detail": other }),
            }
        }
    }

    fn run(pid: u32, rx: Receiver<Cmd>, ready: core::Ready, relay: Relay) {
        let io = match WinIo::open(pid) {
            Ok(io) => io,
            Err(e) => {
                let _ = ready.send(Err(format!("OpenProcess({pid}): {e}")));
                return;
            }
        };
        if io.wow64() {
            let _ = ready.send(Err("32-bit (WOW64) processes are not supported by the native debugger".into()));
            return;
        }
        // SAFETY: plain Win32 calls on this (the debugger) thread.
        if unsafe { DebugActiveProcess(pid) } == 0 {
            // SAFETY: reads the calling thread's last error.
            let code = unsafe { GetLastError() };
            let _ = ready.send(Err(format!("DebugActiveProcess({pid}) failed: error {code} (another debugger attached, a protected process, or EchoDebug lacks the rights; try running it elevated)")));
            return;
        }
        // SAFETY: as above; the target survives the debugger going away.
        unsafe { DebugSetProcessKillOnExit(0) };
        let mut d = Dbg {
            pid, io, hproc: std::ptr::null_mut(), threads: BTreeMap::new(), main_tid: 0, planted: BTreeMap::new(), user: BTreeSet::new(), retired: BTreeSet::new(),
            hw: [None, None, None, None], trace: [false; 4], held: None, focus: 0, last: Value::Null, relay, auto: false, rearm: HashMap::new(),
            user_step: None, suspended: Vec::new(), hw_stopped: BTreeSet::new(), breakins: 0, pause_wanted: false, pause_silent: false, attach_done: false, exited: false,
        };
        if !d.pump_until_held(Duration::from_secs(10)) {
            // SAFETY: undoes the attach above.
            unsafe { DebugActiveProcessStop(pid) };
            let _ = ready.send(Err("the process did not report the initial break-in".into()));
            return;
        }
        let _ = ready.send(Ok(d.threads.keys().map(|t| *t as u64).collect()));
        let finish_exit = |d: &mut Dbg| {
            with_mon(ABI, |m| {
                m.api.stop();
                m.traces.iter_mut().flatten().for_each(|t| t.active = false);
            });
            for a in std::mem::take(&mut d.planted).into_keys() {
                shadow_set(a, None);
            }
            core::end_session();
        };
        loop {
            if d.exited {
                finish_exit(&mut d);
                return;
            }
            let cmd = if d.held.is_some() {
                match rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(c) => Some(c),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => {
                        d.detach();
                        return;
                    }
                }
            } else {
                match rx.try_recv() {
                    Ok(c) => Some(c),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => {
                        d.detach();
                        return;
                    }
                }
            };
            if let Some((req, reply)) = cmd {
                let r = d.command(&req);
                let end = core::ends_session(&req, &r);
                let _ = reply.send(r);
                if end {
                    return;
                }
                continue;
            }
            if d.held.is_none() {
                // drain a burst of events, then look at the command channel again
                for _ in 0..256 {
                    let Some(ev) = wait_event(if d.held.is_none() { 5 } else { 0 }) else { break };
                    if let Some(e) = d.dispatch(ev) {
                        d.relay.emit(e);
                    }
                    if d.held.is_some() || d.exited {
                        break;
                    }
                }
            }
        }
    }
}
