//! Threads, call stacks and handles of a Windows process, served by the relay itself (no Echo
//! agent): `threads`, `stack`, `handles`.
//!
//! * Threads: Toolhelp32 (`TH32CS_SNAPTHREAD`) for the list and base priority,
//!   `NtQuerySystemInformation(SystemProcessInformation)` for state / wait reason / times,
//!   `NtQueryInformationThread` for the Win32 start address (`ThreadQuerySetWin32StartAddress`) and
//!   the TEB (`ThreadBasicInformation`), `GetThreadDescription` (when the OS has it) for names.
//! * Registers: `SuspendThread` → `GetThreadContext` → (unwind while suspended) → `ResumeThread`;
//!   a guard resumes the thread on every path.
//! * Stacks: `unwind.rs` over `ReadProcessMemory`, `.pdata` of every module, export names.
//! * Handles: `NtQuerySystemInformation(SystemExtendedHandleInformation)` filtered to the pid, type
//!   names from `NtQueryObject(ObjectTypesInformation)`; names for disk files, registry keys and
//!   named kernel objects (duplicated into the relay; pipes are never queried, they can block).
//!
//! The FFI is declared here (no extra crates). x64 targets only; WOW64 processes are refused.

use std::collections::HashMap;
use std::ffi::c_void;

use serde_json::{json, Map, Value};

use crate::local::hex_addr;
use crate::local_threads::{bad, failed, frame_json, frame_label, frames_json, max_frames, regs_json};
use crate::unwind::{self, Frame, Memory, Method, ModuleInfo, Regs, Symbols, Unwinder};

type Handle = *mut c_void;
type Bool = i32;

const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
const TH32CS_SNAPTHREAD: u32 = 0x4;
const TH32CS_SNAPMODULE: u32 = 0x8;
const TH32CS_SNAPMODULE32: u32 = 0x10;
const THREAD_SUSPEND_RESUME: u32 = 0x2;
const THREAD_GET_CONTEXT: u32 = 0x8;
const THREAD_QUERY_INFORMATION: u32 = 0x40;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x800;
const PROCESS_VM_READ: u32 = 0x10;
const PROCESS_DUP_HANDLE: u32 = 0x40;
const PROCESS_QUERY_INFORMATION: u32 = 0x400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
const DUPLICATE_SAME_ACCESS: u32 = 0x2;
const FILE_TYPE_DISK: u32 = 1;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
const THREAD_BASIC_INFORMATION: u32 = 0;
const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;
const OBJECT_NAME_INFORMATION: u32 = 1;
const OBJECT_TYPES_INFORMATION: u32 = 3;

#[repr(C)]
struct ThreadEntry32 {
    size: u32,
    usage: u32,
    tid: u32,
    owner_pid: u32,
    base_pri: i32,
    delta_pri: i32,
    flags: u32,
}

#[repr(C)]
struct ModuleEntry32W {
    size: u32,
    module_id: u32,
    pid: u32,
    glbl_usage: u32,
    proc_usage: u32,
    base: *mut u8,
    base_size: u32,
    hmodule: Handle,
    module: [u16; 256],
    exe_path: [u16; 260],
}

/// x64 CONTEXT (1232 bytes, 16-byte aligned). Only the integer/control part is read.
#[repr(C, align(16))]
struct Context {
    home: [u64; 6],
    flags: u32,
    mxcsr: u32,
    segs: [u16; 6],
    eflags: u32,
    dr: [u64; 6],
    /// rax rcx rdx rbx rsp rbp rsi rdi r8..r15: the machine order unwind.rs uses
    gpr: [u64; 16],
    rip: u64,
    rest: [u8; 0x4d0 - 0x100],
}

const _: () = assert!(std::mem::size_of::<Context>() == 0x4d0);

#[repr(C)]
struct ThreadBasicInformation {
    exit_status: i32,
    teb: *mut c_void,
    client_pid: usize,
    client_tid: usize,
    affinity: usize,
    priority: i32,
    base_priority: i32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
    fn Thread32First(snap: Handle, e: *mut ThreadEntry32) -> Bool;
    fn Thread32Next(snap: Handle, e: *mut ThreadEntry32) -> Bool;
    fn Module32FirstW(snap: Handle, e: *mut ModuleEntry32W) -> Bool;
    fn Module32NextW(snap: Handle, e: *mut ModuleEntry32W) -> Bool;
    fn OpenThread(access: u32, inherit: Bool, tid: u32) -> Handle;
    fn OpenProcess(access: u32, inherit: Bool, pid: u32) -> Handle;
    fn SuspendThread(h: Handle) -> u32;
    fn ResumeThread(h: Handle) -> u32;
    fn GetThreadContext(h: Handle, ctx: *mut Context) -> Bool;
    fn ReadProcessMemory(p: Handle, base: *const c_void, buf: *mut c_void, size: usize, read: *mut usize) -> Bool;
    fn CloseHandle(h: Handle) -> Bool;
    fn IsWow64Process(p: Handle, wow: *mut Bool) -> Bool;
    fn GetCurrentProcess() -> Handle;
    fn DuplicateHandle(src_proc: Handle, src: Handle, dst_proc: Handle, dst: *mut Handle, access: u32, inherit: Bool, options: u32) -> Bool;
    fn GetFileType(h: Handle) -> u32;
    fn GetFinalPathNameByHandleW(h: Handle, buf: *mut u16, len: u32, flags: u32) -> u32;
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetProcAddress(m: Handle, name: *const u8) -> *mut c_void;
    fn LocalFree(p: *mut c_void) -> *mut c_void;
}

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtQueryInformationThread(h: Handle, class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQuerySystemInformation(class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryObject(h: Handle, class: u32, buf: *mut c_void, len: u32, ret: *mut u32) -> i32;
}

/// Closes a handle on drop.
struct Owned(Handle);

impl Owned {
    fn open(h: Handle) -> Option<Owned> {
        (!h.is_null() && h != INVALID_HANDLE_VALUE).then_some(Owned(h))
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: the handle came from an Open*/CreateToolhelp32Snapshot/DuplicateHandle call and is closed once
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Resumes a suspended thread on drop.
struct Suspended<'a>(&'a Owned);

impl Drop for Suspended<'_> {
    fn drop(&mut self) {
        // SAFETY: the thread handle has THREAD_SUSPEND_RESUME and was suspended once by us
        unsafe {
            ResumeThread(self.0 .0);
        }
    }
}

/// The target's memory; `shadowed` while the native debugger has int3s planted in it, whose
/// original bytes are shown instead (the unwinder decodes prologs, epilogs and call sites).
struct ProcMem(Handle, bool);

impl ProcMem {
    fn new(h: Handle, pid: u32) -> ProcMem {
        ProcMem(h, crate::windbg::shadows(Some(pid)))
    }
}

impl Memory for ProcMem {
    fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        let mut n = 0usize;
        // SAFETY: buf is valid for buf.len() bytes; ReadProcessMemory fails cleanly on unmapped pages
        let ok = unsafe { ReadProcessMemory(self.0, addr as *const c_void, buf.as_mut_ptr().cast(), buf.len(), &mut n) };
        if ok != 0 && self.1 {
            crate::local_dbg::unshadow(addr, &mut buf[..n]);
        }
        ok != 0 && n == buf.len()
    }
}

fn wide(s: &[u16]) -> String {
    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..n])
}

fn last_error() -> String {
    std::io::Error::last_os_error().to_string()
}

/// (tid, base priority, delta priority) of every thread of `pid`.
fn toolhelp_threads(pid: u32) -> Result<Vec<(u32, i32, i32)>, String> {
    // SAFETY: plain Toolhelp32 enumeration with a correctly sized entry
    unsafe {
        let snap = Owned::open(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)).ok_or_else(last_error)?;
        let mut e: ThreadEntry32 = std::mem::zeroed();
        e.size = std::mem::size_of::<ThreadEntry32>() as u32;
        let mut out = Vec::new();
        let mut ok = Thread32First(snap.0, &mut e);
        while ok != 0 {
            if e.owner_pid == pid {
                out.push((e.tid, e.base_pri, e.delta_pri));
            }
            ok = Thread32Next(snap.0, &mut e);
        }
        Ok(out)
    }
}

/// Loaded modules (name, base, size).
fn toolhelp_modules(pid: u32) -> Vec<ModuleInfo> {
    // SAFETY: plain Toolhelp32 enumeration with a correctly sized entry
    unsafe {
        let Some(snap) = Owned::open(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)) else { return Vec::new() };
        let mut e: ModuleEntry32W = std::mem::zeroed();
        e.size = std::mem::size_of::<ModuleEntry32W>() as u32;
        let mut out = Vec::new();
        let mut ok = Module32FirstW(snap.0, &mut e);
        while ok != 0 {
            out.push(ModuleInfo { name: wide(&e.module), base: e.base as u64, size: e.base_size as u64 });
            ok = Module32NextW(snap.0, &mut e);
        }
        out
    }
}

/// An NtQuery* output buffer. u64 storage keeps it 8-byte aligned; the structures in it carry
/// pointers into the same allocation (UNICODE_STRING buffers), so it is never copied.
struct NtBuf(Vec<u64>);

impl NtBuf {
    fn bytes(&self) -> &[u8] {
        // SAFETY: a u64 slice viewed as bytes, same allocation and length
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast(), self.0.len() * 8) }
    }
    fn base(&self) -> usize {
        self.0.as_ptr() as usize
    }
}

/// Calls an NtQuery* function that reports STATUS_INFO_LENGTH_MISMATCH until the buffer fits.
fn query_growing(mut f: impl FnMut(*mut c_void, u32, *mut u32) -> i32, start: usize, max: usize) -> Result<NtBuf, String> {
    let mut size = start;
    loop {
        let mut buf = vec![0u64; size.div_ceil(8)];
        let mut ret = 0u32;
        let st = f(buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut ret);
        if st == STATUS_INFO_LENGTH_MISMATCH && size < max {
            size = (ret as usize + 0x10000).max(size * 2).min(max);
            continue;
        }
        if st < 0 {
            return Err(format!("NTSTATUS 0x{:08x}", st as u32));
        }
        return Ok(NtBuf(buf));
    }
}

fn rd_u16(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2).map(|s| u16::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}
fn rd_u32(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}

pub const THREAD_STATES: [&str; 10] = ["initialized", "ready", "running", "standby", "terminated", "waiting", "transition", "deferred ready", "gate wait", "waiting for swap"];
pub const WAIT_REASONS: [&str; 41] = [
    "Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended", "UserRequest", "WrExecutive", "WrFreePage", "WrPageIn",
    "WrPoolAllocation", "WrDelayExecution", "WrSuspended", "WrUserRequest", "WrEventPair", "WrQueue", "WrLpcReceive", "WrLpcReply", "WrVirtualMemory",
    "WrPageOut", "WrRendezvous", "WrKeyedEvent", "WrTerminated", "WrProcessInSwap", "WrCpuRateControl", "WrCalloutStack", "WrKernel", "WrResource",
    "WrPushLock", "WrMutex", "WrQuantumEnd", "WrDispatchInt", "WrPreempted", "WrYieldExecution", "WrFastMutex", "WrGuardedMutex", "WrRundown",
    "WrAlertByThreadId", "WrDeferredPreempt", "WrPhysicalFault", "WrIoRing",
];

/// Per-thread scheduler state from SystemProcessInformation: tid → (state, wait reason, priority,
/// kernel+user time in 100 ns, context switches).
fn system_thread_states(pid: u32) -> HashMap<u32, (u32, u32, i32, u64, u32)> {
    let mut out = HashMap::new();
    // SAFETY: the buffer is owned and sized by query_growing
    let Ok(nt) = query_growing(|b, l, r| unsafe { NtQuerySystemInformation(SYSTEM_PROCESS_INFORMATION, b, l, r) }, 1 << 20, 64 << 20) else {
        return out;
    };
    let buf = nt.bytes();
    let mut off = 0usize;
    loop {
        let next = rd_u32(buf, off) as usize;
        let nthreads = rd_u32(buf, off + 4) as usize;
        if rd_u64(buf, off + 0x50) == pid as u64 {
            for i in 0..nthreads.min(65536) {
                // SYSTEM_THREAD_INFORMATION (0x50 bytes) array after the 0x100-byte process entry
                let t = off + 0x100 + i * 0x50;
                if t + 0x50 > buf.len() {
                    break;
                }
                let time = rd_u64(buf, t) + rd_u64(buf, t + 8);
                let tid = rd_u64(buf, t + 48) as u32;
                out.insert(tid, (rd_u32(buf, t + 68), rd_u32(buf, t + 72), rd_u32(buf, t + 56) as i32, time, rd_u32(buf, t + 64)));
            }
            break;
        }
        if next == 0 {
            break;
        }
        off += next;
    }
    out
}

type GetThreadDescriptionFn = unsafe extern "system" fn(Handle, *mut *mut u16) -> i32;

fn thread_description(h: &Owned) -> Option<String> {
    // SAFETY: GetThreadDescription is looked up at run time (Windows 10 1607+); the string it returns
    // is freed with LocalFree as documented
    unsafe {
        let k32: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let m = GetModuleHandleW(k32.as_ptr());
        if m.is_null() {
            return None;
        }
        let p = GetProcAddress(m, c"GetThreadDescription".as_ptr().cast());
        if p.is_null() {
            return None;
        }
        let f: GetThreadDescriptionFn = std::mem::transmute(p);
        let mut s: *mut u16 = std::ptr::null_mut();
        if f(h.0, &mut s) < 0 || s.is_null() {
            return None;
        }
        let mut n = 0usize;
        while *s.add(n) != 0 && n < 512 {
            n += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s.cast());
        Some(out).filter(|x| !x.is_empty())
    }
}

fn start_address(h: &Owned) -> Option<u64> {
    let mut v = 0u64;
    // SAFETY: the output buffer is a u64 of the size passed
    let st = unsafe { NtQueryInformationThread(h.0, THREAD_QUERY_SET_WIN32_START_ADDRESS, (&mut v as *mut u64).cast(), 8, std::ptr::null_mut()) };
    (st >= 0).then_some(v)
}

fn basic_info(h: &Owned) -> Option<ThreadBasicInformation> {
    // SAFETY: the output buffer is a zeroed THREAD_BASIC_INFORMATION of the size passed
    unsafe {
        let mut b: ThreadBasicInformation = std::mem::zeroed();
        let st = NtQueryInformationThread(h.0, THREAD_BASIC_INFORMATION, (&mut b as *mut ThreadBasicInformation).cast(), std::mem::size_of::<ThreadBasicInformation>() as u32, std::ptr::null_mut());
        (st >= 0).then_some(b)
    }
}

/// Suspends the thread, reads its context and runs `f` while it is still suspended.
fn with_context<R>(h: &Owned, f: impl FnOnce(Result<(Regs, u64, u32), String>) -> R) -> R {
    // SAFETY: the handle has THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT; the CONTEXT is aligned and
    // the guard resumes the thread whatever happens next
    unsafe {
        let prev = SuspendThread(h.0);
        if prev == u32::MAX {
            return f(Err(format!("SuspendThread: {}", last_error())));
        }
        let _guard = Suspended(h);
        let mut ctx: Box<Context> = Box::new(std::mem::zeroed());
        ctx.flags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if GetThreadContext(h.0, &mut *ctx) == 0 {
            return f(Err(format!("GetThreadContext: {}", last_error())));
        }
        let mut r = Regs { rip: ctx.rip, ..Default::default() };
        for (i, v) in ctx.gpr.iter().enumerate() {
            r.gpr[i] = Some(*v);
        }
        f(Ok((r, ctx.eflags as u64, prev)))
    }
}

struct Target {
    process: Owned,
    modules: Vec<ModuleInfo>,
}

fn open_target(pid: u32, access: u32) -> Result<Target, String> {
    if pid == std::process::id() {
        return Err("refusing to suspend the relay's own threads".into());
    }
    // SAFETY: plain process open; IsWow64Process writes one BOOL
    unsafe {
        let process = Owned::open(OpenProcess(access, 0, pid)).ok_or_else(|| format!("OpenProcess({pid}): {}", last_error()))?;
        let mut wow: Bool = 0;
        if IsWow64Process(process.0, &mut wow) != 0 && wow != 0 {
            return Err("32-bit (WOW64) processes are not supported: the unwinder is x64 only".into());
        }
        Ok(Target { process, modules: toolhelp_modules(pid) })
    }
}

fn symbolize(un: &mut Unwinder<'_, ProcMem>, frames: &mut [Frame], cache: &mut HashMap<u64, Symbols>) {
    unwind::symbolize(un, frames, &Symbols::default(), cache);
}

fn label_of(un: &mut Unwinder<'_, ProcMem>, addr: u64, cache: &mut HashMap<u64, Symbols>) -> String {
    let mut f = vec![Frame { pc: addr, sp: 0, method: Method::Context, guessed: false, module: None, offset: addr, symbol: None }];
    if let Some(m) = un.module_of(addr) {
        f[0].module = Some(m.name.clone());
        f[0].offset = addr - m.base;
    }
    symbolize(un, &mut f, cache);
    frame_label(&f[0])
}

pub fn handle(req: &Map<String, Value>, pid: u32) -> Value {
    match req.get("type").and_then(Value::as_str).unwrap_or_default() {
        "threads" => threads(req, pid),
        "stack" => stack(req, pid),
        "handles" => handles(pid),
        v => bad(&format!("unknown thread verb {v}")),
    }
}

fn threads(req: &Map<String, Value>, pid: u32) -> Value {
    let t = match open_target(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) {
        Ok(t) => t,
        Err(e) => return failed(e),
    };
    let ids = match toolhelp_threads(pid) {
        Ok(v) => v,
        Err(e) => return failed(format!("CreateToolhelp32Snapshot: {e}")),
    };
    let with_stacks = req.get("stacks").and_then(Value::as_bool).unwrap_or(false);
    let regs_wanted = req.get("registers").and_then(Value::as_bool).unwrap_or(true);
    let max = max_frames(req);
    let states = system_thread_states(pid);
    let mem = ProcMem::new(t.process.0, pid);
    let mut un = Unwinder::new(&mem, t.modules.clone());
    let mut cache = HashMap::new();
    let mut list = Vec::new();
    for (tid, base_pri, delta_pri) in ids {
        let mut v = json!({ "tid": tid, "base_priority": base_pri, "priority_delta": delta_pri });
        if let Some((state, wait, prio, time, switches)) = states.get(&tid) {
            v["state"] = json!(state);
            v["state_name"] = json!(THREAD_STATES.get(*state as usize).copied().unwrap_or("unknown"));
            if *state == 5 {
                v["wait"] = json!(WAIT_REASONS.get(*wait as usize).copied().unwrap_or("unknown"));
            }
            v["priority"] = json!(prio);
            v["time_ms"] = json!(time / 10_000);
            v["context_switches"] = json!(switches);
        }
        // SAFETY: plain thread open
        let access = THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | if regs_wanted { THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT } else { 0 };
        let Some(h) = Owned::open(unsafe { OpenThread(access, 0, tid) }) else {
            v["error"] = json!(format!("OpenThread: {}", last_error()));
            list.push(v);
            continue;
        };
        if let Some(name) = thread_description(&h) {
            v["name"] = json!(name);
        }
        if let Some(s) = start_address(&h) {
            v["start"] = json!(hex_addr(s));
            v["start_label"] = json!(label_of(&mut un, s, &mut cache));
            v["start_source"] = json!("Win32 start address");
        }
        if let Some(b) = basic_info(&h) {
            v["teb"] = json!(hex_addr(b.teb as u64));
            v["priority"] = json!(b.priority);
        }
        if regs_wanted {
            with_context(&h, |r| match r {
                Ok((regs, eflags, prev)) => {
                    v["rip"] = json!(hex_addr(regs.rip));
                    v["rsp"] = json!(hex_addr(regs.rsp()));
                    v["suspend_count"] = json!(prev);
                    v["registers"] = regs_json(&regs, &[("eflags", eflags)]);
                    if with_stacks {
                        let mut frames = un.walk(&regs, max);
                        symbolize(&mut un, &mut frames, &mut cache);
                        v["frames"] = json!(frames_json(&frames));
                    }
                }
                Err(e) => v["registers_error"] = json!(e),
            });
        }
        list.push(v);
    }
    json!({ "type": "threads_result", "success": true, "pid": pid, "platform": "windows", "registers_from": "GetThreadContext", "count": list.len(), "threads": list })
}

fn stack(req: &Map<String, Value>, pid: u32) -> Value {
    let Some(tid) = req.get("tid").and_then(Value::as_u64).map(|t| t as u32) else { return bad("stack requires 'tid'") };
    let t = match open_target(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION) {
        Ok(t) => t,
        Err(e) => return failed(e),
    };
    if !toolhelp_threads(pid).unwrap_or_default().iter().any(|x| x.0 == tid) {
        return bad(&format!("thread {tid} is not a thread of process {pid}"));
    }
    // SAFETY: plain thread open
    let Some(h) = Owned::open(unsafe { OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, 0, tid) }) else {
        return failed(format!("OpenThread({tid}): {}", last_error()));
    };
    let mem = ProcMem::new(t.process.0, pid);
    let mut un = Unwinder::new(&mem, t.modules.clone());
    let max = max_frames(req);
    with_context(&h, |r| match r {
        Ok((regs, eflags, _)) => {
            let mut frames = un.walk(&regs, max);
            symbolize(&mut un, &mut frames, &mut HashMap::new());
            json!({ "type": "stack_result", "success": true, "pid": pid, "tid": tid, "registers_from": "GetThreadContext",
                "registers": regs_json(&regs, &[("eflags", eflags)]), "count": frames.len(),
                "frames": frames.iter().enumerate().map(|(i, f)| frame_json(i, f)).collect::<Vec<_>>() })
        }
        Err(e) => failed(format!("thread {tid}: {e}")),
    })
}

/// Object type index → name (ObjectTypesInformation).
fn object_types() -> HashMap<u16, String> {
    let mut out = HashMap::new();
    // SAFETY: the buffer is owned and sized by query_growing; NtQueryObject with a null handle
    // enumerates the types
    let Ok(nt) = query_growing(|b, l, r| unsafe { NtQueryObject(std::ptr::null_mut(), OBJECT_TYPES_INFORMATION, b, l, r) }, 64 << 10, 4 << 20) else {
        return out;
    };
    let (buf, base) = (nt.bytes(), nt.base());
    let n = rd_u32(buf, 0) as usize;
    let mut off = 8usize; // OBJECT_TYPES_INFORMATION { ULONG NumberOfTypes; } aligned to 8
    for i in 0..n.min(512) {
        if off + 0x68 > buf.len() {
            break;
        }
        let len = rd_u16(buf, off) as usize;
        let max = rd_u16(buf, off + 2) as usize;
        let ptr = rd_u64(buf, off + 8) as usize;
        // TypeIndex (Windows 8.1+); older systems number the types from 2
        let idx = match buf[off + 0x5a] {
            0 => i as u16 + 2,
            x => x as u16,
        };
        let name_off = ptr.wrapping_sub(base);
        if let Some(b) = buf.get(name_off..name_off + len) {
            let w: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            out.insert(idx, String::from_utf16_lossy(&w));
        }
        off += 0x68 + max.div_ceil(8) * 8;
    }
    out
}

/// Object name of a handle duplicated into the relay (types that cannot block only).
fn object_name(dup: &Owned, ty: &str) -> Option<String> {
    match ty {
        "File" => {
            // SAFETY: GetFileType / GetFinalPathNameByHandleW on our own duplicate; only disk files are
            // queried (pipes and some devices can block the call)
            unsafe {
                if GetFileType(dup.0) != FILE_TYPE_DISK {
                    return None;
                }
                let mut buf = vec![0u16; 1024];
                let n = GetFinalPathNameByHandleW(dup.0, buf.as_mut_ptr(), buf.len() as u32, 0) as usize;
                (n > 0 && n < buf.len()).then(|| String::from_utf16_lossy(&buf[..n]).trim_start_matches(r"\\?\").to_owned())
            }
        }
        "Key" | "Section" | "Event" | "Mutant" | "Semaphore" | "Directory" | "SymbolicLink" | "Timer" | "ALPC Port" | "Job" | "Desktop" | "WindowStation" => {
            // SAFETY: the buffer is owned and sized by query_growing; the name points into it
            let nt = query_growing(|b, l, r| unsafe { NtQueryObject(dup.0, OBJECT_NAME_INFORMATION, b, l, r) }, 1024, 64 << 10).ok()?;
            let buf = nt.bytes();
            let len = rd_u16(buf, 0) as usize;
            let ptr = rd_u64(buf, 8) as usize;
            let off = ptr.wrapping_sub(nt.base());
            let b = buf.get(off..off + len)?;
            let w: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            Some(String::from_utf16_lossy(&w)).filter(|s| !s.is_empty())
        }
        _ => None,
    }
}

const MAX_HANDLES: usize = 20_000;

fn handles(pid: u32) -> Value {
    // SAFETY: the buffer is owned and sized by query_growing
    let nt = match query_growing(|b, l, r| unsafe { NtQuerySystemInformation(SYSTEM_EXTENDED_HANDLE_INFORMATION, b, l, r) }, 4 << 20, 512 << 20) {
        Ok(b) => b,
        Err(e) => return failed(format!("NtQuerySystemInformation(SystemExtendedHandleInformation): {e}")),
    };
    let types = object_types();
    // SAFETY: plain process open; a failure only means no names
    let process = Owned::open(unsafe { OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    let buf = nt.bytes();
    let n = rd_u64(buf, 0) as usize;
    let mut list = Vec::new();
    let mut truncated = false;
    for i in 0..n {
        // SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX (40 bytes) after { NumberOfHandles, Reserved }
        let e = 16 + i * 40;
        if e + 40 > buf.len() {
            break;
        }
        if rd_u64(buf, e + 8) != pid as u64 {
            continue;
        }
        if list.len() >= MAX_HANDLES {
            truncated = true;
            break;
        }
        let value = rd_u64(buf, e + 16);
        let access = rd_u32(buf, e + 24);
        let type_index = rd_u16(buf, e + 30);
        let attributes = rd_u32(buf, e + 32);
        let ty = types.get(&type_index).cloned().unwrap_or_else(|| format!("type {type_index}"));
        let name = process.as_ref().and_then(|p| {
            let mut dup: Handle = std::ptr::null_mut();
            // SAFETY: duplicates the target's handle into the relay with the same access; the copy is
            // closed by Owned. The target's own handle is untouched.
            let ok = unsafe { DuplicateHandle(p.0, value as Handle, GetCurrentProcess(), &mut dup, 0, 0, DUPLICATE_SAME_ACCESS) };
            if ok == 0 {
                return None;
            }
            object_name(&Owned::open(dup)?, &ty)
        });
        list.push(json!({
            "handle": hex_addr(value),
            "type": ty,
            "name": name,
            "access": format!("0x{access:x}"),
            "object": hex_addr(rd_u64(buf, e)),
            "attributes": attributes,
        }));
    }
    json!({ "type": "handles_result", "success": true, "pid": pid, "platform": "windows", "count": list.len(), "truncated": truncated, "handles": list })
}
