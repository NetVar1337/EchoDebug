//! Threads, call stacks and open handles of the target (`threads`, `stack`, `handles` verbs).
//!
//! Linux (local backend): the thread list and per-thread state come from `/proc/<pid>/task`;
//! registers from ptrace: every thread is seized, interrupted, read and detached again (the
//! target stops for a few milliseconds per call). Stacks are unwound while the threads are still
//! stopped, so they are consistent. When the ptrace debugger (local_dbg) already owns the threads,
//! their registers come from it instead. Handles are the entries of `/proc/<pid>/fd`.
//!
//! The JSON helpers here are shared with the Windows implementation (`win_threads.rs`).

use serde_json::{json, Map, Value};

use crate::local::hex_addr;
use crate::unwind::{Frame, Regs, REG_NAMES};

pub(crate) const DEFAULT_FRAMES: usize = 64;
pub(crate) const MAX_FRAMES: usize = 512;

pub(crate) fn bad(detail: &str) -> Value {
    json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": detail })
}

pub(crate) fn failed(detail: impl std::fmt::Display) -> Value {
    json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": detail.to_string() })
}

pub(crate) fn max_frames(req: &Map<String, Value>) -> usize {
    req.get("max_frames").and_then(Value::as_u64).map(|n| n as usize).unwrap_or(DEFAULT_FRAMES).clamp(1, MAX_FRAMES)
}

pub(crate) fn frame_json(i: usize, f: &Frame) -> Value {
    json!({
        "index": i,
        "address": hex_addr(f.pc),
        "sp": hex_addr(f.sp),
        "module": f.module,
        "offset": f.module.as_ref().map(|_| hex_addr(f.offset)),
        "symbol": f.symbol.as_ref().map(|s| s.0.clone()),
        "symbol_offset": f.symbol.as_ref().map(|s| s.1),
        "method": f.method.as_str(),
        "guessed": f.guessed,
    })
}

pub(crate) fn frames_json(frames: &[Frame]) -> Vec<Value> {
    frames.iter().enumerate().map(|(i, f)| frame_json(i, f)).collect()
}

pub(crate) fn regs_json(r: &Regs, extra: &[(&str, u64)]) -> Value {
    let mut m = Map::new();
    for (i, n) in REG_NAMES.iter().enumerate() {
        if let Some(v) = r.gpr[i] {
            m.insert((*n).into(), json!(hex_addr(v)));
        }
    }
    m.insert("rip".into(), json!(hex_addr(r.rip)));
    for (k, v) in extra {
        m.insert((*k).into(), json!(hex_addr(*v)));
    }
    Value::Object(m)
}

/// "module+0xoff" or "symbol+0xoff" for a frame (thread start addresses).
pub(crate) fn frame_label(f: &Frame) -> String {
    match (&f.symbol, &f.module) {
        (Some((s, 0)), _) => s.clone(),
        (Some((s, d)), _) => format!("{s}+0x{d:x}"),
        (None, Some(m)) => format!("{m}+0x{:x}", f.offset),
        _ => hex_addr(f.pc),
    }
}

/// `/proc/<pid>/task/<tid>/stat`: state, priority, nice, processor, utime, stime.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TaskStat {
    pub state: char,
    pub utime: u64,
    pub stime: u64,
    pub priority: i64,
    pub nice: i64,
    pub processor: i64,
}

pub fn parse_stat(s: &str) -> Option<TaskStat> {
    // pid (comm) state ppid ... — comm may contain spaces and parentheses: split at the last ')'
    let rest = &s[s.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // f[0] is field 3 (state); field n is f[n - 3]
    let num = |n: usize| f.get(n - 3).and_then(|x| x.parse::<i64>().ok());
    Some(TaskStat {
        state: f.first()?.chars().next()?,
        utime: num(14)? as u64,
        stime: num(15)? as u64,
        priority: num(18)?,
        nice: num(19)?,
        processor: num(39).unwrap_or(-1),
    })
}

pub fn state_name(c: char) -> &'static str {
    match c {
        'R' => "running",
        'S' => "sleeping",
        'D' => "disk sleep",
        'T' => "stopped",
        't' => "tracing stop",
        'Z' => "zombie",
        'X' => "dead",
        'I' => "idle",
        'P' => "parked",
        'W' => "waking",
        _ => "unknown",
    }
}

/// What a `/proc/<pid>/fd` link points at.
pub fn fd_kind(target: &str) -> &'static str {
    if target.starts_with("socket:") {
        "socket"
    } else if target.starts_with("pipe:") {
        "pipe"
    } else if let Some(rest) = target.strip_prefix("anon_inode:") {
        match rest.trim_matches(|c| c == '[' || c == ']') {
            "eventfd" => "eventfd",
            "eventpoll" => "epoll",
            "timerfd" => "timerfd",
            "signalfd" => "signalfd",
            "inotify" => "inotify",
            "pidfd" => "pidfd",
            "io_uring" => "io_uring",
            _ => "anon_inode",
        }
    } else if target.starts_with("/dev/") {
        "device"
    } else if target.starts_with("/memfd:") {
        "memfd"
    } else if target.starts_with('/') {
        "file"
    } else {
        "other"
    }
}

/// `flags:` of `/proc/<pid>/fdinfo/<fd>` (octal) as names.
pub fn open_flags(octal: u64) -> Vec<&'static str> {
    let mut v = vec![match octal & 3 {
        0 => "O_RDONLY",
        1 => "O_WRONLY",
        _ => "O_RDWR",
    }];
    for (bit, name) in [(0o100, "O_CREAT"), (0o2000, "O_APPEND"), (0o4000, "O_NONBLOCK"), (0o40000, "O_DIRECT"), (0o200000, "O_DIRECTORY"), (0o2000000, "O_CLOEXEC"), (0o4010000, "O_SYNC"), (0o20000000, "O_PATH")] {
        if octal & bit == bit {
            v.push(name);
        }
    }
    v
}

#[cfg(not(target_os = "linux"))]
pub fn handle(_relay: &crate::Relay, _req: &Map<String, Value>, _pid: u32) -> Value {
    failed("the local thread backend exists on Linux only")
}

#[cfg(target_os = "linux")]
pub use linux::handle;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, LazyLock, Mutex};
    use std::time::{Duration, Instant};

    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;

    use crate::local::{MemIo, ProcIo};
    use crate::unwind::{self, ModuleInfo, Symbols, Unwinder};
    use crate::Relay;

    struct ProcMem(ProcIo);

    impl unwind::Memory for ProcMem {
        fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
            match self.0.read_at(addr, buf) {
                Ok(n) if n == buf.len() => {
                    crate::local_dbg::unshadow(addr, buf);
                    true
                }
                _ => false,
            }
        }
    }

    /// Registers of one thread plus what the Threads view shows besides the GPRs.
    #[derive(Clone)]
    struct ThreadRegs {
        regs: Regs,
        fs_base: u64,
        eflags: u64,
    }

    fn tids(pid: u32) -> Vec<i32> {
        let mut v: Vec<i32> = std::fs::read_dir(format!("/proc/{pid}/task"))
            .map(|d| d.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    fn task_file(pid: u32, tid: i32, f: &str) -> String {
        std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/{f}")).unwrap_or_default().trim().to_owned()
    }

    fn wait_stop(tid: i32, timeout: Duration) -> Result<Option<Signal>, String> {
        let t0 = Instant::now();
        loop {
            match waitpid(Pid::from_raw(tid), Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {}
                Ok(WaitStatus::PtraceEvent(..)) => return Ok(None),
                // a signal arrived first: deliver it on detach
                Ok(WaitStatus::Stopped(_, sig)) => return Ok(Some(sig).filter(|s| *s != Signal::SIGTRAP)),
                Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) => return Err("thread exited".into()),
                Ok(_) => return Ok(None),
                Err(e) => return Err(format!("waitpid: {e}")),
            }
            if t0.elapsed() > timeout {
                return Err("did not stop".into());
            }
            std::thread::sleep(Duration::from_micros(200));
        }
    }

    fn from_user(r: &nix::libc::user_regs_struct) -> ThreadRegs {
        let mut g = Regs { rip: r.rip, ..Default::default() };
        for (i, v) in [r.rax, r.rcx, r.rdx, r.rbx, r.rsp, r.rbp, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15].into_iter().enumerate() {
            g.gpr[i] = Some(v);
        }
        ThreadRegs { regs: g, fs_base: r.fs_base, eflags: r.eflags }
    }

    fn from_json(v: &Value) -> Option<ThreadRegs> {
        let num = |k: &str| v.get(k).and_then(Value::as_str).and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        let mut g = Regs { rip: num("rip")?, ..Default::default() };
        for (i, n) in REG_NAMES.iter().enumerate() {
            g.gpr[i] = num(n);
        }
        Some(ThreadRegs { regs: g, fs_base: num("fs_base").unwrap_or(0), eflags: num("eflags").unwrap_or(0) })
    }

    type Captured = HashMap<i32, Result<ThreadRegs, String>>;

    /// Stops `tids`, reads their registers, runs `f` while they are still stopped, resumes them.
    fn with_stopped<R>(relay: &Relay, tids: &[i32], f: impl FnOnce(&Captured, &str) -> R) -> R {
        if crate::local_dbg::active() {
            let mut req = Map::new();
            req.insert("type".into(), json!("dbg_all_regs"));
            let r = crate::local_dbg::handle(relay, &req);
            let mut out: Captured = HashMap::new();
            for t in r["threads"].as_array().into_iter().flatten() {
                let Some(tid) = t["tid"].as_i64() else { continue };
                out.insert(tid as i32, from_json(&t["regs"]).ok_or_else(|| "debugger could not read the registers".to_string()));
            }
            for t in tids {
                out.entry(*t).or_insert_with(|| Err("not traced by the debug session".into()));
            }
            return f(&out, "debugger");
        }
        let mut out: Captured = HashMap::new();
        let mut seized = Vec::new();
        for &t in tids {
            match ptrace::seize(Pid::from_raw(t), ptrace::Options::empty()) {
                Ok(()) => seized.push(t),
                Err(e) => {
                    out.insert(t, Err(format!("ptrace: {e} (needs ptrace permission: same user and kernel.yama.ptrace_scope 0, or CAP_SYS_PTRACE)")));
                }
            }
        }
        for &t in &seized {
            let _ = ptrace::interrupt(Pid::from_raw(t));
        }
        let mut sigs: HashMap<i32, Option<Signal>> = HashMap::new();
        for &t in &seized {
            let mut st = wait_stop(t, Duration::from_secs(2));
            if matches!(&st, Err(e) if e == "did not stop") {
                let _ = ptrace::interrupt(Pid::from_raw(t));
                st = wait_stop(t, Duration::from_secs(2));
            }
            match st {
                Ok(sig) => {
                    sigs.insert(t, sig);
                    out.insert(t, ptrace::getregs(Pid::from_raw(t)).map(|r| from_user(&r)).map_err(|e| format!("getregs: {e}")));
                }
                Err(e) => {
                    out.insert(t, Err(e));
                }
            }
        }
        let r = f(&out, "ptrace");
        for &t in &seized {
            let _ = ptrace::detach(Pid::from_raw(t), sigs.get(&t).copied().flatten());
        }
        r
    }

    /// ELF symbols of a file: (lowest PT_LOAD vaddr, [(vaddr, size, name)]).
    type FileSyms = Arc<(u64, Vec<(u64, u64, String)>)>;
    static SYMS: LazyLock<Mutex<HashMap<String, FileSyms>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

    fn file_symbols(path: &str) -> FileSyms {
        if let Some(s) = SYMS.lock().unwrap_or_else(|e| e.into_inner()).get(path) {
            return s.clone();
        }
        let parsed = (|| {
            use object::{Object, ObjectSegment, ObjectSymbol};
            let data = std::fs::read(path).ok()?;
            let file = object::File::parse(&*data).ok()?;
            let lowest = file.segments().map(|s| s.address()).min().unwrap_or(0) & !0xfff;
            let mut v: Vec<(u64, u64, String)> = file
                .symbols()
                .chain(file.dynamic_symbols())
                .filter(|s| s.kind() == object::SymbolKind::Text && s.address() != 0)
                .filter_map(|s| Some((s.address(), s.size(), s.name().ok()?.to_owned())))
                .filter(|s| !s.2.is_empty())
                .collect();
            v.sort();
            v.dedup_by_key(|s| s.0);
            Some((lowest, v))
        })()
        .unwrap_or_default();
        let s = Arc::new(parsed);
        let mut g = SYMS.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() > 256 {
            g.clear();
        }
        g.insert(path.to_owned(), s.clone());
        s
    }

    struct Ctx {
        mem: ProcMem,
        modules: Vec<ModuleInfo>,
        paths: HashMap<String, String>,
    }

    fn context(pid: u32) -> Result<Ctx, String> {
        let io = ProcIo::open(pid).map_err(|e| e.to_string())?;
        let maps = io.maps().map_err(|e| e.to_string())?;
        let mut paths = HashMap::new();
        for m in &maps {
            if m.path.starts_with('/') {
                let name = m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
                paths.entry(name).or_insert_with(|| m.path.trim_end_matches(" (deleted)").to_owned());
            }
        }
        let modules = io
            .modules()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|(n, _, _)| !n.starts_with('[') || n == "[vdso]")
            .map(|(name, base, size)| ModuleInfo { name, base, size })
            .collect();
        Ok(Ctx { mem: ProcMem(io), modules, paths })
    }

    fn unwind_all(ctx: &Ctx, regs: &[(i32, Regs)], max: usize) -> HashMap<i32, Vec<Frame>> {
        let mut un = Unwinder::new(&ctx.mem, ctx.modules.clone());
        let mut out: HashMap<i32, Vec<Frame>> = regs.iter().map(|(t, r)| (*t, un.walk(r, max))).collect();
        // symbols of every module that appears in a frame
        let mut syms = Symbols::default();
        let mut seen: Vec<&str> = Vec::new();
        for frames in out.values() {
            for f in frames {
                let Some(m) = f.module.as_deref() else { continue };
                if seen.contains(&m) {
                    continue;
                }
                seen.push(m);
                let (Some(path), Some(info)) = (ctx.paths.get(m), ctx.modules.iter().find(|x| x.name == m)) else { continue };
                let fs = file_symbols(path);
                let bias = info.base.wrapping_sub(fs.0);
                syms.add(fs.1.iter().map(|(a, s, n)| (a.wrapping_add(bias), *s, n.clone())));
            }
        }
        let mut cache = HashMap::new();
        for frames in out.values_mut() {
            unwind::symbolize(&mut un, frames, &syms, &mut cache);
        }
        out
    }

    const THREAD_ENTRY: &[&str] = &["start_thread", "thread_start", "__clone", "__clone3", "clone", "clone3", "__thread_start"];

    /// A non-main thread's start routine: the frame called by glibc's start_thread / clone, or
    /// (libc stripped of its internal symbols) the outermost frame outside the module the walk
    /// ended in.
    fn start_from_stack(frames: &[Frame]) -> Option<&Frame> {
        if let Some(k) = frames.iter().position(|f| f.symbol.as_ref().is_some_and(|s| THREAD_ENTRY.contains(&s.0.as_str()))) {
            return frames.get(k.checked_sub(1)?);
        }
        let last = frames.last()?;
        if last.guessed || frames.len() < 3 {
            return None;
        }
        frames.iter().rev().find(|f| f.module != last.module && !f.guessed)
    }

    pub fn handle(relay: &Relay, req: &Map<String, Value>, pid: u32) -> Value {
        match req.get("type").and_then(Value::as_str).unwrap_or_default() {
            "threads" => threads(relay, req, pid),
            "stack" => stack(relay, req, pid),
            "handles" => handles(pid),
            v => bad(&format!("unknown thread verb {v}")),
        }
    }

    fn threads(relay: &Relay, req: &Map<String, Value>, pid: u32) -> Value {
        let ctx = match context(pid) {
            Ok(c) => c,
            Err(e) => return failed(e),
        };
        let with_stacks = req.get("stacks").and_then(Value::as_bool).unwrap_or(false);
        let regs_wanted = req.get("registers").and_then(Value::as_bool).unwrap_or(true);
        let max = max_frames(req);
        let ids = tids(pid);
        let entry = crate::local_ext::read_auxv(pid).get(&9).copied(); // AT_ENTRY
        // read before the threads are stopped (they would all show "tracing stop")
        let info: HashMap<i32, (String, TaskStat, String)> =
            ids.iter().map(|&t| (t, (task_file(pid, t, "comm"), parse_stat(&task_file(pid, t, "stat")).unwrap_or_default(), task_file(pid, t, "wchan")))).collect();
        let build = |cap: &Captured, source: &str| -> Value {
            let ok: Vec<(i32, Regs)> = cap.iter().filter_map(|(t, r)| Some((*t, r.as_ref().ok()?.regs.clone()))).collect();
            // stacks are needed for the start routine of non-main threads even when not returned
            let stacks = if regs_wanted { unwind_all(&ctx, &ok, if with_stacks { max } else { 48 }) } else { HashMap::new() };
            let mut un = Unwinder::new(&ctx.mem, ctx.modules.clone());
            let list: Vec<Value> = ids
                .iter()
                .map(|&tid| {
                    let (name, st, wchan) = &info[&tid];
                    let mut t = json!({
                        "tid": tid,
                        "name": name,
                        "main": tid as u32 == pid,
                        "state": st.state.to_string(),
                        "state_name": state_name(st.state),
                        "wait": Some(wchan).filter(|w| !w.is_empty() && *w != "0"),
                        "priority": st.priority,
                        "nice": st.nice,
                        "cpu": st.processor,
                        "time_ms": (st.utime + st.stime) * 10,
                    });
                    match cap.get(&tid) {
                        Some(Ok(r)) => {
                            t["rip"] = json!(hex_addr(r.regs.rip));
                            t["rsp"] = json!(hex_addr(r.regs.rsp()));
                            t["tls"] = json!(hex_addr(r.fs_base));
                            t["registers"] = regs_json(&r.regs, &[("eflags", r.eflags), ("fs_base", r.fs_base)]);
                        }
                        Some(Err(e)) => t["registers_error"] = json!(e),
                        None => {}
                    }
                    let frames = stacks.get(&tid);
                    let (start, source_of_start): (Option<Frame>, &str) = if tid as u32 == pid {
                        let f = entry.map(|e| {
                            let mut v = vec![Frame { pc: e, sp: 0, method: unwind::Method::Context, guessed: false, module: None, offset: 0, symbol: None }];
                            if let Some(m) = un.module_of(e) {
                                v[0].module = Some(m.name.clone());
                                v[0].offset = e - m.base;
                            }
                            let mut cache = HashMap::new();
                            unwind::symbolize(&mut un, &mut v, &Symbols::default(), &mut cache);
                            v.remove(0)
                        });
                        (f, "entry point (AT_ENTRY)")
                    } else {
                        (frames.and_then(|f| start_from_stack(f)).cloned(), "stack (outermost frame below the thread entry)")
                    };
                    if let Some(s) = start {
                        // the routine itself, not the call site inside it
                        let back = s.symbol.as_ref().map(|x| x.1).unwrap_or(0);
                        let f = Frame { pc: s.pc - back, offset: s.offset.saturating_sub(back), symbol: s.symbol.as_ref().map(|x| (x.0.clone(), 0)), ..s.clone() };
                        t["start"] = json!(hex_addr(f.pc));
                        t["start_label"] = json!(frame_label(&f));
                        t["start_source"] = json!(source_of_start);
                    }
                    if with_stacks {
                        if let Some(f) = frames {
                            t["frames"] = json!(frames_json(f));
                        }
                    }
                    t
                })
                .collect();
            json!({ "type": "threads_result", "success": true, "pid": pid, "platform": "linux", "registers_from": source, "count": list.len(), "threads": list })
        };
        if !regs_wanted {
            return build(&HashMap::new(), "none");
        }
        with_stopped(relay, &ids, build)
    }

    fn stack(relay: &Relay, req: &Map<String, Value>, pid: u32) -> Value {
        let tid = req.get("tid").and_then(Value::as_i64).map(|t| t as i32).unwrap_or(pid as i32);
        if !tids(pid).contains(&tid) {
            return bad(&format!("thread {tid} is not a thread of process {pid}"));
        }
        let ctx = match context(pid) {
            Ok(c) => c,
            Err(e) => return failed(e),
        };
        let max = max_frames(req);
        with_stopped(relay, &[tid], |cap, source| match cap.get(&tid) {
            Some(Ok(r)) => {
                let frames = unwind_all(&ctx, &[(tid, r.regs.clone())], max).remove(&tid).unwrap_or_default();
                json!({ "type": "stack_result", "success": true, "pid": pid, "tid": tid, "registers_from": source,
                    "registers": regs_json(&r.regs, &[("eflags", r.eflags), ("fs_base", r.fs_base)]),
                    "count": frames.len(), "frames": frames_json(&frames) })
            }
            Some(Err(e)) => failed(format!("thread {tid}: {e}")),
            None => failed(format!("thread {tid}: no registers")),
        })
    }

    fn handles(pid: u32) -> Value {
        let dir = format!("/proc/{pid}/fd");
        let rd = match std::fs::read_dir(&dir) {
            Ok(d) => d,
            Err(e) => return failed(format!("{dir}: {e}")),
        };
        let mut fds: Vec<i64> = rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect();
        fds.sort();
        let list: Vec<Value> = fds
            .iter()
            .map(|fd| {
                let target = std::fs::read_link(format!("{dir}/{fd}")).map(|p| p.display().to_string()).unwrap_or_default();
                let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).unwrap_or_default();
                let field = |k: &str| info.lines().find_map(|l| l.strip_prefix(k)).map(str::trim);
                let flags = field("flags:").and_then(|f| u64::from_str_radix(f, 8).ok());
                json!({
                    "handle": fd,
                    "type": fd_kind(&target),
                    "name": target,
                    "position": field("pos:").and_then(|p| p.parse::<u64>().ok()),
                    "flags": flags.map(open_flags),
                })
            })
            .collect();
        json!({ "type": "handles_result", "success": true, "pid": pid, "platform": "linux", "count": list.len(), "handles": list })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        fn call(relay: &Relay, pid: u32, v: Value) -> Value {
            let Value::Object(m) = v else { unreachable!() };
            handle(relay, &m, pid)
        }

        /// A real multi-threaded child (when a C compiler is around) or `sleep`: thread list,
        /// registers through ptrace, stacks through .eh_frame into libc, the process keeps running.
        #[test]
        fn threads_and_stacks_of_a_live_process() {
            let relay = Relay::new("t", Duration::from_secs(1));
            let dir = std::env::temp_dir().join(format!("echodebug-thr-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let src = dir.join("t.c");
            std::fs::write(&src, "#include <pthread.h>\n#include <unistd.h>\nvoid *worker(void *a){(void)a;for(;;)pause();return 0;}\nint main(void){pthread_t t;pthread_create(&t,0,worker,0);for(;;)pause();}\n").unwrap();
            let exe = dir.join("t");
            let built = std::process::Command::new("cc").args(["-O0", "-g", "-pthread", "-o"]).arg(&exe).arg(&src).status().map(|s| s.success()).unwrap_or(false);
            let child = if built { std::process::Command::new(&exe).spawn().unwrap() } else { std::process::Command::new("sleep").arg("30").spawn().unwrap() };
            let child = Child(child);
            let pid = child.0.id();
            let want = if built { 2 } else { 1 };
            for _ in 0..200 {
                if tids(pid).len() >= want && task_file(pid, pid as i32, "stat").contains(" S ") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(100));
            let r = call(&relay, pid, json!({ "type": "threads", "stacks": true }));
            assert_eq!(r["success"], true, "{r}");
            let list = r["threads"].as_array().unwrap();
            assert_eq!(list.len(), want, "{r}");
            let main = list.iter().find(|t| t["main"] == true).unwrap();
            if main.get("registers_error").is_some() {
                eprintln!("ptrace not permitted here, skipping the register part: {r}");
                return;
            }
            assert!(main["start"].as_str().unwrap().starts_with("0x"), "{main}");
            assert_eq!(main["start_source"], "entry point (AT_ENTRY)");
            let frames = main["frames"].as_array().unwrap();
            assert!(frames.len() >= 3, "{main}");
            assert!(frames.iter().any(|f| f["module"].as_str().is_some_and(|m| m.starts_with("libc"))), "{main}");
            let exe_name = if built { "t" } else { "sleep" };
            assert!(frames.iter().any(|f| f["module"] == exe_name && f["method"] == "cfi"), "{main}");
            if built {
                assert!(frames.iter().any(|f| f["symbol"] == "main"), "{main}");
                let worker = list.iter().find(|t| t["main"] == false).unwrap();
                assert_eq!(worker["start_label"], "worker", "{worker}");
                assert!(worker["frames"].as_array().unwrap().iter().any(|f| f["symbol"] == "worker"), "{worker}");
                assert!(worker["tls"].as_str().unwrap() != "0x0");
            }
            // single-thread stack, and the process is still alive and running afterwards
            let s = call(&relay, pid, json!({ "type": "stack", "tid": pid, "max_frames": 8 }));
            assert_eq!(s["success"], true, "{s}");
            assert!(s["frames"].as_array().unwrap().len() <= 8);
            let st = task_file(pid, pid as i32, "stat");
            assert!(!st.contains(" t ") && !st.contains(" T "), "left stopped: {st}");
            assert_eq!(call(&relay, pid, json!({ "type": "stack", "tid": 1 }))["type"], "error");

            // while the ptrace debugger owns the threads, their registers come from it
            let Value::Object(att) = json!({ "type": "dbg_attach", "pid": pid }) else { unreachable!() };
            let a = crate::local_dbg::handle(&relay, &att);
            if a["success"] == true {
                let r = call(&relay, pid, json!({ "type": "threads", "stacks": true }));
                assert_eq!(r["registers_from"], "debugger", "{r}");
                assert!(r["threads"][0]["frames"].as_array().is_some_and(|f| f.len() >= 3), "{r}");
                let Value::Object(det) = json!({ "type": "dbg_detach" }) else { unreachable!() };
                crate::local_dbg::handle(&relay, &det);
            }

            let h = call(&relay, pid, json!({ "type": "handles" }));
            assert_eq!(h["success"], true, "{h}");
            assert!(h["handles"].as_array().unwrap().iter().any(|x| x["handle"] == 0), "{h}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parsing_handles_odd_names() {
        let s = "1234 (a b) c)) S 1 1234 1234 0 -1 4194560 100 0 0 0 7 3 0 0 20 0 2 0 12345 1000 100 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 5 0 0 0 0 0";
        let st = parse_stat(s).unwrap();
        assert_eq!(st, TaskStat { state: 'S', utime: 7, stime: 3, priority: 20, nice: 0, processor: 5 });
        assert_eq!(state_name('D'), "disk sleep");
    }

    #[test]
    fn fd_classification() {
        assert_eq!(fd_kind("socket:[123]"), "socket");
        assert_eq!(fd_kind("anon_inode:[eventpoll]"), "epoll");
        assert_eq!(fd_kind("/dev/pts/0"), "device");
        assert_eq!(fd_kind("/home/x.txt"), "file");
        assert_eq!(open_flags(0o2100002), vec!["O_RDWR", "O_CLOEXEC"]);
        assert_eq!(open_flags(0o4000), vec!["O_RDONLY", "O_NONBLOCK"]);
    }
}
