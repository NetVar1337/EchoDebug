//! Platform-neutral pieces of the native debuggers (`local_dbg.rs` on Linux, `windbg.rs` on
//! Windows): the session plumbing both use (one debugger thread, verbs sent over a channel), the
//! register set in the shape the Debugger view shows, DR7 encoding, the "find what accesses this
//! address" tracer, and the API call monitor (signature table, argument decoding, call/return
//! matching). Everything here is pure logic over a memory-read callback, so it is unit-tested on
//! any host.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iced_x86::{Decoder, DecoderOptions, InstructionInfoFactory, OpAccess, Register};
use serde_json::{json, Map, Value};

use crate::Relay;

pub fn hex(v: u64) -> String {
    format!("0x{v:x}")
}

pub fn bad(detail: &str) -> Value {
    json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": detail })
}

pub fn failed(detail: impl std::fmt::Display) -> Value {
    json!({ "type": "error", "code": 3003, "message": "operation failed", "detail": detail.to_string() })
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Reads target memory into the buffer; returns the number of bytes read.
pub type ReadFn<'a> = &'a dyn Fn(u64, &mut [u8]) -> usize;

pub fn read_u64(read: ReadFn, addr: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    (read(addr, &mut b) == 8).then(|| u64::from_le_bytes(b))
}

// ---- registers ----------------------------------------------------------------------------------

/// x86-64 general registers, the same on both debuggers.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Gprs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub eflags: u64,
    pub fs_base: u64,
    pub gs_base: u64,
}

impl Gprs {
    pub fn to_json(&self) -> Value {
        json!({
            "rax": hex(self.rax), "rbx": hex(self.rbx), "rcx": hex(self.rcx), "rdx": hex(self.rdx),
            "rsi": hex(self.rsi), "rdi": hex(self.rdi), "rbp": hex(self.rbp), "rsp": hex(self.rsp),
            "r8": hex(self.r8), "r9": hex(self.r9), "r10": hex(self.r10), "r11": hex(self.r11),
            "r12": hex(self.r12), "r13": hex(self.r13), "r14": hex(self.r14), "r15": hex(self.r15),
            "rip": hex(self.rip), "eflags": hex(self.eflags), "fs_base": hex(self.fs_base), "gs_base": hex(self.gs_base),
        })
    }

    fn slot(&mut self, name: &str) -> Option<&mut u64> {
        Some(match name {
            "rax" => &mut self.rax, "rbx" => &mut self.rbx, "rcx" => &mut self.rcx, "rdx" => &mut self.rdx,
            "rsi" => &mut self.rsi, "rdi" => &mut self.rdi, "rbp" => &mut self.rbp, "rsp" => &mut self.rsp,
            "r8" => &mut self.r8, "r9" => &mut self.r9, "r10" => &mut self.r10, "r11" => &mut self.r11,
            "r12" => &mut self.r12, "r13" => &mut self.r13, "r14" => &mut self.r14, "r15" => &mut self.r15,
            "rip" => &mut self.rip, "eflags" => &mut self.eflags,
            _ => return None,
        })
    }

    /// Applies `{"rax":"0x1", …}` (hex strings or numbers); unknown names are ignored.
    pub fn apply(&mut self, set: &Map<String, Value>) {
        for (k, v) in set {
            let Some(val) = v.as_str().and_then(|s| u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()).or_else(|| v.as_u64()) else { continue };
            if let Some(s) = self.slot(k) {
                *s = val;
            }
        }
    }

    /// Value of a register as iced names it (sub-registers masked; segment bases for fs/gs).
    pub fn get(&self, r: Register) -> Option<u64> {
        use Register as R;
        let full = match r.full_register() {
            R::RAX => self.rax, R::RBX => self.rbx, R::RCX => self.rcx, R::RDX => self.rdx,
            R::RSI => self.rsi, R::RDI => self.rdi, R::RBP => self.rbp, R::RSP => self.rsp,
            R::R8 => self.r8, R::R9 => self.r9, R::R10 => self.r10, R::R11 => self.r11,
            R::R12 => self.r12, R::R13 => self.r13, R::R14 => self.r14, R::R15 => self.r15,
            R::RIP => self.rip,
            R::FS => return Some(self.fs_base),
            R::GS => return Some(self.gs_base),
            R::ES | R::CS | R::SS | R::DS => return Some(0),
            _ => return None,
        };
        let v = match r.size() {
            1 if matches!(r, R::AH | R::BH | R::CH | R::DH) => (full >> 8) & 0xff,
            1 => full & 0xff,
            2 => full & 0xffff,
            4 => full & 0xffff_ffff,
            _ => full,
        };
        Some(v)
    }
}

// ---- hardware breakpoints -----------------------------------------------------------------------

/// One debug-register slot: (address, kind exec|write|rw, len).
pub type HwSlot = Option<(u64, String, u8)>;

/// DR7 for the four slots (local-enable bits, R/W and LEN fields).
pub fn dr7(hw: &[HwSlot; 4]) -> u64 {
    let mut v = 0u64;
    for (i, slot) in hw.iter().enumerate() {
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

/// Parses `dbg_hwbreak {slot, address, kind, len, enabled}` into (slot, new slot value).
pub fn parse_hwbreak(req: &Map<String, Value>) -> Result<(usize, HwSlot), Value> {
    let slot = req.get("slot").and_then(Value::as_u64).unwrap_or(0) as usize;
    if slot > 3 {
        return Err(bad("slot must be 0-3"));
    }
    if !req.get("enabled").and_then(Value::as_bool).unwrap_or(true) {
        return Ok((slot, None));
    }
    let Some(addr) = arg_addr(req, "address") else { return Err(bad("dbg_hwbreak requires 'address'")) };
    let kind = req.get("kind").and_then(Value::as_str).unwrap_or("exec").to_owned();
    if !matches!(kind.as_str(), "exec" | "write" | "rw") {
        return Err(bad("kind must be exec, write or rw"));
    }
    let len = req.get("len").and_then(Value::as_u64).unwrap_or(1) as u8;
    if kind != "exec" && (!matches!(len, 1 | 2 | 4 | 8) || addr % len as u64 != 0) {
        return Err(bad("len must be 1, 2, 4 or 8 and the address aligned to it"));
    }
    Ok((slot, Some((addr, kind, len))))
}

/// The smallest aligned 1/2/4/8-byte debug-register range that covers `[addr, addr+len)`.
pub fn cover(addr: u64, len: u64) -> Option<(u64, u8)> {
    let len = len.max(1);
    [1u64, 2, 4, 8].into_iter().find_map(|l| {
        let base = addr & !(l - 1);
        (base + l >= addr + len).then_some((base, l as u8))
    })
}

pub fn arg_addr(req: &Map<String, Value>, k: &str) -> Option<u64> {
    match req.get(k)? {
        Value::String(s) => u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

// ---- "find what accesses this address" ----------------------------------------------------------

/// The instruction that caused a data-breakpoint trap. x86 reports data breakpoints *after* the
/// access, so rip is the next instruction: decode every candidate that ends exactly at rip and
/// prefer one whose memory operand (computed with the post-access registers) touches the watched
/// range, then one with any memory operand, longest first.
/// `before` holds the bytes that end at `rip`. Returns (address, length, text).
pub fn find_accessor(before: &[u8], rip: u64, regs: &Gprs, watch: (u64, u64), write_only: bool) -> Option<(u64, usize, String)> {
    let mut best: Option<(u8, usize, u64, String)> = None;
    let mut info = InstructionInfoFactory::new();
    for back in 1..=before.len().min(15) {
        let start = before.len() - back;
        let ip = rip.wrapping_sub(back as u64);
        let mut dec = Decoder::with_ip(64, &before[start..], ip, DecoderOptions::NONE);
        let insn = dec.decode();
        if insn.is_invalid() || insn.len() != back {
            continue;
        }
        let mut score = 0u8;
        for m in info.info(&insn).used_memory() {
            let writes = matches!(m.access(), OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite);
            if write_only && !writes {
                continue;
            }
            score = score.max(1);
            let ea = m.virtual_address(0, |r, _, _| if r == Register::RIP { Some(rip) } else { regs.get(r) });
            if let Some(ea) = ea {
                let size = m.memory_size().size().max(1) as u64;
                let hits = ea < watch.0 + watch.1 && watch.0 < ea.wrapping_add(size);
                if hits {
                    score = 2;
                }
            }
        }
        if best.as_ref().is_none_or(|b| score > b.0 || (score == b.0 && back > b.1)) {
            // the same text as the disassembly views (RIP-relative targets annotated)
            let text = crate::local::disasm_one(&before[start..], ip).map(|d| d.1).unwrap_or_default();
            best = Some((score, back, ip, text));
        }
    }
    best.map(|(_, len, ip, text)| (ip, len, text))
}

#[derive(Clone, Debug)]
pub struct TraceHit {
    pub address: u64,
    pub len: usize,
    pub text: String,
    pub count: u64,
    pub tid: u64,
    pub regs: Gprs,
    pub first: u64,
    pub last: u64,
}

/// One "find what writes/accesses" session on one debug-register slot.
#[derive(Clone, Debug)]
pub struct Trace {
    pub slot: usize,
    /// what the user asked for
    pub address: u64,
    pub size: u64,
    /// "write" or "access"
    pub kind: String,
    /// the aligned range the debug register watches
    pub watch: (u64, u8),
    pub active: bool,
    pub total: u64,
    pub started: u64,
    pub hits: BTreeMap<u64, TraceHit>,
}

impl Trace {
    pub fn new(slot: usize, address: u64, size: u64, kind: &str) -> Result<Trace, String> {
        if !matches!(kind, "write" | "access") {
            return Err("kind must be write or access".into());
        }
        let watch = cover(address, size).ok_or_else(|| format!("{size} bytes at {} cross an 8-byte boundary; watch a smaller or aligned range", hex(address)))?;
        Ok(Trace { slot, address, size: size.max(1), kind: kind.into(), watch, active: true, total: 0, started: now_ms(), hits: BTreeMap::new() })
    }

    /// The debug-register slot value for this trace.
    pub fn hw(&self) -> (u64, String, u8) {
        (self.watch.0, if self.kind == "write" { "write" } else { "rw" }.into(), self.watch.1)
    }

    /// Records one trap. Returns a `dbg_access` event when this instruction is new.
    pub fn record(&mut self, before: &[u8], rip: u64, regs: &Gprs, tid: u64) -> Option<Value> {
        self.total += 1;
        let (addr, len, text) = find_accessor(before, rip, regs, (self.address, self.size), self.kind == "write").unwrap_or((rip, 0, "(unknown instruction before this address)".into()));
        let t = now_ms();
        if let Some(h) = self.hits.get_mut(&addr) {
            h.count += 1;
            h.tid = tid;
            h.regs = *regs;
            h.last = t;
            return None;
        }
        self.hits.insert(addr, TraceHit { address: addr, len, text: text.clone(), count: 1, tid, regs: *regs, first: t, last: t });
        Some(json!({ "type": "event", "event": "dbg_access", "slot": self.slot, "watch": hex(self.address), "kind": self.kind, "address": hex(addr), "text": text }))
    }

    pub fn to_json(&self) -> Value {
        let hits: Vec<Value> = self.hits.values().map(|h| json!({
            "address": hex(h.address), "length": h.len, "text": h.text, "count": h.count, "tid": h.tid,
            "regs": h.regs.to_json(), "first": h.first, "last": h.last,
        })).collect();
        json!({ "slot": self.slot, "address": hex(self.address), "size": self.size, "kind": self.kind,
            "watch": { "address": hex(self.watch.0), "len": self.watch.1 }, "active": self.active,
            "total": self.total, "started": self.started, "hits": hits })
    }
}

// ---- API call monitor ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abi {
    /// rcx, rdx, r8, r9, then [rsp+0x28]…
    Win64,
    /// rdi, rsi, rdx, rcx, r8, r9, then [rsp+8]…
    SysV,
}

/// How one argument or return value is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    Hex,
    Ptr,
    Handle,
    I32,
    U32,
    Size,
    Ssize,
    Fd,
    Bool,
    Prot,
    /// NUL-terminated char*
    Str,
    /// NUL-terminated wchar_t* (UTF-16)
    WStr,
    /// a buffer whose length is the argument with this index
    Buf(u8),
    SockAddr,
    /// LSTATUS / NTSTATUS-style: 0 is success
    Status,
    Void,
}

pub struct Sig {
    pub name: &'static str,
    pub args: &'static [(&'static str, Ty)],
    pub ret: Ty,
}

use Ty::*;

/// Built-in signatures: common Win32 (kernel32/kernelbase, advapi32, ws2_32, user32) and libc calls.
pub static SIGS: &[Sig] = &[
    Sig { name: "CreateFileW", args: &[("lpFileName", WStr), ("dwDesiredAccess", Hex), ("dwShareMode", Hex), ("lpSecurityAttributes", Ptr), ("dwCreationDisposition", U32), ("dwFlagsAndAttributes", Hex), ("hTemplateFile", Handle)], ret: Handle },
    Sig { name: "CreateFileA", args: &[("lpFileName", Str), ("dwDesiredAccess", Hex), ("dwShareMode", Hex), ("lpSecurityAttributes", Ptr), ("dwCreationDisposition", U32), ("dwFlagsAndAttributes", Hex), ("hTemplateFile", Handle)], ret: Handle },
    Sig { name: "ReadFile", args: &[("hFile", Handle), ("lpBuffer", Ptr), ("nNumberOfBytesToRead", U32), ("lpNumberOfBytesRead", Ptr), ("lpOverlapped", Ptr)], ret: Bool },
    Sig { name: "WriteFile", args: &[("hFile", Handle), ("lpBuffer", Buf(2)), ("nNumberOfBytesToWrite", U32), ("lpNumberOfBytesWritten", Ptr), ("lpOverlapped", Ptr)], ret: Bool },
    Sig { name: "CloseHandle", args: &[("hObject", Handle)], ret: Bool },
    Sig { name: "DeleteFileW", args: &[("lpFileName", WStr)], ret: Bool },
    Sig { name: "VirtualAlloc", args: &[("lpAddress", Ptr), ("dwSize", Size), ("flAllocationType", Hex), ("flProtect", Prot)], ret: Ptr },
    Sig { name: "VirtualAllocEx", args: &[("hProcess", Handle), ("lpAddress", Ptr), ("dwSize", Size), ("flAllocationType", Hex), ("flProtect", Prot)], ret: Ptr },
    Sig { name: "VirtualFree", args: &[("lpAddress", Ptr), ("dwSize", Size), ("dwFreeType", Hex)], ret: Bool },
    Sig { name: "VirtualProtect", args: &[("lpAddress", Ptr), ("dwSize", Size), ("flNewProtect", Prot), ("lpflOldProtect", Ptr)], ret: Bool },
    Sig { name: "VirtualProtectEx", args: &[("hProcess", Handle), ("lpAddress", Ptr), ("dwSize", Size), ("flNewProtect", Prot), ("lpflOldProtect", Ptr)], ret: Bool },
    Sig { name: "VirtualQuery", args: &[("lpAddress", Ptr), ("lpBuffer", Ptr), ("dwLength", Size)], ret: Size },
    Sig { name: "LoadLibraryW", args: &[("lpLibFileName", WStr)], ret: Ptr },
    Sig { name: "LoadLibraryA", args: &[("lpLibFileName", Str)], ret: Ptr },
    Sig { name: "LoadLibraryExW", args: &[("lpLibFileName", WStr), ("hFile", Handle), ("dwFlags", Hex)], ret: Ptr },
    Sig { name: "LoadLibraryExA", args: &[("lpLibFileName", Str), ("hFile", Handle), ("dwFlags", Hex)], ret: Ptr },
    Sig { name: "GetModuleHandleW", args: &[("lpModuleName", WStr)], ret: Ptr },
    Sig { name: "GetModuleHandleA", args: &[("lpModuleName", Str)], ret: Ptr },
    Sig { name: "GetProcAddress", args: &[("hModule", Ptr), ("lpProcName", Str)], ret: Ptr },
    Sig { name: "OpenProcess", args: &[("dwDesiredAccess", Hex), ("bInheritHandle", Bool), ("dwProcessId", U32)], ret: Handle },
    Sig { name: "ReadProcessMemory", args: &[("hProcess", Handle), ("lpBaseAddress", Ptr), ("lpBuffer", Ptr), ("nSize", Size), ("lpNumberOfBytesRead", Ptr)], ret: Bool },
    Sig { name: "WriteProcessMemory", args: &[("hProcess", Handle), ("lpBaseAddress", Ptr), ("lpBuffer", Buf(3)), ("nSize", Size), ("lpNumberOfBytesWritten", Ptr)], ret: Bool },
    Sig { name: "CreateThread", args: &[("lpThreadAttributes", Ptr), ("dwStackSize", Size), ("lpStartAddress", Ptr), ("lpParameter", Ptr), ("dwCreationFlags", Hex), ("lpThreadId", Ptr)], ret: Handle },
    Sig { name: "CreateRemoteThread", args: &[("hProcess", Handle), ("lpThreadAttributes", Ptr), ("dwStackSize", Size), ("lpStartAddress", Ptr), ("lpParameter", Ptr), ("dwCreationFlags", Hex), ("lpThreadId", Ptr)], ret: Handle },
    Sig { name: "CreateProcessW", args: &[("lpApplicationName", WStr), ("lpCommandLine", WStr), ("lpProcessAttributes", Ptr), ("lpThreadAttributes", Ptr), ("bInheritHandles", Bool), ("dwCreationFlags", Hex)], ret: Bool },
    Sig { name: "Sleep", args: &[("dwMilliseconds", U32)], ret: Void },
    Sig { name: "MessageBoxW", args: &[("hWnd", Handle), ("lpText", WStr), ("lpCaption", WStr), ("uType", Hex)], ret: I32 },
    Sig { name: "MessageBoxA", args: &[("hWnd", Handle), ("lpText", Str), ("lpCaption", Str), ("uType", Hex)], ret: I32 },
    Sig { name: "RegOpenKeyExW", args: &[("hKey", Hex), ("lpSubKey", WStr), ("ulOptions", U32), ("samDesired", Hex), ("phkResult", Ptr)], ret: Status },
    Sig { name: "RegOpenKeyExA", args: &[("hKey", Hex), ("lpSubKey", Str), ("ulOptions", U32), ("samDesired", Hex), ("phkResult", Ptr)], ret: Status },
    Sig { name: "RegQueryValueExW", args: &[("hKey", Hex), ("lpValueName", WStr), ("lpReserved", Ptr), ("lpType", Ptr), ("lpData", Ptr), ("lpcbData", Ptr)], ret: Status },
    Sig { name: "RegSetValueExW", args: &[("hKey", Hex), ("lpValueName", WStr), ("Reserved", U32), ("dwType", U32), ("lpData", Ptr), ("cbData", U32)], ret: Status },
    Sig { name: "RegCloseKey", args: &[("hKey", Hex)], ret: Status },
    Sig { name: "socket", args: &[("af", I32), ("type", I32), ("protocol", I32)], ret: Fd },
    Sig { name: "connect", args: &[("s", Fd), ("name", SockAddr), ("namelen", I32)], ret: I32 },
    Sig { name: "bind", args: &[("s", Fd), ("name", SockAddr), ("namelen", I32)], ret: I32 },
    Sig { name: "send", args: &[("s", Fd), ("buf", Buf(2)), ("len", Size), ("flags", Hex)], ret: Ssize },
    Sig { name: "recv", args: &[("s", Fd), ("buf", Ptr), ("len", Size), ("flags", Hex)], ret: Ssize },
    Sig { name: "sendto", args: &[("s", Fd), ("buf", Buf(2)), ("len", Size), ("flags", Hex), ("to", SockAddr), ("tolen", I32)], ret: Ssize },
    Sig { name: "closesocket", args: &[("s", Fd)], ret: I32 },
    Sig { name: "open", args: &[("pathname", Str), ("flags", Hex), ("mode", Hex)], ret: Fd },
    Sig { name: "open64", args: &[("pathname", Str), ("flags", Hex), ("mode", Hex)], ret: Fd },
    Sig { name: "openat", args: &[("dirfd", Fd), ("pathname", Str), ("flags", Hex), ("mode", Hex)], ret: Fd },
    Sig { name: "fopen", args: &[("pathname", Str), ("mode", Str)], ret: Ptr },
    Sig { name: "read", args: &[("fd", Fd), ("buf", Ptr), ("count", Size)], ret: Ssize },
    Sig { name: "write", args: &[("fd", Fd), ("buf", Buf(2)), ("count", Size)], ret: Ssize },
    Sig { name: "close", args: &[("fd", Fd)], ret: I32 },
    Sig { name: "unlink", args: &[("pathname", Str)], ret: I32 },
    Sig { name: "mmap", args: &[("addr", Ptr), ("length", Size), ("prot", Prot), ("flags", Hex), ("fd", Fd), ("offset", Hex)], ret: Ptr },
    Sig { name: "mprotect", args: &[("addr", Ptr), ("len", Size), ("prot", Prot)], ret: I32 },
    Sig { name: "munmap", args: &[("addr", Ptr), ("length", Size)], ret: I32 },
    Sig { name: "dlopen", args: &[("filename", Str), ("flags", Hex)], ret: Ptr },
    Sig { name: "dlsym", args: &[("handle", Ptr), ("symbol", Str)], ret: Ptr },
    Sig { name: "malloc", args: &[("size", Size)], ret: Ptr },
    Sig { name: "free", args: &[("ptr", Ptr)], ret: Void },
    Sig { name: "getpid", args: &[], ret: I32 },
    Sig { name: "usleep", args: &[("usec", U32)], ret: I32 },
    Sig { name: "sleep", args: &[("seconds", U32)], ret: U32 },
    Sig { name: "nanosleep", args: &[("req", Ptr), ("rem", Ptr)], ret: I32 },
    Sig { name: "execve", args: &[("pathname", Str), ("argv", Ptr), ("envp", Ptr)], ret: I32 },
    Sig { name: "ptrace", args: &[("request", I32), ("pid", I32), ("addr", Ptr), ("data", Ptr)], ret: Ssize },
];

pub fn lookup(name: &str) -> Option<&'static Sig> {
    SIGS.iter().find(|s| s.name == name)
}

fn ty_name(t: Ty) -> String {
    match t {
        Buf(i) => format!("buf(len=arg{i})"),
        other => format!("{other:?}").to_lowercase(),
    }
}

pub fn signatures_json() -> Value {
    Value::Array(SIGS.iter().map(|s| json!({
        "name": s.name,
        "args": s.args.iter().map(|(n, t)| json!({ "name": n, "type": ty_name(*t) })).collect::<Vec<_>>(),
        "ret": ty_name(s.ret),
    })).collect())
}

fn escape(bytes: impl IntoIterator<Item = char>) -> String {
    let mut s = String::new();
    for c in bytes {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => s.push_str(&format!("\\x{:02x}", c as u32)),
            c => s.push(c),
        }
    }
    s
}

fn read_cstr(read: ReadFn, p: u64, max: usize) -> Option<String> {
    let mut buf = vec![0u8; max];
    let n = read(p, &mut buf);
    if n == 0 {
        return None;
    }
    let end = buf[..n].iter().position(|b| *b == 0);
    let s = &buf[..end.unwrap_or(n)];
    Some(format!("\"{}{}\"", escape(String::from_utf8_lossy(s).chars()), if end.is_none() { "…" } else { "" }))
}

fn read_wstr(read: ReadFn, p: u64, max: usize) -> Option<String> {
    let mut buf = vec![0u8; max * 2];
    let n = read(p, &mut buf) / 2;
    if n == 0 {
        return None;
    }
    let units: Vec<u16> = buf[..n * 2].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
    let end = units.iter().position(|u| *u == 0);
    let s = String::from_utf16_lossy(&units[..end.unwrap_or(n)]);
    Some(format!("L\"{}{}\"", escape(s.chars()), if end.is_none() { "…" } else { "" }))
}

fn prot_text(abi: Abi, v: u64) -> String {
    match abi {
        Abi::Win64 => {
            let base = match v & 0xff {
                0x01 => "PAGE_NOACCESS", 0x02 => "PAGE_READONLY", 0x04 => "PAGE_READWRITE", 0x08 => "PAGE_WRITECOPY",
                0x10 => "PAGE_EXECUTE", 0x20 => "PAGE_EXECUTE_READ", 0x40 => "PAGE_EXECUTE_READWRITE", 0x80 => "PAGE_EXECUTE_WRITECOPY",
                _ => return hex(v),
            };
            let mut s = base.to_owned();
            for (bit, n) in [(0x100, "PAGE_GUARD"), (0x200, "PAGE_NOCACHE"), (0x400, "PAGE_WRITECOMBINE")] {
                if v & bit != 0 {
                    s.push('|');
                    s.push_str(n);
                }
            }
            s
        }
        Abi::SysV => {
            if v == 0 {
                return "PROT_NONE".into();
            }
            let parts: Vec<&str> = [(1, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC")].iter().filter(|(b, _)| v & b != 0).map(|(_, n)| *n).collect();
            if v & !7 != 0 || parts.is_empty() { hex(v) } else { parts.join("|") }
        }
    }
}

fn sockaddr_text(abi: Abi, read: ReadFn, p: u64) -> Option<String> {
    let mut b = [0u8; 24];
    if read(p, &mut b) < 8 {
        return None;
    }
    let family = u16::from_le_bytes([b[0], b[1]]);
    let port = u16::from_be_bytes([b[2], b[3]]);
    let inet6 = if abi == Abi::Win64 { 23 } else { 10 };
    if family == 2 {
        Some(format!("{}.{}.{}.{}:{port}", b[4], b[5], b[6], b[7]))
    } else if family == inet6 {
        let groups: Vec<String> = b[8..24].as_chunks::<2>().0.iter().map(|c| format!("{:x}", u16::from_be_bytes(*c))).collect();
        Some(format!("[{}]:{port}", groups.join(":")))
    } else {
        Some(format!("family {family}"))
    }
}

/// Human-readable form of one value (an argument or the return value).
pub fn decode(abi: Abi, ty: Ty, v: u64, args: &[u64], read: ReadFn) -> String {
    match ty {
        Hex | Ptr => hex(v),
        Handle => {
            if v == u64::MAX && abi == Abi::Win64 { "INVALID_HANDLE_VALUE".into() } else { hex(v) }
        }
        I32 => (v as u32 as i32).to_string(),
        U32 => (v as u32).to_string(),
        Size => v.to_string(),
        Ssize => (v as i64).to_string(),
        Fd => if abi == Abi::Win64 { hex(v) } else { (v as u32 as i32).to_string() },
        Bool => if v as u32 == 0 { "FALSE".into() } else { "TRUE".into() },
        Prot => prot_text(abi, v),
        Status => if v as u32 == 0 { "0 (success)".into() } else { format!("{} (error)", v as u32 as i32) },
        Void => String::new(),
        // ordinals (GetProcAddress) and other small values are not pointers
        Str | WStr if v == 0 => "NULL".into(),
        Str | WStr if v < 0x10000 => format!("#{v}"),
        Str => read_cstr(read, v, 260).unwrap_or_else(|| format!("{} (unreadable)", hex(v))),
        WStr => read_wstr(read, v, 260).unwrap_or_else(|| format!("{} (unreadable)", hex(v))),
        Buf(i) => {
            if v == 0 {
                return "NULL".into();
            }
            let len = args.get(i as usize).copied().unwrap_or(0).min(32) as usize;
            let mut b = vec![0u8; len];
            let n = read(v, &mut b);
            let shown = escape(b[..n].iter().map(|c| *c as char));
            let more = args.get(i as usize).copied().unwrap_or(0) > 32;
            format!("{} \"{shown}{}\"", hex(v), if more { "…" } else { "" })
        }
        SockAddr => if v == 0 { "NULL".into() } else { sockaddr_text(abi, read, v).map(|s| format!("{} {s}", hex(v))).unwrap_or_else(|| hex(v)) },
    }
}

/// Argument `i` at function entry (before the prologue).
pub fn arg(abi: Abi, regs: &Gprs, read: ReadFn, i: usize) -> u64 {
    match abi {
        Abi::Win64 => match i {
            0 => regs.rcx,
            1 => regs.rdx,
            2 => regs.r8,
            3 => regs.r9,
            _ => read_u64(read, regs.rsp + 0x28 + 8 * (i as u64 - 4)).unwrap_or(0),
        },
        Abi::SysV => match i {
            0 => regs.rdi,
            1 => regs.rsi,
            2 => regs.rdx,
            3 => regs.rcx,
            4 => regs.r8,
            5 => regs.r9,
            _ => read_u64(read, regs.rsp + 8 + 8 * (i as u64 - 6)).unwrap_or(0),
        },
    }
}

#[derive(Clone, Debug)]
pub struct Hook {
    /// module!function as the user picked it
    pub name: String,
    pub hits: u64,
}

#[derive(Clone, Debug)]
pub struct ApiCall {
    pub seq: u64,
    pub t: u64,
    pub tid: u64,
    pub function: String,
    pub address: u64,
    pub caller: u64,
    /// (name, raw, decoded)
    pub args: Vec<(String, u64, String)>,
    pub ret: Option<u64>,
    pub ret_text: String,
    pub done: bool,
}

impl ApiCall {
    pub fn to_json(&self) -> Value {
        json!({
            "seq": self.seq, "t": self.t, "tid": self.tid, "function": self.function, "address": hex(self.address),
            "caller": hex(self.caller),
            "args": self.args.iter().map(|(n, v, t)| json!({ "name": n, "value": hex(*v), "text": t })).collect::<Vec<_>>(),
            "ret": self.ret.map(hex), "ret_text": self.ret_text, "returned": self.ret.is_some(),
        })
    }
    fn matches(&self, f: &str) -> bool {
        f.is_empty()
            || self.function.to_lowercase().contains(f)
            || self.args.iter().any(|(_, _, t)| t.to_lowercase().contains(f))
            || self.ret_text.to_lowercase().contains(f)
            || hex(self.caller).contains(f)
    }
}

struct PendingRet {
    tid: u64,
    site: u64,
    sp: u64,
    seq: u64,
}

const LOG_MAX: usize = 20_000;
const PENDING_MAX: usize = 4096;

/// Entry int3s on the picked functions, a temporary int3 on each call's return address.
pub struct ApiMon {
    pub abi: Abi,
    pub hooks: BTreeMap<u64, Hook>,
    pending: Vec<PendingRet>,
    log: VecDeque<ApiCall>,
    seq: u64,
    pub active: bool,
    pub dropped: u64,
}

impl ApiMon {
    pub fn new(abi: Abi) -> ApiMon {
        ApiMon { abi, hooks: BTreeMap::new(), pending: Vec::new(), log: VecDeque::new(), seq: 0, active: false, dropped: 0 }
    }

    pub fn is_site(&self, addr: u64) -> bool {
        self.hooks.contains_key(&addr) || self.pending.iter().any(|p| p.site == addr)
    }

    pub fn is_return_site(&self, addr: u64) -> bool {
        self.pending.iter().any(|p| p.site == addr)
    }

    /// A call into a hooked function: logs it, returns the return address to break on.
    pub fn on_entry(&mut self, addr: u64, tid: u64, regs: &Gprs, read: ReadFn) -> Option<u64> {
        let hook = self.hooks.get_mut(&addr)?;
        hook.hits += 1;
        let name = hook.name.clone();
        let short = name.rsplit('!').next().unwrap_or(&name);
        let sig = lookup(short);
        let raw: Vec<u64> = match sig {
            Some(s) => (0..s.args.len()).map(|i| arg(self.abi, regs, read, i)).collect(),
            None => (0..4).map(|i| arg(self.abi, regs, read, i)).collect(),
        };
        let args: Vec<(String, u64, String)> = match sig {
            Some(s) => s.args.iter().enumerate().map(|(i, (n, t))| (n.to_string(), raw[i], decode(self.abi, *t, raw[i], &raw, read))).collect(),
            None => {
                let names: &[&str] = if self.abi == Abi::Win64 { &["rcx", "rdx", "r8", "r9"] } else { &["rdi", "rsi", "rdx", "rcx"] };
                names.iter().zip(&raw).map(|(n, v)| (n.to_string(), *v, hex(*v))).collect()
            }
        };
        let caller = read_u64(read, regs.rsp).unwrap_or(0);
        self.seq += 1;
        let seq = self.seq;
        self.log.push_back(ApiCall { seq, t: now_ms(), tid, function: name, address: addr, caller, args, ret: None, ret_text: String::new(), done: false });
        if self.log.len() > LOG_MAX {
            self.log.pop_front();
            self.dropped += 1;
        }
        if caller == 0 {
            return None;
        }
        self.pending.push(PendingRet { tid, site: caller, sp: regs.rsp.wrapping_add(8), seq });
        if self.pending.len() > PENDING_MAX {
            self.pending.remove(0);
        }
        Some(caller)
    }

    /// A thread reached a return site. True when it completed one of the logged calls.
    pub fn on_return(&mut self, site: u64, tid: u64, regs: &Gprs, read: ReadFn) -> bool {
        let Some(i) = self.pending.iter().position(|p| p.tid == tid && p.site == site && p.sp == regs.rsp) else { return false };
        let p = self.pending.remove(i);
        // frames this thread unwound past without returning (longjmp, exceptions) never will
        self.pending.retain(|q| q.tid != tid || q.sp > regs.rsp);
        if let Some(c) = self.log.iter_mut().rev().find(|c| c.seq == p.seq) {
            let short = c.function.rsplit('!').next().unwrap_or(&c.function).to_owned();
            let raw: Vec<u64> = c.args.iter().map(|a| a.1).collect();
            c.ret = Some(regs.rax);
            c.ret_text = match lookup(&short) {
                Some(s) => decode(self.abi, s.ret, regs.rax, &raw, read),
                None => hex(regs.rax),
            };
            c.done = true;
        }
        true
    }

    /// Return sites still waiting for a thread.
    pub fn return_sites(&self) -> BTreeSet<u64> {
        self.pending.iter().map(|p| p.site).collect()
    }

    pub fn stop(&mut self) {
        self.hooks.clear();
        self.pending.clear();
        self.active = false;
    }

    pub fn clear_log(&mut self) {
        self.log.clear();
        self.dropped = 0;
    }

    pub fn log_json(&self, since: u64, limit: usize, filter: &str) -> Value {
        let f = filter.to_lowercase();
        let entries: Vec<Value> = self.log.iter().filter(|c| c.seq > since && c.matches(&f)).take(limit).map(ApiCall::to_json).collect();
        let next = entries.last().and_then(|e| e["seq"].as_u64()).unwrap_or(since);
        json!({ "active": self.active, "entries": entries, "next": next, "total": self.seq, "dropped": self.dropped,
            "pending_returns": self.pending.len(), "hooks": self.hooks_json() })
    }

    pub fn hooks_json(&self) -> Value {
        Value::Array(self.hooks.iter().map(|(a, h)| json!({ "address": hex(*a), "name": h.name, "hits": h.hits })).collect())
    }
}

// ---- PE exports (Windows module resolution) -----------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum Export {
    At(u64),
    /// "NTDLL.RtlAllocateHeap"
    Forward(String),
}

/// Looks up an export (`name`, or `#ordinal`) in the PE image mapped at `base`.
pub fn pe_export(read: ReadFn, base: u64, name: &str) -> Result<Export, String> {
    let u32_at = |a: u64| -> Option<u32> {
        let mut b = [0u8; 4];
        (read(a, &mut b) == 4).then(|| u32::from_le_bytes(b))
    };
    let mut mz = [0u8; 2];
    if read(base, &mut mz) != 2 || &mz != b"MZ" {
        return Err(format!("no PE image at {}", hex(base)));
    }
    let nt = base + u32_at(base + 0x3c).ok_or("unreadable DOS header")? as u64;
    if u32_at(nt) != Some(0x4550) {
        return Err("bad PE signature".into());
    }
    let mut magic = [0u8; 2];
    read(nt + 24, &mut magic);
    let dd = match u16::from_le_bytes(magic) {
        0x20b => nt + 24 + 112,
        0x10b => nt + 24 + 96,
        m => return Err(format!("unknown optional header magic {m:#x}")),
    };
    let (rva, size) = (u32_at(dd).unwrap_or(0) as u64, u32_at(dd + 4).unwrap_or(0) as u64);
    if rva == 0 || size == 0 {
        return Err("module has no export table".into());
    }
    let dir = base + rva;
    let mut d = [0u8; 40];
    if read(dir, &mut d) != 40 {
        return Err("unreadable export directory".into());
    }
    let f = |o: usize| u32::from_le_bytes(d[o..o + 4].try_into().unwrap()) as u64;
    let (ord_base, n_funcs, n_names, funcs, names, ords) = (f(0x10), f(0x14), f(0x18), f(0x1c), f(0x20), f(0x24));
    let index = if let Some(o) = name.strip_prefix('#') {
        let ord: u64 = o.parse().map_err(|_| format!("bad ordinal {name}"))?;
        ord.checked_sub(ord_base).ok_or_else(|| format!("ordinal {ord} below base {ord_base}"))?
    } else {
        let n = n_names.min(0x10000) as usize;
        let mut tbl = vec![0u8; n * 4];
        if read(base + names, &mut tbl) != tbl.len() {
            return Err("unreadable export name table".into());
        }
        let mut found = None;
        let mut sbuf = vec![0u8; name.len() + 1];
        for (i, c) in tbl.as_chunks::<4>().0.iter().enumerate() {
            let p = base + u32::from_le_bytes(*c) as u64;
            if read(p, &mut sbuf) == sbuf.len() && &sbuf[..name.len()] == name.as_bytes() && sbuf[name.len()] == 0 {
                found = Some(i);
                break;
            }
        }
        let i = found.ok_or_else(|| format!("export {name} not found"))?;
        let mut o = [0u8; 2];
        read(base + ords + 2 * i as u64, &mut o);
        u16::from_le_bytes(o) as u64
    };
    if index >= n_funcs {
        return Err(format!("export index {index} out of range"));
    }
    let frva = u32_at(base + funcs + 4 * index).ok_or("unreadable export address table")? as u64;
    if frva >= rva && frva < rva + size {
        let mut b = [0u8; 128];
        let n = read(base + frva, &mut b);
        let end = b[..n].iter().position(|c| *c == 0).unwrap_or(n);
        return Ok(Export::Forward(String::from_utf8_lossy(&b[..end]).into_owned()));
    }
    Ok(Export::At(base + frva))
}

// ---- shared monitors state ----------------------------------------------------------------------

/// Tracer and API monitor state. It lives outside the debugger thread so results stay readable
/// after the session ended (auto-detach on stop, process exit).
pub struct Monitors {
    pub traces: [Option<Trace>; 4],
    pub api: ApiMon,
}

pub static MON: Mutex<Option<Monitors>> = Mutex::new(None);

pub fn with_mon<R>(abi: Abi, f: impl FnOnce(&mut Monitors) -> R) -> R {
    let mut g = MON.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(|| Monitors { traces: [None, None, None, None], api: ApiMon::new(abi) });
    m.api.abi = abi;
    f(m)
}

pub fn traces_json(abi: Abi) -> Value {
    with_mon(abi, |m| Value::Array(m.traces.iter().flatten().map(Trace::to_json).collect()))
}

// ---- session plumbing ---------------------------------------------------------------------------

pub type Cmd = (Map<String, Value>, Sender<Value>);
/// The debugger thread reports the stopped thread ids (or why it could not attach).
pub type Ready = Sender<Result<Vec<u64>, String>>;

pub struct Session {
    pub tx: Sender<Cmd>,
    pub pid: u32,
}

pub static SESSION: Mutex<Option<Session>> = Mutex::new(None);

pub fn end_session() {
    *SESSION.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

pub fn session_pid() -> Option<u32> {
    SESSION.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|s| s.pid)
}

/// One platform's debugger: how to start its thread, and what it can do without the thread.
pub struct Backend {
    pub name: &'static str,
    pub abi: Abi,
    /// spawns the debugger thread for `pid`; it reports the stopped thread ids (or an error)
    pub spawn: fn(u32, Receiver<Cmd>, Ready, Relay),
    /// `dbg_disasm` over the debuggee's memory (breakpoint bytes hidden)
    pub disasm: fn(u32, &Map<String, Value>) -> Value,
}

fn attach(relay: &Relay, b: &Backend, pid: u32) -> Result<Vec<u64>, Value> {
    if SESSION.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
        return Err(failed("a debug session is already active; dbg_detach first"));
    }
    let (tx, rx) = mpsc::channel::<Cmd>();
    let (ready_tx, ready_rx) = mpsc::channel();
    let relay = relay.clone();
    let spawn = b.spawn;
    std::thread::Builder::new()
        .name(format!("echodebug-{}", b.name))
        .spawn(move || spawn(pid, rx, ready_tx, relay))
        .map_err(|e| failed(format!("cannot start the debugger thread: {e}")))?;
    match ready_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(tids)) => {
            *SESSION.lock().unwrap_or_else(|e| e.into_inner()) = Some(Session { tx, pid });
            Ok(tids)
        }
        Ok(Err(e)) => Err(failed(e)),
        Err(_) => Err(failed("debugger thread did not start")),
    }
}

/// The `dbg_*` verbs, for either backend. `default_pid` is the process the backend is attached to.
pub fn handle(relay: &Relay, req: &Map<String, Value>, default_pid: Option<u32>, b: &Backend) -> Value {
    let verb = req.get("type").and_then(Value::as_str).unwrap_or_default().to_owned();
    let pid_arg = || req.get("pid").and_then(Value::as_u64).map(|p| p as u32).or(default_pid);
    match verb.as_str() {
        "dbg_attach" => {
            let Some(pid) = pid_arg() else { return failed("attach to a process first (Targets), or pass 'pid'") };
            return match attach(relay, b, pid) {
                Ok(tids) => json!({ "type": "dbg_attach_result", "success": true, "pid": pid, "threads": tids, "state": "stopped", "backend": b.name }),
                Err(e) => e,
            };
        }
        "dbg_api_signatures" => return json!({ "type": "dbg_api_signatures_result", "success": true, "abi": format!("{:?}", b.abi).to_lowercase(), "signatures": signatures_json() }),
        "dbg_trace_results" => {
            let slot = req.get("slot").and_then(Value::as_u64);
            let all = traces_json(b.abi);
            let traces: Vec<Value> = all.as_array().into_iter().flatten().filter(|t| slot.is_none() || t["slot"].as_u64() == slot).cloned().collect();
            return json!({ "type": "dbg_trace_results_result", "success": true, "debugging": session_pid().is_some(), "traces": traces });
        }
        "dbg_api_log" => {
            let since = req.get("since").and_then(Value::as_u64).unwrap_or(0);
            let limit = req.get("limit").and_then(Value::as_u64).unwrap_or(1000).clamp(1, 10_000) as usize;
            let filter = req.get("filter").and_then(Value::as_str).unwrap_or("");
            let mut v = with_mon(b.abi, |m| m.api.log_json(since, limit, filter));
            v["type"] = json!("dbg_api_log_result");
            v["success"] = json!(true);
            return v;
        }
        "dbg_api_clear" => {
            with_mon(b.abi, |m| m.api.clear_log());
            return json!({ "type": "dbg_api_clear_result", "success": true });
        }
        "dbg_disasm" => {
            let Some(pid) = session_pid().or_else(pid_arg) else { return failed("no debug session; call dbg_attach first") };
            let mut v = (b.disasm)(pid, req);
            if v["type"] == "disassemble_result" {
                v["type"] = json!("dbg_disasm_result");
            }
            return v;
        }
        _ => {}
    }
    let mut req = req.clone();
    let mut tx = SESSION.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|s| s.tx.clone());
    if tx.is_none() {
        match verb.as_str() {
            "dbg_status" => return json!({ "type": "dbg_status_result", "success": true, "active": false, "backend": b.name }),
            // the access finder and the API monitor attach on their own and detach when stopped
            "dbg_trace_start" | "dbg_api_start" => {
                let Some(pid) = pid_arg() else { return failed("attach to a process first (Targets), or pass 'pid'") };
                if let Err(e) = attach(relay, b, pid) {
                    return e;
                }
                req.insert("auto".into(), json!(true));
                tx = SESSION.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|s| s.tx.clone());
            }
            "dbg_trace_stop" | "dbg_api_stop" => {
                // nothing is debugging: just mark the results finished
                with_mon(b.abi, |m| {
                    m.api.stop();
                    m.traces.iter_mut().flatten().for_each(|t| t.active = false);
                });
                return json!({ "type": format!("{verb}_result"), "success": true, "detached": true, "traces": traces_json(b.abi) });
            }
            _ => return failed("no debug session; call dbg_attach first"),
        }
    }
    let Some(tx) = tx else { return failed("debug session ended") };
    let (rtx, rrx) = mpsc::channel();
    if tx.send((req, rtx)).is_err() {
        end_session();
        return failed("debug session ended");
    }
    let reply = rrx.recv_timeout(Duration::from_secs(20)).unwrap_or_else(|_| failed("debugger did not answer"));
    if verb == "dbg_detach" || reply["detached"] == true {
        end_session();
    }
    reply
}

/// Detaches the active session (restoring breakpoints), if any.
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

/// What a debugger thread does after a command: keep running, or end (detached / process gone).
pub fn ends_session(req: &Map<String, Value>, reply: &Value) -> bool {
    req.get("type").and_then(Value::as_str) == Some("dbg_detach") || reply["detached"] == true
}

/// Parses `dbg_trace_start` into a trace on a free (or the requested) slot.
pub fn parse_trace(req: &Map<String, Value>, hw: &[HwSlot; 4]) -> Result<Trace, Value> {
    let Some(addr) = arg_addr(req, "address") else { return Err(bad("dbg_trace_start requires 'address'")) };
    let size = req.get("size").and_then(Value::as_u64).unwrap_or(4).clamp(1, 8);
    let kind = req.get("kind").and_then(Value::as_str).unwrap_or("write");
    let kind = if kind == "rw" { "access" } else { kind };
    let slot = match req.get("slot").and_then(Value::as_u64) {
        Some(s) if s > 3 => return Err(bad("slot must be 0-3")),
        Some(s) => s as usize,
        None => (0..4).rev().find(|i| hw[*i].is_none()).ok_or_else(|| failed("all four debug registers are in use; clear a hardware breakpoint or stop a trace"))?,
    };
    Trace::new(slot, addr, size, kind).map_err(|e| bad(&e))
}

/// Parses the `functions` list of `dbg_api_start`: "module!name", "!name", "name", "0xaddr=label"
/// or `{name, address}`. Returns (spec, explicit address).
pub fn parse_api_functions(req: &Map<String, Value>) -> Result<Vec<(String, Option<u64>)>, Value> {
    let Some(list) = req.get("functions").and_then(Value::as_array) else { return Err(bad("dbg_api_start requires 'functions' (e.g. [\"kernel32.dll!CreateFileW\"])")) };
    if list.is_empty() || list.len() > 64 {
        return Err(bad("pick 1 to 64 functions"));
    }
    let mut out = Vec::new();
    for f in list {
        match f {
            Value::String(s) => {
                let s = s.trim();
                if let Some((a, label)) = s.split_once('=') {
                    let addr = u64::from_str_radix(a.trim().trim_start_matches("0x"), 16).map_err(|_| bad(&format!("bad address in {s}")))?;
                    out.push((label.trim().to_owned(), Some(addr)));
                } else {
                    out.push((s.to_owned(), None));
                }
            }
            Value::Object(o) => {
                let name = o.get("name").and_then(Value::as_str).unwrap_or("").to_owned();
                let addr = arg_addr(o, "address");
                if name.is_empty() && addr.is_none() {
                    return Err(bad("each function needs 'name' or 'address'"));
                }
                let label = if name.is_empty() { hex(addr.unwrap_or(0)) } else { name };
                out.push((label, addr));
            }
            _ => return Err(bad("functions are strings or {name, address}")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem(base: u64, bytes: Vec<u8>) -> impl Fn(u64, &mut [u8]) -> usize {
        move |a: u64, buf: &mut [u8]| {
            if a < base || a >= base + bytes.len() as u64 {
                return 0;
            }
            let o = (a - base) as usize;
            let n = buf.len().min(bytes.len() - o);
            buf[..n].copy_from_slice(&bytes[o..o + n]);
            n
        }
    }

    #[test]
    fn dr7_and_hw_parsing() {
        let hw: [HwSlot; 4] = [Some((0x1000, "exec".into(), 1)), Some((0x2000, "write".into(), 4)), None, Some((0x3000, "rw".into(), 8))];
        let v = dr7(&hw);
        assert_eq!(v & 0xff, 0b0100_0101);
        assert_eq!((v >> 16) & 0xf, 0);
        assert_eq!((v >> 20) & 0xf, 0b1101);
        assert_eq!((v >> 28) & 0xf, 0b1011);
        let m = |v: Value| v.as_object().unwrap().clone();
        assert!(parse_hwbreak(&m(json!({ "slot": 4, "address": "0x10" }))).is_err());
        assert!(parse_hwbreak(&m(json!({ "slot": 1, "address": "0x11", "kind": "write", "len": 4 }))).is_err());
        assert_eq!(parse_hwbreak(&m(json!({ "slot": 2, "enabled": false }))).unwrap(), (2, None));
        assert_eq!(parse_hwbreak(&m(json!({ "slot": 0, "address": "0x10", "kind": "rw", "len": 8 }))).unwrap().1, Some((0x10, "rw".into(), 8)));
    }

    #[test]
    fn cover_picks_an_aligned_range() {
        assert_eq!(cover(0x1000, 4), Some((0x1000, 4)));
        assert_eq!(cover(0x1003, 1), Some((0x1003, 1)));
        assert_eq!(cover(0x1003, 4), Some((0x1000, 8)));
        assert_eq!(cover(0x1002, 2), Some((0x1002, 2)));
        assert_eq!(cover(0x1001, 2), Some((0x1000, 4)));
        assert_eq!(cover(0x1007, 2), None);
    }

    #[test]
    fn accessor_is_the_instruction_before_rip() {
        // 48 89 07          mov [rdi], rax
        // 48 83 c0 01       add rax, 1     <- rip after the write is here
        let code = [0x90, 0x90, 0x48, 0x89, 0x07];
        let rip = 0x401005;
        let regs = Gprs { rdi: 0x6000, rip, ..Default::default() };
        let (a, len, text) = find_accessor(&code, rip, &regs, (0x6000, 8), true).unwrap();
        assert_eq!((a, len), (0x401002, 3), "{text}");
        assert!(text.contains("mov"), "{text}");
        // rip-relative store: mov dword ptr [rip+0x10], eax (89 05 10 00 00 00)
        let code = [0x89, 0x05, 0x10, 0, 0, 0];
        let rip = 0x500006;
        let (a, _, _) = find_accessor(&code, rip, &Gprs::default(), (rip + 0x10, 4), true).unwrap();
        assert_eq!(a, 0x500000);
        // push rax writes [rsp] (rsp is already decremented when the trap is reported)
        let code = [0x48, 0x89, 0xc3, 0x50]; // mov rbx, rax ; push rax
        let regs = Gprs { rsp: 0x7ff0, ..Default::default() };
        let (a, len, text) = find_accessor(&code, 0x1004, &regs, (0x7ff0, 8), true).unwrap();
        assert_eq!((a, len), (0x1003, 1), "{text}");
    }

    #[test]
    fn trace_aggregates_hits_per_instruction() {
        let mut t = Trace::new(3, 0x6000, 4, "write").unwrap();
        assert_eq!(t.hw(), (0x6000, "write".into(), 4));
        let regs = Gprs { rdi: 0x6000, ..Default::default() };
        let code = [0x90, 0x90, 0x48, 0x89, 0x07];
        let ev = t.record(&code, 0x401005, &regs, 7).unwrap();
        assert_eq!(ev["event"], "dbg_access");
        assert_eq!(ev["address"], "0x401002");
        assert!(t.record(&code, 0x401005, &Gprs { rax: 5, ..regs }, 8).is_none());
        let j = t.to_json();
        assert_eq!(j["total"], 2);
        assert_eq!(j["hits"][0]["count"], 2);
        assert_eq!(j["hits"][0]["tid"], 8);
        assert_eq!(j["hits"][0]["regs"]["rax"], "0x5");
        assert!(Trace::new(0, 0x1007, 2, "write").is_err());
        assert!(Trace::new(0, 0x1000, 2, "exec").is_err());
        let hw: [HwSlot; 4] = [None, None, None, Some((1, "exec".into(), 1))];
        let req = json!({ "address": "0x2000", "kind": "rw", "size": 8 });
        let tr = parse_trace(req.as_object().unwrap(), &hw).unwrap();
        assert_eq!((tr.slot, tr.kind.as_str(), tr.hw().1.as_str()), (2, "access", "rw"));
    }

    #[test]
    fn api_monitor_decodes_win64_calls_and_matches_returns() {
        // a wide string, a return address on the stack, a 5th stack argument
        let base = 0x10000u64;
        let mut bytes = vec![0u8; 0x200];
        for (i, u) in "C:\\x.txt".encode_utf16().enumerate() {
            bytes[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        let rsp = base + 0x100;
        bytes[0x100..0x108].copy_from_slice(&0x1400_0123u64.to_le_bytes());
        bytes[0x128..0x130].copy_from_slice(&3u64.to_le_bytes()); // dwCreationDisposition = OPEN_EXISTING
        let read = mem(base, bytes);
        let mut m = ApiMon::new(Abi::Win64);
        m.hooks.insert(0x7ff0_0000, Hook { name: "kernel32.dll!CreateFileW".into(), hits: 0 });
        m.hooks.insert(0x7ff0_1000, Hook { name: "foo.dll!Mystery".into(), hits: 0 });
        let regs = Gprs { rcx: base, rdx: 0x8000_0000, r8: 1, r9: 0, rsp, ..Default::default() };
        let ret = m.on_entry(0x7ff0_0000, 11, &regs, &read).unwrap();
        assert_eq!(ret, 0x1400_0123);
        assert!(m.is_return_site(ret));
        assert!(m.is_site(0x7ff0_0000));
        // another thread returning through the same site does not complete it
        assert!(!m.on_return(ret, 12, &Gprs { rsp: rsp + 8, rax: 5, ..Default::default() }, &read));
        assert!(m.on_return(ret, 11, &Gprs { rsp: rsp + 8, rax: u64::MAX, ..Default::default() }, &read));
        assert!(m.return_sites().is_empty());
        let log = m.log_json(0, 100, "");
        let e = &log["entries"][0];
        assert_eq!(e["function"], "kernel32.dll!CreateFileW");
        assert_eq!(e["args"][0]["text"], "L\"C:\\\\x.txt\"");
        assert_eq!(e["args"][1]["text"], "0x80000000");
        assert_eq!(e["args"][4]["text"], "3");
        assert_eq!(e["caller"], "0x14000123");
        assert_eq!(e["ret_text"], "INVALID_HANDLE_VALUE");
        // unknown functions show the raw argument registers
        m.on_entry(0x7ff0_1000, 11, &Gprs { rcx: 1, rdx: 2, r8: 3, r9: 4, rsp, ..Default::default() }, &read);
        let log = m.log_json(1, 100, "");
        assert_eq!(log["entries"][0]["args"][3]["name"], "r9");
        assert_eq!(log["entries"][0]["returned"], false);
        assert_eq!(m.log_json(0, 100, "mystery")["entries"].as_array().unwrap().len(), 1);
        assert_eq!(m.log_json(0, 100, "x.txt")["entries"].as_array().unwrap().len(), 1);
        assert_eq!(m.hooks_json()[0]["hits"], 1);
        m.stop();
        assert!(!m.is_site(0x7ff0_0000));
    }

    #[test]
    fn api_monitor_decodes_sysv_calls() {
        let base = 0x20000u64;
        let mut bytes = vec![0u8; 0x200];
        bytes[..3].copy_from_slice(b"hi\n");
        bytes[0x40..0x50].copy_from_slice(&[2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        let read = mem(base, bytes);
        let mut m = ApiMon::new(Abi::SysV);
        m.hooks.insert(0x1000, Hook { name: "libc.so.6!write".into(), hits: 0 });
        m.hooks.insert(0x2000, Hook { name: "connect".into(), hits: 0 });
        m.hooks.insert(0x3000, Hook { name: "mprotect".into(), hits: 0 });
        let regs = Gprs { rdi: 1, rsi: base, rdx: 3, rsp: base + 0x100, ..Default::default() };
        m.on_entry(0x1000, 1, &regs, &read);
        m.on_entry(0x2000, 1, &Gprs { rdi: 3, rsi: base + 0x40, rdx: 16, ..regs }, &read);
        m.on_entry(0x3000, 1, &Gprs { rdi: 0x7000, rsi: 0x1000, rdx: 5, ..regs }, &read);
        let log = m.log_json(0, 10, "");
        assert_eq!(log["entries"][0]["args"][1]["text"], format!("{} \"hi\\n\"", hex(base)));
        assert_eq!(log["entries"][0]["args"][0]["text"], "1");
        assert_eq!(log["entries"][1]["args"][1]["text"], format!("{} 127.0.0.1:8080", hex(base + 0x40)));
        assert_eq!(log["entries"][2]["args"][2]["text"], "PROT_READ|PROT_EXEC");
        assert_eq!(decode(Abi::Win64, Prot, 0x140, &[], &read), "PAGE_EXECUTE_READWRITE|PAGE_GUARD");
        assert_eq!(decode(Abi::Win64, Str, 12, &[], &read), "#12");
        assert_eq!(decode(Abi::SysV, Ssize, u64::MAX, &[], &read), "-1");
        assert_eq!(decode(Abi::Win64, Status, 2, &[], &read), "2 (error)");
        assert!(signatures_json().as_array().unwrap().iter().any(|s| s["name"] == "VirtualProtect"));
    }

    #[test]
    fn api_function_specs() {
        let req = json!({ "functions": ["kernel32.dll!CreateFileW", "0x1000=mine", { "name": "x", "address": "0x2000" }, "write"] });
        let v = parse_api_functions(req.as_object().unwrap()).unwrap();
        assert_eq!(v[0], ("kernel32.dll!CreateFileW".into(), None));
        assert_eq!(v[1], ("mine".into(), Some(0x1000)));
        assert_eq!(v[2], ("x".into(), Some(0x2000)));
        assert!(parse_api_functions(json!({ "functions": [] }).as_object().unwrap()).is_err());
    }

    /// A minimal PE32+ image: export directory with one function and one forwarder.
    fn tiny_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        let dd = 0x98 + 112;
        b[dd..dd + 4].copy_from_slice(&0x200u32.to_le_bytes());
        b[dd + 4..dd + 8].copy_from_slice(&0x100u32.to_le_bytes());
        let put = |b: &mut Vec<u8>, o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        put(&mut b, 0x210, 1); // ordinal base
        put(&mut b, 0x214, 2); // functions
        put(&mut b, 0x218, 2); // names
        put(&mut b, 0x21c, 0x240); // AddressOfFunctions
        put(&mut b, 0x220, 0x250); // AddressOfNames
        put(&mut b, 0x224, 0x260); // AddressOfNameOrdinals
        put(&mut b, 0x240, 0x1234);
        put(&mut b, 0x244, 0x280); // forwarder string inside the export directory
        put(&mut b, 0x250, 0x270);
        put(&mut b, 0x254, 0x278);
        b[0x260..0x264].copy_from_slice(&[0, 0, 1, 0]);
        b[0x270..0x274].copy_from_slice(b"Foo\0");
        b[0x278..0x27c].copy_from_slice(b"Bar\0");
        b[0x280..0x28e].copy_from_slice(b"NTDLL.RtlBaz\0\0");
        b
    }

    #[test]
    fn pe_exports_and_forwarders() {
        let base = 0x7ff8_0000_0000u64;
        let read = mem(base, tiny_pe());
        assert_eq!(pe_export(&read, base, "Foo").unwrap(), Export::At(base + 0x1234));
        assert_eq!(pe_export(&read, base, "Bar").unwrap(), Export::Forward("NTDLL.RtlBaz".into()));
        assert_eq!(pe_export(&read, base, "#1").unwrap(), Export::At(base + 0x1234));
        assert!(pe_export(&read, base, "Fo").is_err());
        assert!(pe_export(&read, base + 0x10, "Foo").is_err());
    }

    #[test]
    fn registers_round_trip() {
        let mut g = Gprs { rax: 0x1122_3344_5566_7788, ..Default::default() };
        assert_eq!(g.get(Register::EAX), Some(0x5566_7788));
        assert_eq!(g.get(Register::AH), Some(0x77));
        assert_eq!(g.get(Register::AL), Some(0x88));
        g.apply(json!({ "rbx": "0x10", "rip": 32, "bogus": "1" }).as_object().unwrap());
        assert_eq!((g.rbx, g.rip), (0x10, 32));
        assert_eq!(g.to_json()["rbx"], "0x10");
    }
}
