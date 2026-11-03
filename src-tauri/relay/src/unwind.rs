//! x86-64 call-stack unwinding, independent of where memory comes from.
//!
//! Everything reads the target through the [`Memory`] callback, so the same code walks a live
//! Linux process (`/proc/<pid>/mem`), a Windows process (`ReadProcessMemory`) or a test fixture.
//!
//! * **PE** modules: the exception directory (`.pdata` RUNTIME_FUNCTIONs) and their UNWIND_INFO
//!   (`.xdata`), interpreted like `RtlVirtualUnwind`: every UWOP code (push / alloc small and
//!   large / set frame register / save non-volatile and XMM, near and far / machine frames),
//!   chained unwind info, the prolog offset (codes not yet executed are skipped), indirect
//!   RUNTIME_FUNCTION entries, and `ret` epilogs (`add rsp` / `lea rsp` + pops + `ret`) recognised
//!   from the code bytes. A PE function without `.pdata` is a leaf (return address at `[rsp]`).
//! * **ELF** modules: `.eh_frame` CFI found through `PT_GNU_EH_FRAME` (`.eh_frame_hdr` binary
//!   search table, or a linear walk when the table is missing): CIE/FDE parsing with the `z`, `R`,
//!   `P`, `L` and `S` augmentations, the DW_CFA row program (advance / offset / restore / register /
//!   remember / def_cfa*, expressions and the GNU extensions) and a DWARF expression stack machine
//!   for `DW_CFA_def_cfa_expression` / `DW_CFA_expression` (PLT stubs, signal trampolines).
//! * Anything else (no unwind data, JIT code, a corrupt row): the frame-pointer chain, then a
//!   stack scan for return addresses that follow a `call`. Those frames are flagged `guessed`.

use std::collections::HashMap;

/// Reads target memory: fills `buf` from `addr`, `false` when any byte is unreadable.
pub trait Memory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> bool;

    fn u8(&self, addr: u64) -> Option<u8> {
        let mut b = [0u8; 1];
        self.read(addr, &mut b).then_some(b[0])
    }
    fn u16(&self, addr: u64) -> Option<u16> {
        let mut b = [0u8; 2];
        self.read(addr, &mut b).then(|| u16::from_le_bytes(b))
    }
    fn u32(&self, addr: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        self.read(addr, &mut b).then(|| u32::from_le_bytes(b))
    }
    fn u64(&self, addr: u64) -> Option<u64> {
        let mut b = [0u8; 8];
        self.read(addr, &mut b).then(|| u64::from_le_bytes(b))
    }
    fn bytes(&self, addr: u64, n: usize) -> Option<Vec<u8>> {
        let mut b = vec![0u8; n];
        self.read(addr, &mut b).then_some(b)
    }
}

impl<F: Fn(u64, &mut [u8]) -> bool> Memory for F {
    fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        self(addr, buf)
    }
}

/// A flat byte image mapped at `base` (tests, file-backed analysis).
pub struct Flat<'a> {
    pub base: u64,
    pub data: &'a [u8],
}

impl Memory for Flat<'_> {
    fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        let Some(off) = addr.checked_sub(self.base) else { return false };
        let Ok(off) = usize::try_from(off) else { return false };
        match self.data.get(off..off.saturating_add(buf.len())) {
            Some(s) if s.len() == buf.len() => {
                buf.copy_from_slice(s);
                true
            }
            _ => false,
        }
    }
}

/// Several regions at once (a module image plus a stack, say).
pub struct Regions(pub Vec<(u64, Vec<u8>)>);

impl Memory for Regions {
    fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        self.0.iter().any(|(base, data)| Flat { base: *base, data }.read(addr, buf))
    }
}

// ---------------------------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------------------------

/// Machine (Windows CONTEXT / UWOP) register order.
pub const RAX: usize = 0;
pub const RCX: usize = 1;
pub const RDX: usize = 2;
pub const RBX: usize = 3;
pub const RSP: usize = 4;
pub const RBP: usize = 5;
pub const RSI: usize = 6;
pub const RDI: usize = 7;
pub const REG_NAMES: [&str; 16] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

/// General-purpose registers (None: not known in this frame) plus rip.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    pub gpr: [Option<u64>; 16],
    pub rip: u64,
}

impl Regs {
    pub fn new(rip: u64, rsp: u64, rbp: u64) -> Self {
        let mut r = Regs { rip, ..Default::default() };
        r.gpr[RSP] = Some(rsp);
        r.gpr[RBP] = Some(rbp);
        r
    }
    pub fn rsp(&self) -> u64 {
        self.gpr[RSP].unwrap_or(0)
    }
    pub fn set(&mut self, i: usize, v: u64) {
        self.gpr[i] = Some(v);
    }
    pub fn by_name(&mut self, name: &str, v: u64) {
        if name == "rip" {
            self.rip = v;
        } else if let Some(i) = REG_NAMES.iter().position(|n| *n == name) {
            self.gpr[i] = Some(v);
        }
    }
}

/// DWARF x86-64 register number → machine index (16 = return address / rip).
fn dwarf_to_machine(r: u16) -> Option<usize> {
    Some(match r {
        0 => RAX,
        1 => RDX,
        2 => RCX,
        3 => RBX,
        4 => RSI,
        5 => RDI,
        6 => RBP,
        7 => RSP,
        8..=15 => r as usize,
        16 => 16,
        _ => return None,
    })
}

fn get_dwarf(regs: &Regs, r: u16) -> Option<u64> {
    match dwarf_to_machine(r)? {
        16 => Some(regs.rip),
        i => regs.gpr[i],
    }
}

// ---------------------------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// the thread's registers
    Context,
    /// PE .pdata / UNWIND_INFO
    Pdata,
    /// PE function without unwind data: return address at [rsp]
    Leaf,
    /// ELF .eh_frame CFI
    Cfi,
    /// rbp chain (no unwind data)
    FramePointer,
    /// return address found by scanning the stack
    Scan,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Context => "context",
            Method::Pdata => "pdata",
            Method::Leaf => "leaf",
            Method::Cfi => "cfi",
            Method::FramePointer => "frame-pointer",
            Method::Scan => "stack-scan",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub pc: u64,
    pub sp: u64,
    /// how this frame was recovered from the one below it
    pub method: Method,
    /// recovered by a heuristic (frame pointer / stack scan / leaf without unwind data)
    pub guessed: bool,
    pub module: Option<String>,
    pub offset: u64,
    /// nearest preceding symbol and the distance to it
    pub symbol: Option<(String, u64)>,
}

/// One RUNTIME_FUNCTION.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}

enum Tables {
    Pe { pdata: Vec<RuntimeFunction> },
    Elf { eh: Option<EhFrame> },
    Unknown,
}

pub struct Unwinder<'a, M: Memory + ?Sized> {
    mem: &'a M,
    modules: Vec<ModuleInfo>,
    tables: HashMap<u64, Tables>,
    cies: HashMap<u64, Option<Cie>>,
    /// how many stack slots the return-address scan looks at
    pub max_scan: usize,
}

const MAX_PDATA: usize = 1 << 20;

impl<'a, M: Memory + ?Sized> Unwinder<'a, M> {
    pub fn new(mem: &'a M, mut modules: Vec<ModuleInfo>) -> Self {
        modules.sort_by_key(|m| m.base);
        Unwinder { mem, modules, tables: HashMap::new(), cies: HashMap::new(), max_scan: 2048 }
    }

    pub fn module_of(&self, addr: u64) -> Option<&ModuleInfo> {
        let i = self.modules.partition_point(|m| m.base <= addr);
        let m = self.modules.get(i.checked_sub(1)?)?;
        (addr < m.base.saturating_add(m.size)).then_some(m)
    }

    fn tables(&mut self, base: u64) -> &Tables {
        if !self.tables.contains_key(&base) {
            let t = load_tables(self.mem, base);
            self.tables.insert(base, t);
        }
        &self.tables[&base]
    }

    /// The RUNTIME_FUNCTION covering `addr` in a PE module (direct entries only).
    pub fn pe_function(&mut self, addr: u64) -> Option<(u64, RuntimeFunction)> {
        let base = self.module_of(addr)?.base;
        let Tables::Pe { pdata } = self.tables(base) else { return None };
        let rva = u32::try_from(addr - base).ok()?;
        let i = pdata.partition_point(|f| f.begin <= rva);
        let f = *pdata.get(i.checked_sub(1)?)?;
        (rva < f.end).then_some((base, f))
    }

    /// Walks the stack from `regs` (the thread's context). At most `max` frames.
    pub fn walk(&mut self, regs: &Regs, max: usize) -> Vec<Frame> {
        let mut out = Vec::new();
        let mut cur = regs.clone();
        let mut exact_pc = true; // the top frame (and a frame interrupted by a signal) is not a return address
        let (mut method, mut guessed) = (Method::Context, false);
        while out.len() < max.max(1) {
            out.push(self.frame(&cur, method, guessed));
            let Some((next, m, g, signal)) = self.step(&cur, exact_pc, out.len() == 1) else { break };
            // the stack grows down: a caller lives above its callee (a machine frame may switch
            // stacks, so .pdata frames are exempt; the frame limit bounds a loop)
            if next.rip == 0 || (next.rip == cur.rip && next.rsp() == cur.rsp()) || (next.rsp() <= cur.rsp() && m != Method::Pdata) {
                break;
            }
            // a heuristic return address outside every module is the end of the line
            if g && self.module_of(next.rip).is_none() {
                break;
            }
            exact_pc = signal;
            cur = next;
            method = m;
            guessed = g;
        }
        out
    }

    fn frame(&self, r: &Regs, method: Method, guessed: bool) -> Frame {
        let m = self.module_of(r.rip);
        Frame {
            pc: r.rip,
            sp: r.rsp(),
            method,
            guessed,
            module: m.map(|m| m.name.clone()),
            offset: m.map(|m| r.rip - m.base).unwrap_or(r.rip),
            symbol: None,
        }
    }

    /// One unwind step: the caller's registers, how they were found, whether that was a guess, and
    /// whether the caller's pc is exact (we came out of a signal frame).
    pub fn step(&mut self, regs: &Regs, exact_pc: bool, top: bool) -> Option<(Regs, Method, bool, bool)> {
        let pc = regs.rip;
        let lookup = if exact_pc { pc } else { pc.saturating_sub(1) };
        let base = self.module_of(lookup).map(|m| m.base);
        if let Some(base) = base {
            let kind = match self.tables(base) {
                Tables::Pe { .. } => 1,
                Tables::Elf { eh: Some(_) } => 2,
                _ => 0,
            };
            if kind == 1 {
                if let Some((base, f)) = self.pe_function(lookup) {
                    let mut r = regs.clone();
                    if pe_unwind(self.mem, base, f, pc, &mut r, top).is_some() {
                        return Some((r, Method::Pdata, false, false));
                    }
                } else if top || exact_pc {
                    // leaf: no prolog, nothing saved, return address on top of the stack
                    let rsp = regs.gpr[RSP]?;
                    let ra = self.mem.u64(rsp)?;
                    let mut r = regs.clone();
                    r.rip = ra;
                    r.set(RSP, rsp + 8);
                    return Some((r, Method::Leaf, false, false));
                }
            } else if kind == 2 {
                match self.cfi_step(base, lookup, regs) {
                    Cfi::Next(r) => return Some((r.0, Method::Cfi, false, r.1)),
                    Cfi::End => return None,
                    Cfi::NoInfo => {}
                }
            }
        }
        self.fallback(regs)
    }

    fn cfi_step(&mut self, base: u64, lookup: u64, regs: &Regs) -> Cfi {
        let mem = self.mem;
        let fde_addr = {
            let Tables::Elf { eh: Some(eh) } = self.tables(base) else { return Cfi::NoInfo };
            match eh.find(mem, lookup) {
                Some(a) => a,
                None => return Cfi::NoInfo,
            }
        };
        let Some(fde) = parse_fde(mem, fde_addr, &mut self.cies) else { return Cfi::NoInfo };
        if lookup < fde.pc_begin || lookup >= fde.pc_begin + fde.pc_range {
            return Cfi::NoInfo;
        }
        let Some(row) = run_cfa(mem, &fde, lookup) else { return Cfi::NoInfo };
        // DW_CFA_undefined on the return address marks the outermost frame (_start, clone)
        if row.regs.get(fde.cie.ra_reg as usize) == Some(&Rule::Undefined) {
            return Cfi::End;
        }
        match apply_row(mem, &row, regs, fde.cie.ra_reg) {
            Some(r) => Cfi::Next(Box::new((r, fde.cie.signal))),
            None => Cfi::NoInfo,
        }
    }

    /// Frame pointer chain, then a stack scan. Both are guesses.
    fn fallback(&self, regs: &Regs) -> Option<(Regs, Method, bool, bool)> {
        let rsp = regs.gpr[RSP]?;
        if let Some(rbp) = regs.gpr[RBP] {
            if rbp >= rsp && rbp - rsp < 16 << 20 && rbp % 8 == 0 {
                if let (Some(saved), Some(ra)) = (self.mem.u64(rbp), self.mem.u64(rbp + 8)) {
                    if self.module_of(ra).is_some() && self.after_call(ra) {
                        let mut r = regs.clone();
                        r.rip = ra;
                        r.set(RSP, rbp + 16);
                        r.set(RBP, saved);
                        return Some((r, Method::FramePointer, true, false));
                    }
                }
            }
        }
        // scan for something that looks like a return address
        let n = self.max_scan;
        let mut chunk = vec![0u8; 8 * 256];
        let mut slot = rsp & !7;
        let mut done = 0usize;
        while done < n {
            let take = (n - done).min(256);
            let buf = &mut chunk[..take * 8];
            if !self.mem.read(slot, buf) {
                // the stack ends at a page boundary: read what is left one qword at a time
                for i in 0..take {
                    let Some(v) = self.mem.u64(slot + i as u64 * 8) else { break };
                    if let Some(r) = self.scan_hit(regs, v, slot + i as u64 * 8) {
                        return Some(r);
                    }
                }
                return None;
            }
            for i in 0..take {
                let v = u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
                if let Some(r) = self.scan_hit(regs, v, slot + i as u64 * 8) {
                    return Some(r);
                }
            }
            slot += take as u64 * 8;
            done += take;
        }
        None
    }

    fn scan_hit(&self, regs: &Regs, v: u64, at: u64) -> Option<(Regs, Method, bool, bool)> {
        if v == regs.rip || self.module_of(v).is_none() || !self.after_call(v) {
            return None;
        }
        let mut r = regs.clone();
        r.rip = v;
        r.set(RSP, at + 8);
        Some((r, Method::Scan, true, false))
    }

    /// Does a `call` instruction end right before `ra`?
    pub fn after_call(&self, ra: u64) -> bool {
        let Some(b) = self.mem.bytes(ra.wrapping_sub(7), 7) else { return false };
        // call rel32
        if b[2] == 0xe8 {
            return true;
        }
        // call [rip+disp32] / call [reg+disp32] (FF /2 with mod 10 or rip-relative)
        if b[1] == 0xff && (b[2] & 0x38) == 0x10 && (b[2] & 0xc7 == 0x05 || (b[2] & 0xc0 == 0x80 && b[2] & 7 != 4)) {
            return true;
        }
        if b[0] == 0xff && (b[1] & 0x38) == 0x10 && b[1] & 0xc0 == 0x80 && b[1] & 7 == 4 {
            return true; // call [reg+sib+disp32]
        }
        // call [reg+disp8]
        if b[4] == 0xff && (b[5] & 0x38) == 0x10 && b[5] & 0xc0 == 0x40 && b[5] & 7 != 4 {
            return true;
        }
        if b[3] == 0xff && (b[4] & 0x38) == 0x10 && b[4] & 0xc0 == 0x40 && b[4] & 7 == 4 {
            return true; // call [reg+sib+disp8]
        }
        // call reg / call [reg]
        if b[5] == 0xff && (b[6] & 0x38) == 0x10 && (b[6] & 0xc0 == 0xc0 || (b[6] & 0xc0 == 0 && b[6] & 7 != 4 && b[6] & 7 != 5)) {
            return true;
        }
        if b[4] == 0xff && (b[5] & 0x38) == 0x10 && b[5] & 0xc0 == 0 && b[5] & 7 == 4 {
            return true; // call [reg+sib]
        }
        false
    }
}

enum Cfi {
    Next(Box<(Regs, bool)>),
    End,
    NoInfo,
}

fn load_tables(mem: &(impl Memory + ?Sized), base: u64) -> Tables {
    let Some(magic) = mem.u32(base) else { return Tables::Unknown };
    if magic & 0xffff == 0x5a4d {
        return Tables::Pe { pdata: read_pdata(mem, base).unwrap_or_default() };
    }
    if magic == 0x464c_457f {
        return Tables::Elf { eh: EhFrame::locate(mem, base) };
    }
    Tables::Unknown
}

// ---------------------------------------------------------------------------------------------
// PE: headers, .pdata, exports
// ---------------------------------------------------------------------------------------------

/// (rva, size) of data directory `index` of the PE32+ image at `base`.
pub fn pe_directory(mem: &(impl Memory + ?Sized), base: u64, index: u32) -> Option<(u32, u32)> {
    let nt = base + mem.u32(base + 0x3c)? as u64;
    if mem.u32(nt)? != 0x4550 {
        return None;
    }
    let oh = nt + 24;
    let (dirs, count) = match mem.u16(oh)? {
        0x20b => (oh + 112, mem.u32(oh + 108)?),
        0x10b => (oh + 96, mem.u32(oh + 92)?),
        _ => return None,
    };
    if index >= count.min(16) {
        return None;
    }
    let rva = mem.u32(dirs + index as u64 * 8)?;
    let size = mem.u32(dirs + index as u64 * 8 + 4)?;
    (rva != 0 && size != 0).then_some((rva, size))
}

/// The exception directory, sorted by begin address.
pub fn read_pdata(mem: &(impl Memory + ?Sized), base: u64) -> Option<Vec<RuntimeFunction>> {
    let (rva, size) = pe_directory(mem, base, 3)?;
    let n = (size as usize / 12).min(MAX_PDATA);
    let raw = mem.bytes(base + rva as u64, n * 12)?;
    let mut v: Vec<RuntimeFunction> = raw
        .as_chunks::<12>()
        .0
        .iter()
        .map(|c| RuntimeFunction {
            begin: u32::from_le_bytes(c[0..4].try_into().unwrap()),
            end: u32::from_le_bytes(c[4..8].try_into().unwrap()),
            unwind: u32::from_le_bytes(c[8..12].try_into().unwrap()),
        })
        .filter(|f| f.begin != 0 && f.end > f.begin)
        .collect();
    v.sort_by_key(|f| f.begin);
    Some(v)
}

/// Exported functions (rva, name) of the PE image at `base`, sorted by rva.
pub fn pe_exports(mem: &(impl Memory + ?Sized), base: u64) -> Vec<(u64, String)> {
    let Some((rva, size)) = pe_directory(mem, base, 0) else { return Vec::new() };
    let d = base + rva as u64;
    let (Some(nfuncs), Some(nnames), Some(funcs), Some(names), Some(ords)) =
        (mem.u32(d + 20), mem.u32(d + 24), mem.u32(d + 28), mem.u32(d + 32), mem.u32(d + 36))
    else {
        return Vec::new();
    };
    let nnames = nnames.min(65536) as usize;
    let nfuncs = nfuncs.min(65536);
    let (Some(name_tab), Some(ord_tab)) = (mem.bytes(base + names as u64, nnames * 4), mem.bytes(base + ords as u64, nnames * 2)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for i in 0..nnames {
        let nrva = u32::from_le_bytes(name_tab[i * 4..i * 4 + 4].try_into().unwrap());
        let ord = u16::from_le_bytes(ord_tab[i * 2..i * 2 + 2].try_into().unwrap()) as u32;
        if ord >= nfuncs {
            continue;
        }
        let Some(frva) = mem.u32(base + funcs as u64 + ord as u64 * 4) else { continue };
        if frva >= rva && frva < rva + size {
            continue; // forwarder
        }
        if let Some(name) = read_cstr(mem, base + nrva as u64, 256) {
            out.push((frva as u64, name));
        }
    }
    out.sort();
    out
}

pub fn read_cstr(mem: &(impl Memory + ?Sized), addr: u64, max: usize) -> Option<String> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 64];
    let mut a = addr;
    while out.len() < max {
        if !mem.read(a, &mut chunk) {
            // near the end of a mapping: byte by byte
            loop {
                let b = mem.u8(a)?;
                if b == 0 || out.len() >= max {
                    return String::from_utf8(out).ok();
                }
                out.push(b);
                a += 1;
            }
        }
        if let Some(z) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..z]);
            return String::from_utf8(out).ok();
        }
        out.extend_from_slice(&chunk);
        a += 64;
    }
    String::from_utf8(out).ok()
}

// ---------------------------------------------------------------------------------------------
// PE: UNWIND_INFO
// ---------------------------------------------------------------------------------------------

pub const UNW_FLAG_EHANDLER: u8 = 1;
pub const UNW_FLAG_UHANDLER: u8 = 2;
pub const UNW_FLAG_CHAININFO: u8 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindCode {
    pub offset: u8,
    pub op: u8,
    pub info: u8,
    /// the extra slots of the code (ALLOC_LARGE, SAVE_*), as one value
    pub operand: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindInfo {
    pub version: u8,
    pub flags: u8,
    pub prolog_size: u8,
    pub frame_reg: u8,
    pub frame_offset: u8,
    pub codes: Vec<UnwindCode>,
    /// language handler RVA (EHANDLER / UHANDLER)
    pub handler: Option<u32>,
    /// RVA of the handler's data right after the handler RVA
    pub handler_data: Option<u32>,
    /// the parent function of a chained entry
    pub chained: Option<RuntimeFunction>,
}

/// Number of 16-bit slots a code takes.
fn code_slots(op: u8, info: u8) -> usize {
    match op {
        1 => if info == 0 { 2 } else { 3 },
        4 | 8 => 2,
        5 | 9 => 3,
        // UWOP_EPILOG (v2) and the rest
        _ => 1,
    }
}

/// Parses the UNWIND_INFO at `base + rva`.
pub fn parse_unwind_info(mem: &(impl Memory + ?Sized), base: u64, rva: u32) -> Option<UnwindInfo> {
    let at = base + rva as u64;
    let hdr = mem.bytes(at, 4)?;
    let version = hdr[0] & 7;
    let flags = hdr[0] >> 3;
    if version != 1 && version != 2 {
        return None;
    }
    let count = hdr[2] as usize;
    let slots = mem.bytes(at + 4, count * 2)?;
    let slot = |i: usize| u16::from_le_bytes([slots[i * 2], slots[i * 2 + 1]]);
    let mut codes = Vec::new();
    let mut i = 0;
    while i < count {
        let (offset, b) = (slots[i * 2], slots[i * 2 + 1]);
        let (op, info) = (b & 0xf, b >> 4);
        let n = code_slots(op, info);
        if i + n > count {
            return None;
        }
        let operand = match (op, n) {
            (_, 2) => slot(i + 1) as u32,
            (_, 3) => slot(i + 1) as u32 | (slot(i + 2) as u32) << 16,
            _ => 0,
        };
        codes.push(UnwindCode { offset, op, info, operand });
        i += n;
    }
    let tail = at + 4 + (((count + 1) & !1) * 2) as u64;
    let (mut handler, mut handler_data, mut chained) = (None, None, None);
    if flags & UNW_FLAG_CHAININFO != 0 {
        let b = mem.bytes(tail, 12)?;
        chained = Some(RuntimeFunction {
            begin: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            end: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            unwind: u32::from_le_bytes(b[8..12].try_into().unwrap()),
        });
    } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        handler = Some(mem.u32(tail)?);
        handler_data = Some((tail + 4 - base) as u32);
    }
    Some(UnwindInfo { version, flags, prolog_size: hdr[1], frame_reg: hdr[3] & 0xf, frame_offset: hdr[3] >> 4, codes, handler, handler_data, chained })
}

/// Follows an indirect RUNTIME_FUNCTION (UnwindData with bit 0 set points at another entry).
fn resolve_unwind_rva(mem: &(impl Memory + ?Sized), base: u64, mut unwind: u32) -> Option<u32> {
    for _ in 0..4 {
        if unwind & 1 == 0 {
            return Some(unwind);
        }
        unwind = mem.u32(base + (unwind & !1) as u64 + 8)?;
    }
    None
}

/// `RtlVirtualUnwind` for one function: updates `regs` to the caller's registers.
pub fn pe_unwind(mem: &(impl Memory + ?Sized), base: u64, f: RuntimeFunction, pc: u64, regs: &mut Regs, top: bool) -> Option<()> {
    let mut func = f;
    let mut prolog_offset = pc.checked_sub(base + func.begin as u64)?;
    let mut first = true;
    let mut machine_frame = false;
    for _ in 0..32 {
        let info = parse_unwind_info(mem, base, resolve_unwind_rva(mem, base, func.unwind)?)?;
        let sets_fp = info.frame_reg != 0 && info.codes.iter().any(|c| c.op == 3 && (c.offset as u64) <= prolog_offset);
        let frame = if sets_fp { regs.gpr[info.frame_reg as usize]?.wrapping_sub(info.frame_offset as u64 * 16) } else { regs.gpr[RSP]? };
        // an epilog only exists in the primary function and only after its prolog; the top frame
        // is the only one that can be inside one (callers sit right after a call)
        if first && top && prolog_offset >= info.prolog_size as u64 && unwind_epilog(mem, pc, (base + f.begin as u64, base + f.end as u64), &info, regs).is_some() {
            return Some(());
        }
        for c in &info.codes {
            if (c.offset as u64) > prolog_offset {
                continue; // not executed yet
            }
            let rsp = regs.gpr[RSP]?;
            match c.op {
                0 => {
                    regs.gpr[c.info as usize] = Some(mem.u64(rsp)?);
                    regs.set(RSP, rsp + 8);
                }
                1 => {
                    let n = if c.info == 0 { c.operand as u64 * 8 } else { c.operand as u64 };
                    regs.set(RSP, rsp + n);
                }
                2 => regs.set(RSP, rsp + c.info as u64 * 8 + 8),
                3 => regs.set(RSP, frame),
                4 => regs.gpr[c.info as usize] = Some(mem.u64(frame + c.operand as u64 * 8)?),
                5 => regs.gpr[c.info as usize] = Some(mem.u64(frame + c.operand as u64)?),
                // XMM saves (we do not track vector registers) and the v2 epilog descriptors
                6 | 8 | 9 => {}
                10 => {
                    let mut sp = rsp;
                    if c.info != 0 {
                        sp += 8; // error code
                    }
                    regs.rip = mem.u64(sp)?;
                    regs.set(RSP, mem.u64(sp + 24)?);
                    machine_frame = true;
                }
                _ => return None,
            }
        }
        match info.chained {
            Some(parent) => {
                func = parent;
                prolog_offset = u64::MAX; // the parent's prolog ran completely
                first = false;
            }
            None => break,
        }
    }
    if !machine_frame {
        let rsp = regs.gpr[RSP]?;
        regs.rip = mem.u64(rsp)?;
        regs.set(RSP, rsp + 8);
    }
    Some(())
}

/// If `pc` sits in an epilog (`add rsp, n` | `lea rsp, [fp+n]`, pops, then `ret` or a tail-call
/// `jmp` out of the function), unwinds by executing it.
fn unwind_epilog(mem: &(impl Memory + ?Sized), pc: u64, func: (u64, u64), info: &UnwindInfo, regs: &mut Regs) -> Option<()> {
    let code = mem.bytes(pc, 48).or_else(|| mem.bytes(pc, 16))?;
    let mut i = 0usize;
    let mut sp = regs.gpr[RSP]?;
    let rex_w = |b: u8| b & 0xf8 == 0x48;
    // add rsp, imm8 / imm32
    if code.len() >= 4 && rex_w(code[0]) && code[0] & 1 == 0 && code[1] == 0x83 && code[2] == 0xc4 {
        sp = sp.wrapping_add(code[3] as i8 as i64 as u64);
        i = 4;
    } else if code.len() >= 7 && rex_w(code[0]) && code[0] & 1 == 0 && code[1] == 0x81 && code[2] == 0xc4 {
        sp = sp.wrapping_add(i32::from_le_bytes(code[3..7].try_into().unwrap()) as i64 as u64);
        i = 7;
    } else if code.len() >= 4 && rex_w(code[0]) && code[1] == 0x8d && (code[2] >> 3) & 7 == 4 {
        // lea rsp, [base + disp]
        if info.frame_reg == 0 {
            return None;
        }
        let modrm = code[2];
        let rm = (modrm & 7) as usize | if code[0] & 1 != 0 { 8 } else { 0 };
        if rm != info.frame_reg as usize || modrm & 7 == 4 {
            return None;
        }
        let basev = regs.gpr[rm]?;
        match modrm >> 6 {
            1 => {
                sp = basev.wrapping_add(code[3] as i8 as i64 as u64);
                i = 4;
            }
            2 if code.len() >= 7 => {
                sp = basev.wrapping_add(i32::from_le_bytes(code[3..7].try_into().unwrap()) as i64 as u64);
                i = 7;
            }
            _ => return None,
        }
    }
    let mut pops: Vec<usize> = Vec::new();
    loop {
        match code.get(i..) {
            Some([0x58..=0x5f, ..]) => {
                pops.push((code[i] - 0x58) as usize);
                i += 1;
            }
            Some([0x41, b @ 0x58..=0x5f, ..]) => {
                pops.push((*b - 0x58) as usize + 8);
                i += 2;
            }
            Some([0xc3, ..]) | Some([0xc2, _, _, ..]) | Some([0xf3, 0xc3, ..]) => break,
            // tail call: jmp rel32 / rel8 to outside the function, or jmp [rip+disp32]
            Some([0xe9, a, b, c, d, ..]) => {
                let to = (pc + i as u64 + 5).wrapping_add(i32::from_le_bytes([*a, *b, *c, *d]) as i64 as u64);
                if to >= func.0 && to < func.1 {
                    return None;
                }
                break;
            }
            Some([0xeb, d, ..]) => {
                let to = (pc + i as u64 + 2).wrapping_add(*d as i8 as i64 as u64);
                if to >= func.0 && to < func.1 {
                    return None;
                }
                break;
            }
            Some([0xff, 0x25, ..]) | Some([0x48, 0xff, 0x25, ..]) => break,
            _ => return None,
        }
    }
    let mut out = regs.clone();
    for r in pops {
        out.gpr[r] = Some(mem.u64(sp)?);
        sp += 8;
    }
    out.rip = mem.u64(sp)?;
    out.set(RSP, sp + 8);
    *regs = out;
    Some(())
}

// ---------------------------------------------------------------------------------------------
// ELF: .eh_frame_hdr / .eh_frame
// ---------------------------------------------------------------------------------------------

const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

const DW_EH_PE_OMIT: u8 = 0xff;

struct EhFrame {
    /// .eh_frame_hdr address (datarel base for its table)
    hdr: u64,
    table: Option<(u64, u64, u8)>, // (table address, count, encoding)
    eh_frame: u64,
    /// built on first use when there is no search table: (pc_begin, pc_end, fde)
    linear: std::cell::OnceCell<Vec<(u64, u64, u64)>>,
}

/// Reads an unsigned LEB128 at `*p`.
fn uleb(mem: &(impl Memory + ?Sized), p: &mut u64) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    loop {
        let b = mem.u8(*p)?;
        *p += 1;
        if shift < 64 {
            v |= ((b & 0x7f) as u64) << shift;
        }
        shift += 7;
        if b & 0x80 == 0 {
            return Some(v);
        }
        if shift > 70 {
            return None;
        }
    }
}

fn sleb(mem: &(impl Memory + ?Sized), p: &mut u64) -> Option<i64> {
    let mut v = 0i64;
    let mut shift = 0;
    loop {
        let b = mem.u8(*p)?;
        *p += 1;
        if shift < 64 {
            v |= ((b & 0x7f) as i64) << shift;
        }
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && b & 0x40 != 0 {
                v |= -1i64 << shift;
            }
            return Some(v);
        }
        if shift > 70 {
            return None;
        }
    }
}

/// Decodes a DW_EH_PE-encoded pointer at `*p`. `datarel` is the base for DW_EH_PE_datarel.
fn read_encoded(mem: &(impl Memory + ?Sized), p: &mut u64, enc: u8, datarel: u64) -> Option<u64> {
    if enc == DW_EH_PE_OMIT {
        return None;
    }
    let field = *p;
    let raw = match enc & 0x0f {
        0x00 => {
            *p += 8;
            mem.u64(field)?
        }
        0x01 => uleb(mem, p)?,
        0x02 => {
            *p += 2;
            mem.u16(field)? as u64
        }
        0x03 => {
            *p += 4;
            mem.u32(field)? as u64
        }
        0x04 => {
            *p += 8;
            mem.u64(field)?
        }
        0x09 => sleb(mem, p)? as u64,
        0x0a => {
            *p += 2;
            mem.u16(field)? as i16 as i64 as u64
        }
        0x0b => {
            *p += 4;
            mem.u32(field)? as i32 as i64 as u64
        }
        0x0c => {
            *p += 8;
            mem.u64(field)?
        }
        _ => return None,
    };
    let v = match enc & 0x70 {
        0x00 => raw,
        0x10 => raw.wrapping_add(field),
        0x30 => raw.wrapping_add(datarel),
        _ => return None, // textrel / funcrel / aligned: not used in .eh_frame on x86-64
    };
    if enc & 0x80 != 0 {
        return mem.u64(v);
    }
    Some(v)
}

impl EhFrame {
    fn locate(mem: &(impl Memory + ?Sized), base: u64) -> Option<EhFrame> {
        if mem.u8(base + 4)? != 2 {
            return None; // ELF64 only
        }
        let phoff = mem.u64(base + 0x20)?;
        let phentsize = mem.u16(base + 0x36)? as u64;
        let phnum = mem.u16(base + 0x38)? as u64;
        if phentsize < 56 || phnum > 256 {
            return None;
        }
        let mut lowest = u64::MAX;
        let mut eh = None;
        for i in 0..phnum {
            let ph = base + phoff + i * phentsize;
            let ty = mem.u32(ph)?;
            let vaddr = mem.u64(ph + 16)?;
            if ty == PT_LOAD {
                lowest = lowest.min(vaddr);
            } else if ty == PT_GNU_EH_FRAME {
                eh = Some(vaddr);
            }
        }
        let bias = base.wrapping_sub(if lowest == u64::MAX { 0 } else { lowest & !0xfff });
        let hdr = bias.wrapping_add(eh?);
        Self::from_hdr(mem, hdr)
    }

    fn from_hdr(mem: &(impl Memory + ?Sized), hdr: u64) -> Option<EhFrame> {
        let h = mem.bytes(hdr, 4)?;
        if h[0] != 1 {
            return None;
        }
        let mut p = hdr + 4;
        let eh_frame = read_encoded(mem, &mut p, h[1], hdr)?;
        let count = if h[2] == DW_EH_PE_OMIT { None } else { read_encoded(mem, &mut p, h[2], hdr) };
        let table = match count {
            // the search table is only usable in the common datarel|sdata4 encoding
            Some(n) if h[3] == 0x3b && n > 0 && n < 1 << 24 => Some((p, n, h[3])),
            _ => None,
        };
        Some(EhFrame { hdr, table, eh_frame, linear: std::cell::OnceCell::new() })
    }

    /// Address of the FDE whose range may contain `pc`.
    fn find(&self, mem: &(impl Memory + ?Sized), pc: u64) -> Option<u64> {
        if let Some((tab, n, _)) = self.table {
            let (mut lo, mut hi) = (0u64, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let loc = self.hdr.wrapping_add(mem.u32(tab + mid * 8)? as i32 as i64 as u64);
                if loc <= pc {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let i = lo.checked_sub(1)?;
            return Some(self.hdr.wrapping_add(mem.u32(tab + i * 8 + 4)? as i32 as i64 as u64));
        }
        let list = self.linear.get_or_init(|| linear_fdes(mem, self.eh_frame));
        let i = list.partition_point(|e| e.0 <= pc);
        let e = list.get(i.checked_sub(1)?)?;
        (pc < e.1).then_some(e.2)
    }
}

/// Every FDE of an .eh_frame without a search table (bounded).
fn linear_fdes(mem: &(impl Memory + ?Sized), start: u64) -> Vec<(u64, u64, u64)> {
    let mut out = Vec::new();
    let mut cies = HashMap::new();
    let mut p = start;
    for _ in 0..200_000 {
        let Some(len) = mem.u32(p) else { break };
        if len == 0 {
            break;
        }
        let (body, next) = if len == 0xffff_ffff {
            let Some(l) = mem.u64(p + 4) else { break };
            (p + 12, p + 12 + l)
        } else {
            (p + 4, p + 4 + len as u64)
        };
        if mem.u32(body).is_some_and(|id| id != 0) {
            if let Some(f) = parse_fde(mem, p, &mut cies) {
                out.push((f.pc_begin, f.pc_begin + f.pc_range, p));
            }
        }
        p = next;
    }
    out.sort();
    out
}

#[derive(Clone, Debug)]
struct Cie {
    code_align: u64,
    data_align: i64,
    ra_reg: u16,
    fde_enc: u8,
    lsda_enc: u8,
    signal: bool,
    has_aug_data: bool,
    insns: (u64, u64),
}

#[derive(Clone, Debug)]
struct Fde {
    cie: Cie,
    pc_begin: u64,
    pc_range: u64,
    insns: (u64, u64),
}

/// (body start, end) of the CIE/FDE record at `p`.
fn record(mem: &(impl Memory + ?Sized), p: u64) -> Option<(u64, u64, bool)> {
    let len = mem.u32(p)?;
    if len == 0 {
        return None;
    }
    if len == 0xffff_ffff {
        let l = mem.u64(p + 4)?;
        return Some((p + 12, p + 12 + l, true));
    }
    Some((p + 4, p + 4 + len as u64, false))
}

fn parse_cie(mem: &(impl Memory + ?Sized), at: u64) -> Option<Cie> {
    let (body, end, wide) = record(mem, at)?;
    let mut p = body;
    let id = if wide { mem.u64(p)? } else { mem.u32(p)? as u64 };
    p += if wide { 8 } else { 4 };
    if id != 0 {
        return None;
    }
    let version = mem.u8(p)?;
    p += 1;
    let aug = read_cstr(mem, p, 16)?;
    p += aug.len() as u64 + 1;
    if aug.contains("eh") {
        p += 8;
    }
    let code_align = uleb(mem, &mut p)?;
    let data_align = sleb(mem, &mut p)?;
    let ra_reg = if version == 1 {
        p += 1;
        mem.u8(p - 1)? as u16
    } else {
        uleb(mem, &mut p)? as u16
    };
    let mut cie = Cie { code_align, data_align, ra_reg, fde_enc: 0, lsda_enc: DW_EH_PE_OMIT, signal: false, has_aug_data: false, insns: (0, end) };
    if let Some(rest) = aug.strip_prefix('z') {
        cie.has_aug_data = true;
        let len = uleb(mem, &mut p)?;
        let data_end = p + len;
        for c in rest.chars() {
            match c {
                'R' => {
                    cie.fde_enc = mem.u8(p)?;
                    p += 1;
                }
                'L' => {
                    cie.lsda_enc = mem.u8(p)?;
                    p += 1;
                }
                'P' => {
                    let enc = mem.u8(p)?;
                    p += 1;
                    read_encoded(mem, &mut p, enc & 0x7f, 0)?; // personality (not needed)
                }
                'S' => cie.signal = true,
                'B' | 'G' => {}
                _ => break,
            }
        }
        p = data_end;
    } else if !aug.is_empty() {
        return None; // unknown augmentation without 'z': cannot skip it
    }
    cie.insns = (p, end);
    Some(cie)
}

fn parse_fde(mem: &(impl Memory + ?Sized), at: u64, cies: &mut HashMap<u64, Option<Cie>>) -> Option<Fde> {
    let (body, end, wide) = record(mem, at)?;
    let mut p = body;
    let ptr = if wide { mem.u64(p)? } else { mem.u32(p)? as u64 };
    if ptr == 0 {
        return None; // a CIE
    }
    let cie_at = p.checked_sub(ptr)?;
    p += if wide { 8 } else { 4 };
    let cie = cies.entry(cie_at).or_insert_with(|| parse_cie(mem, cie_at)).clone()?;
    let pc_begin = read_encoded(mem, &mut p, cie.fde_enc, 0)?;
    let pc_range = read_encoded(mem, &mut p, cie.fde_enc & 0x0f, 0)?;
    if cie.has_aug_data {
        let len = uleb(mem, &mut p)?;
        p += len;
    }
    Some(Fde { cie, pc_begin, pc_range, insns: (p, end) })
}

#[derive(Clone, Debug, PartialEq)]
enum Rule {
    Undefined,
    Same,
    Offset(i64),
    ValOffset(i64),
    Register(u16),
    Expr(u64, u64),
    ValExpr(u64, u64),
}

#[derive(Clone, Debug, PartialEq)]
enum CfaRule {
    RegOffset(u16, i64),
    Expr(u64, u64),
}

#[derive(Clone, Debug)]
struct Row {
    cfa: CfaRule,
    regs: [Rule; 17],
}

fn initial_row() -> Row {
    Row { cfa: CfaRule::RegOffset(7, 8), regs: std::array::from_fn(|_| Rule::Same) }
}

/// Runs the CIE's initial instructions, then the FDE's up to `pc`.
fn run_cfa(mem: &(impl Memory + ?Sized), fde: &Fde, pc: u64) -> Option<Row> {
    let mut row = initial_row();
    let mut loc = fde.pc_begin;
    exec_cfa(mem, &fde.cie, fde.cie.insns, &mut row, None, &mut loc, u64::MAX)?;
    let init = row.clone();
    exec_cfa(mem, &fde.cie, fde.insns, &mut row, Some(&init), &mut loc, pc)?;
    Some(row)
}

fn exec_cfa(mem: &(impl Memory + ?Sized), cie: &Cie, (start, end): (u64, u64), row: &mut Row, init: Option<&Row>, loc: &mut u64, pc: u64) -> Option<()> {
    let mut p = start;
    let mut stack: Vec<Row> = Vec::new();
    let set = |row: &mut Row, r: u64, rule: Rule| {
        if let Some(slot) = row.regs.get_mut(r as usize) {
            *slot = rule;
        }
    };
    let restore = |row: &mut Row, r: u64| {
        if let (Some(i), Some(slot)) = (init, row.regs.get_mut(r as usize)) {
            *slot = i.regs.get(r as usize).cloned().unwrap_or(Rule::Same);
        }
    };
    let mut steps = 0;
    while p < end {
        steps += 1;
        if steps > 100_000 {
            return None;
        }
        let op = mem.u8(p)?;
        p += 1;
        let advance = |loc: &mut u64, delta: u64| -> bool {
            *loc = loc.wrapping_add(delta.wrapping_mul(cie.code_align));
            *loc > pc
        };
        match op >> 6 {
            1 => {
                if advance(loc, (op & 0x3f) as u64) {
                    return Some(());
                }
                continue;
            }
            2 => {
                let off = uleb(mem, &mut p)? as i64 * cie.data_align;
                set(row, (op & 0x3f) as u64, Rule::Offset(off));
                continue;
            }
            3 => {
                restore(row, (op & 0x3f) as u64);
                continue;
            }
            _ => {}
        }
        match op {
            0x00 => {}
            0x01 => {
                *loc = read_encoded(mem, &mut p, cie.fde_enc, 0)?;
                if *loc > pc {
                    return Some(());
                }
            }
            0x02 => {
                let d = mem.u8(p)? as u64;
                p += 1;
                if advance(loc, d) {
                    return Some(());
                }
            }
            0x03 => {
                let d = mem.u16(p)? as u64;
                p += 2;
                if advance(loc, d) {
                    return Some(());
                }
            }
            0x04 => {
                let d = mem.u32(p)? as u64;
                p += 4;
                if advance(loc, d) {
                    return Some(());
                }
            }
            0x05 => {
                let r = uleb(mem, &mut p)?;
                let off = uleb(mem, &mut p)? as i64 * cie.data_align;
                set(row, r, Rule::Offset(off));
            }
            0x06 => {
                let r = uleb(mem, &mut p)?;
                restore(row, r);
            }
            0x07 => {
                let r = uleb(mem, &mut p)?;
                set(row, r, Rule::Undefined);
            }
            0x08 => {
                let r = uleb(mem, &mut p)?;
                set(row, r, Rule::Same);
            }
            0x09 => {
                let r = uleb(mem, &mut p)?;
                let r2 = uleb(mem, &mut p)?;
                set(row, r, Rule::Register(r2 as u16));
            }
            0x0a => stack.push(row.clone()),
            0x0b => {
                // restore_state keeps the current location
                let s = stack.pop()?;
                *row = s;
            }
            0x0c => {
                let r = uleb(mem, &mut p)?;
                let off = uleb(mem, &mut p)?;
                row.cfa = CfaRule::RegOffset(r as u16, off as i64);
            }
            0x0d => {
                let r = uleb(mem, &mut p)? as u16;
                row.cfa = match row.cfa {
                    CfaRule::RegOffset(_, off) => CfaRule::RegOffset(r, off),
                    _ => CfaRule::RegOffset(r, 0),
                };
            }
            0x0e => {
                let off = uleb(mem, &mut p)? as i64;
                if let CfaRule::RegOffset(r, _) = row.cfa {
                    row.cfa = CfaRule::RegOffset(r, off);
                }
            }
            0x0f => {
                let len = uleb(mem, &mut p)?;
                row.cfa = CfaRule::Expr(p, p + len);
                p += len;
            }
            0x10 | 0x16 => {
                let r = uleb(mem, &mut p)?;
                let len = uleb(mem, &mut p)?;
                set(row, r, if op == 0x10 { Rule::Expr(p, p + len) } else { Rule::ValExpr(p, p + len) });
                p += len;
            }
            0x11 => {
                let r = uleb(mem, &mut p)?;
                let off = sleb(mem, &mut p)? * cie.data_align;
                set(row, r, Rule::Offset(off));
            }
            0x12 => {
                let r = uleb(mem, &mut p)?;
                let off = sleb(mem, &mut p)? * cie.data_align;
                row.cfa = CfaRule::RegOffset(r as u16, off);
            }
            0x13 => {
                let off = sleb(mem, &mut p)? * cie.data_align;
                if let CfaRule::RegOffset(r, _) = row.cfa {
                    row.cfa = CfaRule::RegOffset(r, off);
                }
            }
            0x14 => {
                let r = uleb(mem, &mut p)?;
                let off = uleb(mem, &mut p)? as i64 * cie.data_align;
                set(row, r, Rule::ValOffset(off));
            }
            0x15 => {
                let r = uleb(mem, &mut p)?;
                let off = sleb(mem, &mut p)? * cie.data_align;
                set(row, r, Rule::ValOffset(off));
            }
            // DW_CFA_GNU_args_size
            0x2e => {
                uleb(mem, &mut p)?;
            }
            // DW_CFA_GNU_negative_offset_extended
            0x2f => {
                let r = uleb(mem, &mut p)?;
                let off = -(uleb(mem, &mut p)? as i64) * cie.data_align;
                set(row, r, Rule::Offset(off));
            }
            _ => return None,
        }
    }
    Some(())
}

/// A DWARF expression over the frame's registers. `push` is the initial stack (the CFA for
/// DW_CFA_expression).
fn eval_expr(mem: &(impl Memory + ?Sized), (start, end): (u64, u64), regs: &Regs, push: Option<u64>) -> Option<u64> {
    let mut st: Vec<u64> = push.into_iter().collect();
    let mut p = start;
    let mut steps = 0;
    macro_rules! pop {
        () => {
            st.pop()?
        };
    }
    while p < end {
        steps += 1;
        if steps > 10_000 || st.len() > 64 {
            return None;
        }
        let op = mem.u8(p)?;
        p += 1;
        match op {
            0x03 => {
                st.push(mem.u64(p)?);
                p += 8;
            }
            0x06 => {
                let a = pop!();
                st.push(mem.u64(a)?);
            }
            0x08 => {
                st.push(mem.u8(p)? as u64);
                p += 1;
            }
            0x09 => {
                st.push(mem.u8(p)? as i8 as i64 as u64);
                p += 1;
            }
            0x0a => {
                st.push(mem.u16(p)? as u64);
                p += 2;
            }
            0x0b => {
                st.push(mem.u16(p)? as i16 as i64 as u64);
                p += 2;
            }
            0x0c => {
                st.push(mem.u32(p)? as u64);
                p += 4;
            }
            0x0d => {
                st.push(mem.u32(p)? as i32 as i64 as u64);
                p += 4;
            }
            0x0e | 0x0f => {
                st.push(mem.u64(p)?);
                p += 8;
            }
            0x10 => st.push(uleb(mem, &mut p)?),
            0x11 => st.push(sleb(mem, &mut p)? as u64),
            0x12 => st.push(*st.last()?),
            0x13 => {
                pop!();
            }
            0x14 => st.push(*st.get(st.len().checked_sub(2)?)?),
            0x15 => {
                let i = mem.u8(p)? as usize;
                p += 1;
                st.push(*st.get(st.len().checked_sub(i + 1)?)?);
            }
            0x16 => {
                let n = st.len();
                if n < 2 {
                    return None;
                }
                st.swap(n - 1, n - 2);
            }
            0x17 => {
                let n = st.len();
                if n < 3 {
                    return None;
                }
                let top = st[n - 1];
                st[n - 1] = st[n - 2];
                st[n - 2] = st[n - 3];
                st[n - 3] = top;
            }
            0x19 => {
                let a = pop!() as i64;
                st.push(a.unsigned_abs());
            }
            0x1f => {
                let a = pop!();
                st.push((a as i64).wrapping_neg() as u64);
            }
            0x20 => {
                let a = pop!();
                st.push(!a);
            }
            0x23 => {
                let a = pop!();
                st.push(a.wrapping_add(uleb(mem, &mut p)?));
            }
            0x1a | 0x1b | 0x1c | 0x1d | 0x1e | 0x21 | 0x22 | 0x24 | 0x25 | 0x26 | 0x27 | 0x29..=0x2e => {
                let b = pop!();
                let a = pop!();
                st.push(match op {
                    0x1a => a & b,
                    0x1b => {
                        if b == 0 {
                            return None;
                        }
                        ((a as i64).wrapping_div(b as i64)) as u64
                    }
                    0x1c => a.wrapping_sub(b),
                    0x1d => {
                        if b == 0 {
                            return None;
                        }
                        a % b
                    }
                    0x1e => a.wrapping_mul(b),
                    0x21 => a | b,
                    0x22 => a.wrapping_add(b),
                    0x24 => a.checked_shl(b as u32).unwrap_or(0),
                    0x25 => a.checked_shr(b as u32).unwrap_or(0),
                    0x26 => ((a as i64) >> b.min(63)) as u64,
                    0x27 => a ^ b,
                    0x29 => (a == b) as u64,
                    0x2a => ((a as i64) >= (b as i64)) as u64,
                    0x2b => ((a as i64) > (b as i64)) as u64,
                    0x2c => ((a as i64) <= (b as i64)) as u64,
                    0x2d => ((a as i64) < (b as i64)) as u64,
                    _ => (a != b) as u64,
                });
            }
            0x28 => {
                let off = mem.u16(p)? as i16 as i64;
                p += 2;
                if pop!() != 0 {
                    p = p.wrapping_add(off as u64);
                }
            }
            0x2f => {
                let off = mem.u16(p)? as i16 as i64;
                p += 2;
                p = p.wrapping_add(off as u64);
            }
            0x30..=0x4f => st.push((op - 0x30) as u64),
            0x70..=0x8f => {
                let off = sleb(mem, &mut p)?;
                st.push(get_dwarf(regs, (op - 0x70) as u16)?.wrapping_add(off as u64));
            }
            0x92 => {
                let r = uleb(mem, &mut p)? as u16;
                let off = sleb(mem, &mut p)?;
                st.push(get_dwarf(regs, r)?.wrapping_add(off as u64));
            }
            0x96 => {}
            _ => return None,
        }
    }
    st.pop()
}

/// The caller's registers from a CFA row.
fn apply_row(mem: &(impl Memory + ?Sized), row: &Row, regs: &Regs, ra_reg: u16) -> Option<Regs> {
    let cfa = match row.cfa {
        CfaRule::RegOffset(r, off) => get_dwarf(regs, r)?.wrapping_add(off as u64),
        CfaRule::Expr(s, e) => eval_expr(mem, (s, e), regs, None)?,
    };
    let mut out = regs.clone();
    for (dw, rule) in row.regs.iter().enumerate() {
        let dw = dw as u16;
        let v = match rule {
            Rule::Same => continue,
            Rule::Undefined => {
                if dw == ra_reg {
                    return None; // outermost frame
                }
                if let Some(i) = dwarf_to_machine(dw).filter(|&i| i < 16) {
                    out.gpr[i] = None;
                }
                continue;
            }
            Rule::Offset(o) => mem.u64(cfa.wrapping_add(*o as u64)),
            Rule::ValOffset(o) => Some(cfa.wrapping_add(*o as u64)),
            Rule::Register(r) => get_dwarf(regs, *r),
            Rule::Expr(s, e) => eval_expr(mem, (*s, *e), regs, Some(cfa)).and_then(|a| mem.u64(a)),
            Rule::ValExpr(s, e) => eval_expr(mem, (*s, *e), regs, Some(cfa)),
        };
        if dw == ra_reg {
            out.rip = v?;
        } else if let Some(i) = dwarf_to_machine(dw).filter(|&i| i < 16) {
            out.gpr[i] = v;
        }
    }
    if matches!(row.regs.get(ra_reg as usize), Some(Rule::Same) | None) {
        // no rule for the return address: it is the register itself (unusual; keep going)
        out.rip = get_dwarf(regs, ra_reg)?;
    }
    out.set(RSP, cfa);
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------------------------

/// Nearest-preceding-symbol lookup over (address, size, name) tuples, absolute addresses.
#[derive(Default)]
pub struct Symbols {
    list: Vec<(u64, u64, String)>,
}

impl Symbols {
    pub fn new(mut list: Vec<(u64, u64, String)>) -> Self {
        list.sort_by_key(|s| s.0);
        Symbols { list }
    }
    pub fn add(&mut self, more: impl IntoIterator<Item = (u64, u64, String)>) {
        self.list.extend(more);
        self.list.sort_by_key(|s| s.0);
    }
    /// Nearest symbol at or below `addr`, within its size (or `slack` bytes when the size is 0) and
    /// inside `[lo, hi)`.
    pub fn lookup(&self, addr: u64, lo: u64, hi: u64, slack: u64) -> Option<(String, u64)> {
        let i = self.list.partition_point(|s| s.0 <= addr);
        let (a, size, name) = self.list.get(i.checked_sub(1)?)?;
        if *a < lo || *a >= hi {
            return None;
        }
        let d = addr - a;
        let limit = if *size > 0 { *size } else { slack };
        (d < limit.max(1)).then(|| (name.clone(), d))
    }
}

/// Fills `frame.symbol` from `syms` (absolute addresses) and PE exports read from memory.
pub fn symbolize<M: Memory + ?Sized>(un: &mut Unwinder<'_, M>, frames: &mut [Frame], syms: &Symbols, export_cache: &mut HashMap<u64, Symbols>) {
    for f in frames.iter_mut() {
        let Some(m) = un.module_of(f.pc).cloned() else { continue };
        let lookup = if f.method == Method::Context { f.pc } else { f.pc.saturating_sub(1) };
        // function bounds from .pdata make export lookups exact for PE
        let func = un.pe_function(lookup).map(|(b, rf)| (b + rf.begin as u64, b + rf.end as u64));
        if let Some((name, d)) = syms.lookup(lookup, m.base, m.base + m.size, 1 << 20) {
            f.symbol = Some((name, d + (f.pc - lookup)));
            continue;
        }
        let mem = un.mem;
        let ex = export_cache.entry(m.base).or_insert_with(|| {
            Symbols::new(pe_exports(mem, m.base).into_iter().map(|(rva, n)| (m.base + rva, 0, n)).collect())
        });
        let slack = func.map(|(b, e)| if b <= lookup { e - b } else { 0 }).unwrap_or(1 << 16);
        if let Some((name, d)) = ex.lookup(lookup, func.map(|x| x.0).unwrap_or(m.base), m.base + m.size, slack) {
            f.symbol = Some((name, d + (f.pc - lookup)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- PE fixture builder -----------------------------------------------------------------

    /// A mapped PE32+ image at `base`: headers, `.text` at 0x1000, `.pdata`, `.xdata` at 0x3000.
    struct PeFix {
        img: Vec<u8>,
        pdata: Vec<RuntimeFunction>,
        xdata_at: u32,
    }

    impl PeFix {
        fn new(code: &[(u32, &[u8])]) -> Self {
            let mut img = vec![0u8; 0x6000];
            img[0] = b'M';
            img[1] = b'Z';
            img[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            img[0x80..0x84].copy_from_slice(&0x4550u32.to_le_bytes());
            img[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
            let oh = 0x98;
            img[oh..oh + 2].copy_from_slice(&0x20bu16.to_le_bytes());
            img[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes());
            for (rva, bytes) in code {
                img[*rva as usize..*rva as usize + bytes.len()].copy_from_slice(bytes);
            }
            PeFix { img, pdata: Vec::new(), xdata_at: 0x3000 }
        }

        /// Adds UNWIND_INFO (codes as raw 16-bit slots) and returns its RVA.
        fn xdata(&mut self, flags: u8, prolog: u8, frame: (u8, u8), slots: &[u16], tail: &[u8]) -> u32 {
            let at = self.xdata_at as usize;
            self.img[at] = 1 | flags << 3;
            self.img[at + 1] = prolog;
            self.img[at + 2] = slots.len() as u8;
            self.img[at + 3] = frame.0 | frame.1 << 4;
            for (i, s) in slots.iter().enumerate() {
                self.img[at + 4 + i * 2..at + 6 + i * 2].copy_from_slice(&s.to_le_bytes());
            }
            let t = at + 4 + ((slots.len() + 1) & !1) * 2;
            self.img[t..t + tail.len()].copy_from_slice(tail);
            self.xdata_at = ((t + tail.len() + 3) & !3) as u32;
            at as u32
        }

        fn func(&mut self, begin: u32, end: u32, unwind: u32) {
            self.pdata.push(RuntimeFunction { begin, end, unwind });
        }

        fn build(mut self) -> Vec<u8> {
            let at = 0x2000usize;
            for (i, f) in self.pdata.iter().enumerate() {
                let o = at + i * 12;
                self.img[o..o + 4].copy_from_slice(&f.begin.to_le_bytes());
                self.img[o + 4..o + 8].copy_from_slice(&f.end.to_le_bytes());
                self.img[o + 8..o + 12].copy_from_slice(&f.unwind.to_le_bytes());
            }
            let dir = 0x98 + 112 + 3 * 8;
            self.img[dir..dir + 4].copy_from_slice(&(at as u32).to_le_bytes());
            self.img[dir + 4..dir + 8].copy_from_slice(&((self.pdata.len() * 12) as u32).to_le_bytes());
            self.img
        }
    }

    /// UWOP slot: (prolog offset, op, info)
    fn op(off: u8, op: u8, info: u8) -> u16 {
        off as u16 | ((op | info << 4) as u16) << 8
    }

    const BASE: u64 = 0x1_4000_0000;
    const STACK: u64 = 0x7000_0000;

    fn stack(words: &[u64]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    fn modules() -> Vec<ModuleInfo> {
        vec![ModuleInfo { name: "game.exe".into(), base: BASE, size: 0x6000 }]
    }

    #[test]
    fn pe_push_alloc_and_save_nonvol() {
        // func A (0x1000..0x1100): push rbx; push rsi; sub rsp, 0x28; mov [rsp+0x48], rdi
        // codes (reverse prolog order): SAVE_NONVOL rdi @0x40/8, ALLOC_SMALL 0x28, PUSH rsi, PUSH rbx
        let mut fx = PeFix::new(&[(0x1000, &[0x53, 0x56, 0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0x7c, 0x24, 0x48, 0x90, 0x90]), (0x1200, &[0xe8, 0, 0, 0, 0, 0x90])]);
        let x = fx.xdata(0, 11, (0, 0), &[op(11, 4, RDI as u8), 9, op(6, 2, 4), op(2, 0, RSI as u8), op(1, 0, RBX as u8)], &[]);
        fx.func(0x1000, 0x1100, x);
        let img = fx.build();
        // stack at the body (rsp after the prolog): 0x28 alloc, then rsi, rbx, return address
        let mut st = vec![0u64; 5];
        st.extend([0x5151, 0xb0b0, BASE + 0x1205, 0, 0xd1d1]);
        let mem = Regions(vec![(BASE, img), (STACK, stack(&st))]);
        let mut un = Unwinder::new(&mem, modules());
        let regs = Regs::new(BASE + 0x1050, STACK, 0x1234);
        let (r, m, g, _) = un.step(&regs, true, true).unwrap();
        assert_eq!((m, g), (Method::Pdata, false));
        assert_eq!(r.rip, BASE + 0x1205);
        assert_eq!(r.rsp(), STACK + 0x40);
        assert_eq!(r.gpr[RSI], Some(0x5151));
        assert_eq!(r.gpr[RBX], Some(0xb0b0));
        assert_eq!(r.gpr[RDI], Some(0xd1d1), "SAVE_NONVOL reads frame + 0x48");
        assert_eq!(r.gpr[RBP], Some(0x1234), "untouched registers survive");

        // inside the prolog after `push rbx; push rsi` only: the alloc and the save are skipped
        let mem2 = Regions(vec![(BASE, mem.0[0].1.clone()), (STACK, stack(&[0x5151, 0xb0b0, BASE + 0x1205]))]);
        let mut un2 = Unwinder::new(&mem2, modules());
        let (r2, ..) = un2.step(&Regs::new(BASE + 0x1002, STACK, 0), true, true).unwrap();
        assert_eq!(r2.rip, BASE + 0x1205);
        assert_eq!(r2.rsp(), STACK + 0x18);
        assert_eq!(r2.gpr[RDI], None);
    }

    #[test]
    fn pe_alloc_large_frame_register_and_chain() {
        // parent (0x1000..0x1040): push rbp; sub rsp, 0x1000 (ALLOC_LARGE info 0, /8); lea rbp, [rsp+0x20]
        let mut fx = PeFix::new(&[(0x1000, &[0x90; 0x80])]);
        let parent = fx.xdata(0, 13, (RBP as u8, 2), &[op(13, 3, 0), op(8, 1, 0), 0x1000 / 8, op(1, 0, RBP as u8)], &[]);
        fx.func(0x1000, 0x1040, parent);
        // chained fragment (0x1040..0x1080): saved r12 with SAVE_NONVOL_FAR at frame+0x10008? keep near: push r12
        let mut chain_tail = Vec::new();
        chain_tail.extend_from_slice(&0x1000u32.to_le_bytes());
        chain_tail.extend_from_slice(&0x1040u32.to_le_bytes());
        chain_tail.extend_from_slice(&parent.to_le_bytes());
        let frag = fx.xdata(UNW_FLAG_CHAININFO, 2, (0, 0), &[op(2, 0, 12)], &chain_tail);
        fx.func(0x1040, 0x1080, frag);
        let img = fx.build();
        // rsp in the fragment body; frame: [r12][alloc 0x1000][rbp][ret]
        let mut st = vec![0xc12u64];
        st.extend(std::iter::repeat_n(0, 0x1000 / 8));
        st.extend([0xbbbb, BASE + 0x1000 + 0x70]);
        let mem = Regions(vec![(BASE, img), (STACK, stack(&st))]);
        let mut un = Unwinder::new(&mem, modules());
        // rbp = (rsp after alloc) + 0x20
        let rsp_body = STACK;
        let regs = Regs::new(BASE + 0x1050, rsp_body, rsp_body + 8 + 0x20);
        let (r, m, ..) = un.step(&regs, true, true).unwrap();
        assert_eq!(m, Method::Pdata);
        assert_eq!(r.gpr[12], Some(0xc12));
        assert_eq!(r.gpr[RBP], Some(0xbbbb));
        assert_eq!(r.rip, BASE + 0x1070);
        assert_eq!(r.rsp(), STACK + 8 + 0x1000 + 16);
    }

    #[test]
    fn pe_machine_frame_and_epilog() {
        // an interrupt handler: PUSH_MACHFRAME with error code
        let mut fx = PeFix::new(&[(0x1000, &[0x90; 0x10]), (0x1100, &[0x48, 0x83, 0xc4, 0x28, 0x5b, 0x41, 0x5c, 0xc3])]);
        let x = fx.xdata(0, 0, (0, 0), &[op(0, 10, 1)], &[]);
        fx.func(0x1000, 0x1010, x);
        // a function whose epilog is `add rsp, 0x28; pop rbx; pop r12; ret`
        let y = fx.xdata(0, 6, (0, 0), &[op(6, 2, 4), op(2, 0, 12), op(1, 0, RBX as u8)], &[]);
        fx.func(0x1100 - 0x40, 0x1110, y);
        let img = fx.build();
        let mem = Regions(vec![(BASE, img.clone()), (STACK, stack(&[0xe, BASE + 0x1234, 0x33, 0x246, STACK + 0x800, 0x2b]))]);
        let mut un = Unwinder::new(&mem, modules());
        let (r, ..) = un.step(&Regs::new(BASE + 0x1004, STACK, 0), true, true).unwrap();
        assert_eq!(r.rip, BASE + 0x1234);
        assert_eq!(r.rsp(), STACK + 0x800);

        let mut st = vec![0u64; 5];
        st.extend([0xb, 0xc, BASE + 0x1300]);
        let mem = Regions(vec![(BASE, img), (STACK, stack(&st))]);
        let mut un = Unwinder::new(&mem, modules());
        let (r, ..) = un.step(&Regs::new(BASE + 0x1100, STACK, 0), true, true).unwrap();
        assert_eq!((r.rip, r.rsp(), r.gpr[RBX], r.gpr[12]), (BASE + 0x1300, STACK + 0x40, Some(0xb), Some(0xc)));
        // at the `pop r12`: rbx is already restored, only r12 and the return remain
        let mem = Regions(vec![(BASE, mem.0[0].1.clone()), (STACK, stack(&[0xc, BASE + 0x1300]))]);
        let mut un = Unwinder::new(&mem, modules());
        let (r, ..) = un.step(&Regs::new(BASE + 0x1105, STACK, 0), true, true).unwrap();
        assert_eq!((r.rip, r.gpr[12]), (BASE + 0x1300, Some(0xc)));
    }

    #[test]
    fn pe_leaf_and_handlers_and_walk() {
        // main (0x1000..0x1080) calls leaf at 0x1100 (no pdata) from 0x1010; main: sub rsp, 0x28
        let mut code = vec![0x90u8; 0x80];
        code[0x0b] = 0xe8; // call at 0x100b..0x1010
        let mut fx = PeFix::new(&[(0x1000, &code), (0x1100, &[0xc3])]);
        let mut tail = 0x1500u32.to_le_bytes().to_vec();
        tail.extend_from_slice(&1u32.to_le_bytes()); // scope count
        tail.extend_from_slice(&[0x08, 0x10, 0, 0, 0x20, 0x10, 0, 0, 0x01, 0, 0, 0, 0x30, 0x10, 0, 0]);
        let x = fx.xdata(UNW_FLAG_EHANDLER, 4, (0, 0), &[op(4, 2, 4)], &tail);
        fx.func(0x1000, 0x1080, x);
        let img = fx.build();
        let info = parse_unwind_info(&Flat { base: BASE, data: &img }, BASE, x).unwrap();
        assert_eq!(info.handler, Some(0x1500));
        assert_eq!(info.handler_data, Some(x + 4 + 2 + 2 + 4));
        assert_eq!(info.codes, vec![UnwindCode { offset: 4, op: 2, info: 4, operand: 0 }]);

        let st = stack(&[BASE + 0x1010, 0, 0, 0, 0, 0, 0x7777_0000]);
        let mem = Regions(vec![(BASE, img), (STACK, st)]);
        let mut un = Unwinder::new(&mem, modules());
        let frames = un.walk(&Regs::new(BASE + 0x1100, STACK, 0), 16);
        assert_eq!(frames[0].method, Method::Context);
        assert_eq!((frames[1].pc, frames[1].method, frames[1].guessed), (BASE + 0x1010, Method::Leaf, false));
        assert_eq!(frames[1].module.as_deref(), Some("game.exe"));
        assert_eq!(frames[1].offset, 0x1010);
        // main unwinds to 0x77770000, outside every module: the walk stops after it
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[2].pc, 0x7777_0000);
    }

    #[test]
    fn fallback_frame_pointer_then_scan_is_guessed() {
        // no modules with unwind data: a JIT-like region with `call` sites
        let mut code = vec![0x90u8; 0x100];
        code[0x40 - 5] = 0xe8;
        code[0x80 - 5] = 0xe8;
        let jit = 0x5000_0000u64;
        let mods = vec![ModuleInfo { name: "jit".into(), base: jit, size: 0x100 }];
        // rbp chain: [rbp] = next rbp, [rbp+8] = jit+0x40
        let st = stack(&[0, 0, STACK + 0x20, jit + 0x40, 0, 0, 0, jit + 0x80, 0]);
        let mem = Regions(vec![(jit, code), (STACK, st)]);
        let mut un = Unwinder::new(&mem, mods);
        let frames = un.walk(&Regs::new(jit + 0x10, STACK, STACK + 0x10), 8);
        assert_eq!((frames[1].pc, frames[1].method, frames[1].guessed), (jit + 0x40, Method::FramePointer, true));
        assert_eq!(frames[1].sp, STACK + 0x20);
        // next rbp = STACK+0x20 → [STACK+0x20]=0 is no frame; scan finds jit+0x80 at STACK+0x38
        assert_eq!((frames[2].pc, frames[2].method, frames[2].guessed), (jit + 0x80, Method::Scan, true));
        assert_eq!(frames.len(), 3);
    }

    #[test]
    fn exports_and_symbolize() {
        let mut fx = PeFix::new(&[(0x1000, &[0x90; 0x40])]);
        let x = fx.xdata(0, 0, (0, 0), &[], &[]);
        fx.func(0x1000, 0x1040, x);
        fx.func(0x1040, 0x1080, x);
        let mut img = fx.build();
        // export directory at 0x4000: one function "Tick" at 0x1000
        let d = 0x4000usize;
        let put = |img: &mut Vec<u8>, o: usize, v: u32| img[o..o + 4].copy_from_slice(&v.to_le_bytes());
        put(&mut img, d + 20, 1);
        put(&mut img, d + 24, 1);
        put(&mut img, d + 28, 0x4100);
        put(&mut img, d + 32, 0x4110);
        put(&mut img, d + 36, 0x4120);
        put(&mut img, 0x4100, 0x1000);
        put(&mut img, 0x4110, 0x4130);
        img[0x4120] = 0;
        img[0x4130..0x4135].copy_from_slice(b"Tick\0");
        let dir = 0x98 + 112;
        put(&mut img, dir, 0x4000);
        put(&mut img, dir + 4, 0x200);
        let mem = Flat { base: BASE, data: &img };
        assert_eq!(pe_exports(&mem, BASE), vec![(0x1000, "Tick".to_string())]);
        let mut un = Unwinder::new(&mem, modules());
        let mut frames = vec![Frame { pc: BASE + 0x1010, sp: 0, method: Method::Pdata, guessed: false, module: None, offset: 0, symbol: None }];
        symbolize(&mut un, &mut frames, &Symbols::default(), &mut HashMap::new());
        assert_eq!(frames[0].symbol, Some(("Tick".into(), 0x10)));
        // in the next function (per .pdata) the export does not apply
        frames[0].pc = BASE + 0x1050;
        frames[0].symbol = None;
        symbolize(&mut un, &mut frames, &Symbols::default(), &mut HashMap::new());
        assert_eq!(frames[0].symbol, None);
    }

    /// Lays a PE file out by section (RVA-indexed), like the loader.
    fn map_pe(file: &[u8]) -> Vec<u8> {
        let rd32 = |o: usize| u32::from_le_bytes(file[o..o + 4].try_into().unwrap()) as usize;
        let rd16 = |o: usize| u16::from_le_bytes(file[o..o + 2].try_into().unwrap()) as usize;
        let nt = rd32(0x3c);
        let (nsec, opt) = (rd16(nt + 6), rd16(nt + 20));
        let mut img = vec![0u8; rd32(nt + 24 + 56)];
        let hdr = rd32(nt + 24 + 60);
        img[..hdr].copy_from_slice(&file[..hdr]);
        for i in 0..nsec {
            let s = nt + 24 + opt + i * 40;
            let (va, raw_size, raw) = (rd32(s + 12), rd32(s + 16), rd32(s + 20));
            let n = raw_size.min(file.len().saturating_sub(raw)).min(img.len() - va);
            img[va..va + n].copy_from_slice(&file[raw..raw + n]);
        }
        img
    }

    /// clang/lld output (src/lib/analysis/fixtures/fix-seh.exe, see fix-seh.c):
    /// guarded @0x1010: push rbp; push rsi; sub rsp, 0x28; lea rbp, [rsp+0x20] (frame register),
    /// epilog @0x1047: add rsp, 0x28; pop rsi; pop rbp; ret
    /// mainCRTStartup @0x10a0: sub rsp, 0x28; call [GetTickCount]; mov ecx, eax; add rsp, 0x28; jmp guarded
    #[test]
    fn pe_real_compiler_output() {
        let img = map_pe(include_bytes!("../../../src/lib/analysis/fixtures/fix-seh.exe"));
        assert_eq!(read_pdata(&Flat { base: BASE, data: &img }, BASE).unwrap().len(), 3);
        let s = STACK;
        // body of guarded (return address of the GetTickCount call), rbp = frame + 0x20
        let mut st = vec![0u64; 5];
        st.extend([0x5151, 0xbbbb, BASE + 0x2000_0000]);
        let mem = Regions(vec![(BASE, img.clone()), (s, stack(&st))]);
        let mods = vec![ModuleInfo { name: "fix-seh.exe".into(), base: BASE, size: img.len() as u64 }];
        let mut un = Unwinder::new(&mem, mods.clone());
        let (r, m, ..) = un.step(&Regs::new(BASE + 0x102a, s, s + 0x20), false, false).unwrap();
        assert_eq!((m, r.rip, r.rsp(), r.gpr[RSI], r.gpr[RBP]), (Method::Pdata, BASE + 0x2000_0000, s + 0x40, Some(0x5151), Some(0xbbbb)));
        // rsp moved by the callee? the frame register still finds the frame
        let (r, ..) = un.step(&Regs::new(BASE + 0x102a, s - 0x100, s + 0x20), false, false).unwrap();
        assert_eq!(r.rsp(), s + 0x40);
        // top frame stopped on the epilog's `add rsp, 0x28`
        let (r, ..) = un.step(&Regs::new(BASE + 0x1047, s, 0), true, true).unwrap();
        assert_eq!((r.rip, r.gpr[RSI], r.gpr[RBP]), (BASE + 0x2000_0000, Some(0x5151), Some(0xbbbb)));
        // mainCRTStartup at its tail-call jmp: the stack is already released
        let mem = Regions(vec![(BASE, img), (s, stack(&[BASE + 0x3000_0000]))]);
        let mut un = Unwinder::new(&mem, mods);
        let (r, ..) = un.step(&Regs::new(BASE + 0x10b0, s, 0), true, true).unwrap();
        assert_eq!((r.rip, r.rsp()), (BASE + 0x3000_0000, s + 8));
    }

    // ---- ELF / CFI fixtures -----------------------------------------------------------------

    fn uleb_enc(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    /// An ELF64 image at `base`: header, PT_LOAD, PT_GNU_EH_FRAME → .eh_frame_hdr at 0x800, a CIE
    /// and the given FDEs (pc range, instructions) in .eh_frame at 0x900, code at 0x1000.
    fn elf_image(fdes: &[(u32, u32, Vec<u8>)], with_table: bool, cie_insns: &[u8], aug: &str) -> Vec<u8> {
        let mut img = vec![0u8; 0x3000];
        img[0..4].copy_from_slice(b"\x7fELF");
        img[4] = 2;
        img[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        img[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        img[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes());
        let ph = |img: &mut Vec<u8>, i: usize, ty: u32, vaddr: u64| {
            let o = 0x40 + i * 56;
            img[o..o + 4].copy_from_slice(&ty.to_le_bytes());
            img[o + 16..o + 24].copy_from_slice(&vaddr.to_le_bytes());
        };
        ph(&mut img, 0, PT_LOAD, 0);
        ph(&mut img, 1, PT_GNU_EH_FRAME, 0x800);
        // .eh_frame
        let mut eh = Vec::new();
        let mut cie = vec![0, 0, 0, 0, 1];
        cie.extend_from_slice(aug.as_bytes());
        cie.push(0);
        uleb_enc(1, &mut cie); // code align
        cie.push(0x78); // data align -8
        cie.push(16); // RA
        if aug.starts_with('z') {
            cie.push(1); // aug data length
            cie.push(0x1b); // FDE encoding pcrel|sdata4
        }
        cie.extend_from_slice(cie_insns);
        while (cie.len() + 4) % 8 != 0 {
            cie.push(0);
        }
        eh.extend_from_slice(&(cie.len() as u32).to_le_bytes());
        eh.extend_from_slice(&cie);
        let mut fde_offs = Vec::new();
        for (begin, len, insns) in fdes {
            let at = eh.len();
            fde_offs.push((*begin, at));
            let mut f = Vec::new();
            f.extend_from_slice(&((at + 4) as u32).to_le_bytes()); // CIE pointer: back to offset 0
            let field = 0x900 + at + 8;
            f.extend_from_slice(&((*begin as i64 - field as i64) as i32).to_le_bytes());
            f.extend_from_slice(&len.to_le_bytes());
            if aug.starts_with('z') {
                f.push(0);
            }
            f.extend_from_slice(insns);
            while (f.len() + 4) % 8 != 0 {
                f.push(0);
            }
            eh.extend_from_slice(&(f.len() as u32).to_le_bytes());
            eh.extend_from_slice(&f);
        }
        eh.extend_from_slice(&[0, 0, 0, 0]);
        img[0x900..0x900 + eh.len()].copy_from_slice(&eh);
        // .eh_frame_hdr
        let mut h = vec![1, 0x1b, if with_table { 0x03 } else { 0xff }, 0x3b];
        h.extend_from_slice(&(0x900i32 - 0x804).to_le_bytes());
        if with_table {
            h.extend_from_slice(&(fdes.len() as u32).to_le_bytes());
            let mut sorted = fde_offs.clone();
            sorted.sort();
            for (begin, at) in sorted {
                h.extend_from_slice(&((begin as i64 - 0x800) as i32).to_le_bytes());
                h.extend_from_slice(&((0x900 + at) as i32 - 0x800).to_le_bytes());
            }
        }
        img[0x800..0x800 + h.len()].copy_from_slice(&h);
        img
    }

    const ELF_BASE: u64 = 0x5555_0000_0000;

    /// Standard CIE: CFA = rsp+8, RA at CFA-8
    const CIE: &[u8] = &[0x0c, 7, 8, 0x90, 1];

    fn elf_mods() -> Vec<ModuleInfo> {
        vec![ModuleInfo { name: "a.out".into(), base: ELF_BASE, size: 0x3000 }]
    }

    #[test]
    fn cfi_push_rbp_frame() {
        // f at 0x1000: push rbp (1 byte); mov rbp, rsp (3 bytes); ...
        // DW_CFA_advance_loc 1; def_cfa_offset 16; offset rbp, 2 (cfa-16); advance 3; def_cfa_register rbp
        let f = vec![0x41, 0x0e, 16, 0x86, 2, 0x43, 0x0d, 6];
        // g at 0x1100: sub rsp, 0x18 after 4 bytes; remember/restore around an epilog
        let g = vec![0x44, 0x0e, 0x20, 0x0a, 0x48, 0x0e, 8, 0x41, 0x0b];
        for table in [true, false] {
            let img = elf_image(&[(0x1000, 0x80, f.clone()), (0x1100, 0x40, g.clone())], table, CIE, "zR");
            let st = stack(&[0x11, 0x22, 0x33, ELF_BASE + 0x1010, 0x44]);
            let mem = Regions(vec![(ELF_BASE, img), (STACK, st)]);
            let mut un = Unwinder::new(&mem, elf_mods());
            // in f's body: rbp = STACK + 0x10 (saved rbp at STACK+0x10, RA at +0x18)
            let regs = Regs::new(ELF_BASE + 0x1020, STACK + 0x8, STACK + 0x10);
            let (r, m, g2, sig) = un.step(&regs, true, true).unwrap();
            assert_eq!((m, g2, sig), (Method::Cfi, false, false));
            assert_eq!(r.rip, ELF_BASE + 0x1010);
            assert_eq!(r.gpr[RBP], Some(0x33));
            assert_eq!(r.rsp(), STACK + 0x20);
            // at f+0 (before push): CFA = rsp+8
            let (r, ..) = un.step(&Regs::new(ELF_BASE + 0x1000, STACK + 0x18, 7), true, true).unwrap();
            assert_eq!((r.rip, r.rsp(), r.gpr[RBP]), (ELF_BASE + 0x1010, STACK + 0x20, Some(7)));
            // g after the restore_state (offset 0x0d): CFA back to rsp+0x20
            let (r, ..) = un.step(&Regs::new(ELF_BASE + 0x110d, STACK, 0), true, true).unwrap();
            assert_eq!((r.rip, r.rsp()), (ELF_BASE + 0x1010, STACK + 0x20));
            // g inside the epilog window (offset 0x0c): CFA = rsp+8
            let (r, ..) = un.step(&Regs::new(ELF_BASE + 0x110c, STACK + 0x10, 0), true, true).unwrap();
            assert_eq!(r.rip, 0x33);
        }
    }

    #[test]
    fn cfi_expression_cfa_like_plt() {
        // PLT: CFA = rsp + 8 + ((rip & 15) >= 11) * 8
        let expr = [0x77, 8, 0x80, 0, 0x3f, 0x1a, 0x3b, 0x2a, 0x33, 0x24, 0x22];
        let mut ins = vec![0x0f, expr.len() as u8];
        ins.extend_from_slice(&expr);
        let img = elf_image(&[(0x1000, 0x20, ins)], true, CIE, "zR");
        let st = stack(&[ELF_BASE + 0x1500, ELF_BASE + 0x1600, 0]);
        let mem = Regions(vec![(ELF_BASE, img), (STACK, st)]);
        let mut un = Unwinder::new(&mem, elf_mods());
        let (r, ..) = un.step(&Regs::new(ELF_BASE + 0x1004, STACK, 0), true, true).unwrap();
        assert_eq!(r.rip, ELF_BASE + 0x1500);
        let (r, ..) = un.step(&Regs::new(ELF_BASE + 0x100c, STACK, 0), true, true).unwrap();
        assert_eq!(r.rip, ELF_BASE + 0x1600, "(rip & 15) >= 11 pushed one more slot");
        assert_eq!(r.rsp(), STACK + 16);
    }

    #[test]
    fn cfi_undefined_ra_ends_and_signal_frame() {
        // _start: DW_CFA_undefined rip
        let img = elf_image(&[(0x1000, 0x10, vec![0x07, 16])], true, CIE, "zR");
        let mem = Regions(vec![(ELF_BASE, img), (STACK, stack(&[0, 0]))]);
        let mut un = Unwinder::new(&mem, elf_mods());
        let frames = un.walk(&Regs::new(ELF_BASE + 0x1004, STACK, 0), 8);
        assert_eq!(frames.len(), 1, "RA undefined: outermost frame, and no guessing past it");

        // signal trampoline: CFA = [rsp + 0xa0] style expression: rip at rsp+0xa8 via DW_CFA_expression
        // (here: CFA = rsp + 0x10; rip = *(rsp + 0x8) through an expression on the CFA)
        let ins = vec![0x0c, 7, 0x10, 0x10, 16, 2, 0x77, 8];
        let img = elf_image(&[(0x1000, 0x10, ins)], true, CIE, "zRS");
        let mem = Regions(vec![(ELF_BASE, img), (STACK, stack(&[0, ELF_BASE + 0x1008, 0]))]);
        let mut un = Unwinder::new(&mem, elf_mods());
        let (r, _, _, signal) = un.step(&Regs::new(ELF_BASE + 0x1004, STACK, 0), true, true).unwrap();
        assert!(signal);
        assert_eq!(r.rip, ELF_BASE + 0x1008);
        assert_eq!(r.rsp(), STACK + 0x10);
    }

    #[test]
    fn leb_and_encodings() {
        let data = [0xe5, 0x8e, 0x26, 0x7f, 0x80, 0x7f];
        let mem = Flat { base: 0x100, data: &data };
        let mut p = 0x100;
        assert_eq!(uleb(&mem, &mut p), Some(624485));
        assert_eq!(sleb(&mem, &mut p), Some(-1));
        assert_eq!(sleb(&mem, &mut p), Some(-128));
        let d = (-16i32).to_le_bytes();
        let mem = Flat { base: 0x1000, data: &d };
        let mut p = 0x1000;
        assert_eq!(read_encoded(&mem, &mut p, 0x1b, 0), Some(0x1000 - 16));
        let mut p = 0x1000;
        assert_eq!(read_encoded(&mem, &mut p, 0x3b, 0x2000), Some(0x2000 - 16));
    }

    #[test]
    fn after_call_shapes() {
        let mut code = vec![0x90u8; 64];
        code[10..15].copy_from_slice(&[0xe8, 1, 2, 3, 4]); // call rel32 → ra 15
        code[20..26].copy_from_slice(&[0xff, 0x15, 1, 2, 3, 4]); // call [rip+x] → ra 26
        code[30..32].copy_from_slice(&[0xff, 0xd0]); // call rax → ra 32
        code[40..43].copy_from_slice(&[0xff, 0x50, 0x08]); // call [rax+8] → ra 43
        let mem = Flat { base: 0x1000, data: &code };
        let un = Unwinder::new(&mem, vec![]);
        for ra in [15, 26, 32, 43] {
            assert!(un.after_call(0x1000 + ra), "ra {ra}");
        }
        assert!(!un.after_call(0x1000 + 50));
    }

    /// The real thing: unwind this test's own stack through its own .eh_frame (Linux).
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[inline(never)]
    fn unwinds_own_stack_with_eh_frame() {
        use std::os::unix::fs::FileExt;
        let mem_file = std::fs::File::open("/proc/self/mem").unwrap();
        let mem = |a: u64, b: &mut [u8]| mem_file.read_exact_at(b, a).is_ok();
        let maps = crate::local::parse_maps(&std::fs::read_to_string("/proc/self/maps").unwrap());
        let mut mods: Vec<ModuleInfo> = Vec::new();
        for m in maps.iter().filter(|m| m.path.starts_with('/')) {
            match mods.iter_mut().find(|x| x.name == m.path) {
                Some(x) => x.size = m.end.max(x.base + x.size) - x.base,
                None => mods.push(ModuleInfo { name: m.path.clone(), base: m.start, size: m.end - m.start }),
            }
        }
        let (rip, rsp, rbp): (u64, u64, u64);
        unsafe {
            std::arch::asm!("lea {0}, [rip]", "mov {1}, rsp", "mov {2}, rbp", out(reg) rip, out(reg) rsp, out(reg) rbp);
        }
        let mut un = Unwinder::new(&mem, mods);
        let frames = un.walk(&Regs::new(rip, rsp, rbp), 64);
        let exe = std::fs::read_link("/proc/self/exe").unwrap().display().to_string();
        let cfi_in_exe = frames.iter().skip(1).filter(|f| f.method == Method::Cfi && f.module.as_deref() == Some(exe.as_str())).count();
        assert!(frames.len() >= 4, "{frames:#?}");
        assert!(cfi_in_exe >= 3, "{frames:#?}");
        // the walk reaches libc (thread start) without guessing
        assert!(frames.iter().take(4).all(|f| !f.guessed), "{frames:#?}");
        assert!(frames.iter().any(|f| f.method == Method::Cfi && f.module.as_deref().is_some_and(|m| m.contains("libc"))), "{frames:#?}");
    }
}
