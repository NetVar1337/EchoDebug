//! x86-64 lifter: instructions → expression trees, symbolic execution over a block or an
//! execution trace, an expression simplifier (constant folding, algebraic identities and
//! sampling-verified MBA simplification), trace slicing for deobfuscation, and VM handler
//! extraction for devirtualization.
//!
//! The model: every GPR starts as a symbol (`rax`, `rbx`, …); memory reads become `ld64(addr)`
//! unless an earlier store in the same run wrote that exact address (stores at structurally
//! different addresses are assumed not to alias). Flags are tracked only as "the last
//! compare/test", which is enough to name branch conditions. Instructions outside the supported
//! set clobber what they write with fresh symbols and are listed under `unsupported`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::rc::Rc;

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, InstructionInfoFactory, IntelFormatter, Mnemonic, OpAccess, OpKind, Register};
use serde_json::{json, Value};

// ---- expressions ---------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Op {
    Add, Sub, Mul, And, Or, Xor, Shl, Shr, Sar,
    Rol(u8), Ror(u8),
    Eq, Ne, Ult, Ule, Slt, Sle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UOp { Not, Neg, Sx(u8), Zx(u8), Bswap(u8) }

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum E {
    C(u64),
    S(Rc<str>),
    B(Op, Rc<E>, Rc<E>),
    U(UOp, Rc<E>),
    Ld(Rc<E>, u8),
}

pub type X = Rc<E>;

pub fn c(v: u64) -> X { Rc::new(E::C(v)) }
pub fn s(n: &str) -> X { Rc::new(E::S(n.into())) }
pub fn b(op: Op, a: X, b: X) -> X { Rc::new(E::B(op, a, b)) }
pub fn u(op: UOp, a: X) -> X { Rc::new(E::U(op, a)) }

pub fn mask(bits: u8) -> u64 { if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 } }

fn sx(v: u64, bits: u8) -> u64 {
    if bits >= 64 { v } else { let sh = 64 - bits as u32; (((v << sh) as i64) >> sh) as u64 }
}

impl fmt::Display for E {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            E::C(v) => if *v > 0xffff_ffff_ffff_0000 { write!(f, "-0x{:x}", v.wrapping_neg()) } else if *v < 10 { write!(f, "{v}") } else { write!(f, "0x{v:x}") },
            E::S(n) => write!(f, "{n}"),
            E::Ld(a, n) => write!(f, "[{a}]{}", match n { 1 => ".b", 2 => ".w", 4 => ".d", _ => "" }),
            E::U(op, a) => match op {
                UOp::Not => write!(f, "~{}", paren(a)),
                UOp::Neg => write!(f, "-{}", paren(a)),
                UOp::Sx(n) => write!(f, "sx{n}({a})"),
                UOp::Zx(n) => write!(f, "zx{n}({a})"),
                UOp::Bswap(n) => write!(f, "bswap{n}({a})"),
            },
            E::B(Op::Add, a, k) if matches!(**k, E::C(v) if v > 0xffff_ffff_0000_0000) => {
                let E::C(v) = **k else { unreachable!() };
                write!(f, "{} - 0x{:x}", paren(a), v.wrapping_neg())
            }
            E::B(op, a, b) => {
                let sym = match op {
                    Op::Add => "+", Op::Sub => "-", Op::Mul => "*", Op::And => "&", Op::Or => "|", Op::Xor => "^",
                    Op::Shl => "<<", Op::Shr => ">>", Op::Sar => ">>s", Op::Eq => "==", Op::Ne => "!=",
                    Op::Ult => "<u", Op::Ule => "<=u", Op::Slt => "<s", Op::Sle => "<=s",
                    Op::Rol(w) => return write!(f, "rol{w}({a}, {b})"),
                    Op::Ror(w) => return write!(f, "ror{w}({a}, {b})"),
                };
                write!(f, "{} {sym} {}", paren(a), paren(b))
            }
        }
    }
}

fn paren(e: &E) -> String {
    match e {
        E::B(..) => format!("({e})"),
        _ => e.to_string(),
    }
}

fn size(e: &E) -> usize {
    match e {
        E::C(_) | E::S(_) => 1,
        E::U(_, a) => 1 + size(a),
        E::Ld(a, _) => 1 + size(a),
        E::B(_, a, b) => 1 + size(a) + size(b),
    }
}

/// Free variables: symbols and (whole) loads, which are opaque inputs to the expression.
fn vars(e: &X, out: &mut Vec<X>) {
    match &**e {
        E::S(_) | E::Ld(..) => if !out.contains(e) { out.push(e.clone()) },
        E::U(_, a) => vars(a, out),
        E::B(_, a, b) => { vars(a, out); vars(b, out); }
        E::C(_) => {}
    }
}

pub fn eval(e: &E, env: &HashMap<X, u64>) -> u64 {
    match e {
        E::C(v) => *v,
        E::S(_) | E::Ld(..) => env.get(&Rc::new(e.clone())).copied().unwrap_or(0),
        E::U(op, a) => {
            let x = eval(a, env);
            match op {
                UOp::Not => !x,
                UOp::Neg => x.wrapping_neg(),
                UOp::Sx(n) => sx(x & mask(*n), *n),
                UOp::Zx(n) => x & mask(*n),
                UOp::Bswap(n) => if *n == 32 { (x as u32).swap_bytes() as u64 } else { x.swap_bytes() },
            }
        }
        E::B(op, a, b) => {
            let (x, y) = (eval(a, env), eval(b, env));
            match op {
                Op::Add => x.wrapping_add(y),
                Op::Sub => x.wrapping_sub(y),
                Op::Mul => x.wrapping_mul(y),
                Op::And => x & y,
                Op::Or => x | y,
                Op::Xor => x ^ y,
                Op::Shl => if y >= 64 { 0 } else { x << y },
                Op::Shr => if y >= 64 { 0 } else { x >> y },
                Op::Sar => ((x as i64) >> y.min(63)) as u64,
                Op::Rol(w) => rot(x, y, *w, true),
                Op::Ror(w) => rot(x, y, *w, false),
                Op::Eq => (x == y) as u64,
                Op::Ne => (x != y) as u64,
                Op::Ult => (x < y) as u64,
                Op::Ule => (x <= y) as u64,
                Op::Slt => ((x as i64) < (y as i64)) as u64,
                Op::Sle => ((x as i64) <= (y as i64)) as u64,
            }
        }
    }
}

fn rot(x: u64, y: u64, w: u8, left: bool) -> u64 {
    let w = w as u32;
    let m = mask(w as u8);
    let x = x & m;
    let r = (y as u32) % w;
    if r == 0 { return x; }
    let v = if left { (x << r) | (x >> (w - r)) } else { (x >> r) | (x << (w - r)) };
    v & m
}

// ---- simplification ------------------------------------------------------------------------------

fn commutative(op: Op) -> bool { matches!(op, Op::Add | Op::Mul | Op::And | Op::Or | Op::Xor | Op::Eq | Op::Ne) }

/// Structural simplification, then sampling-verified replacement by a small equivalent.
pub fn simp(e: &X) -> X {
    let r = simp_struct(e);
    if size(&r) > 4 { mba(&r).unwrap_or(r) } else { r }
}

fn simp_struct(e: &X) -> X {
    match &**e {
        E::C(_) | E::S(_) => e.clone(),
        E::Ld(a, n) => Rc::new(E::Ld(simp_struct(a), *n)),
        E::U(op, a) => {
            let a = simp_struct(a);
            if let E::C(_) = *a { return c(eval(&E::U(*op, a.clone()), &HashMap::new())); }
            match (op, &*a) {
                (UOp::Not, E::U(UOp::Not, x)) | (UOp::Neg, E::U(UOp::Neg, x)) => x.clone(),
                (UOp::Zx(64), _) | (UOp::Sx(64), _) => a,
                (UOp::Zx(n), E::U(UOp::Zx(m), x)) if m <= n => u(UOp::Zx(*m), x.clone()),
                // sxN / zxN only look at the low N bits: a mask of at least N bits is redundant
                (UOp::Sx(n) | UOp::Zx(n), E::B(Op::And, x, k)) if matches!(**k, E::C(v) if v & mask(*n) == mask(*n)) => simp_struct(&u(*op, x.clone())),
                _ => u(*op, a),
            }
        }
        E::B(op, a, bb) => {
            let (mut a, mut bb) = (simp_struct(a), simp_struct(bb));
            if let (E::C(_), E::C(_)) = (&*a, &*bb) {
                return c(eval(&E::B(*op, a, bb), &HashMap::new()));
            }
            // constants to the right, otherwise a stable order, for commutative ops
            let is_i = |e: &E| matches!(e, E::S(n) if &**n == "i"); // the loop index reads best last
            if commutative(*op) && (matches!(*a, E::C(_)) || (!matches!(*bb, E::C(_)) && (is_i(&a) || (!is_i(&bb) && a > bb)))) {
                std::mem::swap(&mut a, &mut bb);
            }
            let k = if let E::C(v) = *bb { Some(v) } else { None };
            // x & m is x when m keeps every bit x can have
            if let (Op::And, Some(m)) = (op, k) {
                if mask(bits(&a)) & !m == 0 { return a; }
                if mask(bits(&a)) & m == 0 { return c(0); }
                // distribute a constant mask over | and ^ so partial-register merges collapse
                if let E::B(o @ (Op::Or | Op::Xor), x, y) = &*a {
                    return simp_struct(&b(*o, b(Op::And, x.clone(), c(m)), b(Op::And, y.clone(), c(m))));
                }
            }
            match (op, k) {
                (Op::Add | Op::Sub | Op::Or | Op::Xor | Op::Shl | Op::Shr | Op::Sar, Some(0)) => return a,
                (Op::Rol(_) | Op::Ror(_), Some(0)) => return a,
                (Op::Mul, Some(1)) | (Op::And, Some(u64::MAX)) => return a,
                (Op::Mul | Op::And, Some(0)) => return c(0),
                (Op::Or, Some(u64::MAX)) => return c(u64::MAX),
                (Op::Xor, Some(u64::MAX)) => return simp_struct(&u(UOp::Not, a)),
                (Op::Sub, Some(v)) => return simp_struct(&b(Op::Add, a, c(v.wrapping_neg()))),
                _ => {}
            }
            if a == bb {
                match op {
                    Op::Xor | Op::Sub => return c(0),
                    Op::And | Op::Or => return a,
                    Op::Eq | Op::Ule | Op::Sle => return c(1),
                    Op::Ne | Op::Ult | Op::Slt => return c(0),
                    _ => {}
                }
            }
            // (x op c1) op c2 → x op (c1 op c2) for associative ops
            if let (Some(k2), E::B(op1, x, k1)) = (k, &*a) {
                if op1 == op && matches!(op, Op::Add | Op::Xor | Op::And | Op::Or | Op::Mul) {
                    if let E::C(k1) = **k1 {
                        return simp_struct(&b(*op, x.clone(), c(eval(&E::B(*op, c(k1), c(k2)), &HashMap::new()))));
                    }
                }
            }
            // x + (-y) → x - y ; x - (-y) → x + y
            if let E::U(UOp::Neg, y) = &*bb {
                if *op == Op::Add { return simp_struct(&b(Op::Sub, a, y.clone())); }
                if *op == Op::Sub { return simp_struct(&b(Op::Add, a, y.clone())); }
            }
            b(*op, a, bb)
        }
    }
}

/// Upper bound on the number of significant bits of a value.
fn bits(e: &E) -> u8 {
    match e {
        E::C(v) => (64 - v.leading_zeros()) as u8,
        E::Ld(_, n) => n * 8,
        E::U(UOp::Zx(n), _) => *n,
        E::B(Op::And, a, b) => bits(a).min(bits(b)),
        E::B(Op::Or | Op::Xor, a, b) => bits(a).max(bits(b)),
        E::B(Op::Shr, a, k) => match **k { E::C(v) if v < 64 => bits(a).saturating_sub(v as u8), _ => bits(a) },
        E::B(Op::Eq | Op::Ne | Op::Ult | Op::Ule | Op::Slt | Op::Sle, ..) => 1,
        _ => 64,
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Mixed boolean-arithmetic simplification: if the expression equals a much smaller candidate
/// over its (≤ 3) inputs on 96 random and edge-case assignments, use the candidate.
fn mba(e: &X) -> Option<X> {
    let mut vs = Vec::new();
    vars(e, &mut vs);
    if vs.len() > 3 { return None; }
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let edge = [0u64, 1, u64::MAX, 0x8000_0000_0000_0000, 0xffff_ffff, 0x7fff_ffff_ffff_ffff];
    let samples: Vec<HashMap<X, u64>> = (0..96)
        .map(|i| vs.iter().enumerate().map(|(k, v)| (v.clone(), if i < 6 { edge[(i + k) % edge.len()] } else { rng.next() })).collect())
        .collect();
    let want: Vec<u64> = samples.iter().map(|env| eval(e, env)).collect();
    if want.iter().all(|w| *w == want[0]) {
        return Some(c(want[0]));
    }
    let mut cands: Vec<X> = Vec::new();
    for v in &vs {
        cands.extend([v.clone(), u(UOp::Not, v.clone()), u(UOp::Neg, v.clone())]);
    }
    for (i, x) in vs.iter().enumerate() {
        for y in vs.iter().skip(i + 1) {
            let (x, y) = (x.clone(), y.clone());
            for op in [Op::Add, Op::Xor, Op::And, Op::Or, Op::Mul] {
                cands.push(b(op, x.clone(), y.clone()));
                cands.push(u(UOp::Not, b(op, x.clone(), y.clone())));
            }
            cands.push(b(Op::Sub, x.clone(), y.clone()));
            cands.push(b(Op::Sub, y.clone(), x.clone()));
            cands.push(b(Op::And, x.clone(), u(UOp::Not, y.clone())));
            cands.push(b(Op::And, u(UOp::Not, x.clone()), y.clone()));
            cands.push(b(Op::Or, x.clone(), u(UOp::Not, y.clone())));
            cands.push(b(Op::Or, u(UOp::Not, x), y));
        }
    }
    if vs.len() == 3 {
        let (x, y, z) = (vs[0].clone(), vs[1].clone(), vs[2].clone());
        for (o1, o2) in [(Op::Add, Op::Add), (Op::Xor, Op::Xor), (Op::And, Op::And), (Op::Or, Op::Or), (Op::Add, Op::Xor), (Op::Xor, Op::Add)] {
            cands.push(b(o2, b(o1, x.clone(), y.clone()), z.clone()));
        }
    }
    // a candidate plus or xor a constant (opaque constants are common in MBA)
    let base = cands.clone();
    for k in &base {
        let d = want[0].wrapping_sub(eval(k, &samples[0]));
        cands.push(b(Op::Add, k.clone(), c(d)));
        let d = want[0] ^ eval(k, &samples[0]);
        cands.push(b(Op::Xor, k.clone(), c(d)));
    }
    let n = size(e);
    cands.into_iter().filter(|k| size(k) < n).find(|k| samples.iter().zip(&want).all(|(env, w)| eval(k, env) == *w)).map(|k| simp_struct(&k))
}

// ---- symbolic machine ----------------------------------------------------------------------------

const GPRS: [&str; 16] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

fn gpr_index(r: Register) -> Option<(usize, u8, bool)> {
    if r == Register::None || !r.is_gpr() { return None; }
    let full = r.full_register();
    let idx = (full as usize).checked_sub(Register::RAX as usize)?;
    if idx >= 16 { return None; }
    let high = matches!(r, Register::AH | Register::CH | Register::DH | Register::BH);
    Some((idx, (r.size() * 8) as u8, high))
}

/// Location written by an instruction, for slicing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Loc {
    Reg(usize),
    Mem(usize), // store id
    Flags,
}

#[derive(Clone)]
struct Store {
    addr: X,
    size: u8,
    val: X,
    def: usize, // instruction index that wrote it
}

#[derive(Clone)]
pub struct Machine {
    regs: [X; 16],
    reg_def: [Option<usize>; 16],
    stores: Vec<Store>,
    /// last flag-setting comparison: (mnemonic, a, b, width)
    flags: Option<(Mnemonic, X, X, u8)>,
    flags_def: Option<usize>,
    fresh: usize,
    pub unsupported: BTreeMap<String, usize>,
    /// per executed instruction: (address, text, locations read, locations written)
    log: Vec<Step>,
}

#[derive(Clone)]
pub struct Step {
    pub address: u64,
    pub text: String,
    pub effect: String,
    reads: Vec<Loc>,
    reads_def: Vec<usize>,
    writes: Vec<Loc>,
}

impl Default for Machine {
    fn default() -> Self { Self::new() }
}

impl Machine {
    pub fn new() -> Self {
        Machine {
            regs: GPRS.map(s),
            reg_def: [None; 16],
            stores: Vec::new(),
            flags: None,
            flags_def: None,
            fresh: 0,
            unsupported: BTreeMap::new(),
            log: Vec::new(),
        }
    }

    /// Loops grow expressions without bound: past a size limit a value becomes a fresh unknown.
    fn cap(&mut self, e: X) -> X {
        if size(&e) > 160 { self.fresh_sym("big") } else { e }
    }

    fn fresh_sym(&mut self, what: &str) -> X {
        self.fresh += 1;
        s(&format!("{what}#{}", self.fresh))
    }

    fn get_reg(&mut self, r: Register, cur: &mut Step) -> X {
        let Some((i, bits, high)) = gpr_index(r) else { return self.fresh_sym(&format!("{r:?}").to_lowercase()) };
        cur.reads.push(Loc::Reg(i));
        if let Some(d) = self.reg_def[i] { cur.reads_def.push(d); }
        let v = self.regs[i].clone();
        if high { return simp_struct(&b(Op::And, b(Op::Shr, v, c(8)), c(0xff))); }
        if bits == 64 { v } else { simp_struct(&b(Op::And, v, c(mask(bits)))) }
    }

    fn set_reg(&mut self, r: Register, v: X, idx: usize, cur: &mut Step) {
        let Some((i, bits, high)) = gpr_index(r) else { return };
        let old = self.regs[i].clone();
        let nv = match (bits, high) {
            (64, _) => v,
            (32, _) => b(Op::And, v, c(0xffff_ffff)),
            (8, true) => b(Op::Or, b(Op::And, old, c(!0xff00)), b(Op::Shl, b(Op::And, v, c(0xff)), c(8))),
            (n, _) => b(Op::Or, b(Op::And, old, c(!mask(n))), b(Op::And, v, c(mask(n)))),
        };
        self.regs[i] = self.cap(simp_struct(&nv));
        self.reg_def[i] = Some(idx);
        cur.writes.push(Loc::Reg(i));
    }

    fn mem_addr(&mut self, ins: &Instruction, cur: &mut Step) -> X {
        if ins.memory_base() == Register::RIP || ins.is_ip_rel_memory_operand() {
            return c(ins.ip_rel_memory_address());
        }
        let mut a = c(ins.memory_displacement64());
        if ins.memory_base() != Register::None {
            a = b(Op::Add, self.get_reg(ins.memory_base(), cur), a);
        }
        if ins.memory_index() != Register::None {
            let ix = self.get_reg(ins.memory_index(), cur);
            a = b(Op::Add, a, b(Op::Mul, ix, c(ins.memory_index_scale() as u64)));
        }
        match ins.memory_segment() {
            Register::FS => a = b(Op::Add, a, s("fs_base")),
            Register::GS => a = b(Op::Add, a, s("gs_base")),
            _ => {}
        }
        simp_struct(&a)
    }

    fn load(&mut self, addr: X, size: u8, cur: &mut Step) -> X {
        if let Some(st) = self.stores.iter().rev().find(|st| st.addr == addr) {
            let id = self.stores.iter().rposition(|x| x.addr == addr).unwrap_or(0);
            cur.reads.push(Loc::Mem(id));
            cur.reads_def.push(st.def);
            if st.size == size { return st.val.clone(); }
            if st.size > size { return simp_struct(&b(Op::And, st.val.clone(), c(mask(size * 8)))); }
        }
        Rc::new(E::Ld(addr, size))
    }

    fn store(&mut self, addr: X, size: u8, val: X, idx: usize, cur: &mut Step) {
        let val = self.cap(if size < 8 { simp_struct(&b(Op::And, val, c(mask(size * 8)))) } else { val });
        self.stores.push(Store { addr, size, val, def: idx });
        cur.writes.push(Loc::Mem(self.stores.len() - 1));
    }

    fn read_op(&mut self, ins: &Instruction, n: u32, cur: &mut Step) -> X {
        match ins.op_kind(n) {
            OpKind::Register => self.get_reg(ins.op_register(n), cur),
            OpKind::Memory => {
                let a = self.mem_addr(ins, cur);
                let sz = ins.memory_size().size().max(1) as u8;
                self.load(a, sz, cur)
            }
            OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64
            | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 | OpKind::Immediate32to64
            | OpKind::Immediate8_2nd => c(ins.immediate(n)),
            _ => self.fresh_sym("op"),
        }
    }

    fn write_op(&mut self, ins: &Instruction, n: u32, v: X, idx: usize, cur: &mut Step) {
        match ins.op_kind(n) {
            OpKind::Register => self.set_reg(ins.op_register(n), v, idx, cur),
            OpKind::Memory => {
                let a = self.mem_addr(ins, cur);
                let sz = ins.memory_size().size().max(1) as u8;
                self.store(a, sz, v, idx, cur);
            }
            _ => {}
        }
    }

    fn width(ins: &Instruction, n: u32) -> u8 {
        match ins.op_kind(n) {
            OpKind::Register => (ins.op_register(n).size() * 8) as u8,
            OpKind::Memory => (ins.memory_size().size() * 8) as u8,
            _ => 64,
        }
    }

    fn push(&mut self, v: X, idx: usize, cur: &mut Step) {
        let sp = simp_struct(&b(Op::Add, self.get_reg(Register::RSP, cur), c(8u64.wrapping_neg())));
        self.set_reg(Register::RSP, sp.clone(), idx, cur);
        self.store(sp, 8, v, idx, cur);
    }

    fn pop(&mut self, idx: usize, cur: &mut Step) -> X {
        let sp = self.get_reg(Register::RSP, cur);
        let v = self.load(sp.clone(), 8, cur);
        self.set_reg(Register::RSP, simp_struct(&b(Op::Add, sp, c(8))), idx, cur);
        v
    }

    /// Condition of a jcc/setcc/cmovcc from the last compare, as a 0/1 expression.
    pub fn condition(&self, m: Mnemonic) -> Option<X> {
        let (kind, a, bb, w) = self.flags.clone()?;
        let cc = format!("{m:?}").to_lowercase();
        let cc = cc.trim_start_matches("cmov").trim_start_matches("set").trim_start_matches('j').to_owned();
        let (a, bb) = if w < 64 { (b(Op::And, a, c(mask(w))), b(Op::And, bb, c(mask(w)))) } else { (a, bb) };
        let sxa = || if w < 64 { u(UOp::Sx(w), a.clone()) } else { a.clone() };
        let sxb = || if w < 64 { u(UOp::Sx(w), bb.clone()) } else { bb.clone() };
        let e = match kind {
            Mnemonic::Test => {
                let t = b(Op::And, a.clone(), bb.clone());
                match cc.as_str() {
                    "e" | "z" => b(Op::Eq, t, c(0)),
                    "ne" | "nz" => b(Op::Ne, t, c(0)),
                    "s" => b(Op::Slt, if w < 64 { u(UOp::Sx(w), t) } else { t }, c(0)),
                    "ns" => b(Op::Sle, c(0), if w < 64 { u(UOp::Sx(w), t) } else { t }),
                    // test clears OF, so the signed conditions reduce to the sign and zero of a & b
                    "le" | "ng" => b(Op::Sle, if w < 64 { u(UOp::Sx(w), t) } else { t }, c(0)),
                    "g" | "nle" => b(Op::Slt, c(0), if w < 64 { u(UOp::Sx(w), t) } else { t }),
                    "l" | "nge" => b(Op::Slt, if w < 64 { u(UOp::Sx(w), t) } else { t }, c(0)),
                    "ge" | "nl" => b(Op::Sle, c(0), if w < 64 { u(UOp::Sx(w), t) } else { t }),
                    _ => return None,
                }
            }
            _ => match cc.as_str() {
                "e" | "z" => b(Op::Eq, a, bb),
                "ne" | "nz" => b(Op::Ne, a, bb),
                "b" | "c" | "nae" => b(Op::Ult, a, bb),
                "ae" | "nb" | "nc" => b(Op::Ule, bb, a),
                "be" | "na" => b(Op::Ule, a, bb),
                "a" | "nbe" => b(Op::Ult, bb, a),
                "l" | "nge" => b(Op::Slt, sxa(), sxb()),
                "ge" | "nl" => b(Op::Sle, sxb(), sxa()),
                "le" | "ng" => b(Op::Sle, sxa(), sxb()),
                "g" | "nle" => b(Op::Slt, sxb(), sxa()),
                _ => return None,
            },
        };
        Some(simp_struct(&e))
    }

    /// Executes one decoded instruction symbolically. Control flow is left to the caller.
    pub fn exec(&mut self, ins: &Instruction, text: String, info: &mut InstructionInfoFactory) {
        let idx = self.log.len();
        let mut cur = Step { address: ins.ip(), text, effect: String::new(), reads: Vec::new(), reads_def: Vec::new(), writes: Vec::new() };
        let m = ins.mnemonic();
        let w0 = Self::width(ins, 0);
        let set_flags = |me: &mut Machine, cur: &mut Step, k: Mnemonic, a: X, bb: X, w: u8| {
            me.flags = Some((k, a, bb, w));
            me.flags_def = Some(idx);
            cur.writes.push(Loc::Flags);
        };
        let binop = |op: Op| -> Option<Op> { Some(op) };
        let arith = match m {
            Mnemonic::Add => binop(Op::Add),
            Mnemonic::Sub => binop(Op::Sub),
            Mnemonic::And => binop(Op::And),
            Mnemonic::Or => binop(Op::Or),
            Mnemonic::Xor => binop(Op::Xor),
            Mnemonic::Shl | Mnemonic::Sal => binop(Op::Shl),
            Mnemonic::Shr => binop(Op::Shr),
            Mnemonic::Sar => binop(Op::Sar),
            Mnemonic::Rol => binop(Op::Rol(w0)),
            Mnemonic::Ror => binop(Op::Ror(w0)),
            _ => None,
        };
        match m {
            Mnemonic::Mov => {
                let v = self.read_op(ins, 1, &mut cur);
                self.write_op(ins, 0, v, idx, &mut cur);
            }
            Mnemonic::Movzx => {
                let v = self.read_op(ins, 1, &mut cur);
                self.write_op(ins, 0, v, idx, &mut cur);
            }
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                let w1 = Self::width(ins, 1);
                let v = self.read_op(ins, 1, &mut cur);
                self.write_op(ins, 0, simp_struct(&u(UOp::Sx(w1), v)), idx, &mut cur);
            }
            Mnemonic::Lea => {
                let a = self.mem_addr(ins, &mut cur);
                self.write_op(ins, 0, a, idx, &mut cur);
            }
            _ if arith.is_some() => {
                let op = arith.unwrap_or(Op::Add);
                let a = self.read_op(ins, 0, &mut cur);
                let mut bb = self.read_op(ins, 1, &mut cur);
                if matches!(op, Op::Shl | Op::Shr | Op::Sar | Op::Rol(_) | Op::Ror(_)) {
                    bb = simp_struct(&b(Op::And, bb, c(if w0 == 64 { 63 } else { 31 })));
                }
                let a_w = if w0 < 64 && matches!(op, Op::Shr) { simp_struct(&b(Op::And, a.clone(), c(mask(w0)))) } else if w0 < 64 && op == Op::Sar { simp_struct(&u(UOp::Sx(w0), a.clone())) } else { a.clone() };
                let r = simp_struct(&b(op, a_w, bb.clone()));
                // flags of sub/and are the classic cmp/test idioms
                match op {
                    Op::Sub => set_flags(self, &mut cur, Mnemonic::Cmp, a, bb, w0),
                    Op::And => set_flags(self, &mut cur, Mnemonic::Test, a, bb, w0),
                    _ => set_flags(self, &mut cur, Mnemonic::Test, r.clone(), r.clone(), w0),
                }
                self.write_op(ins, 0, r, idx, &mut cur);
            }
            Mnemonic::Not | Mnemonic::Neg => {
                let a = self.read_op(ins, 0, &mut cur);
                self.write_op(ins, 0, simp_struct(&u(if m == Mnemonic::Not { UOp::Not } else { UOp::Neg }, a)), idx, &mut cur);
            }
            Mnemonic::Inc | Mnemonic::Dec => {
                let a = self.read_op(ins, 0, &mut cur);
                let r = simp_struct(&b(Op::Add, a, c(if m == Mnemonic::Inc { 1 } else { u64::MAX })));
                set_flags(self, &mut cur, Mnemonic::Test, r.clone(), r.clone(), w0);
                self.write_op(ins, 0, r, idx, &mut cur);
            }
            Mnemonic::Imul if ins.op_count() >= 2 => {
                let (x, y) = if ins.op_count() == 3 { (self.read_op(ins, 1, &mut cur), self.read_op(ins, 2, &mut cur)) } else { (self.read_op(ins, 0, &mut cur), self.read_op(ins, 1, &mut cur)) };
                self.write_op(ins, 0, simp_struct(&b(Op::Mul, x, y)), idx, &mut cur);
            }
            Mnemonic::Cmp => {
                let a = self.read_op(ins, 0, &mut cur);
                let bb = self.read_op(ins, 1, &mut cur);
                set_flags(self, &mut cur, Mnemonic::Cmp, a, bb, w0);
            }
            Mnemonic::Test => {
                let a = self.read_op(ins, 0, &mut cur);
                let bb = self.read_op(ins, 1, &mut cur);
                set_flags(self, &mut cur, Mnemonic::Test, a, bb, w0);
            }
            Mnemonic::Push => {
                let v = self.read_op(ins, 0, &mut cur);
                self.push(v, idx, &mut cur);
            }
            Mnemonic::Pop => {
                let v = self.pop(idx, &mut cur);
                self.write_op(ins, 0, v, idx, &mut cur);
            }
            Mnemonic::Pushfq => {
                let v = self.fresh_sym("rflags");
                self.push(v, idx, &mut cur);
            }
            Mnemonic::Popfq => {
                let _ = self.pop(idx, &mut cur);
                self.flags = None;
            }
            Mnemonic::Xchg => {
                let a = self.read_op(ins, 0, &mut cur);
                let bb = self.read_op(ins, 1, &mut cur);
                self.write_op(ins, 0, bb, idx, &mut cur);
                self.write_op(ins, 1, a, idx, &mut cur);
            }
            Mnemonic::Bswap => {
                let a = self.read_op(ins, 0, &mut cur);
                self.write_op(ins, 0, simp_struct(&u(UOp::Bswap(w0), a)), idx, &mut cur);
            }
            Mnemonic::Cdqe => {
                let a = self.get_reg(Register::EAX, &mut cur);
                self.set_reg(Register::RAX, simp_struct(&u(UOp::Sx(32), a)), idx, &mut cur);
            }
            Mnemonic::Nop | Mnemonic::Endbr64 | Mnemonic::Int3 | Mnemonic::Pause => {}
            Mnemonic::Call => {
                // the call's own effect: push the return address (the callee follows in a trace)
                self.push(c(ins.next_ip()), idx, &mut cur);
            }
            Mnemonic::Ret => {
                let _ = self.pop(idx, &mut cur);
                if ins.op_count() == 1 {
                    let sp = self.get_reg(Register::RSP, &mut cur);
                    self.set_reg(Register::RSP, simp_struct(&b(Op::Add, sp, c(ins.immediate(0)))), idx, &mut cur);
                }
            }
            Mnemonic::Jmp => {
                if ins.op_kind(0) == OpKind::Register || ins.op_kind(0) == OpKind::Memory {
                    let _ = self.read_op(ins, 0, &mut cur); // the dispatch target is a dependency
                }
            }
            _ if ins.is_jcc_short_or_near() => {
                if let Some(d) = self.flags_def { cur.reads.push(Loc::Flags); cur.reads_def.push(d); }
            }
            _ if format!("{m:?}").starts_with("Set") => {
                let v = self.condition(m).unwrap_or_else(|| self.fresh_sym("setcc"));
                if let Some(d) = self.flags_def { cur.reads_def.push(d); }
                self.write_op(ins, 0, v, idx, &mut cur);
            }
            _ => {
                // unsupported: everything it writes becomes unknown
                *self.unsupported.entry(format!("{m:?}").to_lowercase()).or_insert(0) += 1;
                let used = info.info(ins);
                for r in used.used_registers() {
                    if matches!(r.access(), OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite) {
                        if let Some((i, _, _)) = gpr_index(r.register()) {
                            let full = GPRS[i];
                            self.regs[i] = self.fresh_sym(full);
                            self.reg_def[i] = Some(idx);
                            cur.writes.push(Loc::Reg(i));
                        }
                    }
                }
                for mm in used.used_memory() {
                    if matches!(mm.access(), OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite | OpAccess::ReadCondWrite) {
                        let a = self.mem_addr(ins, &mut cur);
                        let v = self.fresh_sym("mem");
                        self.store(a, mm.memory_size().size().max(1) as u8, v, idx, &mut cur);
                    }
                }
                self.flags = None;
            }
        }
        cur.effect = cur
            .writes
            .iter()
            .filter_map(|w| match w {
                Loc::Reg(i) => Some(format!("{} = {}", GPRS[*i], self.regs[*i])),
                Loc::Mem(id) => self.stores.get(*id).map(|st| format!("[{}]{} = {}", st.addr, size_suffix(st.size), st.val)),
                Loc::Flags => None,
            })
            .collect::<Vec<_>>()
            .join("; ");
        self.log.push(cur);
    }

    /// Final register expressions that differ from their initial symbols.
    pub fn changed_regs(&self) -> Vec<(String, String)> {
        GPRS.iter().enumerate().filter(|(i, n)| *self.regs[*i] != *s(n)).map(|(i, n)| (n.to_string(), simp(&self.regs[i]).to_string())).collect()
    }

    /// Last store per address, in order.
    /// A store into the stack below the final rsp was popped: scratch, not an output.
    fn dead_stack(&self, st: &Store) -> bool {
        match (stack_off(&st.addr), stack_off(&self.regs[4])) {
            (Some(k), Some(sp)) => k < sp,
            _ => false,
        }
    }

    /// Last store per address, in order; runs of strided stores with one formula are folded
    /// into a single `base + i` entry (loop summarization).
    pub fn final_stores(&self) -> Vec<(String, u8, String)> {
        let mut seen = HashSet::new();
        let mut list: Vec<(X, u8, X)> = Vec::new();
        for st in self.stores.iter().rev() {
            if seen.insert(st.addr.clone()) && !self.dead_stack(st) {
                list.push((simp_struct(&st.addr), st.size, st.val.clone()));
            }
        }
        list.reverse();
        let i = s("i");
        let mut out: Vec<(String, u8, String)> = Vec::new();
        let mut k = 0;
        while k < list.len() {
            let (addr, size, val) = &list[k];
            let (base, off) = split_off(addr);
            let tmpl = templ(val, off, &i);
            let mut n = 1;
            while k + n < list.len() && n < 1 << 20 {
                let (a2, s2, v2) = &list[k + n];
                let (b2, o2) = split_off(a2);
                if s2 != size || b2 != base || o2 != off.wrapping_add(n as u64 * *size as u64) || templ(v2, o2, &i) != tmpl { break; }
                n += 1;
            }
            if n >= 4 {
                let idx = if *size > 1 { format!("i*{size}") } else { "i".into() };
                let a = if off == 0 { format!("{base} + {idx}") } else { format!("{base} + {} + {idx}", c(off)) };
                out.push((format!("{a}  for i in 0..{n:#x}"), *size, simp(&tmpl).to_string()));
            } else {
                for (a2, s2, v2) in &list[k..k + n] {
                    out.push((simp(a2).to_string(), *s2, simp(v2).to_string()));
                }
            }
            k += n;
        }
        out
    }

    /// Indices of the instructions the final state depends on: the definitions of every changed
    /// register and of the last store per address, followed back through their inputs.
    pub fn slice(&self, keep_rsp: bool) -> HashSet<usize> {
        self.slice_from(keep_rsp, &[])
    }

    /// The flag-setting instruction a final conditional branch depends on.
    pub fn flags_def(&self) -> Option<usize> { self.flags_def }

    pub fn slice_from(&self, keep_rsp: bool, extra: &[usize]) -> HashSet<usize> {
        let mut work: Vec<usize> = extra.to_vec();
        for (i, d) in self.reg_def.iter().enumerate() {
            if i == 4 && !keep_rsp { continue; }
            if let Some(d) = d {
                if *self.regs[i] != *s(GPRS[i]) { work.push(*d); }
            }
        }
        let mut seen_addr = HashSet::new();
        for st in self.stores.iter().rev() {
            if seen_addr.insert(st.addr.clone()) && !self.dead_stack(st) { work.push(st.def); }
        }
        // dispatch targets (indirect jumps) are part of the semantics too
        for (i, st) in self.log.iter().enumerate() {
            if st.text.starts_with("jmp") && !st.reads.is_empty() { work.push(i); }
        }
        let mut live = HashSet::new();
        while let Some(i) = work.pop() {
            if !live.insert(i) { continue; }
            if let Some(st) = self.log.get(i) { work.extend(st.reads_def.iter().copied()); }
        }
        live
    }

    pub fn steps(&self) -> &[Step] { &self.log }
}

/// base + constant offset
fn split_off(a: &X) -> (X, u64) {
    match &**a {
        E::B(Op::Add, x, k) => match **k { E::C(v) => (x.clone(), v), _ => (a.clone(), 0) },
        _ => (a.clone(), 0),
    }
}

/// The value with every load at `base + off` rewritten to `base + i` (+ the stride is implied):
/// identical templates across consecutive stores mean one loop body.
fn templ(e: &X, off: u64, i: &X) -> X {
    match &**e {
        E::Ld(a, n) => {
            let (base, o) = split_off(a);
            if o == off { Rc::new(E::Ld(simp_struct(&b(Op::Add, base, i.clone())), *n)) } else { e.clone() }
        }
        E::U(op, a) => u(*op, templ(a, off, i)),
        E::B(op, a, bb) => b(*op, templ(a, off, i), templ(bb, off, i)),
        _ => e.clone(),
    }
}

/// `rsp + k` → k (stack-relative addresses of the initial rsp).
fn stack_off(e: &E) -> Option<i64> {
    match e {
        E::S(n) if &**n == "rsp" => Some(0),
        E::B(Op::Add, a, k) => match (&**a, &**k) {
            (E::S(n), E::C(v)) if &**n == "rsp" => Some(*v as i64),
            _ => None,
        },
        _ => None,
    }
}

fn size_suffix(n: u8) -> &'static str {
    match n { 1 => ".b", 2 => ".w", 4 => ".d", _ => "" }
}

// ---- drivers -------------------------------------------------------------------------------------

/// Byte source for decoding: (address) → up to 16 bytes there.
pub trait Code {
    fn at(&self, addr: u64) -> Option<Vec<u8>>;
}

pub struct Pages(pub HashMap<u64, Vec<u8>>);

impl Code for Pages {
    fn at(&self, addr: u64) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(16);
        for i in 0..16u64 {
            let a = addr + i;
            match self.0.get(&(a & !0xfff)).and_then(|p| p.get((a & 0xfff) as usize)) {
                Some(b) => out.push(*b),
                None => break,
            }
        }
        if out.is_empty() { None } else { Some(out) }
    }
}

fn decode(code: &dyn Code, addr: u64) -> Option<(Instruction, String)> {
    let bytes = code.at(addr)?;
    let mut d = Decoder::with_ip(64, &bytes, addr, DecoderOptions::NONE);
    let ins = d.decode();
    if ins.is_invalid() { return None; }
    let mut text = String::new();
    let mut f = IntelFormatter::new();
    f.options_mut().set_hex_prefix("0x");
    f.options_mut().set_hex_suffix("");
    f.options_mut().set_uppercase_hex(false);
    f.options_mut().set_leading_zeros(false);
    f.options_mut().set_branch_leading_zeros(false);
    f.format(&ins, &mut text);
    Some((ins, text))
}

fn summary(m: &Machine) -> Value {
    json!({
        "registers": m.changed_regs().into_iter().map(|(r, e)| json!({ "register": r, "value": e })).collect::<Vec<_>>(),
        "stores": m.final_stores().into_iter().map(|(a, n, v)| json!({ "address": a, "size": n, "value": v })).collect::<Vec<_>>(),
        "unsupported": m.unsupported,
    })
}

fn hexa(v: u64) -> String { format!("0x{v:x}") }

/// Lifts straight-line code from `start` until a branch, return or `max` instructions.
pub fn lift_block(code: &dyn Code, start: u64, max: usize) -> Value {
    let mut m = Machine::new();
    let mut info = InstructionInfoFactory::new();
    let mut ip = start;
    let mut end = json!(null);
    for _ in 0..max.clamp(1, 4096) {
        let Some((ins, text)) = decode(code, ip) else {
            end = json!({ "kind": "undecodable", "address": hexa(ip) });
            break;
        };
        m.exec(&ins, text.clone(), &mut info);
        ip = ins.next_ip();
        if ins.is_jcc_short_or_near() {
            let cond = m.condition(ins.mnemonic()).map(|e| simp(&e));
            let opaque = cond.as_ref().and_then(|e| if let E::C(v) = **e { Some(v != 0) } else { None });
            end = json!({ "kind": "branch", "instruction": text, "condition": cond.map(|e| e.to_string()), "taken": hexa(ins.near_branch_target()), "fallthrough": hexa(ins.next_ip()), "opaque": opaque.map(|t| if t { "always taken" } else { "never taken" }) });
            break;
        }
        if matches!(ins.mnemonic(), Mnemonic::Ret | Mnemonic::Jmp) {
            end = json!({ "kind": format!("{:?}", ins.mnemonic()).to_lowercase(), "instruction": text, "target": if ins.op_kind(0) == OpKind::NearBranch64 { Some(hexa(ins.near_branch_target())) } else { None } });
            break;
        }
    }
    // a block that ends in a conditional branch has the branch condition as an output too
    let extra: Vec<usize> = if end["kind"] == "branch" { m.flags_def().into_iter().chain([m.steps().len().saturating_sub(1)]).collect() } else { Vec::new() };
    let live = m.slice_from(false, &extra);
    let insns: Vec<Value> = m.steps().iter().enumerate().map(|(i, st)| json!({ "address": hexa(st.address), "text": st.text, "effect": st.effect, "live": live.contains(&i) })).collect();
    let mut out = summary(&m);
    out["instructions"] = json!(insns);
    out["end"] = end;
    out["dead"] = json!(m.steps().len() - live.len());
    out
}

/// Symbolic execution along an execution trace (addresses in order). Branch conditions are
/// recorded; constant ones are opaque predicates. The slice gives the deobfuscated listing.
pub fn lift_trace(code: &dyn Code, trace: &[u64], max_listing: usize) -> Value {
    let mut m = Machine::new();
    let mut info = InstructionInfoFactory::new();
    let mut conds: Vec<Value> = Vec::new();
    let mut missing = 0usize;
    for (k, &a) in trace.iter().enumerate() {
        let Some((ins, text)) = decode(code, a) else { missing += 1; continue };
        m.exec(&ins, text.clone(), &mut info);
        if ins.is_jcc_short_or_near() {
            let taken = trace.get(k + 1).map(|n| *n == ins.near_branch_target());
            // full simplification (MBA) only for the branches that are reported
            let cond = m.condition(ins.mnemonic()).map(|e| if conds.len() < 2000 { simp(&e) } else { e });
            let opaque = cond.as_ref().map(|e| matches!(**e, E::C(_))).unwrap_or(false);
            if conds.len() < 2000 {
                conds.push(json!({ "address": hexa(a), "instruction": text, "condition": cond.map(|e| e.to_string()), "taken": taken, "opaque": opaque }));
            }
        }
    }
    let live = m.slice(false);
    let steps = m.steps();
    // the cleaned listing: live instructions with repeating cycles (loops) folded
    let kept: Vec<&Step> = steps.iter().enumerate().filter(|(i, _)| live.contains(i)).map(|(_, st)| st).collect();
    let listing = fold_loops(&kept, max_listing);
    let unique: HashSet<u64> = trace.iter().copied().collect();
    let mut out = summary(&m);
    out["executed"] = json!(steps.len());
    out["unique_addresses"] = json!(unique.len());
    out["live"] = json!(live.len());
    out["removed"] = json!(steps.len() - live.len());
    out["undecodable"] = json!(missing);
    out["listing"] = json!(listing);
    out["conditions"] = json!(conds);
    out["opaque_predicates"] = json!(conds.iter().filter(|c| c["opaque"] == true).count());
    out
}

/// Listing entries; a cycle of up to 64 instructions repeated back to back is shown once with a
/// `{ "loop": length, "times": n }` marker after it.
fn fold_loops(kept: &[&Step], max: usize) -> Vec<Value> {
    let addrs: Vec<u64> = kept.iter().map(|s| s.address).collect();
    let n = addrs.len();
    let mut out = Vec::new();
    let mut p = 0;
    while p < n && out.len() < max {
        let mut best = None;
        for l in 1..=64.min((n - p) / 2) {
            if addrs[p..p + l] == addrs[p + l..p + 2 * l] {
                let mut k = 2;
                while p + (k + 1) * l <= n && addrs[p + k * l..p + (k + 1) * l] == addrs[p..p + l] {
                    k += 1;
                }
                best = Some((l, k));
                break;
            }
        }
        let take = best.map(|(l, _)| l).unwrap_or(1);
        for st in &kept[p..p + take] {
            out.push(json!({ "address": hexa(st.address), "text": st.text, "effect": st.effect }));
        }
        match best {
            Some((l, k)) => {
                out.push(json!({ "loop": l, "times": k }));
                p += l * k;
            }
            None => p += 1,
        }
    }
    out
}

/// VM devirtualization aid: finds the dispatcher (the indirect jump or ret with the most distinct
/// successors), splits the trace into handler executions, lifts every distinct handler from a
/// fresh symbolic state and lists the virtual instruction stream.
pub fn devirt(code: &dyn Code, trace: &[u64], max_vtrace: usize) -> Value {
    let mut succ: HashMap<u64, HashSet<u64>> = HashMap::new();
    let mut is_dispatch: HashMap<u64, bool> = HashMap::new();
    for w in trace.windows(2) {
        let entry = is_dispatch.entry(w[0]).or_insert_with(|| {
            decode(code, w[0]).map(|(i, _)| {
                (i.mnemonic() == Mnemonic::Jmp && matches!(i.op_kind(0), OpKind::Register | OpKind::Memory)) || i.mnemonic() == Mnemonic::Ret || (i.mnemonic() == Mnemonic::Call && matches!(i.op_kind(0), OpKind::Register | OpKind::Memory))
            }).unwrap_or(false)
        });
        if *entry { succ.entry(w[0]).or_default().insert(w[1]); }
    }
    let Some((&disp, targets)) = succ.iter().filter(|(_, t)| t.len() >= 3).max_by_key(|(_, t)| t.len()) else {
        return json!({ "dispatcher": null, "note": "no indirect jump with three or more distinct targets in this trace: not a VM loop, or the trace is too short" });
    };
    // handler executions: from a dispatch target up to and including the next dispatch
    let mut runs: Vec<(u64, std::ops::Range<usize>)> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &a) in trace.iter().enumerate() {
        if a == disp {
            if let Some(s0) = start.take() { runs.push((trace[s0], s0..i + 1)); }
            if i + 1 < trace.len() { start = Some(i + 1); }
        }
    }
    let mut order: Vec<u64> = Vec::new();
    let mut count: HashMap<u64, usize> = HashMap::new();
    let mut first: HashMap<u64, std::ops::Range<usize>> = HashMap::new();
    for (h, r) in &runs {
        *count.entry(*h).or_insert(0) += 1;
        if !first.contains_key(h) {
            first.insert(*h, r.clone());
            order.push(*h);
        }
    }
    let mut info = InstructionInfoFactory::new();
    let mut vip_votes: HashMap<String, usize> = HashMap::new();
    let handlers: Vec<Value> = order.iter().enumerate().map(|(id, h)| {
        let r = first[h].clone();
        let mut m = Machine::new();
        for &a in &trace[r.clone()] {
            if let Some((ins, text)) = decode(code, a) { m.exec(&ins, text, &mut info); }
        }
        // a VIP-like register: advanced by a small constant and used as a load address
        for (reg, val) in m.changed_regs() {
            if let Some(rest) = val.strip_prefix(&format!("{reg} + ")) {
                if rest.len() <= 4 && m.steps().iter().any(|st| st.text.contains(&format!("[{reg}"))) {
                    *vip_votes.entry(reg).or_insert(0) += 1;
                }
            }
        }
        let live = m.slice(true);
        let body: Vec<String> = m.steps().iter().enumerate().filter(|(i, _)| live.contains(i)).map(|(_, st)| st.text.clone()).collect();
        let mut v = summary(&m);
        v["id"] = json!(id);
        v["address"] = json!(hexa(*h));
        v["executions"] = json!(count[h]);
        v["length"] = json!(r.len());
        v["body"] = json!(body.into_iter().take(64).collect::<Vec<_>>());
        v
    }).collect();
    let ids: HashMap<u64, usize> = order.iter().enumerate().map(|(i, h)| (*h, i)).collect();
    let vtrace: Vec<usize> = runs.iter().take(max_vtrace).map(|(h, _)| ids[h]).collect();
    let vip = vip_votes.into_iter().max_by_key(|(_, n)| *n).map(|(r, _)| r);
    json!({
        "dispatcher": hexa(disp),
        "dispatch_targets": targets.len(),
        "handler_executions": runs.len(),
        "vip_register": vip,
        "handlers": handlers,
        "virtual_trace": vtrace,
        "virtual_trace_truncated": runs.len() > max_vtrace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Bytes(u64, Vec<u8>);
    impl Code for Bytes {
        fn at(&self, a: u64) -> Option<Vec<u8>> {
            let o = a.checked_sub(self.0)? as usize;
            if o >= self.1.len() { return None; }
            Some(self.1[o..(o + 16).min(self.1.len())].to_vec())
        }
    }
    fn hx(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
    }
    /// addresses of each instruction in straight-line code
    fn linear(code: &Bytes) -> Vec<u64> {
        let mut out = Vec::new();
        let mut ip = code.0;
        while let Some((ins, _)) = decode(code, ip) { out.push(ip); ip = ins.next_ip(); }
        out
    }

    #[test]
    fn simplifies_mba_and_identities() {
        let (x, y) = (s("x"), s("y"));
        // (x | y) - (x & y) == x ^ y
        let e = b(Op::Sub, b(Op::Or, x.clone(), y.clone()), b(Op::And, x.clone(), y.clone()));
        assert_eq!(simp(&e).to_string(), "x ^ y");
        // (x ^ y) + 2*(x & y) == x + y
        let e = b(Op::Add, b(Op::Xor, x.clone(), y.clone()), b(Op::Mul, c(2), b(Op::And, x.clone(), y.clone())));
        assert_eq!(simp(&e).to_string(), "x + y");
        // ((x + 5) + 7) ^ 0 == x + 0xc
        assert_eq!(simp(&b(Op::Xor, b(Op::Add, b(Op::Add, x.clone(), c(5)), c(7)), c(0))).to_string(), "x + 0xc");
        assert_eq!(simp(&b(Op::Xor, x.clone(), x.clone())).to_string(), "0");
        assert_eq!(simp(&u(UOp::Sx(32), b(Op::And, x.clone(), c(0xffff_ffff)))).to_string(), "sx32(x)");
        assert_eq!(simp(&b(Op::Add, x.clone(), c(8u64.wrapping_neg()))).to_string(), "x - 0x8");
        // x*x - x*x is constant
        assert_eq!(simp(&b(Op::Sub, b(Op::Mul, x.clone(), x.clone()), b(Op::Mul, x.clone(), x))).to_string(), "0");
    }

    #[test]
    fn lifts_a_block_and_finds_dead_code() {
        // mov rax, rcx ; xor rbx, rbx ; add rax, 0x10 ; mov rbx, 5 (kills the xor) ; nop ; ret
        let code = Bytes(0x1000, hx("4889c8 4831db 4883c010 48c7c305000000 90 c3"));
        let r = lift_block(&code, 0x1000, 64);
        let regs: HashMap<String, String> = r["registers"].as_array().unwrap().iter().map(|v| (v["register"].as_str().unwrap().into(), v["value"].as_str().unwrap().into())).collect();
        assert_eq!(regs["rax"], "rcx + 0x10");
        assert_eq!(regs["rbx"], "5");
        assert_eq!(r["end"]["kind"], "ret");
        let dead: Vec<&str> = r["instructions"].as_array().unwrap().iter().filter(|i| i["live"] == false).map(|i| i["text"].as_str().unwrap()).collect();
        assert!(dead.iter().any(|t| t.starts_with("xor")), "{dead:?}");
    }

    #[test]
    fn opaque_predicate_and_mba_obfuscated_add() {
        // rax = (rcx|rdx) + (rcx&rdx)  [== rcx+rdx]; cmp rax, rax ; je +0
        //   mov rax,rcx ; or rax,rdx ; mov r8,rcx ; and r8,rdx ; add rax,r8 ; mov r9,rax ; cmp r9,rax ; je
        let code = Bytes(0x2000, hx("4889c8 4809d0 4989c8 4921d0 4c01c0 4989c1 4939c1 7400"));
        let r = lift_block(&code, 0x2000, 64);
        let rax = r["registers"].as_array().unwrap().iter().find(|v| v["register"] == "rax").unwrap()["value"].as_str().unwrap().to_owned();
        assert_eq!(rax, "rcx + rdx");
        assert_eq!(r["end"]["opaque"], "always taken", "{r}");
    }

    #[test]
    fn trace_deobfuscation_and_stack_memory() {
        // push rcx ; mov rcx, 0x1234 (junk) ; pop rax ; inc rax ; push rbx ; pop rbx ; ret-less end
        let code = Bytes(0x3000, hx("51 48c7c134120000 58 48ffc0 53 5b"));
        let t = linear(&code);
        let r = lift_trace(&code, &t, 100);
        let regs: HashMap<String, String> = r["registers"].as_array().unwrap().iter().map(|v| (v["register"].as_str().unwrap().into(), v["value"].as_str().unwrap().into())).collect();
        assert_eq!(regs["rax"], "rcx + 1", "{r}");
        assert_eq!(regs["rcx"], "0x1234");
        assert!(r["removed"].as_u64().unwrap() >= 2, "push rbx / pop rbx are junk: {r}");
    }

    #[test]
    fn folds_a_decryption_loop() {
        // loop: mov al,[rsi+rcx] ; xor al,0x5a ; mov [rdi+rcx],al ; inc rcx ; cmp rcx,rdx ; jb loop
        let code = Bytes(0x4000, hx("8a040e 345a 88040f 48ffc1 4839d1 72f1"));
        let body: Vec<u64> = linear(&code);
        // rcx starts as a symbol: give it 0 with a preceding xor ecx,ecx is not in the bytes, so
        // emulate the effect by starting from a machine with rcx = 0
        let mut m = Machine::new();
        m.regs[1] = c(0);
        let mut info = InstructionInfoFactory::new();
        for _ in 0..8 {
            for a in &body {
                let (ins, text) = decode(&code, *a).unwrap();
                m.exec(&ins, text, &mut info);
            }
        }
        let st = m.final_stores();
        assert_eq!(st.len(), 1, "{st:?}");
        assert_eq!(st[0].0, "rdi + i  for i in 0..0x8");
        assert_eq!(st[0].2, "[rsi + i].b ^ 0x5a", "{st:?}");
        assert!(m.changed_regs().iter().any(|(r, v)| r == "rcx" && v == "8"));
        // the trace listing shows the body once with a repeat marker
        let t: Vec<u64> = (0..8).flat_map(|_| body.clone()).collect();
        let r = lift_trace(&code, &t, 100);
        let marker = r["listing"].as_array().unwrap().iter().find(|e| e.get("loop").is_some()).cloned();
        assert!(marker.is_some_and(|m| m["times"].as_u64().unwrap() >= 7), "{r}");
    }

    #[test]
    fn finds_a_vm_dispatcher_and_handlers() {
        // a toy VM: rsi = VIP over bytecode, rdi = handler table base (unknown); dispatcher at 0x5000
        //   0x5000: movzx eax, byte [rsi] ; inc rsi ; jmp [rdi + rax*8]
        //   handler A @0x5100: add rbx, 1 ; jmp 0x5000
        //   handler B @0x5200: sub rbx, 2 ; jmp 0x5000
        //   handler C @0x5300: xor rbx, rcx ; jmp 0x5000
        let mut img = vec![0x90u8; 0x400];
        let put = |img: &mut Vec<u8>, o: usize, b: &[u8]| img[o..o + b.len()].copy_from_slice(b);
        put(&mut img, 0x000, &hx("0fb606 48ffc6 ff24c7"));
        let jmp_back = |from: u64| { let rel = (0x5000i64 - (from as i64 + 5)) as i32; let mut v = vec![0xe9]; v.extend(rel.to_le_bytes()); v };
        put(&mut img, 0x100, &hx("4883c301"));
        put(&mut img, 0x104, &jmp_back(0x5104));
        put(&mut img, 0x200, &hx("4883eb02"));
        put(&mut img, 0x204, &jmp_back(0x5204));
        put(&mut img, 0x300, &hx("4831cb"));
        put(&mut img, 0x303, &jmp_back(0x5303));
        let code = Bytes(0x5000, img);
        let disp = [0x5000, 0x5003, 0x5006];
        let mut t: Vec<u64> = disp.to_vec();
        for h in [0x5100u64, 0x5200, 0x5100, 0x5300, 0x5200, 0x5100] {
            let (body, jmp) = match h { 0x5100 => (0x5100, 0x5104), 0x5200 => (0x5200, 0x5204), _ => (0x5300, 0x5303) };
            t.extend([body, jmp]);
            t.extend(disp);
        }
        let r = devirt(&code, &t, 100);
        assert_eq!(r["dispatcher"], "0x5006", "{r}");
        assert_eq!(r["handlers"].as_array().unwrap().len(), 3);
        assert_eq!(r["virtual_trace"], json!([0, 1, 0, 2, 1, 0]));
        let h0 = &r["handlers"][0];
        assert!(h0["registers"].as_array().unwrap().iter().any(|v| v["register"] == "rbx" && v["value"] == "rbx + 1"), "{h0}");
        assert_eq!(r["vip_register"], "rsi");
    }
}
