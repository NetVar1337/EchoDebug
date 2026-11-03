//! x64dbg-style extras for both native debuggers (`local_dbg.rs` on Linux, `windbg.rs` on
//! Windows), all pure logic over a memory-read callback so it is unit-tested on any host:
//!
//! * the **expression language** of x64dbg's command bar and breakpoint conditions: registers and
//!   sub-registers (`rax`, `eax`, `al`, `ah`, `r8d`, …, `cip` / `csp` aliases), flags (`_zf`, `zf`,
//!   …), numbers in **hex by default** (`10` is 0x10, `.10` is decimal ten, `0x` allowed),
//!   memory (`[expr]` reads a qword, `byte:[…]` / `word:[…]` / `dword:[…]` / `qword:[…]`),
//!   `+ - * / % & | ^ ~ ! << >> == != < <= > >= && ||` with C precedence (unsigned),
//!   variables `$hits` (alias `$breakpointcounter`), `$tid`, `$pid`, module names (their base),
//!   string literals and the functions `arg(n)` / `arg.get(n)` (n-th argument at function entry),
//!   `ReadByte/Word/Dword/Qword/Ptr` (also `byte()` …), `mem.valid`, `mod.base` (of an address,
//!   or of a module named by a string, for names with a '-'), `utf8` / `ansi` / `utf16` /
//!   `str` (string at an address), `strlen`, `streq`, `strieq`, `strstr`, `stristr`;
//! * **log format strings** (`hit {d:$hits}: {s:arg(0)} rcx={rcx}`): `{expr}` and `{x:expr}` hex,
//!   `{p:expr}` padded pointer, `{d:…}` signed and `{u:…}` unsigned decimal, `{s:…}` string at the
//!   address, `{a:…}` address as `module+0x…`, `{i:…}` the instruction there, `{{` / `}}` braces;
//! * the **breakpoint table**: per-breakpoint break condition, log text, log condition, hit
//!   counter and single-shot flag, plus the temporary breakpoints behind step over / step out /
//!   run to cursor (bound to a thread and a stack depth so recursion does not stop early);
//! * **stepping plans** (what step over and step out run to) and the annotated **stack view**.

use std::collections::{BTreeMap, VecDeque};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter};
use serde_json::{json, Map, Value};

use crate::dbg_core::{arg as call_arg, hex, Abi, Gprs, ReadFn};
use crate::local::MapLine;

// ---- expressions ---------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Num(u64),
    Str(String),
}

impl Val {
    fn num(&self) -> Result<u64, String> {
        match self {
            Val::Num(n) => Ok(*n),
            Val::Str(s) => Err(format!("\"{s}\" is a string, not a number")),
        }
    }

    pub fn truthy(&self) -> bool {
        match self {
            Val::Num(n) => *n != 0,
            Val::Str(s) => !s.is_empty(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Num(u64),
    Word(String),
    Str(String),
    Op(&'static str),
}

const OPS: [&str; 26] = [
    "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "<", ">", "(", ")", "[", "]", ",", ":",
];

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '@')
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let cs: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '"' {
            let mut s = String::new();
            i += 1;
            loop {
                match cs.get(i) {
                    None => return Err("unterminated string".into()),
                    Some('"') => break,
                    Some('\\') => {
                        i += 1;
                        match cs.get(i) {
                            Some('n') => s.push('\n'),
                            Some('t') => s.push('\t'),
                            Some(c) => s.push(*c),
                            None => return Err("unterminated string".into()),
                        }
                    }
                    Some(c) => s.push(*c),
                }
                i += 1;
            }
            i += 1;
            out.push(Tok::Str(s));
            continue;
        }
        if is_word_char(c) {
            let start = i;
            while i < cs.len() && is_word_char(cs[i]) {
                i += 1;
            }
            let w: String = cs[start..i].iter().collect();
            out.push(number(&w).map(Tok::Num).unwrap_or(Tok::Word(w)));
            continue;
        }
        let rest: String = cs[i..cs.len().min(i + 2)].iter().collect();
        let Some(op) = OPS.iter().find(|o| rest.starts_with(**o)) else { return Err(format!("unexpected '{c}'")) };
        out.push(Tok::Op(op));
        i += op.chars().count();
    }
    Ok(out)
}

/// x64dbg number syntax: hex by default, `0x` prefix allowed, `.digits` is decimal.
fn number(w: &str) -> Option<u64> {
    if let Some(d) = w.strip_prefix('.') {
        return (!d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())).then(|| d.parse().ok()).flatten();
    }
    let h = w.strip_prefix("0x").or_else(|| w.strip_prefix("0X")).unwrap_or(w);
    (!h.is_empty() && h.len() <= 16 && h.bytes().all(|b| b.is_ascii_hexdigit())).then(|| u64::from_str_radix(h, 16).ok()).flatten()
}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Num(u64),
    Str(String),
    Ident(String),
    /// size in bytes, address
    Mem(u8, Box<Expr>),
    Unary(&'static str, Box<Expr>),
    Bin(&'static str, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
}

/// Binary operators from the loosest to the tightest binding.
const LEVELS: [&[&str]; 10] = [&["||"], &["&&"], &["|"], &["^"], &["&"], &["==", "!="], &["<", "<=", ">", ">="], &["<<", ">>"], &["+", "-"], &["*", "/", "%"]];

struct Parser {
    toks: Vec<Tok>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at)
    }

    fn eat(&mut self, op: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Op(o)) if *o == op) {
            self.at += 1;
            return true;
        }
        false
    }

    fn expect(&mut self, op: &str) -> Result<(), String> {
        if self.eat(op) {
            Ok(())
        } else {
            Err(format!("expected '{op}'"))
        }
    }

    fn binary(&mut self, level: usize) -> Result<Expr, String> {
        if level == LEVELS.len() {
            return self.unary();
        }
        let mut lhs = self.binary(level + 1)?;
        while let Some(Tok::Op(o)) = self.peek() {
            let Some(op) = LEVELS[level].iter().find(|x| **x == *o).copied() else { break };
            self.at += 1;
            let rhs = self.binary(level + 1)?;
            lhs = Expr::Bin(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        for op in ["-", "!", "~", "+"] {
            if self.eat(op) {
                let e = self.unary()?;
                return Ok(if op == "+" { e } else { Expr::Unary(op, Box::new(e)) });
            }
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        let Some(t) = self.toks.get(self.at).cloned() else { return Err("unexpected end of expression".into()) };
        self.at += 1;
        match t {
            Tok::Num(n) => Ok(Expr::Num(n)),
            Tok::Str(s) => Ok(Expr::Str(s)),
            Tok::Op("(") => {
                let e = self.binary(0)?;
                self.expect(")")?;
                Ok(e)
            }
            Tok::Op("[") => {
                let e = self.binary(0)?;
                self.expect("]")?;
                Ok(Expr::Mem(8, Box::new(e)))
            }
            Tok::Word(w) => {
                let lw = w.to_ascii_lowercase();
                let size = match lw.as_str() {
                    "byte" => Some(1),
                    "word" => Some(2),
                    "dword" => Some(4),
                    "qword" | "ptr" => Some(8),
                    _ => None,
                };
                if let Some(sz) = size {
                    if self.eat(":") {
                        self.expect("[")?;
                        let e = self.binary(0)?;
                        self.expect("]")?;
                        return Ok(Expr::Mem(sz, Box::new(e)));
                    }
                }
                if self.eat("(") {
                    let mut args = Vec::new();
                    if !self.eat(")") {
                        loop {
                            args.push(self.binary(0)?);
                            if self.eat(")") {
                                break;
                            }
                            self.expect(",")?;
                        }
                    }
                    return Ok(Expr::Call(lw, args));
                }
                Ok(Expr::Ident(w))
            }
            Tok::Op(o) => Err(format!("unexpected '{o}'")),
        }
    }
}

/// A parsed expression; evaluate it with [`Compiled::eval`].
#[derive(Clone, Debug, PartialEq)]
pub struct Compiled(Expr);

pub fn parse(src: &str) -> Result<Compiled, String> {
    let toks = lex(src)?;
    if toks.is_empty() {
        return Err("empty expression".into());
    }
    let mut p = Parser { toks, at: 0 };
    let e = p.binary(0)?;
    if p.at != p.toks.len() {
        return Err(format!("unexpected {:?} after the expression", p.toks[p.at]));
    }
    Ok(Compiled(e))
}

/// What an expression can see: one stopped thread.
pub struct Ctx<'a> {
    pub regs: &'a Gprs,
    pub read: ReadFn<'a>,
    pub abi: Abi,
    pub tid: u64,
    pub pid: u32,
    /// the breakpoint's hit counter (`$hits`), 0 outside a breakpoint
    pub hits: u64,
    /// (name, base, size)
    pub modules: &'a [(String, u64, u64)],
}

fn register(regs: &Gprs, name: &str) -> Option<u64> {
    let full = |n: &str| -> Option<u64> {
        Some(match n {
            "rax" => regs.rax, "rbx" => regs.rbx, "rcx" => regs.rcx, "rdx" => regs.rdx,
            "rsi" => regs.rsi, "rdi" => regs.rdi, "rbp" => regs.rbp, "rsp" => regs.rsp,
            "r8" => regs.r8, "r9" => regs.r9, "r10" => regs.r10, "r11" => regs.r11,
            "r12" => regs.r12, "r13" => regs.r13, "r14" => regs.r14, "r15" => regs.r15,
            "rip" => regs.rip, "eflags" | "rflags" | "cflags" => regs.eflags,
            "fs_base" | "fsbase" => regs.fs_base, "gs_base" | "gsbase" => regs.gs_base,
            _ => return None,
        })
    };
    if let Some(v) = full(name) {
        return Some(v);
    }
    // x64dbg's pointer-size aliases: cax, cbx, …, cip, csp
    if let Some(r) = name.strip_prefix('c').filter(|r| matches!(*r, "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" | "sp" | "ip")) {
        return full(&format!("r{r}"));
    }
    // legacy sub-registers
    let legacy = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
    for l in legacy {
        let r = full(&format!("r{l}"))?;
        if name == format!("e{l}") {
            return Some(r & 0xffff_ffff);
        }
        if name == l {
            return Some(r & 0xffff);
        }
    }
    for (l, n) in [("al", "rax"), ("bl", "rbx"), ("cl", "rcx"), ("dl", "rdx"), ("sil", "rsi"), ("dil", "rdi"), ("bpl", "rbp"), ("spl", "rsp")] {
        if name == l {
            return full(n).map(|v| v & 0xff);
        }
    }
    for (h, n) in [("ah", "rax"), ("bh", "rbx"), ("ch", "rcx"), ("dh", "rdx")] {
        if name == h {
            return full(n).map(|v| (v >> 8) & 0xff);
        }
    }
    // r8d / r8w / r8b
    if let Some(stem) = name.strip_prefix('r') {
        let (num, mask) = match stem.chars().last()? {
            'd' => (&stem[..stem.len() - 1], 0xffff_ffff),
            'w' => (&stem[..stem.len() - 1], 0xffff),
            'b' => (&stem[..stem.len() - 1], 0xff),
            _ => return None,
        };
        if num.parse::<u8>().is_ok_and(|n| (8..=15).contains(&n)) {
            return full(&format!("r{num}")).map(|v| v & mask);
        }
    }
    None
}

fn flag(regs: &Gprs, name: &str) -> Option<u64> {
    let bit = match name.trim_start_matches('_') {
        "cf" => 0,
        "pf" => 2,
        "af" => 4,
        "zf" => 6,
        "sf" => 7,
        "tf" => 8,
        "if" => 9,
        "df" => 10,
        "of" => 11,
        _ => return None,
    };
    Some((regs.eflags >> bit) & 1)
}

fn read_exact(ctx: &Ctx, addr: u64, buf: &mut [u8]) -> Result<(), String> {
    if (ctx.read)(addr, buf) == buf.len() {
        Ok(())
    } else {
        Err(format!("cannot read {} byte(s) at {}", buf.len(), hex(addr)))
    }
}

fn read_sized(ctx: &Ctx, addr: u64, size: u8) -> Result<u64, String> {
    let mut b = [0u8; 8];
    read_exact(ctx, addr, &mut b[..size as usize])?;
    Ok(u64::from_le_bytes(b))
}

const MAX_STR: usize = 512;

fn read_ansi(read: ReadFn, addr: u64) -> Option<String> {
    let mut b = vec![0u8; MAX_STR];
    let n = read(addr, &mut b);
    if n == 0 {
        return None;
    }
    let end = b[..n].iter().position(|c| *c == 0).unwrap_or(n);
    Some(String::from_utf8_lossy(&b[..end]).into_owned())
}

fn read_utf16(read: ReadFn, addr: u64) -> Option<String> {
    let mut b = vec![0u8; MAX_STR * 2];
    let n = read(addr, &mut b) / 2;
    if n == 0 {
        return None;
    }
    let units: Vec<u16> = (0..n).map(|i| u16::from_le_bytes([b[2 * i], b[2 * i + 1]])).take_while(|u| *u != 0).collect();
    Some(String::from_utf16_lossy(&units))
}

/// A printable string at `addr`, as UTF-16 when it looks like one (ASCII then NUL), else UTF-8.
/// `None` unless it has at least `min` printable characters.
pub fn guess_string(read: ReadFn, addr: u64, min: usize) -> Option<(String, bool)> {
    let printable = |s: &str| s.chars().count() >= min && s.chars().all(|c| !c.is_control() || c == '\t' || c == '\n' || c == '\r');
    let mut head = [0u8; 4];
    if read(addr, &mut head) == 4 && head[0] != 0 && head[1] == 0 && head[2] != 0 && head[3] == 0 {
        if let Some(s) = read_utf16(read, addr).filter(|s| printable(s)) {
            return Some((s, true));
        }
    }
    read_ansi(read, addr).filter(|s| printable(s) && !s.contains('\u{fffd}')).map(|s| (s, false))
}

fn want_args(name: &str, args: &[Val], n: usize) -> Result<(), String> {
    if args.len() == n {
        Ok(())
    } else {
        Err(format!("{name}() takes {n} argument(s), got {}", args.len()))
    }
}

fn want_str(name: &str, v: &Val, ctx: &Ctx) -> Result<String, String> {
    match v {
        Val::Str(s) => Ok(s.clone()),
        // a number is an address: the string there
        Val::Num(a) => guess_string(ctx.read, *a, 0).map(|s| s.0).ok_or_else(|| format!("{name}(): no string at {}", hex(*a))),
    }
}

impl Compiled {
    pub fn eval(&self, ctx: &Ctx) -> Result<Val, String> {
        eval(&self.0, ctx)
    }

    /// The expression as a number (strings are an error).
    pub fn eval_num(&self, ctx: &Ctx) -> Result<u64, String> {
        self.eval(ctx)?.num()
    }
}

fn eval(e: &Expr, ctx: &Ctx) -> Result<Val, String> {
    Ok(match e {
        Expr::Num(n) => Val::Num(*n),
        Expr::Str(s) => Val::Str(s.clone()),
        Expr::Ident(w) => Val::Num(ident(w, ctx)?),
        Expr::Mem(size, a) => {
            let a = eval(a, ctx)?.num()?;
            Val::Num(read_sized(ctx, a, *size)?)
        }
        Expr::Unary(op, x) => {
            let v = eval(x, ctx)?;
            match *op {
                "!" => Val::Num(!v.truthy() as u64),
                "-" => Val::Num(v.num()?.wrapping_neg()),
                _ => Val::Num(!v.num()?),
            }
        }
        Expr::Bin(op, a, b) => {
            // short-circuit: `[rcx] == 1 && …` must not read through a null pointer
            if *op == "&&" {
                return Ok(Val::Num((eval(a, ctx)?.truthy() && eval(b, ctx)?.truthy()) as u64));
            }
            if *op == "||" {
                return Ok(Val::Num((eval(a, ctx)?.truthy() || eval(b, ctx)?.truthy()) as u64));
            }
            let (x, y) = (eval(a, ctx)?, eval(b, ctx)?);
            if let (Val::Str(s), Val::Str(t)) = (&x, &y) {
                return match *op {
                    "==" => Ok(Val::Num((s == t) as u64)),
                    "!=" => Ok(Val::Num((s != t) as u64)),
                    "+" => Ok(Val::Str(format!("{s}{t}"))),
                    _ => Err(format!("'{op}' does not apply to strings")),
                };
            }
            let (x, y) = (x.num()?, y.num()?);
            Val::Num(match *op {
                "+" => x.wrapping_add(y),
                "-" => x.wrapping_sub(y),
                "*" => x.wrapping_mul(y),
                "/" => x.checked_div(y).ok_or("division by zero")?,
                "%" => x.checked_rem(y).ok_or("division by zero")?,
                "&" => x & y,
                "|" => x | y,
                "^" => x ^ y,
                "<<" => x.checked_shl(y as u32).unwrap_or(0),
                ">>" => x.checked_shr(y as u32).unwrap_or(0),
                "==" => (x == y) as u64,
                "!=" => (x != y) as u64,
                "<" => (x < y) as u64,
                "<=" => (x <= y) as u64,
                ">" => (x > y) as u64,
                ">=" => (x >= y) as u64,
                _ => return Err(format!("unknown operator {op}")),
            })
        }
        Expr::Call(name, args) => {
            let vals = args.iter().map(|a| eval(a, ctx)).collect::<Result<Vec<_>, _>>()?;
            call(name, &vals, ctx)?
        }
    })
}

fn ident(w: &str, ctx: &Ctx) -> Result<u64, String> {
    let lw = w.to_ascii_lowercase();
    if let Some(v) = register(ctx.regs, &lw).or_else(|| flag(ctx.regs, &lw)) {
        return Ok(v);
    }
    match lw.as_str() {
        "$hits" | "$breakpointcounter" | "$hitcount" => return Ok(ctx.hits),
        "$tid" => return Ok(ctx.tid),
        "$pid" => return Ok(ctx.pid as u64),
        "$ip" => return Ok(ctx.regs.rip),
        "$sp" => return Ok(ctx.regs.rsp),
        _ => {}
    }
    if let Some(base) = module_named(&lw, ctx.modules) {
        return Ok(base);
    }
    Err(format!("unknown symbol '{w}' (numbers are hex: write .{w} for decimal; a module name with '-' needs mod.base(\"name\"))"))
}

/// A module's base by name: with or without the extension, any case.
fn module_named(name: &str, modules: &[(String, u64, u64)]) -> Option<u64> {
    let lw = name.to_ascii_lowercase();
    modules.iter().find_map(|(n, base, _)| {
        let s = n.rsplit(['/', '\\']).next().unwrap_or(n).to_ascii_lowercase();
        (s == lw || s.split('.').next() == Some(lw.as_str())).then_some(*base)
    })
}

fn call(name: &str, a: &[Val], ctx: &Ctx) -> Result<Val, String> {
    let num = |i: usize| a.get(i).ok_or_else(|| format!("{name}() is missing an argument")).and_then(Val::num);
    Ok(match name {
        "arg" | "arg.get" => {
            want_args(name, a, 1)?;
            Val::Num(call_arg(ctx.abi, ctx.regs, ctx.read, num(0)? as usize))
        }
        "readbyte" | "byte" | "readword" | "word" | "readdword" | "dword" | "readqword" | "qword" | "readptr" | "ptr" => {
            want_args(name, a, 1)?;
            let size = match name.trim_start_matches("read") {
                "byte" => 1,
                "word" => 2,
                "dword" => 4,
                _ => 8,
            };
            Val::Num(read_sized(ctx, num(0)?, size)?)
        }
        // x64dbg's mod.base(addr); also mod.base("name") for names an expression cannot spell
        "mod.base" => {
            want_args(name, a, 1)?;
            Val::Num(match &a[0] {
                Val::Str(m) => module_named(m, ctx.modules).ok_or_else(|| format!("no module named {m}"))?,
                Val::Num(x) => ctx.modules.iter().find(|(_, b, s)| *b <= *x && *x < b.saturating_add(*s)).map(|m| m.1).ok_or_else(|| format!("{} is in no module", hex(*x)))?,
            })
        }
        "mem.valid" | "valid" => {
            want_args(name, a, 1)?;
            let mut b = [0u8; 1];
            Val::Num(((ctx.read)(num(0)?, &mut b) == 1) as u64)
        }
        "utf8" | "ansi" => {
            want_args(name, a, 1)?;
            let p = num(0)?;
            Val::Str(read_ansi(ctx.read, p).ok_or_else(|| format!("cannot read a string at {}", hex(p)))?)
        }
        "utf16" => {
            want_args(name, a, 1)?;
            let p = num(0)?;
            Val::Str(read_utf16(ctx.read, p).ok_or_else(|| format!("cannot read a string at {}", hex(p)))?)
        }
        "str" => {
            want_args(name, a, 1)?;
            Val::Str(want_str(name, &a[0], ctx)?)
        }
        "strlen" => {
            want_args(name, a, 1)?;
            Val::Num(want_str(name, &a[0], ctx)?.chars().count() as u64)
        }
        "streq" | "strieq" | "strstr" | "stristr" => {
            want_args(name, a, 2)?;
            let (mut s, mut t) = (want_str(name, &a[0], ctx)?, want_str(name, &a[1], ctx)?);
            if name.starts_with("stri") {
                (s, t) = (s.to_lowercase(), t.to_lowercase());
            }
            let r = if name.ends_with("eq") { s == t } else { s.contains(&t) };
            Val::Num(r as u64)
        }
        _ => return Err(format!("unknown function {name}()")),
    })
}

// ---- log format strings -------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Seg {
    Text(String),
    Field(char, Compiled),
}

/// A parsed log format string.
#[derive(Clone, Debug, PartialEq)]
pub struct Format(Vec<Seg>);

pub fn parse_format(src: &str) -> Result<Format, String> {
    let mut segs = Vec::new();
    let mut text = String::new();
    let cs: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '{' if cs.get(i + 1) == Some(&'{') => {
                text.push('{');
                i += 2;
            }
            '}' if cs.get(i + 1) == Some(&'}') => {
                text.push('}');
                i += 2;
            }
            '{' => {
                let Some(len) = cs[i + 1..].iter().position(|c| *c == '}') else { return Err("unclosed '{' in the log text".into()) };
                let inner: String = cs[i + 1..i + 1 + len].iter().collect();
                let (kind, expr) = match inner.split_once(':') {
                    Some((k, e)) if k.len() == 1 && "xpdusai".contains(k) => (k.chars().next().unwrap_or('x'), e),
                    _ => ('x', inner.as_str()),
                };
                let c = parse(expr).map_err(|e| format!("{{{inner}}}: {e}"))?;
                if !text.is_empty() {
                    segs.push(Seg::Text(std::mem::take(&mut text)));
                }
                segs.push(Seg::Field(kind, c));
                i += len + 2;
            }
            c => {
                text.push(c);
                i += 1;
            }
        }
    }
    if !text.is_empty() {
        segs.push(Seg::Text(text));
    }
    Ok(Format(segs))
}

/// `module+0x10` when `addr` lies in a module, else the hex address.
pub fn symbolize(addr: u64, modules: &[(String, u64, u64)]) -> String {
    match modules.iter().find(|(_, b, s)| *b <= addr && addr < b.saturating_add(*s)) {
        Some((n, b, _)) => format!("{}+{:#x}", n.rsplit(['/', '\\']).next().unwrap_or(n), addr - b),
        None => hex(addr),
    }
}

/// One instruction at `addr` in Intel syntax.
pub fn insn_text(read: ReadFn, addr: u64) -> Option<(String, usize)> {
    let mut b = [0u8; 16];
    let n = read(addr, &mut b);
    if n == 0 {
        return None;
    }
    let mut dec = Decoder::with_ip(64, &b[..n], addr, DecoderOptions::NONE);
    let ins = dec.decode();
    if ins.is_invalid() {
        return None;
    }
    let mut f = IntelFormatter::new();
    let mut out = String::new();
    f.format(&ins, &mut out);
    Some((out, ins.len()))
}

impl Format {
    pub fn render(&self, ctx: &Ctx) -> String {
        let mut out = String::new();
        for s in &self.0 {
            match s {
                Seg::Text(t) => out.push_str(t),
                Seg::Field(kind, e) => match e.eval(ctx) {
                    Err(err) => out.push_str(&format!("{{error: {err}}}")),
                    Ok(Val::Str(s)) => out.push_str(&s),
                    Ok(Val::Num(v)) => out.push_str(&match kind {
                        'd' => (v as i64).to_string(),
                        'u' => v.to_string(),
                        'p' => format!("{v:016X}"),
                        's' => match guess_string(ctx.read, v, 0) {
                            Some((s, _)) => format!("\"{s}\""),
                            None => format!("{{no string at {}}}", hex(v)),
                        },
                        'a' => symbolize(v, ctx.modules),
                        'i' => insn_text(ctx.read, v).map(|i| i.0).unwrap_or_else(|| format!("{{no instruction at {}}}", hex(v))),
                        _ => format!("{v:X}"),
                    }),
                },
            }
        }
        out
    }
}

// ---- the breakpoint table -----------------------------------------------------------------------

/// What a software breakpoint does when it is hit (x64dbg's Edit breakpoint dialog).
#[derive(Clone, Debug, Default)]
pub struct BpOpts {
    /// break only when this is non-zero (empty: always)
    pub condition: String,
    /// log this format string on a hit (empty: nothing)
    pub log: String,
    /// log only when this is non-zero (empty: always)
    pub log_condition: String,
    /// remove the breakpoint the first time it breaks
    pub once: bool,
    pub hits: u64,
    cond: Option<Compiled>,
    log_fmt: Option<Format>,
    log_cond: Option<Compiled>,
}

impl BpOpts {
    /// Validates and compiles the expressions.
    pub fn new(condition: &str, log: &str, log_condition: &str, once: bool) -> Result<BpOpts, String> {
        let opt = |s: &str, what: &str| -> Result<Option<Compiled>, String> {
            if s.trim().is_empty() {
                Ok(None)
            } else {
                parse(s).map(Some).map_err(|e| format!("{what}: {e}"))
            }
        };
        Ok(BpOpts {
            cond: opt(condition, "break condition")?,
            log_cond: opt(log_condition, "log condition")?,
            log_fmt: if log.is_empty() { None } else { Some(parse_format(log).map_err(|e| format!("log text: {e}"))?) },
            condition: condition.trim().to_owned(),
            log: log.to_owned(),
            log_condition: log_condition.trim().to_owned(),
            once,
            hits: 0,
        })
    }

    pub fn to_json(&self, addr: u64) -> Value {
        json!({ "address": hex(addr), "condition": self.condition, "log": self.log, "log_condition": self.log_condition, "once": self.once, "hits": self.hits })
    }
}

/// A one-shot breakpoint behind step over / step out / run to cursor.
#[derive(Clone, Debug, PartialEq)]
pub struct Temp {
    pub addr: u64,
    /// only this thread stops on it
    pub tid: Option<u64>,
    /// only once the stack is back at this depth (rsp >= min_rsp): a recursive call passing the
    /// same return address deeper down does not count
    pub min_rsp: Option<u64>,
    /// the stop reason: step_over, step_out, run_to
    pub reason: &'static str,
}

/// What to do with a thread that hit an int3 of the table.
#[derive(Debug, PartialEq)]
pub struct Outcome {
    /// stop the process (else step the thread past the int3 and run on)
    pub stop: bool,
    /// the dbg_stop reason and extra fields
    pub reason: &'static str,
    pub extra: Value,
    /// `dbg_log` events to broadcast
    pub events: Vec<Value>,
    /// a single-shot user breakpoint fired: remove it
    pub remove: bool,
}

const LOG_KEEP: usize = 5000;

#[derive(Default)]
pub struct Breaks {
    pub opts: BTreeMap<u64, BpOpts>,
    pub temps: Vec<Temp>,
    log: VecDeque<Value>,
    next: u64,
}

impl Breaks {
    pub fn is_temp(&self, addr: u64) -> bool {
        self.temps.iter().any(|t| t.addr == addr)
    }

    /// Ends a run-to: every temporary breakpoint is dropped; returns their addresses.
    pub fn take_temps(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.temps).into_iter().map(|t| t.addr).collect()
    }

    /// Forgets every breakpoint option and temporary breakpoint (the log stays).
    pub fn reset(&mut self) {
        self.opts.clear();
        self.temps.clear();
    }

    pub fn list_json(&self, user: impl IntoIterator<Item = u64>) -> Value {
        Value::Array(user.into_iter().map(|a| self.opts.get(&a).cloned().unwrap_or_default().to_json(a)).collect())
    }

    /// A thread hit the int3 at `addr` (`user`: a user breakpoint sits there). `ctx.regs.rip` is
    /// the breakpoint address.
    pub fn hit(&mut self, addr: u64, user: bool, ctx: &mut Ctx) -> Outcome {
        let mut out = Outcome { stop: false, reason: "breakpoint", extra: json!({}), events: Vec::new(), remove: false };
        if user {
            let o = self.opts.entry(addr).or_default();
            o.hits += 1;
            ctx.hits = o.hits;
            let brk = match &o.cond {
                None => Ok(true),
                Some(c) => c.eval(ctx).map(|v| v.truthy()),
            };
            match brk {
                Ok(b) => out.stop = b,
                Err(e) => {
                    // a condition that cannot be evaluated breaks, and says why
                    out.stop = true;
                    out.extra = json!({ "condition_error": e });
                }
            }
            out.extra["hits"] = json!(o.hits);
            if let Some(f) = &o.log_fmt {
                let log = match &o.log_cond {
                    None => true,
                    Some(c) => c.eval(ctx).map(|v| v.truthy()).unwrap_or(true),
                };
                if log {
                    let text = f.render(ctx);
                    self.next += 1;
                    let ev = json!({ "type": "event", "event": "dbg_log", "seq": self.next, "t": now_ms(), "tid": ctx.tid, "address": hex(addr), "hits": o.hits, "text": text });
                    out.events.push(ev.clone());
                    self.log.push_back(ev);
                    while self.log.len() > LOG_KEEP {
                        self.log.pop_front();
                    }
                }
            }
            out.remove = out.stop && o.once;
        }
        if !out.stop {
            if let Some(t) = self.temps.iter().find(|t| t.addr == addr && t.tid.is_none_or(|x| x == ctx.tid) && t.min_rsp.is_none_or(|m| ctx.regs.rsp >= m)) {
                out.stop = true;
                out.reason = t.reason;
            }
        }
        out
    }

    pub fn log_json(&self, since: u64, limit: usize) -> Value {
        let entries: Vec<&Value> = self.log.iter().filter(|e| e["seq"].as_u64().unwrap_or(0) > since).take(limit).collect();
        let next = entries.last().and_then(|e| e["seq"].as_u64()).unwrap_or(since);
        json!({ "entries": entries, "next": next, "total": self.next })
    }

    pub fn clear_log(&mut self) {
        self.log.clear();
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Parses `dbg_break`'s options. `None` when the request sets none (keep what is there).
pub fn parse_opts(req: &Map<String, Value>, old: Option<&BpOpts>) -> Result<Option<BpOpts>, String> {
    let keys = ["condition", "log", "log_condition", "once"];
    if !keys.iter().any(|k| req.contains_key(*k)) && !req.contains_key("reset_hits") {
        return Ok(None);
    }
    let s = |k: &str, prev: Option<&String>| req.get(k).and_then(Value::as_str).map(str::to_owned).or_else(|| prev.cloned()).unwrap_or_default();
    let mut o = BpOpts::new(
        &s("condition", old.map(|o| &o.condition)),
        &s("log", old.map(|o| &o.log)),
        &s("log_condition", old.map(|o| &o.log_condition)),
        req.get("once").and_then(Value::as_bool).unwrap_or(old.is_some_and(|o| o.once)),
    )?;
    if req.get("reset_hits") != Some(&json!(true)) {
        o.hits = old.map(|o| o.hits).unwrap_or(0);
    }
    Ok(Some(o))
}

// ---- stepping plans -----------------------------------------------------------------------------

/// Step over: a `call` (any form) or a `rep`-prefixed string instruction runs to the instruction
/// after it on this thread; anything else is a plain single step (`None`).
pub fn step_over_target(read: ReadFn, regs: &Gprs, tid: u64) -> Option<Temp> {
    let mut b = [0u8; 16];
    let n = read(regs.rip, &mut b);
    let mut dec = Decoder::with_ip(64, &b[..n], regs.rip, DecoderOptions::NONE);
    let ins = dec.decode();
    if ins.is_invalid() {
        return None;
    }
    let over = matches!(ins.flow_control(), FlowControl::Call | FlowControl::IndirectCall)
        || ((ins.has_rep_prefix() || ins.has_repe_prefix() || ins.has_repne_prefix()) && ins.is_string_instruction());
    over.then(|| Temp { addr: ins.next_ip(), tid: Some(tid), min_rsp: Some(regs.rsp), reason: "step_over" })
}

struct ReadMem<'a>(ReadFn<'a>);

impl crate::unwind::Memory for ReadMem<'_> {
    fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        (self.0)(addr, buf) == buf.len()
    }
}

fn unwind_regs(regs: &Gprs) -> crate::unwind::Regs {
    let mut r = crate::unwind::Regs::new(regs.rip, regs.rsp, regs.rbp);
    for (n, v) in [
        ("rax", regs.rax), ("rcx", regs.rcx), ("rdx", regs.rdx), ("rbx", regs.rbx), ("rsi", regs.rsi), ("rdi", regs.rdi),
        ("r8", regs.r8), ("r9", regs.r9), ("r10", regs.r10), ("r11", regs.r11), ("r12", regs.r12), ("r13", regs.r13), ("r14", regs.r14), ("r15", regs.r15),
    ] {
        r.by_name(n, v);
    }
    r
}

fn unwind_modules(modules: &[(String, u64, u64)]) -> Vec<crate::unwind::ModuleInfo> {
    modules.iter().map(|(n, b, s)| crate::unwind::ModuleInfo { name: n.clone(), base: *b, size: *s }).collect()
}

/// Step out (x64dbg's "execute till return", WinDbg's `gu`): the caller's frame from the unwinder
/// (.pdata / .eh_frame, else frame pointer or stack scan). Returns the temporary breakpoint and how
/// the return address was found.
pub fn step_out_target(read: ReadFn, regs: &Gprs, tid: u64, modules: &[(String, u64, u64)]) -> Result<(Temp, Value), String> {
    let mem = ReadMem(read);
    let mut un = crate::unwind::Unwinder::new(&mem, unwind_modules(modules));
    let frames = un.walk(&unwind_regs(regs), 2);
    let Some(caller) = frames.get(1) else { return Err(format!("no caller found for {} (no unwind data, frame pointer or return address on the stack)", hex(regs.rip))) };
    let how = json!({ "return_to": hex(caller.pc), "return_to_text": symbolize(caller.pc, modules), "method": caller.method.as_str(), "guessed": caller.guessed });
    Ok((Temp { addr: caller.pc, tid: Some(tid), min_rsp: Some(caller.sp), reason: "step_out" }, how))
}

// ---- the stack view -----------------------------------------------------------------------------

/// `count` qwords from `from` (default rsp), each annotated like x64dbg's stack pane: the return
/// address of a call-stack frame, a return address (follows a `call`), a code pointer, a pointer
/// into the stack, or a string.
pub fn stack_view(read: ReadFn, regs: &Gprs, from: Option<u64>, count: usize, modules: &[(String, u64, u64)], maps: &[MapLine]) -> Value {
    let start = from.unwrap_or(regs.rsp) & !7;
    let mem = ReadMem(read);
    let mut un = crate::unwind::Unwinder::new(&mem, unwind_modules(modules));
    // frame n's return address sits just below the caller's stack pointer
    let frames = un.walk(&unwind_regs(regs), 64);
    let ret_slots: BTreeMap<u64, usize> = frames.iter().enumerate().skip(1).filter(|(_, f)| !f.guessed).map(|(i, f)| (f.sp.wrapping_sub(8), i)).collect();
    let stack = maps.iter().find(|m| m.start <= regs.rsp && regs.rsp < m.end).map(|m| (m.start, m.end));
    let exec = |a: u64| maps.iter().any(|m| m.executable && m.start <= a && a < m.end);
    let mut rows = Vec::with_capacity(count);
    for i in 0..count.clamp(1, 1024) {
        let at = start.wrapping_add(8 * i as u64);
        let Some(v) = crate::dbg_core::read_u64(read, at) else { break };
        let mut row = json!({ "address": hex(at), "value": hex(v), "offset": (at as i64).wrapping_sub(regs.rsp as i64) });
        if let Some(f) = ret_slots.get(&at) {
            row["kind"] = json!("return");
            row["frame"] = json!(f);
            row["text"] = json!(format!("return to {} from {}", symbolize(v, modules), symbolize(frames[*f - 1].pc, modules)));
        } else if exec(v) {
            let ret = un.after_call(v);
            row["kind"] = json!(if ret { "return" } else { "code" });
            row["text"] = json!(if ret { format!("return to {}", symbolize(v, modules)) } else { symbolize(v, modules) });
        } else if stack.is_some_and(|(lo, hi)| lo <= v && v < hi) {
            row["kind"] = json!("stack");
        } else if let Some((s, wide)) = (v > 0x10000).then(|| guess_string(read, v, 4)).flatten() {
            row["kind"] = json!("string");
            let short: String = s.chars().take(96).collect();
            row["text"] = json!(format!("{}\"{}\"", if wide { "L" } else { "" }, short.escape_debug()));
        }
        if at == regs.rsp {
            row["rsp"] = json!(true);
        }
        if at == regs.rbp {
            row["rbp"] = json!(true);
        }
        rows.push(row);
    }
    json!({ "rsp": hex(regs.rsp), "rbp": hex(regs.rbp), "entries": rows })
}

/// A backend's module list for expressions with the time it was read.
pub type ModCache = std::cell::RefCell<Option<(std::time::Instant, Vec<(String, u64, u64)>)>>;

/// What the read-only inspection verbs need from a debugger backend.
pub trait Host {
    /// target memory with breakpoint bytes hidden; bytes read
    fn host_read(&self, addr: u64, buf: &mut [u8]) -> usize;
    fn host_modules(&self) -> Vec<(String, u64, u64)>;
    fn host_maps(&self) -> Vec<MapLine>;
    fn host_pid(&self) -> u32;
}

/// `dbg_eval` / `dbg_format` / `dbg_stack` for a stopped thread of `h`.
pub fn inspect(h: &impl Host, abi: Abi, req: &Map<String, Value>, regs: &Gprs, tid: u64) -> Value {
    let verb = req.get("type").and_then(Value::as_str).unwrap_or_default();
    let read = |a: u64, b: &mut [u8]| h.host_read(a, b);
    let modules = h.host_modules();
    let ctx = Ctx { regs, read: &read, abi, tid, pid: h.host_pid(), hits: 0, modules: &modules };
    let text = |k: &str| req.get(k).and_then(Value::as_str).unwrap_or_default();
    let mut v = match verb {
        "dbg_eval" => eval_json(text("expr"), &ctx),
        "dbg_format" => format_json(text("text"), &ctx),
        _ => {
            let from = match req.get("address").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                None => None,
                Some(s) => match parse(s).and_then(|c| c.eval_num(&ctx)) {
                    Ok(a) => Some(a),
                    Err(e) => return crate::dbg_core::bad(&format!("address: {e}")),
                },
            };
            let count = req.get("count").and_then(Value::as_u64).unwrap_or(64).clamp(1, 1024) as usize;
            let mut v = stack_view(&read, regs, from, count, &modules, &h.host_maps());
            v["success"] = json!(true);
            v
        }
    };
    if v["type"] != "error" {
        v["type"] = json!(format!("{verb}_result"));
        v["tid"] = json!(tid);
    }
    v
}

/// `dbg_eval`: an expression over a stopped thread, as hex, unsigned and signed decimal (or a string).
pub fn eval_json(src: &str, ctx: &Ctx) -> Value {
    match parse(src).and_then(|c| c.eval(ctx)) {
        Ok(Val::Num(v)) => json!({ "success": true, "value": hex(v), "unsigned": v.to_string(), "signed": (v as i64).to_string(), "symbol": symbolize(v, ctx.modules) }),
        Ok(Val::Str(s)) => json!({ "success": true, "string": s }),
        Err(e) => json!({ "type": "error", "code": 3002, "message": "bad expression", "detail": e }),
    }
}

/// `dbg_format`: a log format string rendered against a stopped thread.
pub fn format_json(src: &str, ctx: &Ctx) -> Value {
    match parse_format(src) {
        Ok(f) => json!({ "success": true, "text": f.render(ctx) }),
        Err(e) => json!({ "type": "error", "code": 3002, "message": "bad format string", "detail": e }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem(base: u64, bytes: Vec<u8>) -> impl Fn(u64, &mut [u8]) -> usize {
        move |a: u64, buf: &mut [u8]| {
            if a < base || a >= base + bytes.len() as u64 {
                return 0;
            }
            let off = (a - base) as usize;
            let n = buf.len().min(bytes.len() - off);
            buf[..n].copy_from_slice(&bytes[off..off + n]);
            n
        }
    }

    fn regs() -> Gprs {
        Gprs { rax: 0x1122_3344_5566_7788, rcx: 0x1000, rdx: 2, rsp: 0x2000, rip: 0x401000, eflags: 0x246, r8: 0xffff_ffff_0000_0005, ..Default::default() }
    }

    fn image() -> Vec<u8> {
        // 0x1000: "hello\0", 0x1010: L"wide\0", 0x1020: qword 0x1000, 0x2000.. stack
        let mut m = vec![0u8; 0x1100];
        m[..6].copy_from_slice(b"hello\0");
        for (i, c) in "wide".encode_utf16().enumerate() {
            m[0x10 + 2 * i..0x12 + 2 * i].copy_from_slice(&c.to_le_bytes());
        }
        m[0x20..0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        // the stack at 0x2000 (offset 0x1000): return address, then win64 shadow space + args
        m[0x1000..0x1008].copy_from_slice(&0x40_1234u64.to_le_bytes());
        m[0x1028..0x1030].copy_from_slice(&0x77u64.to_le_bytes());
        m
    }

    fn ctx_eval(src: &str) -> Result<Val, String> {
        let r = regs();
        let m = mem(0x1000, image());
        let mods = vec![("C:\\app\\Game.exe".to_owned(), 0x40_0000u64, 0x10_0000u64)];
        let ctx = Ctx { regs: &r, read: &m, abi: Abi::Win64, tid: 7, pid: 42, hits: 3, modules: &mods };
        parse(src)?.eval(&ctx)
    }

    fn n(src: &str) -> u64 {
        match ctx_eval(src) {
            Ok(Val::Num(v)) => v,
            other => panic!("{src}: {other:?}"),
        }
    }

    #[test]
    fn numbers_are_hex_unless_dotted() {
        assert_eq!(n("10"), 0x10);
        assert_eq!(n(".10"), 10);
        assert_eq!(n("0x10"), 0x10);
        assert_eq!(n("ff+1"), 0x100);
        assert_eq!(n("-1"), u64::MAX);
    }

    #[test]
    fn registers_and_sub_registers() {
        assert_eq!(n("rax"), 0x1122_3344_5566_7788);
        assert_eq!(n("eax"), 0x5566_7788);
        assert_eq!(n("ax"), 0x7788);
        assert_eq!(n("al"), 0x88);
        assert_eq!(n("ah"), 0x77);
        assert_eq!(n("r8d"), 5);
        assert_eq!(n("r8w"), 5);
        assert_eq!(n("cip"), 0x401000);
        assert_eq!(n("RCX"), 0x1000);
        assert_eq!(n("zf"), 1);
        assert_eq!(n("_cf"), 0);
    }

    #[test]
    fn precedence_and_logic() {
        assert_eq!(n("1+2*3"), 7);
        assert_eq!(n("(1+2)*3"), 9);
        assert_eq!(n("1<<4|1"), 0x11);
        assert_eq!(n("rdx==2 && rcx==1000"), 1);
        assert_eq!(n("rdx==3 || !0"), 1);
        assert_eq!(n("~0 >> .60"), 0xf);
        assert_eq!(n("5 > 3 == 1"), 1);
        assert!(ctx_eval("1/0").unwrap_err().contains("division"));
    }

    #[test]
    fn short_circuit_skips_bad_reads() {
        assert_eq!(n("0 && [0]"), 0);
        assert!(ctx_eval("[0]").is_err());
    }

    #[test]
    fn memory_and_functions() {
        assert_eq!(n("[rcx+20]"), 0x1000);
        assert_eq!(n("byte:[rcx]"), b'h' as u64);
        assert_eq!(n("word:[rcx]"), u16::from_le_bytes(*b"he") as u64);
        assert_eq!(n("ReadDword(rcx)"), u32::from_le_bytes(*b"hell") as u64);
        assert_eq!(n("[[rcx+20]]"), u64::from_le_bytes(*b"hello\0\0\0"));
        assert_eq!(n("mem.valid(rcx)"), 1);
        assert_eq!(n("mem.valid(0)"), 0);
        // win64: arg 0 is rcx, arg 4 at [rsp+28]
        assert_eq!(n("arg(0)"), 0x1000);
        assert_eq!(n("arg.get(4)"), 0x77);
        assert_eq!(n("$hits"), 3);
        assert_eq!(n("$breakpointcounter == 3"), 1);
        assert_eq!(n("$tid"), 7);
        assert_eq!(n("$pid"), 42);
        assert_eq!(n("game"), 0x40_0000);
        assert_eq!(n("game.exe+10"), 0x40_0010);
        assert_eq!(n("mod.base(\"GAME.EXE\")"), 0x40_0000);
        assert_eq!(n("mod.base(rip)"), 0x40_0000);
        assert_eq!(n("rip - mod.base(rip)"), 0x1000);
        assert!(ctx_eval("mod.base(0)").unwrap_err().contains("no module"));
        assert!(ctx_eval("mod.base(\"nope\")").unwrap_err().contains("no module"));
    }

    #[test]
    fn strings() {
        assert_eq!(ctx_eval("utf8(rcx)").unwrap(), Val::Str("hello".into()));
        assert_eq!(ctx_eval("utf16(rcx+10)").unwrap(), Val::Str("wide".into()));
        assert_eq!(n("streq(utf8(rcx), \"hello\")"), 1);
        assert_eq!(n("strieq(rcx, \"HELLO\")"), 1);
        assert_eq!(n("stristr(rcx+10, \"ID\")"), 1);
        assert_eq!(n("strstr(rcx, \"xyz\")"), 0);
        assert_eq!(n("strlen(rcx)"), 5);
        assert_eq!(n("utf8(rcx) == \"hello\""), 1);
    }

    #[test]
    fn parse_errors_are_reported() {
        assert!(parse("").is_err());
        assert!(parse("1 +").is_err());
        assert!(parse("(1").is_err());
        assert!(parse("1 2").is_err());
        assert!(parse("\"abc").is_err());
        assert!(ctx_eval("nosuchthing").unwrap_err().contains("unknown symbol"));
        assert!(ctx_eval("nofn(1)").unwrap_err().contains("unknown function"));
        assert!(ctx_eval("arg()").unwrap_err().contains("takes 1"));
    }

    #[test]
    fn format_strings() {
        let r = regs();
        let m = mem(0x1000, image());
        let mut code = vec![0u8; 0x10];
        code[..3].copy_from_slice(&[0x48, 0x89, 0xc8]); // mov rax, rcx
        let c = mem(0x401000, code);
        let read = |a: u64, b: &mut [u8]| -> usize { if a >= 0x401000 { c(a, b) } else { m(a, b) } };
        let mods = vec![("/usr/bin/game".to_owned(), 0x40_0000u64, 0x10_0000u64)];
        let ctx = Ctx { regs: &r, read: &read, abi: Abi::SysV, tid: 1, pid: 1, hits: 12, modules: &mods };
        let f = parse_format("#{d:$hits} {s:rcx} {s:rcx+10} rdx={rdx} {u:-1} {d:-1} {p:rcx} {a:rip+4} {i:rip} {{x}}").unwrap();
        assert_eq!(f.render(&ctx), "#12 \"hello\" \"wide\" rdx=2 18446744073709551615 -1 0000000000001000 game+0x1004 mov rax,rcx {x}");
        assert!(parse_format("{rax").is_err());
        assert!(parse_format("{1 +}").is_err());
        assert!(parse_format("{[0]}").unwrap().render(&ctx).contains("error"));
    }

    #[test]
    fn conditional_and_logging_breakpoints() {
        let mut b = Breaks::default();
        b.opts.insert(0x401000, BpOpts::new("$hits >= 3", "hit {d:$hits} rcx={rcx}", "$hits % 2", false).unwrap());
        let r = regs();
        let m = mem(0x1000, image());
        let mut ctx = Ctx { regs: &r, read: &m, abi: Abi::Win64, tid: 9, pid: 1, hits: 0, modules: &[] };
        let o1 = b.hit(0x401000, true, &mut ctx);
        assert!(!o1.stop);
        assert_eq!(o1.events.len(), 1);
        assert_eq!(o1.events[0]["text"], "hit 1 rcx=1000");
        let o2 = b.hit(0x401000, true, &mut ctx);
        assert!(!o2.stop && o2.events.is_empty());
        let o3 = b.hit(0x401000, true, &mut ctx);
        assert!(o3.stop);
        assert_eq!(o3.extra["hits"], 3);
        assert_eq!(b.log_json(0, 10)["entries"].as_array().unwrap().len(), 2);
        assert_eq!(b.log_json(1, 10)["entries"][0]["seq"], 2);

        // a broken condition breaks and says why
        b.opts.insert(0x500, BpOpts::new("[0] == 1", "", "", true).unwrap());
        let o = b.hit(0x500, true, &mut ctx);
        assert!(o.stop && o.remove);
        assert!(o.extra["condition_error"].as_str().unwrap().contains("cannot read"));
        assert!(BpOpts::new("1 +", "", "", false).is_err());
        assert!(BpOpts::new("", "{x", "", false).is_err());
    }

    #[test]
    fn temporary_breakpoints_follow_thread_and_depth() {
        let mut b = Breaks::default();
        b.temps.push(Temp { addr: 0x401000, tid: Some(9), min_rsp: Some(0x2000), reason: "step_over" });
        let m = mem(0x1000, image());
        let deeper = Gprs { rsp: 0x1f00, ..regs() };
        let mut ctx = Ctx { regs: &deeper, read: &m, abi: Abi::Win64, tid: 9, pid: 1, hits: 0, modules: &[] };
        assert!(!b.hit(0x401000, false, &mut ctx).stop, "a recursive call deeper on the stack");
        let r = regs();
        let mut other = Ctx { regs: &r, read: &m, abi: Abi::Win64, tid: 8, pid: 1, hits: 0, modules: &[] };
        assert!(!b.hit(0x401000, false, &mut other).stop, "another thread");
        let mut same = Ctx { regs: &r, read: &m, abi: Abi::Win64, tid: 9, pid: 1, hits: 0, modules: &[] };
        let o = b.hit(0x401000, false, &mut same);
        assert!(o.stop);
        assert_eq!(o.reason, "step_over");
        assert!(b.is_temp(0x401000));
        assert_eq!(b.take_temps(), vec![0x401000]);
        assert!(!b.is_temp(0x401000));
    }

    #[test]
    fn options_update_keeps_what_is_not_given() {
        let mut req = Map::new();
        req.insert("condition".into(), json!("rax == 1"));
        let o = parse_opts(&req, None).unwrap().unwrap();
        assert_eq!(o.condition, "rax == 1");
        let mut old = o.clone();
        old.hits = 5;
        let mut req = Map::new();
        req.insert("log".into(), json!("x={rax}"));
        let o = parse_opts(&req, Some(&old)).unwrap().unwrap();
        assert_eq!((o.condition.as_str(), o.log.as_str(), o.hits), ("rax == 1", "x={rax}", 5));
        req.insert("reset_hits".into(), json!(true));
        assert_eq!(parse_opts(&req, Some(&old)).unwrap().unwrap().hits, 0);
        assert!(parse_opts(&Map::new(), Some(&old)).unwrap().is_none());
        let mut bad = Map::new();
        bad.insert("condition".into(), json!("(("));
        assert!(parse_opts(&bad, None).is_err());
    }

    #[test]
    fn step_over_runs_past_calls_and_rep() {
        let r = Gprs { rip: 0x1000, rsp: 0x8000, ..Default::default() };
        // call rel32
        let m = mem(0x1000, vec![0xe8, 0, 0, 0, 0, 0x90]);
        assert_eq!(step_over_target(&m, &r, 3), Some(Temp { addr: 0x1005, tid: Some(3), min_rsp: Some(0x8000), reason: "step_over" }));
        // call qword [rip+0]
        let m = mem(0x1000, vec![0xff, 0x15, 0, 0, 0, 0]);
        assert_eq!(step_over_target(&m, &r, 3).unwrap().addr, 0x1006);
        // rep movsb
        let m = mem(0x1000, vec![0xf3, 0xa4]);
        assert_eq!(step_over_target(&m, &r, 3).unwrap().addr, 0x1002);
        // mov eax, 1 / jmp: a plain step
        assert!(step_over_target(&mem(0x1000, vec![0xb8, 1, 0, 0, 0]), &r, 3).is_none());
        assert!(step_over_target(&mem(0x1000, vec![0xeb, 0x00]), &r, 3).is_none());
    }

    #[test]
    fn step_out_uses_the_return_address() {
        // a leaf with no unwind data: the return address at [rsp] follows a call
        let mut m = vec![0u8; 0x3000];
        m[0x100..0x105].copy_from_slice(&[0xe8, 0, 0, 0, 0]); // call at 0x10100, returns to 0x10105
        m[0x2000..0x2008].copy_from_slice(&0x10105u64.to_le_bytes());
        let read = mem(0x10000, m);
        let r = Gprs { rip: 0x10500, rsp: 0x12000, rbp: 0, ..Default::default() };
        let (t, how) = step_out_target(&read, &r, 5, &[("x".into(), 0x10000, 0x3000)]).unwrap();
        assert_eq!(t.addr, 0x10105);
        assert_eq!(t.tid, Some(5));
        assert_eq!(t.min_rsp, Some(0x12008));
        assert_eq!(how["return_to"], "0x10105");
    }

    #[test]
    fn stack_view_annotates() {
        let mut m = vec![0u8; 0x3000];
        m[0x100..0x105].copy_from_slice(&[0xe8, 0, 0, 0, 0]);
        m[0x2000..0x2008].copy_from_slice(&0x10105u64.to_le_bytes()); // return address
        m[0x2008..0x2010].copy_from_slice(&0x10200u64.to_le_bytes()); // code pointer
        m[0x2010..0x2018].copy_from_slice(&0x12020u64.to_le_bytes()); // into the stack
        m[0x2018..0x2020].copy_from_slice(&0x11000u64.to_le_bytes()); // a string
        m[0x1000..0x1006].copy_from_slice(b"hello\0");
        let read = mem(0x10000, m);
        let maps = vec![
            MapLine { start: 0x10000, end: 0x11000, writable: false, executable: true, path: "/bin/x".into() },
            MapLine { start: 0x11000, end: 0x12000, writable: true, executable: false, path: "/bin/x".into() },
            MapLine { start: 0x12000, end: 0x13000, writable: true, executable: false, path: "[stack]".into() },
        ];
        let r = Gprs { rip: 0x10500, rsp: 0x12000, rbp: 0x12010, ..Default::default() };
        let v = stack_view(&read, &r, None, 5, &[("/bin/x".into(), 0x10000, 0x2000)], &maps);
        let e = v["entries"].as_array().unwrap();
        assert_eq!(e[0]["kind"], "return");
        assert_eq!(e[0]["rsp"], true);
        assert!(e[0]["text"].as_str().unwrap().starts_with("return to x+0x105"), "{}", e[0]);
        assert_eq!(e[1]["kind"], "code");
        assert_eq!(e[2]["kind"], "stack");
        assert_eq!(e[2]["rbp"], true);
        assert_eq!(e[3]["kind"], "string");
        assert_eq!(e[3]["text"], "\"hello\"");
        assert!(e[4].get("kind").is_none());
        assert_eq!(e[4]["offset"], 0x20);
    }

    #[test]
    fn eval_json_shapes() {
        let r = regs();
        let m = mem(0x1000, image());
        let ctx = Ctx { regs: &r, read: &m, abi: Abi::Win64, tid: 1, pid: 1, hits: 0, modules: &[] };
        let v = eval_json("rdx - 3", &ctx);
        assert_eq!(v["value"], "0xffffffffffffffff");
        assert_eq!(v["signed"], "-1");
        assert_eq!(eval_json("utf8(rcx)", &ctx)["string"], "hello");
        assert_eq!(eval_json("((", &ctx)["type"], "error");
        assert_eq!(format_json("{d:rdx}", &ctx)["text"], "2");
    }
}
