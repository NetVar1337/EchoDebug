// The decompiler's intermediate representation: expressions over locations
// (registers, flags, promoted stack slots), memory loads and stores, calls,
// and the block terminators. irlift.ts builds it from instructions,
// dataflow.ts propagates and prunes it, unflatten.ts rewires it and
// decompile.ts structures and prints it.
import type { Insn } from "./structure";

export type Abi = "win64" | "sysv";

export type BinOp =
  | "+" | "-" | "*" | "/" | "/u" | "%" | "%u" | "&" | "|" | "^" | "<<" | ">>" | ">>s" | "rol" | "ror"
  | "&&" | "||" | "min" | "max";
export type CmpOp = "==" | "!=" | "<" | "<=" | ">" | ">=" | "<u" | "<=u" | ">u" | ">=u";

export type Expr =
  | { k: "c"; v: bigint; w: number; fl?: boolean }
  /** read of a location's low `w` bits; `rd` are the reaching definitions (set by dataflow) */
  | { k: "l"; loc: string; w: number; rd?: number[] }
  /** address of the stack slot at entry-rsp + off */
  | { k: "sa"; off: number }
  | { k: "ld"; a: Expr; w: number; fl?: boolean }
  | { k: "b"; op: BinOp; a: Expr; b: Expr; w: number; fl?: boolean }
  | { k: "u"; op: "-" | "~" | "!" | "sqrt"; a: Expr; w: number; fl?: boolean }
  /** zero/sign extension, truncation, or an int<->float conversion (`to`) */
  | { k: "cast"; a: Expr; w: number; s?: boolean; to?: "f32" | "f64" | "int" }
  | { k: "cmp"; op: CmpOp; a: Expr; b: Expr; fl?: boolean }
  /** the value of the flags location: what the last flag-setting instruction compared */
  | { k: "flags"; kind: "cmp" | "test" | "res" | "fcmp"; a: Expr; b: Expr; w: number }
  /** a condition code applied to a flags value */
  | { k: "cc"; cc: string; f: Expr }
  | { k: "sel"; c: Expr; a: Expr; b: Expr; w: number }
  /** `old` with its low (or, with hi, bits 8..15) `w` bits replaced by `v` */
  | { k: "part"; old: Expr; v: Expr; w: number; hi?: boolean }
  | { k: "call"; target: Expr; args: Expr[]; w: number; name?: string; fl?: boolean }
  | { k: "raw"; text: string; w: number };

export type Stmt =
  | { k: "set"; id: number; dst: string; w: number; src: Expr; addr: string; push?: boolean }
  | { k: "st"; id: number; a: Expr; w: number; v: Expr; addr: string; fl?: boolean }
  /** a call; `dst` receives the return value (rax, xmm0) or null when it is unused */
  | { k: "call"; id: number; dst: string | null; call: Extract<Expr, { k: "call" }>; addr: string }
  /** registers a call leaves undefined */
  | { k: "clob"; id: number; locs: string[]; addr: string }
  /** an instruction the lifter does not model: kept as text, conservatively reads and writes */
  | { k: "asm"; id: number; text: string; uses: Expr[]; defs: string[]; addr: string };

export type Case = { vals: bigint[]; to: number };

export type Term =
  | { k: "jump"; to: number }
  | { k: "cond"; c: Expr; t: number; f: number; addr: string }
  | { k: "switch"; x: Expr; cases: Case[]; def: number | null; addr: string }
  | { k: "ret"; v: Expr | null; fv?: Expr | null; addr: string }
  | { k: "tail"; call: Extract<Expr, { k: "call" }>; addr: string }
  | { k: "ijump"; x: Expr; addr: string }
  | { k: "stop"; addr: string }
  | { k: "end" };

export type IrBlock = { id: number; start: bigint; addr: string; insns: Insn[]; stmts: Stmt[]; term: Term; dead?: boolean };

export type IrFunc = {
  blocks: IrBlock[];
  abi: Abi;
  /** promoted stack slots (offset from entry rsp) */
  slots: Set<number>;
  /** next free statement id */
  nextId: number;
  /** filled by dataflow.analyzeSignature */
  sig?: { args: string[]; ret: "void" | "int" | "float" };
};

// ---------------------------------------------------------------------------
// small helpers

export const mask = (w: number): bigint => (w >= 64 ? 0xffffffffffffffffn : (1n << BigInt(w)) - 1n);
export const c = (v: bigint | number, w = 64): Expr => ({ k: "c", v: BigInt.asUintN(Math.min(64, w), BigInt(v)), w });
export const loc = (l: string, w = 64): Expr => ({ k: "l", loc: l, w });
export const isC = (e: Expr): e is Extract<Expr, { k: "c" }> => e.k === "c";
/** Signed value of a constant at its width. */
export const sval = (e: Extract<Expr, { k: "c" }>): bigint => BigInt.asIntN(Math.min(64, e.w), e.v);

export function width(e: Expr): number {
  switch (e.k) {
    case "cmp":
    case "cc":
      return 1;
    case "sa":
      return 64;
    case "flags":
      return e.w;
    case "part":
      return 64;
    default:
      return e.w;
  }
}

export function isFloat(e: Expr): boolean {
  switch (e.k) {
    case "c":
    case "ld":
    case "b":
    case "u":
    case "call":
      return !!e.fl;
    case "cast":
      return e.to === "f32" || e.to === "f64";
    case "l":
      return e.loc.startsWith("xmm");
    case "sel":
      return isFloat(e.a);
    default:
      return false;
  }
}

/** Child expressions, in evaluation order. */
export function kids(e: Expr): Expr[] {
  switch (e.k) {
    case "ld":
    case "u":
    case "cast":
      return [e.a];
    case "b":
    case "cmp":
    case "flags":
      return [e.a, e.b];
    case "cc":
      return [e.f];
    case "sel":
      return [e.c, e.a, e.b];
    case "part":
      return [e.old, e.v];
    case "call":
      return [e.target, ...e.args];
    default:
      return [];
  }
}

/** Rebuilds `e` with its children mapped by `f` (shallow). */
export function mapKids(e: Expr, f: (x: Expr) => Expr): Expr {
  switch (e.k) {
    case "ld":
    case "u":
    case "cast":
      return { ...e, a: f(e.a) };
    case "b":
    case "cmp":
    case "flags":
      return { ...e, a: f(e.a), b: f(e.b) };
    case "cc":
      return { ...e, f: f(e.f) };
    case "sel":
      return { ...e, c: f(e.c), a: f(e.a), b: f(e.b) };
    case "part":
      return { ...e, old: f(e.old), v: f(e.v) };
    case "call":
      return { ...e, target: f(e.target), args: e.args.map(f) };
    case "l":
      return { ...e, rd: e.rd ? [...e.rd] : undefined };
    default:
      return { ...e };
  }
}

export function clone(e: Expr): Expr {
  return mapKids(e, clone);
}

/** Visits every node (pre-order). */
export function walk(e: Expr, f: (x: Expr) => void): void {
  f(e);
  for (const k of kids(e)) walk(k, f);
}

export function some(e: Expr, p: (x: Expr) => boolean): boolean {
  if (p(e)) return true;
  return kids(e).some((k) => some(k, p));
}

/** Expressions a statement reads. */
export function stmtUses(s: Stmt): Expr[] {
  switch (s.k) {
    case "set":
      return [s.src];
    case "st":
      return [s.a, s.v];
    case "call":
      return [s.call];
    case "asm":
      return s.uses;
    case "clob":
      return [];
  }
}

/** Locations a statement defines. */
export function stmtDefs(s: Stmt): string[] {
  switch (s.k) {
    case "set":
      return [s.dst];
    case "call":
      return s.dst ? [s.dst] : [];
    case "clob":
      return s.locs;
    case "asm":
      return s.defs;
    default:
      return [];
  }
}

export function termUses(t: Term): Expr[] {
  switch (t.k) {
    case "cond":
      return [t.c];
    case "switch":
      return [t.x];
    case "ret":
      return [t.v, t.fv].filter((x): x is Expr => !!x);
    case "tail":
      return [t.call];
    case "ijump":
      return [t.x];
    default:
      return [];
  }
}

export function mapStmtUses(s: Stmt, f: (x: Expr) => Expr): void {
  switch (s.k) {
    case "set":
      s.src = f(s.src);
      break;
    case "st":
      s.a = f(s.a);
      s.v = f(s.v);
      break;
    case "call":
      s.call = f(s.call) as Extract<Expr, { k: "call" }>;
      break;
    case "asm":
      s.uses = s.uses.map(f);
      break;
  }
}

export function mapTermUses(t: Term, f: (x: Expr) => Expr): void {
  switch (t.k) {
    case "cond":
      t.c = f(t.c);
      break;
    case "switch":
      t.x = f(t.x);
      break;
    case "ret":
      if (t.v) t.v = f(t.v);
      if (t.fv) t.fv = f(t.fv);
      break;
    case "tail":
      t.call = f(t.call) as Extract<Expr, { k: "call" }>;
      break;
    case "ijump":
      t.x = f(t.x);
      break;
  }
}

export function succOf(t: Term): number[] {
  switch (t.k) {
    case "jump":
      return [t.to];
    case "cond":
      return t.t === t.f ? [t.t] : [t.t, t.f];
    case "switch": {
      const s = new Set(t.cases.map((x) => x.to));
      if (t.def !== null) s.add(t.def);
      return [...s];
    }
    default:
      return [];
  }
}

/** Replaces every edge to `from` with an edge to `to`. */
export function retarget(t: Term, from: number, to: number): void {
  const r = (x: number) => (x === from ? to : x);
  if (t.k === "jump") t.to = r(t.to);
  else if (t.k === "cond") {
    t.t = r(t.t);
    t.f = r(t.f);
  } else if (t.k === "switch") {
    t.cases.forEach((x) => (x.to = r(x.to)));
    if (t.def !== null) t.def = r(t.def);
  }
}

export function equal(a: Expr, b: Expr): boolean {
  if (a.k !== b.k) return false;
  switch (a.k) {
    case "c":
      return a.v === (b as typeof a).v && a.w === (b as typeof a).w;
    case "l": {
      const y = b as typeof a;
      return a.loc === y.loc && a.w === y.w && (a.rd ?? []).join() === (y.rd ?? []).join();
    }
    case "sa":
      return a.off === (b as typeof a).off;
    case "raw":
      return a.text === (b as typeof a).text;
    case "b":
    case "u":
    case "cmp":
      if (a.op !== (b as typeof a).op) return false;
      break;
    case "cc":
      if (a.cc !== (b as typeof a).cc) return false;
      break;
    case "flags":
      if (a.kind !== (b as typeof a).kind) return false;
      break;
    case "call":
      return false; // two calls are never the same value
  }
  if (width(a) !== width(b)) return false;
  if (a.k === "cast" && (a.s !== (b as typeof a).s || a.to !== (b as typeof a).to)) return false;
  const ka = kids(a);
  const kb = kids(b);
  return ka.length === kb.length && ka.every((x, i) => equal(x, kb[i]));
}

// ---------------------------------------------------------------------------
// conditions

const kNegCmp: Record<CmpOp, CmpOp> = { "==": "!=", "!=": "==", "<": ">=", ">=": "<", "<=": ">", ">": "<=", "<u": ">=u", ">=u": "<u", "<=u": ">u", ">u": "<=u" };

/** Logical negation, pushed into comparisons and through && / || (De Morgan). */
export function negate(e: Expr): Expr {
  if (e.k === "cmp") return { ...e, op: kNegCmp[e.op] };
  if (e.k === "u" && e.op === "!") return e.a;
  if (e.k === "c") return c(e.v === 0n ? 1 : 0, 1);
  if (e.k === "b" && (e.op === "&&" || e.op === "||")) return { k: "b", op: e.op === "&&" ? "||" : "&&", a: negate(e.a), b: negate(e.b), w: 1 };
  return { k: "u", op: "!", a: e, w: 1 };
}

/** The comparison a condition code expresses over a flags value; `raw` when it is not expressible. */
export function ccCond(cc: string, f: Expr): Expr {
  const name = cc.replace(/^(j|set|cmov)/, "");
  const canon: Record<string, string> = { z: "e", nz: "ne", nge: "l", nl: "ge", ng: "le", nle: "g", c: "b", nae: "b", nb: "ae", nc: "ae", na: "be", nbe: "a", pe: "p", po: "np" };
  const k = canon[name] ?? name;
  if (f.k !== "flags") return { k: "cc", cc: k, f };
  const zero = (x: Expr) => c(0, width(x));
  if (f.kind === "cmp") {
    const m: Record<string, CmpOp> = { e: "==", ne: "!=", l: "<", ge: ">=", le: "<=", g: ">", b: "<u", ae: ">=u", be: "<=u", a: ">u" };
    if (m[k]) return { k: "cmp", op: m[k], a: f.a, b: f.b };
    if (k === "s" || k === "ns") return { k: "cmp", op: k === "s" ? "<" : ">=", a: { k: "b", op: "-", a: f.a, b: f.b, w: f.w }, b: c(0, f.w) };
    return { k: "cc", cc: k, f };
  }
  if (f.kind === "test" || f.kind === "res") {
    const v: Expr = f.kind === "res" ? f.a : equal(f.a, f.b) ? f.a : { k: "b", op: "&", a: f.a, b: f.b, w: f.w };
    const m: Record<string, CmpOp> = { e: "==", ne: "!=", s: "<", ns: ">=", l: "<", ge: ">=", le: "<=", g: ">" };
    if (m[k]) return { k: "cmp", op: m[k], a: v, b: zero(v) };
    if (f.kind === "test") {
      // CF = 0 after test
      if (k === "b") return c(0, 1);
      if (k === "ae") return c(1, 1);
      if (k === "be") return { k: "cmp", op: "==", a: v, b: zero(v) };
      if (k === "a") return { k: "cmp", op: "!=", a: v, b: zero(v) };
    }
    return { k: "cc", cc: k, f };
  }
  // ucomiss / comisd: CF and ZF as an unsigned compare
  const m: Record<string, CmpOp> = { e: "==", ne: "!=", b: "<", ae: ">=", be: "<=", a: ">" };
  if (m[k]) return { k: "cmp", op: m[k], a: f.a, b: f.b, fl: true };
  return { k: "cc", cc: k, f };
}

// ---------------------------------------------------------------------------
// simplification

function foldBin(op: BinOp, a: bigint, b: bigint, w: number): bigint | null {
  const m = mask(w);
  const sa = BigInt.asIntN(w, a);
  const sb = BigInt.asIntN(w, b);
  switch (op) {
    case "+":
      return (a + b) & m;
    case "-":
      return (a - b) & m;
    case "*":
      return (a * b) & m;
    case "&":
      return a & b;
    case "|":
      return a | b;
    case "^":
      return a ^ b;
    case "<<":
      return (a << (b & 63n)) & m;
    case ">>":
      return (a & m) >> (b & 63n);
    case ">>s":
      return BigInt.asUintN(w, sa >> (b & 63n));
    case "/u":
      return b === 0n ? null : (a & m) / b;
    case "%u":
      return b === 0n ? null : (a & m) % b;
    case "/":
      return sb === 0n ? null : BigInt.asUintN(w, sa / sb);
    case "%":
      return sb === 0n ? null : BigInt.asUintN(w, sa % sb);
    case "&&":
      return a !== 0n && b !== 0n ? 1n : 0n;
    case "||":
      return a !== 0n || b !== 0n ? 1n : 0n;
    default:
      return null;
  }
}

function foldCmp(op: CmpOp, a: bigint, b: bigint, w: number): boolean {
  const sa = BigInt.asIntN(w, a);
  const sb = BigInt.asIntN(w, b);
  switch (op) {
    case "==":
      return a === b;
    case "!=":
      return a !== b;
    case "<":
      return sa < sb;
    case "<=":
      return sa <= sb;
    case ">":
      return sa > sb;
    case ">=":
      return sa >= sb;
    case "<u":
      return a < b;
    case "<=u":
      return a <= b;
    case ">u":
      return a > b;
    case ">=u":
      return a >= b;
  }
}

/** Narrows `e` to its low `w` bits. */
export function narrow(e: Expr, w: number): Expr {
  const ew = width(e);
  if (ew === w) return e;
  if (e.k === "c") return c(e.v, w);
  if (e.k === "l") return { ...e, w: Math.min(e.w, w) };
  if (e.k === "call" && w < ew && !e.fl) return { ...e, w };
  if (ew < w) return { k: "cast", a: e, w, s: false };
  return simp({ k: "cast", a: e, w, s: false });
}

/** Constant folding and algebraic clean-up, bottom-up. */
export function simp(e: Expr): Expr {
  const x = mapKids(e, simp);
  switch (x.k) {
    case "b": {
      const { a, b, w, op } = x;
      if (x.fl) return x;
      if (isC(a) && isC(b)) {
        const v = foldBin(op, a.v, b.v, w);
        if (v !== null) return c(v, w);
      }
      if (op === "&&" || op === "||") {
        if (isC(a)) return (a.v !== 0n) === (op === "&&") ? b : c(op === "||" ? 1 : 0, 1);
        if (isC(b)) return (b.v !== 0n) === (op === "&&") ? a : c(op === "||" ? 1 : 0, 1);
        return x;
      }
      // constants to the right of commutative operators
      if (isC(a) && ["+", "*", "&", "|", "^"].includes(op)) return simp({ ...x, a: b, b: a });
      if (isC(b)) {
        const v = b.v;
        if (v === 0n && ["+", "-", "|", "^", "<<", ">>", ">>s"].includes(op)) return narrowTo(a, w);
        if (v === 0n && (op === "*" || op === "&")) return c(0, w);
        if (v === 1n && (op === "*" || op === "/u" || op === "/")) return narrowTo(a, w);
        if (op === "&" && v === mask(w)) return narrowTo(a, w);
        if (op === "-") return simp({ k: "b", op: "+", a, b: c(-v, w), w });
        // (y + c1) + c2
        if (op === "+" && a.k === "b" && a.op === "+" && isC(a.b) && a.w === w) return simp({ k: "b", op: "+", a: a.a, b: c(a.b.v + v, w), w });
        // (y & m) & m2, (y ^ c1) ^ c2
        if ((op === "&" || op === "^" || op === "|") && a.k === "b" && a.op === op && isC(a.b)) {
          const f = foldBin(op, a.b.v, v, w)!;
          return simp({ k: "b", op, a: a.a, b: c(f, w), w });
        }
      }
      if ((op === "^" || op === "-") && equal(a, b) && !hasCall(a)) return c(0, w);
      if (op === "+" && b.k === "u" && b.op === "-") return { k: "b", op: "-", a, b: b.a, w };
      return x;
    }
    case "u": {
      if (x.fl) return x;
      const a = x.a;
      if (x.op === "!") {
        if (a.k === "c") return c(a.v === 0n ? 1 : 0, 1);
        if (a.k === "cmp" && !a.fl) return { ...a, op: kNegCmp[a.op] };
        if (a.k === "u" && a.op === "!") return a.a;
        return x;
      }
      if (isC(a)) return c(x.op === "-" ? -a.v : ~a.v, x.w);
      if (a.k === "u" && a.op === x.op && x.op !== "sqrt") return a.a;
      return x;
    }
    case "cast": {
      const a = x.a;
      if (x.to) return x;
      const aw = width(a);
      if (isC(a)) return c(x.s && aw < x.w ? BigInt.asIntN(aw, a.v) : a.v, x.w);
      if (aw === x.w && !isFloat(a)) return a;
      if (a.k === "l" && x.w < aw) return { ...a, w: x.w };
      // truncating an extension back to (or below) its source
      if (a.k === "cast" && !a.to && x.w <= aw) {
        const iw = width(a.a);
        if (x.w === iw) return a.a;
        if (x.w < iw) return simp({ k: "cast", a: a.a, w: x.w });
        return { ...x, a: a.a, s: a.s };
      }
      if (x.w < aw && a.k === "ld") return { ...a, w: x.w };
      if (x.w < aw && a.k === "b" && ["+", "-", "*", "&", "|", "^"].includes(a.op) && !a.fl)
        return simp({ ...a, a: narrow(a.a, x.w), b: narrow(a.b, x.w), w: x.w });
      if (a.k === "cmp" || a.k === "cc") return { ...x, s: false };
      return x;
    }
    case "cmp": {
      const { a, b } = x;
      if (x.fl) return x;
      if (isC(a) && isC(b)) return c(foldCmp(x.op, a.v, b.v, Math.max(width(a), width(b))) ? 1 : 0, 1);
      // constant on the right
      if (isC(a) && !isC(b)) {
        const swap: Record<CmpOp, CmpOp> = { "==": "==", "!=": "!=", "<": ">", ">": "<", "<=": ">=", ">=": "<=", "<u": ">u", ">u": "<u", "<=u": ">=u", ">=u": "<=u" };
        return { ...x, op: swap[x.op], a: b, b: a };
      }
      // (y + k) == c  ->  y == c - k (signed orders too, assuming no overflow, as C code would)
      if (["==", "!=", "<", "<=", ">", ">="].includes(x.op) && a.k === "b" && a.op === "+" && isC(a.b) && isC(b)) return simp({ ...x, a: a.a, b: c(b.v - a.b.v, a.w) });
      // (y - z) == 0  ->  y == z
      if ((x.op === "==" || x.op === "!=") && isC(b) && b.v === 0n && a.k === "b" && a.op === "-") return { ...x, a: a.a, b: a.b };
      // a boolean compared with zero
      if ((x.op === "==" || x.op === "!=") && isC(b) && b.v === 0n) {
        const inner = a.k === "cast" && !a.to && isBool(a.a) ? a.a : isBool(a) ? a : null;
        if (inner) return x.op === "!=" ? inner : simp({ k: "u", op: "!", a: inner, w: 1 });
      }
      if (equal(a, b) && !hasCall(a)) return c(["==", "<=", ">=", "<=u", ">=u"].includes(x.op) ? 1 : 0, 1);
      return x;
    }
    case "cc": {
      if (x.f.k === "flags") {
        const r = ccCond(x.cc, x.f);
        return r.k === "cc" ? r : simp(r);
      }
      return x;
    }
    case "sel": {
      if (isC(x.c)) return x.c.v !== 0n ? x.a : x.b;
      if (equal(x.a, x.b)) return x.a;
      return x;
    }
    case "part": {
      const m = mask(x.w) << (x.hi ? 8n : 0n);
      if (isC(x.old) && isC(x.v)) return c((x.old.v & ~m) | ((x.v.v << (x.hi ? 8n : 0n)) & m), 64);
      if (isC(x.old) && (x.old.v & ~m) === 0n && !x.hi) return simp({ k: "cast", a: narrow(x.v, x.w), w: 64, s: false });
      return x;
    }
    case "flags":
      return x;
    default:
      return x;
  }
}

function narrowTo(e: Expr, w: number): Expr {
  return width(e) === w ? e : narrow(e, w);
}

export function isBool(e: Expr): boolean {
  return e.k === "cmp" || e.k === "cc" || (e.k === "u" && e.op === "!") || (e.k === "b" && (e.op === "&&" || e.op === "||"));
}

export function hasCall(e: Expr): boolean {
  return some(e, (x) => x.k === "call");
}

export function hasLoad(e: Expr): boolean {
  return some(e, (x) => x.k === "ld" || x.k === "call");
}

/** Replaces location reads by `f`'s result (when it returns one). */
export function substLocs(e: Expr, f: (x: Extract<Expr, { k: "l" }>) => Expr | null): Expr {
  if (e.k === "l") {
    const r = f(e);
    return r ?? e;
  }
  return mapKids(e, (k) => substLocs(k, f));
}

/** Evaluates `e` with the given location values; null when the result is not constant. */
export function evalConst(e: Expr, env: (x: Extract<Expr, { k: "l" }>) => bigint | null): bigint | null {
  const r = simp(substLocs(e, (x) => {
    const v = env(x);
    return v === null ? null : c(v, x.w);
  }));
  return r.k === "c" ? r.v : null;
}
