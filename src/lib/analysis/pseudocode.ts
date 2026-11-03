// Structured pseudocode on top of structure.ts: a deliberately small
// "decompiler-lite". Regions become if/else, while, do-while and goto where
// structuring fails; common x64 instructions become C-like statements and
// everything else stays as the raw asm line in a comment. Registers are not
// turned into variables and no types are recovered.
import { branchOf, mnemonicOf, postDominators, type Cfg, type Insn } from "./structure";

export type Abi = "win64" | "sysv";
export type Options = { abi?: Abi; nameOf?: (address: string) => string };

// ---------------------------------------------------------------------------
// operands

/** One instruction in Intel order: `mov rax, qword ptr [rbp-0x8]`. */
export type Normal = { mn: string; ops: string[]; ripTarget: bigint | null };

/** Splits on commas that are not inside brackets or parentheses. */
function splitOps(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of s) {
    if (ch === "[" || ch === "(") depth++;
    if (ch === "]" || ch === ")") depth--;
    if (ch === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const kSizeWord: Record<string, string> = { b: "byte", w: "word", l: "dword", q: "qword" };

/** AT&T operand -> Intel operand text. */
function attOperand(op: string, size: string | null, branch: boolean): string {
  let o = op.trim().replace(/^\*/, "");
  if (o.startsWith("$")) return o.slice(1);
  if (/^%\w+$/.test(o)) return o.slice(1);
  let seg = "";
  const sm = /^%(\w+):(.*)$/.exec(o);
  if (sm) {
    seg = sm[1] + ":";
    o = sm[2];
  }
  const m = /^(-?(?:0x[0-9a-f]+|\d+))?\((%\w+)?(?:,(%\w+)(?:,(\d))?)?\)$/i.exec(o);
  const ptr = size ? `${size} ptr ` : "";
  if (!m) {
    if (seg) return `${ptr}${seg}[${o}]`;
    // a bare number is an absolute memory operand, except as a branch target
    return !branch && /^-?(0x[0-9a-f]+|\d+)$/i.test(o) ? `${ptr}[${o}]` : o;
  }
  const [, disp, base, index, scale] = m;
  let inner = base ? base.slice(1) : "";
  if (index) inner += (inner ? "+" : "") + index.slice(1) + (scale && scale !== "1" ? "*" + scale : "");
  if (disp && disp !== "0") inner += disp.startsWith("-") ? disp : (inner ? "+" : "") + disp;
  return `${ptr}${seg}[${inner || "0"}]`;
}

const kKnown = new Set(["mov", "lea", "add", "sub", "and", "or", "xor", "shl", "sal", "shr", "sar", "imul", "cmp", "test", "inc", "dec", "neg", "not", "push", "pop", "call", "ret", "jmp", "nop", "movabs"]);

/** Normalizes Intel or AT&T (GAS) text to Intel order and Intel operand syntax. */
export function normalize(text: string): Normal {
  const cm = /;\s*(0x[0-9a-f]+)\s*$/i.exec(text);
  const ripTarget = cm ? BigInt(cm[1]) : null;
  const body = text.replace(/;.*$/, "").trim();
  const sp = body.search(/\s/);
  let mn = (sp < 0 ? body : body.slice(0, sp)).toLowerCase();
  const rest = sp < 0 ? "" : body.slice(sp + 1).trim();
  const att = /%[a-z]/i.test(rest) || /(^|,)\s*\$/.test(rest);
  if (!att) return { mn, ops: rest ? splitOps(rest) : [], ripTarget };

  let size: string | null = null;
  const z = /^mov([sz])([bw])([wlq])$/.exec(mn);
  if (mn === "movslq") mn = "movsxd";
  else if (z) {
    mn = z[1] === "z" ? "movzx" : "movsx";
  } else if (!kKnown.has(mn) && kKnown.has(mn.slice(0, -1)) && kSizeWord[mn.slice(-1)]) {
    size = kSizeWord[mn.slice(-1)];
    mn = mn.slice(0, -1);
  }
  const ops = splitOps(rest).map((o) => attOperand(o, size, /^(call|j[a-z]+|loop[a-z]*)$/.test(mn))).reverse();
  return { mn, ops, ripTarget };
}

/** Width in bits of a general-purpose register, or 0 when `r` is not one. */
export function regWidth(r: string): number {
  if (/^r([abcd]x|[sd]i|[sb]p|ip|\d+)$/.test(r)) return 64;
  if (/^(e([abcd]x|[sd]i|[sb]p|ip)|r\d+d)$/.test(r)) return 32;
  if (/^([abcd]x|[sd]i|[sb]p|r\d+w)$/.test(r)) return 16;
  if (/^([abcd][lh]|[sd]il|[sb]pl|r\d+b)$/.test(r)) return 8;
  return 0;
}

/** The 64-bit register an alias belongs to: `ecx` -> `rcx`, `r8d` -> `r8`. */
function reg64(r: string): string {
  const n = /^r(\d+)[dwb]?$/.exec(r);
  if (n) return "r" + n[1];
  const m = /^[re]?([abcd])[xlh]$/.exec(r);
  if (m) return `r${m[1]}x`;
  const s = /^[re]?([sd]i|[sb]p)l?$/.exec(r);
  return s ? "r" + s[1] : r;
}

const kTypeOf: Record<string, string> = { byte: "u8", word: "u16", dword: "u32", qword: "u64", xmmword: "u128", tbyte: "f80" };
const kTypeOfWidth: Record<number, string> = { 8: "u8", 16: "u16", 32: "u32", 64: "u64" };
const kMem = /^(?:(byte|word|dword|qword|xmmword|tbyte)\s+ptr\s+)?(?:(\w+):)?\[(.+)\]$/i;

function spaced(inner: string): string {
  return inner.replace(/\s+/g, "").replace(/([+-])/g, " $1 ").replace(/^ - /, "-").trim();
}

/** Address expression of a memory operand (no dereference); rip-relative becomes the absolute target. */
function addressOf(op: string, rip: bigint | null): string | null {
  const m = kMem.exec(op);
  if (!m) return null;
  if (/\brip\b/i.test(m[3]) && rip !== null) return "0x" + rip.toString(16);
  return (m[2] ? m[2] + ":" : "") + spaced(m[3]);
}

type Ctx = { rip: bigint | null; nameOf?: (a: string) => string };

/** C expression for an operand; `width` sizes an untyped memory access. */
function expr(op: string, ctx: Ctx, width = 64): string {
  const m = kMem.exec(op);
  if (!m) return op;
  const type = m[1] ? kTypeOf[m[1].toLowerCase()] : kTypeOfWidth[width] ?? "u64";
  const addr = addressOf(op, ctx.rip)!;
  return /^[\w:]+$/.test(addr) ? `*(${type}*)${addr}` : `*(${type}*)(${addr})`;
}

/** Absolute target of a rip-relative operand: the backend's annotation, or next-insn + disp. */
function ripOf(insn: Insn, n: Normal): bigint | null {
  if (n.ripTarget !== null) return n.ripTarget;
  const m = /\[rip\s*([+-])\s*0x([0-9a-f]+)\]/i.exec(n.ops.join(","));
  if (!m) return null;
  const disp = BigInt("0x" + m[2]);
  return BigInt(insn.address) + BigInt(insn.length) + (m[1] === "-" ? -disp : disp);
}

// ---------------------------------------------------------------------------
// conditions

export type Cond = { a: string; op: string; b: string } | { raw: string };

const kCc: Record<string, string> = {
  e: "eq", z: "eq", ne: "ne", nz: "ne", l: "lt", nge: "lt", ge: "ge", nl: "ge", le: "le", ng: "le", g: "gt", nle: "gt",
  b: "ult", c: "ult", nae: "ult", ae: "uge", nb: "uge", nc: "uge", be: "ule", na: "ule", a: "ugt", nbe: "ugt", s: "neg", ns: "pos",
};
const kOp: Record<string, string> = { eq: "==", ne: "!=", lt: "<", ge: ">=", le: "<=", gt: ">", ult: "<", uge: ">=", ule: "<=", ugt: ">" };
const kNeg: Record<string, string> = { "==": "!=", "!=": "==", "<": ">=", ">=": "<", "<=": ">", ">": "<=" };
const kFlagSafe = new Set(["mov", "movabs", "movzx", "movsx", "movsxd", "lea", "push", "pop", "nop"]);
const kFlagSetter = new Set(["cmp", "test", "sub", "add", "and", "or", "xor", "inc", "dec", "neg"]);

export function negate(c: Cond): Cond {
  if ("raw" in c) return { raw: `!(${c.raw})` };
  return { a: c.a, op: kNeg[c.op], b: c.b };
}

export function condText(c: Cond): string {
  return "raw" in c ? c.raw : `${c.a} ${c.op} ${c.b}`;
}

/**
 * Condition under which the jcc is taken, from the flag-setting instruction
 * before it in the same block. Returns the index of a cmp/test that the
 * condition consumes (it is then not printed as a statement).
 */
export function conditionOf(insns: readonly Insn[], ctxBase: Omit<Ctx, "rip"> = {}): { cond: Cond; consumed: number } {
  const last = insns[insns.length - 1];
  const jmn = mnemonicOf(last.text);
  const cc = kCc[jmn.slice(1)];
  const fallback = { cond: { raw: `COND(${jmn})` }, consumed: -1 };
  if (!cc) return fallback;
  const clobbered = new Set<string>(); // registers written between the flag setter and the jcc
  for (let i = insns.length - 2; i >= 0; i--) {
    const n = normalize(insns[i].text);
    if (kFlagSafe.has(n.mn)) {
      if (n.ops[0] && regWidth(n.ops[0])) clobbered.add(reg64(n.ops[0]));
      continue;
    }
    if (!kFlagSetter.has(n.mn)) return fallback;
    const reads = (n.ops.join(" ").match(/\b[a-z][a-z0-9]{1,4}\b/g) ?? []).filter((r) => regWidth(r)).map(reg64);
    if (reads.some((r) => clobbered.has(r))) return fallback;
    const ctx: Ctx = { ...ctxBase, rip: ripOf(insns[i], n) };
    const w = regWidth(n.ops[0]) || regWidth(n.ops[1] ?? "") || 64;
    const a = expr(n.ops[0], ctx, w);
    const b = n.ops[1] !== undefined ? expr(n.ops[1], ctx, w) : "";
    const unsigned = (x: string) => (/^\*\(/.test(x) ? x : `(u${w})${x}`);
    if (n.mn === "cmp") {
      if (cc === "neg" || cc === "pos") return { cond: { a: `${a} - ${b}`, op: cc === "neg" ? "<" : ">=", b: "0" }, consumed: i };
      return { cond: { a: cc.startsWith("u") ? unsigned(a) : a, op: kOp[cc], b }, consumed: i };
    }
    if (n.mn === "test") {
      const v = a === b ? a : `(${a} & ${b})`;
      const op = { eq: "==", ne: "!=", neg: "<", pos: ">=", le: "<=", gt: ">" }[cc];
      return op ? { cond: { a: v, op, b: "0" }, consumed: i } : fallback;
    }
    // arithmetic: only the result-vs-zero conditions are expressible after the fact
    const op = { eq: "==", ne: "!=", neg: "<", pos: ">=" }[cc];
    return op ? { cond: { a, op, b: "0" }, consumed: -1 } : fallback;
  }
  return fallback;
}

// ---------------------------------------------------------------------------
// statements

const kArgs: Record<Abi, string[]> = { win64: ["rcx", "rdx", "r8", "r9"], sysv: ["rdi", "rsi", "rdx", "rcx", "r8", "r9"] };
const kCompound: Record<string, string> = { add: "+=", sub: "-=", and: "&=", or: "|=", xor: "^=", shl: "<<=", sal: "<<=", shr: ">>=", sar: ">>=", imul: "*=" };

function calleeName(target: string, ctx: Ctx): string {
  if (/^0x[0-9a-f]+$/i.test(target)) {
    const hex = BigInt(target).toString(16); // the local backend pads: 0x0000000000401050
    return ctx.nameOf?.("0x" + hex) || `sub_${hex}`;
  }
  return target;
}

/**
 * Translates one instruction. `written` collects argument registers set since
 * the last call (64-bit names) so a call can show its likely arguments.
 * Returns null for instructions that carry nothing (nop, endbr64).
 */
export function translate(insn: Insn, abi: Abi = "win64", written: Set<string> = new Set(), nameOf?: (a: string) => string): string | null {
  const n = normalize(insn.text);
  const ctx: Ctx = { rip: ripOf(insn, n), nameOf };
  const [d, s, t] = n.ops;
  const raw = `// ${insn.text.trim()}`;
  const w = regWidth(d ?? "") || regWidth(s ?? "") || 64;
  const dst = d !== undefined ? expr(d, ctx, w) : "";
  const src = s !== undefined ? expr(s, ctx, w) : "";
  const lval = dst.startsWith("*") ? `(${dst})` : dst;
  const callArgs = () => {
    const regs = kArgs[abi];
    let k = 0;
    regs.forEach((r, i) => written.has(r) && (k = i + 1));
    written.clear();
    return regs.slice(0, k).join(", ");
  };
  let out: string | null = raw;
  if (/^nop[wlq]?$/.test(n.mn) || (n.mn === "xchg" && d === s)) return null; // padding
  switch (n.mn) {
    case "nop":
    case "endbr64":
      return null;
    case "mov":
    case "movabs":
    case "movzx":
    case "movsx":
    case "movsxd":
      if (n.ops.length === 2) out = `${dst} = ${src};`;
      break;
    case "lea": {
      const addr = s !== undefined ? addressOf(s, ctx.rip) : null;
      if (addr && n.ops.length === 2) out = `${dst} = ${addr};`;
      break;
    }
    case "xor":
    case "sub":
      if (n.ops.length === 2 && d === s && regWidth(d)) {
        out = `${dst} = 0;`;
        break;
      }
    // fallthrough
    case "add":
    case "and":
    case "or":
    case "shl":
    case "sal":
    case "shr":
    case "sar":
    case "imul":
      if (n.ops.length === 2) out = `${dst} ${kCompound[n.mn]} ${src};`;
      else if (n.ops.length === 1 && /^s[ah][lr]$/.test(n.mn)) out = `${dst} ${kCompound[n.mn]} 1;`;
      else if (n.ops.length === 3 && n.mn === "imul") out = `${dst} = ${src} * ${expr(t, ctx, w)};`;
      break;
    case "inc":
      if (n.ops.length === 1) out = `${lval}++;`;
      break;
    case "dec":
      if (n.ops.length === 1) out = `${lval}--;`;
      break;
    case "neg":
      if (n.ops.length === 1) out = `${dst} = -${dst};`;
      break;
    case "not":
      if (n.ops.length === 1) out = `${dst} = ~${dst};`;
      break;
    case "call":
      if (n.ops.length === 1) out = `rax = ${calleeName(dst, ctx)}(${callArgs()});`;
      break;
    case "ret":
    case "retq":
    case "retn":
      out = "return rax;";
      break;
    case "jmp":
      // only reached for jumps that leave the function: a tail call
      if (n.ops.length === 1 && /^0x[0-9a-f]+$/i.test(d)) out = `return ${calleeName(d, ctx)}(${callArgs()}); // tail call`;
      else out = `${raw}  (indirect jump, targets unknown)`;
      break;
  }
  if (d !== undefined && regWidth(d) && n.ops.length >= 2 && n.mn !== "cmp" && n.mn !== "test") written.add(reg64(d));
  return out;
}

// ---------------------------------------------------------------------------
// structuring

export type Stmt =
  | { k: "s"; text: string; addr: string }
  | { k: "if"; cond: Cond; addr: string; then: Stmt[]; else: Stmt[] }
  | { k: "while" | "do"; cond: Cond; addr: string; body: Stmt[] }
  | { k: "loop"; addr: string; body: Stmt[] }
  | { k: "goto" | "label"; block: number }
  | { k: "break" | "continue" };

export type Structured = { body: Stmt[]; labels: Set<number> };

type LoopCtx = { header: number; exit: number | null; latch: number | null };

/** Structures the CFG into nested statements. Blocks reached a second time become `goto`. */
export function structure(cfg: Cfg, opts: Options = {}): Structured {
  const abi = opts.abi ?? "win64";
  const ipdom = postDominators(cfg);
  const emitted = new Set<number>();
  const labels = new Set<number>();

  const isCond = (b: number) => cfg.blocks[b].succ.some((e) => e.kind === "true") && cfg.blocks[b].succ.some((e) => e.kind === "false");
  const succOf = (b: number, kind: string) => cfg.blocks[b].succ.find((e) => e.kind === kind)!.to;
  const condOf = (b: number) => {
    const blk = cfg.blocks[b];
    const r = conditionOf(blk.insns, { nameOf: opts.nameOf });
    // a jcc whose flags were set in the single predecessor (`cmp; jl ..; jg ..`)
    if (!("raw" in r.cond) || blk.pred.length !== 1) return r;
    const p = cfg.blocks[blk.pred[0]].insns;
    const again = conditionOf([...p.slice(0, -1), ...blk.insns], { nameOf: opts.nameOf });
    return "raw" in again.cond ? r : { cond: again.cond, consumed: -1 };
  };

  /** Statements of a block without its closing branch and a cmp/test folded into the condition. */
  const stmts = (b: number): Stmt[] => {
    const blk = cfg.blocks[b];
    const consumed = isCond(b) ? condOf(b).consumed : -1;
    const written = new Set<string>();
    const out: Stmt[] = [];
    blk.insns.forEach((insn, i) => {
      if (i === consumed) return;
      const br = branchOf(insn.text);
      if (i === blk.insns.length - 1 && br && ((br.kind === "jcc" && isCond(b)) || (br.kind === "jmp" && blk.succ.length > 0))) return;
      // a jcc whose target is outside the listing has no edge: keep it visible
      const text = br?.kind === "jcc" ? `// ${insn.text.trim()}  (conditional branch out of the function)` : translate(insn, abi, written, opts.nameOf);
      if (text !== null) out.push({ k: "s", text, addr: insn.address });
    });
    return out;
  };
  const addrOf = (b: number) => cfg.blocks[b].insns[0].address;

  const region = (start: number | null, follow: number | null, ctx: LoopCtx | null, out: Stmt[], entering = false): void => {
    let b = start;
    let first = entering;
    const leave = (x: number): Stmt | null => {
      if (ctx && x === ctx.header) return { k: "continue" };
      if (ctx && x === ctx.exit) return { k: "break" };
      if (emitted.has(x)) {
        labels.add(x);
        return { k: "goto", block: x };
      }
      return null;
    };
    while (b !== null && b !== follow) {
      const exitStmt = first ? null : leave(b);
      first = false;
      if (exitStmt) {
        out.push(exitStmt);
        return;
      }
      const loop = cfg.loops.find((l) => l.header === b);
      if (loop && !(ctx && ctx.header === b)) {
        b = emitLoop(loop.header, out);
        continue;
      }
      emitted.add(b);
      out.push({ k: "label", block: b }, ...stmts(b));
      if (ctx && b === ctx.latch) return;
      const blk = cfg.blocks[b];
      if (isCond(b)) {
        const c = condOf(b).cond;
        const t = succOf(b, "true");
        const f = succOf(b, "false");
        const lt = t === follow ? null : leave(t);
        const lf = f === follow ? null : leave(f);
        if (lt || lf) {
          // one arm is a break/continue/goto: `if (c) break;` and carry on with the other arm
          out.push({ k: "if", cond: lt ? c : negate(c), addr: addrOf(b), then: [lt ?? lf!], else: [] });
          b = lt ? f : t;
          continue;
        }
        const join = ipdom[b] >= 0 ? ipdom[b] : null;
        const thenS: Stmt[] = [];
        const elseS: Stmt[] = [];
        if (t === join) {
          region(f, join, ctx, thenS);
          out.push({ k: "if", cond: negate(c), addr: addrOf(b), then: thenS, else: [] });
        } else if (f === join) {
          region(t, join, ctx, thenS);
          out.push({ k: "if", cond: c, addr: addrOf(b), then: thenS, else: [] });
        } else {
          region(t, join, ctx, thenS);
          region(f, join, ctx, elseS);
          out.push({ k: "if", cond: c, addr: addrOf(b), then: thenS, else: elseS });
        }
        b = join;
      } else b = blk.succ.length === 1 ? blk.succ[0].to : null;
    }
  };

  /** Emits the loop headed by `h`; returns the block after it. */
  const emitLoop = (h: number, out: Stmt[]): number | null => {
    const loop = cfg.loops.find((l) => l.header === h)!;
    const exits = [...new Set([...loop.body].flatMap((b) => cfg.blocks[b].succ.map((e) => e.to)).filter((x) => !loop.body.has(x)))].sort((a, b) => a - b);
    const exit = ipdom[h] >= 0 && !loop.body.has(ipdom[h]) ? ipdom[h] : exits[0] ?? null;
    const body: Stmt[] = [];
    if (isCond(h) && stmts(h).length === 0) {
      const t = succOf(h, "true");
      const f = succOf(h, "false");
      if ((t === exit && loop.body.has(f)) || (f === exit && loop.body.has(t))) {
        // while (cond) { ... }: the header is nothing but the test
        emitted.add(h);
        const c = condOf(h).cond;
        region(t === exit ? f : t, h, { header: h, exit, latch: null }, body);
        out.push({ k: "label", block: h }, { k: "while", cond: t === exit ? negate(c) : c, addr: addrOf(h), body: trimContinue(body) });
        return exit;
      }
    }
    const latch = loop.latches.length === 1 ? loop.latches[0] : null;
    if (latch !== null && isCond(latch)) {
      const t = succOf(latch, "true");
      const f = succOf(latch, "false");
      if ((t === h && f === exit) || (f === h && t === exit)) {
        // do { ... } while (cond): the latch tests and jumps back
        region(h, null, { header: h, exit, latch }, body, true);
        const c = condOf(latch).cond;
        out.push({ k: "do", cond: t === h ? c : negate(c), addr: addrOf(latch), body });
        return exit;
      }
    }
    region(h, null, { header: h, exit, latch: null }, body, true);
    out.push({ k: "loop", addr: addrOf(h), body: trimContinue(body) });
    return exit;
  };

  const body: Stmt[] = [];
  if (cfg.blocks.length) region(0, null, null, body);
  // whatever the entry never reaches (indirect-jump targets, padding) follows under its label
  for (const b of cfg.blocks) {
    if (emitted.has(b.id)) continue;
    if (b.insns.every((i) => /^(int3|nop|ud2)$/.test(mnemonicOf(i.text)))) continue;
    labels.add(b.id);
    region(b.id, null, null, body);
  }
  return { body, labels };
}

function trimContinue(body: Stmt[]): Stmt[] {
  return body.length && body[body.length - 1].k === "continue" ? body.slice(0, -1) : body;
}

// ---------------------------------------------------------------------------
// rendering

export type PseudoLine = { indent: number; text: string; addr?: string };

export function labelName(cfg: Cfg, block: number): string {
  return `loc_${cfg.blocks[block].start.toString(16)}`;
}

/** Flattens structured statements into indented lines; each line keeps the address it came from. */
export function render(cfg: Cfg, s: Structured): PseudoLine[] {
  const out: PseudoLine[] = [];
  const walk = (list: Stmt[], indent: number) => {
    for (const st of list) {
      switch (st.k) {
        case "s":
          out.push({ indent, text: st.text, addr: st.addr });
          break;
        case "label":
          if (s.labels.has(st.block)) out.push({ indent: Math.max(0, indent - 1), text: `${labelName(cfg, st.block)}:`, addr: cfg.blocks[st.block].insns[0].address });
          break;
        case "goto":
          out.push({ indent, text: `goto ${labelName(cfg, st.block)};`, addr: cfg.blocks[st.block].insns[0].address });
          break;
        case "break":
        case "continue":
          out.push({ indent, text: `${st.k};` });
          break;
        case "if":
          out.push({ indent, text: `if (${condText(st.cond)}) {`, addr: st.addr });
          walk(st.then, indent + 1);
          if (st.else.length) {
            out.push({ indent, text: "} else {" });
            walk(st.else, indent + 1);
          }
          out.push({ indent, text: "}" });
          break;
        case "while":
          out.push({ indent, text: `while (${condText(st.cond)}) {`, addr: st.addr });
          walk(st.body, indent + 1);
          out.push({ indent, text: "}" });
          break;
        case "loop":
          out.push({ indent, text: "while (1) {", addr: st.addr });
          walk(st.body, indent + 1);
          out.push({ indent, text: "}" });
          break;
        case "do":
          out.push({ indent, text: "do {" });
          walk(st.body, indent + 1);
          out.push({ indent, text: `} while (${condText(st.cond)});`, addr: st.addr });
          break;
      }
    }
  };
  walk(s.body, 1);
  return out;
}

/** CFG -> pseudocode lines, the whole pipeline. */
export function pseudocode(cfg: Cfg, opts: Options = {}): PseudoLine[] {
  return render(cfg, structure(cfg, opts));
}
