// Instructions -> IR. Works on structure.ts blocks (Intel or AT&T text,
// normalized by pseudocode.normalize). A first pass tracks rsp / rbp relative
// to the entry stack pointer so stack accesses become slots; slots whose
// address never escapes are promoted to locations (variables), the rest stay
// memory. Calls get their arguments from the argument registers (and stack
// argument slots) written since the previous call, or from a prototype.
import { branchOf, mnemonicOf, type Cfg, type Insn } from "./structure";
import { normalize, regWidth, type Normal } from "./pseudocode";
import { c, loc, type Abi, type Case, type Expr, type IrBlock, type IrFunc, type Stmt, type Term } from "./ir";
import { lookupPrototype, type Prototype } from "./prototypes";

export type LiftOptions = {
  abi?: Abi;
  /** user / symbol name of an address (0x hex), "" when unknown */
  nameOf?: (address: string) => string;
  /** prototypes of callees; defaults to the registered providers + the built-in table */
  prototypeOf?: (address: string | null, name: string | null) => Prototype | null | undefined;
};

export const kArgRegs: Record<Abi, string[]> = { win64: ["rcx", "rdx", "r8", "r9"], sysv: ["rdi", "rsi", "rdx", "rcx", "r8", "r9"] };
export const kArgXmm: Record<Abi, string[]> = { win64: ["xmm0", "xmm1", "xmm2", "xmm3"], sysv: ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"] };
const kVolatile: Record<Abi, string[]> = {
  win64: ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "flags"],
  sysv: ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", ...Array.from({ length: 16 }, (_, i) => `xmm${i}`), "flags"],
};
/** First stack argument, relative to rsp at the call: win64 skips the 0x20 shadow space. */
export const kStackArgBase: Record<Abi, number> = { win64: 0x20, sysv: 0 };

/** The 64-bit register an alias belongs to: `ecx` -> `rcx`, `r8d` -> `r8`, `ah` -> `rax`. */
export function reg64(r: string): string {
  const n = /^r(\d+)[dwb]?$/.exec(r);
  if (n) return "r" + n[1];
  const m = /^[re]?([abcd])[xlh]$/.exec(r);
  if (m) return `r${m[1]}x`;
  const s = /^[re]?([sd]i|[sb]p)l?$/.exec(r);
  return s ? "r" + s[1] : r;
}

const isXmm = (r: string) => /^[xy]mm\d+$/.test(r);
const xmmName = (r: string) => r.replace(/^y/, "x");

type Mem = { size: number | null; seg: string; base: string; index: string; scale: number; disp: bigint; rip: boolean; abs: boolean };
const kSize: Record<string, number> = { byte: 8, word: 16, dword: 32, qword: 64, xmmword: 128, tbyte: 80, ymmword: 256 };

function parseMem(op: string): Mem | null {
  const m = /^(?:(byte|word|dword|qword|xmmword|tbyte|ymmword)\s+ptr\s+)?(?:(\w+):)?\[(.+)\]$/i.exec(op.trim());
  if (!m) return null;
  const r: Mem = { size: m[1] ? kSize[m[1].toLowerCase()] : null, seg: m[2]?.toLowerCase() ?? "", base: "", index: "", scale: 1, disp: 0n, rip: false, abs: false };
  const inner = m[3].replace(/\s+/g, "").toLowerCase();
  for (const t of inner.match(/[+-]?[^+-]+/g) ?? []) {
    const neg = t.startsWith("-");
    const body = t.replace(/^[+-]/, "");
    const sc = /^(\w+)\*(\d)$/.exec(body) ?? /^(\d)\*(\w+)$/.exec(body)?.slice(0).reverse();
    if (/^(0x[0-9a-f]+|\d+)$/.test(body)) r.disp += neg ? -BigInt(body) : BigInt(body);
    else if (sc && /^\*?\w+$/.test(sc[1]) && regWidth(sc[1])) {
      r.index = sc[1];
      r.scale = Number(sc[2]);
    } else if (body === "rip" || body === "eip") r.rip = true;
    else if (regWidth(body)) {
      if (!r.base) r.base = body;
      else r.index = body;
    } else return null;
  }
  r.abs = !r.base && !r.index && !r.rip;
  return r;
}

/** Signed value of an immediate operand, or null. */
function imm(op: string): bigint | null {
  const t = op.trim().toLowerCase();
  if (/^-?(0x[0-9a-f]+|\d+)$/.test(t)) return t.startsWith("-") ? -BigInt(t.slice(1)) : BigInt(t);
  return null;
}

type Frame = { sp: number | null; bp: number | null; k: Map<string, bigint> };
const copyFrame = (f: Frame): Frame => ({ sp: f.sp, bp: f.bp, k: new Map() });

/** Stack offset (from entry rsp) a memory operand addresses, without an index register. */
function stackOff(m: Mem, f: Frame): number | null {
  if (m.seg || m.index) return null;
  const b = m.base ? reg64(m.base) : "";
  if (b === "rsp" && f.sp !== null) return f.sp + Number(m.disp);
  if (b === "rbp" && f.bp !== null) return f.bp + Number(m.disp);
  return null;
}

/** Effect of one instruction on the tracked frame registers. */
function frameStep(n: Normal, f: Frame): void {
  const [d, s] = n.ops;
  const dr = d && regWidth(d) ? reg64(d) : "";
  const sr = s && regWidth(s) ? reg64(s) : "";
  const iv = s !== undefined ? imm(s) : null;
  switch (n.mn) {
    case "push":
      if (f.sp !== null) f.sp -= 8;
      return;
    case "pop":
      if (f.sp !== null) f.sp += 8;
      if (dr === "rbp") f.bp = null;
      if (dr === "rsp") f.sp = null;
      return;
    case "leave":
      f.sp = f.bp === null ? null : f.bp + 8;
      f.bp = null;
      return;
    case "call":
    case "ret":
      return;
  }
  if (dr === "rsp") {
    if ((n.mn === "sub" || n.mn === "add") && f.sp !== null) {
      const v = iv ?? (sr ? f.k.get(sr) ?? null : null);
      f.sp = v === null ? null : f.sp + (n.mn === "sub" ? -1 : 1) * Number(BigInt.asIntN(64, v));
    } else if (n.mn === "mov" && sr === "rbp") f.sp = f.bp;
    else if (n.mn === "lea") {
      const m = parseMem(s);
      const o = m ? stackOff(m, f) : null;
      f.sp = o;
    } else f.sp = null;
    return;
  }
  if (dr === "rbp") {
    if (n.mn === "mov" && sr === "rsp") f.bp = f.sp;
    else if (n.mn === "lea") {
      const m = parseMem(s);
      f.bp = m && reg64(m.base) === "rsp" && !m.index && f.sp !== null ? f.sp + Number(m.disp) : null;
    } else f.bp = null;
  }
  if (dr) {
    if ((n.mn === "mov" || n.mn === "movabs") && iv !== null) f.k.set(dr, BigInt.asUintN(64, iv));
    else f.k.delete(dr);
  }
}

/** Entry frame state of every block (rsp relative to the entry rsp, rbp when it is a frame pointer). */
function frames(cfg: Cfg): (Frame | null)[] {
  const out: (Frame | null)[] = cfg.blocks.map(() => null);
  if (!cfg.blocks.length) return out;
  out[0] = { sp: 0, bp: null, k: new Map() };
  const work = [0];
  while (work.length) {
    const b = work.pop()!;
    const f = copyFrame(out[b]!);
    for (const i of cfg.blocks[b].insns) frameStep(normalize(i.text), f);
    for (const e of cfg.blocks[b].succ) {
      if (out[e.to]) continue;
      out[e.to] = copyFrame(f);
      work.push(e.to);
    }
  }
  for (let b = 0; b < out.length; b++) if (!out[b]) out[b] = { sp: null, bp: null, k: new Map() };
  return out;
}

/** Source width of AT&T movz/movs forms (`movzbl` reads a byte), which normalize() drops. */
function attExtendWidth(text: string): number | null {
  const m = /^\s*mov([sz])([bwl])([wlq])\s/i.exec(text);
  if (m) return { b: 8, w: 16, l: 32 }[m[2].toLowerCase() as "b" | "w" | "l"];
  if (/^\s*movslq\s/i.test(text)) return 32;
  return null;
}

const kAttAlias: Record<string, string> = { cltq: "cdqe", cqto: "cqo", cltd: "cdq", cwtl: "cwde", cbtw: "cbw" };
const kFlagSafe = new Set(["mov", "movabs", "movzx", "movsx", "movsxd", "lea", "push", "pop", "nop", "leave", "xchg", "not", "bswap", "cdqe", "cdq", "cqo", "cwde", "cbw", "endbr64"]);

/** Implicit registers of instructions the lifter keeps as text. */
const kImplicit: Record<string, { uses: string[]; defs: string[] }> = {
  cpuid: { uses: ["rax", "rcx"], defs: ["rax", "rbx", "rcx", "rdx"] },
  rdtsc: { uses: [], defs: ["rax", "rdx"] },
  rdtscp: { uses: [], defs: ["rax", "rdx", "rcx"] },
  xgetbv: { uses: ["rcx"], defs: ["rax", "rdx"] },
  syscall: { uses: ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"], defs: ["rax", "rcx", "r11"] },
  mul: { uses: ["rax"], defs: ["rax", "rdx"] },
  imul: { uses: ["rax"], defs: ["rax", "rdx"] },
  cmpxchg: { uses: ["rax"], defs: ["rax"] },
  rep: { uses: ["rdi", "rsi", "rcx", "rax"], defs: ["rdi", "rsi", "rcx"] },
  repe: { uses: ["rdi", "rsi", "rcx", "rax"], defs: ["rdi", "rsi", "rcx"] },
  repz: { uses: ["rdi", "rsi", "rcx", "rax"], defs: ["rdi", "rsi", "rcx"] },
  repne: { uses: ["rdi", "rsi", "rcx", "rax"], defs: ["rdi", "rsi", "rcx"] },
  repnz: { uses: ["rdi", "rsi", "rcx", "rax"], defs: ["rdi", "rsi", "rcx"] },
  movsb: { uses: ["rdi", "rsi"], defs: ["rdi", "rsi"] },
  stosb: { uses: ["rdi", "rax"], defs: ["rdi"] },
};

const kSse: Record<string, { op: "+" | "-" | "*" | "/" | "min" | "max"; w: number }> = {
  addss: { op: "+", w: 32 }, subss: { op: "-", w: 32 }, mulss: { op: "*", w: 32 }, divss: { op: "/", w: 32 }, minss: { op: "min", w: 32 }, maxss: { op: "max", w: 32 },
  addsd: { op: "+", w: 64 }, subsd: { op: "-", w: 64 }, mulsd: { op: "*", w: 64 }, divsd: { op: "/", w: 64 }, minsd: { op: "min", w: 64 }, maxsd: { op: "max", w: 64 },
};
const kSseMov: Record<string, number> = { movss: 32, movsd: 64, movaps: 128, movups: 128, movapd: 128, movupd: 128, movdqa: 128, movdqu: 128, movq: 64, movd: 32, vmovss: 32, vmovsd: 64, vmovaps: 128, vmovups: 128 };

const kFlagsCmp = new Set(["cmp", "sub"]);

/** Lifts every block of `cfg`. Slots and frames are computed for the whole function first. */
export function liftFunction(cfg: Cfg, opts: LiftOptions = {}): IrFunc {
  const abi = opts.abi ?? "win64";
  const nameOf = opts.nameOf ?? (() => "");
  const protoOf = opts.prototypeOf ?? lookupPrototype;
  const entry = frames(cfg);

  // --- which stack slots can become variables
  const accesses = new Map<number, Set<number>>(); // offset -> widths
  const taken: number[] = [];
  const direct = new Set<number>(); // offsets accessed by something other than push / pop / leave
  const note = (off: number, w: number, saved = false) => {
    if (!saved) direct.add(off);
    let s = accesses.get(off);
    if (!s) accesses.set(off, (s = new Set()));
    s.add(w);
  };
  cfg.blocks.forEach((b, bi) => {
    const f = copyFrame(entry[bi]!);
    for (const insn of b.insns) {
      const n = normalize(insn.text);
      if (n.mn === "push" && f.sp !== null) note(f.sp - 8, 64, true);
      if (n.mn === "pop" && f.sp !== null) note(f.sp, 64, true);
      if (n.mn === "leave" && f.bp !== null) note(f.bp, 64, true);
      n.ops.forEach((op, i) => {
        const m = parseMem(op);
        if (m) {
          const o = stackOff(m, f);
          const w = m.size ?? (regWidth(n.ops[1 - i] ?? "") || (isXmm(n.ops[1 - i] ?? "") ? kSseMov[n.mn] ?? 64 : 64));
          if (o !== null) {
            if (n.mn === "lea") taken.push(o);
            else note(o, w);
          } else if (m.index && m.base && ["rsp", "rbp"].includes(reg64(m.base))) {
            const base = stackOff({ ...m, index: "" }, f);
            if (base !== null) taken.push(base);
          }
        } else if (regWidth(op) && i > 0 && ["rsp", "rbp"].includes(reg64(op)) && !(n.mn === "mov" && ["rsp", "rbp"].includes(reg64(n.ops[0])))) {
          // the frame address itself escapes (mov rcx, rsp)
          const r = reg64(op);
          const o = r === "rsp" ? f.sp : f.bp;
          if (o !== null && !["add", "sub", "and", "cmp"].includes(n.mn)) taken.push(o);
        }
      });
      frameStep(n, f);
    }
  });
  const takenSorted = [...new Set(taken)].sort((x, y) => x - y);
  const slots = new Set<number>();
  const offs = [...accesses.keys()].sort((x, y) => x - y);
  for (const off of offs) {
    const widths = [...accesses.get(off)!];
    const maxW = Math.max(...widths);
    const end = off + maxW / 8;
    // escaped: inside the object an address was taken of (up to 0x40 bytes, the next taken
    // address or the return address). Saved-register slots never alias anything.
    const esc = direct.has(off) && takenSorted.some((t, i) => {
      const next = takenSorted[i + 1] ?? Infinity;
      const limit = Math.min(next, t < 0 ? 0 : Infinity, t + 0x40);
      return off >= t && off < limit;
    });
    const overlaps = offs.some((o) => o !== off && o < end && o + Math.max(...accesses.get(o)!) / 8 > off);
    if (!esc && !overlaps && maxW <= 64 && off !== 0) slots.add(off);
  }
  const slotMax = new Map<number, number>([...slots].map((o) => [o, Math.max(...accesses.get(o)!)]));

  let nextId = 1;
  const id = () => nextId++;
  const blocks: IrBlock[] = cfg.blocks.map((b, bi) => {
    const f = copyFrame(entry[bi]!);
    const stmts: Stmt[] = [];
    const written = new Set<string>(); // argument locations written since the previous call
    let term: Term | null = null;
    const succ = (kind: string) => b.succ.find((e) => e.kind === kind)?.to;

    for (let ii = 0; ii < b.insns.length; ii++) {
      const insn = b.insns[ii];
      const addr = insn.address;
      const n = normalize(insn.text);
      if (kAttAlias[n.mn]) n.mn = kAttAlias[n.mn];
      const next = BigInt(insn.address) + BigInt(insn.length);
      const ripAbs = (m: Mem): bigint => (n.ripTarget !== null ? n.ripTarget : next + m.disp);

      /** address expression of a memory operand */
      const addrOf = (m: Mem): Expr => {
        const so = stackOff(m, f);
        if (so !== null) return { k: "sa", off: so };
        if (m.rip) return c(ripAbs(m));
        let e: Expr | null = null;
        const add = (x: Expr) => (e = e ? { k: "b", op: "+", a: e, b: x, w: 64 } : x);
        if (m.base) add(regVal(m.base, 64));
        if (m.index) {
          const iv = regVal(m.index, 64);
          add(m.scale === 1 ? iv : { k: "b", op: "*", a: iv, b: c(m.scale), w: 64 });
        }
        if (m.disp !== 0n || !e) add(c(m.disp));
        return m.seg ? { k: "b", op: "+", a: { k: "raw", text: `__${m.seg}base`, w: 64 }, b: e!, w: 64 } : e!;
      };
      /** value of a register (rsp / rbp as frame addresses when tracked) */
      const regVal = (r: string, w: number): Expr => {
        const r64 = reg64(r);
        if (r64 === "rsp" && f.sp !== null) return { k: "sa", off: f.sp };
        if (r64 === "rbp" && f.bp !== null) return { k: "sa", off: f.bp };
        if (/^[abcd]h$/.test(r)) return { k: "cast", a: { k: "b", op: ">>", a: loc(r64), b: c(8), w: 64 }, w: 8 };
        if (isXmm(r)) return loc(xmmName(r), w);
        return loc(r64, Math.min(w, regWidth(r) || 64));
      };
      const slotOf = (m: Mem): number | null => {
        const o = stackOff(m, f);
        return o !== null && slots.has(o) ? o : null;
      };
      const opWidth = (op: string | undefined): number | null => {
        if (op === undefined) return null;
        if (regWidth(op)) return regWidth(op);
        if (isXmm(op)) return 128;
        return parseMem(op)?.size ?? null;
      };
      /** read an operand */
      const rd = (op: string, w: number, fl = false): Expr => {
        const iv = imm(op);
        if (iv !== null) return c(iv, w);
        if (regWidth(op) || isXmm(op)) return regVal(op, w);
        const m = parseMem(op);
        if (!m) return { k: "raw", text: op, w };
        const so = slotOf(m);
        if (so !== null) return loc(`s${so}`, w);
        if (m.seg && !m.base && !m.index) return { k: "raw", text: `__read${m.seg}${{ 8: "byte", 16: "word", 32: "dword", 64: "qword" }[w] ?? "qword"}(0x${m.disp.toString(16)})`, w };
        return { k: "ld", a: addrOf(m), w, ...(fl ? { fl: true } : {}) };
      };
      /** write an operand */
      const wr = (op: string, w: number, v: Expr, extra: { push?: boolean; fl?: boolean } = {}) => {
        if (regWidth(op)) {
          const r64 = reg64(op);
          if ((r64 === "rsp" && f.sp !== null) || (r64 === "rbp" && f.bp !== null && n.mn !== "pop")) return;
          const rw = regWidth(op);
          if (/^[abcd]h$/.test(op)) stmts.push({ k: "set", id: id(), dst: r64, w: 64, src: { k: "part", old: loc(r64), v, w: 8, hi: true }, addr });
          else if (rw < 32) stmts.push({ k: "set", id: id(), dst: r64, w: 64, src: { k: "part", old: loc(r64), v, w: rw }, addr });
          else stmts.push({ k: "set", id: id(), dst: r64, w: rw, src: v, addr });
          written.add(r64);
          return;
        }
        if (isXmm(op)) {
          stmts.push({ k: "set", id: id(), dst: xmmName(op), w, src: v, addr });
          written.add(xmmName(op));
          return;
        }
        const m = parseMem(op);
        if (!m) return asm();
        const so = slotOf(m);
        if (so !== null) {
          const max = slotMax.get(so)!;
          const src: Expr = w < max ? { k: "part", old: loc(`s${so}`), v, w } : v;
          stmts.push({ k: "set", id: id(), dst: `s${so}`, w: w < max ? 64 : w, src, addr, ...(extra.push ? { push: true } : {}) });
          written.add(`s${so}`);
          return;
        }
        stmts.push({ k: "st", id: id(), a: addrOf(m), w, v, addr, ...(extra.fl ? { fl: true } : {}) });
      };
      const setFlags = (kind: "cmp" | "test" | "res" | "fcmp", a: Expr, b: Expr, w: number): void => {
        stmts.push({ k: "set", id: id(), dst: "flags", w, src: { k: "flags", kind, a, b, w }, addr });
      };
      function asm(): void {
        const text = insn.text.trim();
        const uses: Expr[] = [];
        const defs = new Set<string>();
        const first = mnemonicOf(text);
        const imp = kImplicit[first] ?? kImplicit[n.mn];
        n.ops.forEach((op, i) => {
          if (regWidth(op) || isXmm(op)) {
            uses.push(regVal(op, opWidth(op) ?? 64));
            if (i === 0 && !["push", "cmp", "test", "bt"].includes(n.mn)) defs.add(isXmm(op) ? xmmName(op) : reg64(op));
          } else {
            const m = parseMem(op);
            if (m) {
              const so = slotOf(m);
              if (so !== null) {
                uses.push(loc(`s${so}`));
                if (i === 0) defs.add(`s${so}`);
              } else uses.push({ k: "ld", a: addrOf(m), w: m.size ?? 64 });
            }
          }
        });
        if (imp) {
          imp.uses.forEach((r) => uses.push(loc(r)));
          imp.defs.forEach((r) => defs.add(r));
        }
        if (!kFlagSafe.has(n.mn)) defs.add("flags");
        for (const r of ["rsp", "rbp"]) {
          if (defs.has(r) && ((r === "rsp" && f.sp !== null) || (r === "rbp" && f.bp !== null))) defs.delete(r);
        }
        stmts.push({ k: "asm", id: id(), text, uses: uses.filter((u) => u.k !== "sa"), defs: [...defs], addr });
      }

      /** callee name and prototype for a call / tail-jump operand */
      const callee = (op: string): { target: Expr; name: string | null; address: string | null } => {
        const t = /^(0x[0-9a-f]+)$/i.exec(op.trim());
        if (t) {
          const address = "0x" + BigInt(t[1]).toString(16);
          return { target: c(BigInt(t[1])), name: nameOf(address) || null, address };
        }
        const m = parseMem(op);
        if (m && (m.rip || m.abs)) {
          const slot = m.rip ? ripAbs(m) : m.disp;
          const address = "0x" + slot.toString(16);
          return { target: { k: "ld", a: c(slot), w: 64 }, name: nameOf(address) || null, address: null };
        }
        return { target: rd(op, 64), name: null, address: null };
      };
      const callExpr = (op: string): { e: Extract<Expr, { k: "call" }>; proto: Prototype | null } => {
        const { target, name, address } = callee(op);
        const proto = protoOf(address, name) ?? null;
        const ints = kArgRegs[abi];
        const xmms = kArgXmm[abi];
        const args: Expr[] = [];
        const stackBase = f.sp !== null ? f.sp + kStackArgBase[abi] : null;
        const stackArg = (k: number): Expr => (stackBase !== null && slots.has(stackBase + 8 * k) ? loc(`s${stackBase + 8 * k}`) : stackBase !== null ? { k: "ld", a: { k: "sa", off: stackBase + 8 * k }, w: 64 } : c(0));
        const isF = (t?: string) => t === "float" || t === "double";
        // the argument registers written since the previous call
        const guess = (): Expr[] => {
          const out: Expr[] = [];
          let count = 0;
          ints.forEach((r, i) => (written.has(r) || (abi === "win64" && written.has(xmms[i]))) && (count = i + 1));
          let stackCount = 0;
          if (stackBase !== null) for (let k = 0; k < 16; k++) if (written.has(`s${stackBase + 8 * k}`)) stackCount = k + 1;
          if (stackCount) count = ints.length + stackCount;
          for (let i = 0; i < count; i++) {
            if (i < ints.length) out.push(abi === "win64" && written.has(xmms[i]) && !written.has(ints[i]) ? loc(xmms[i], 64) : loc(ints[i]));
            else out.push(stackArg(i - ints.length));
          }
          if (abi === "sysv") {
            let nf = 0;
            xmms.forEach((x, i) => written.has(x) && (nf = i + 1));
            for (let i = 0; i < nf; i++) out.push(loc(xmms[i], 64));
          }
          return out;
        };
        if (proto?.args) {
          let ni = 0;
          let nf = 0;
          proto.args.forEach((a, i) => {
            const fw = a.type === "float" ? 32 : 64;
            if (abi === "win64") {
              if (i < 4) args.push(isF(a.type) ? loc(xmms[i], fw) : loc(ints[i]));
              else args.push(stackArg(i - 4));
            } else if (isF(a.type)) args.push(nf < 8 ? loc(xmms[nf++], fw) : c(0));
            else args.push(ni < 6 ? loc(ints[ni++]) : stackArg(ni++ - 6));
          });
          // variadic: whatever else was written after the fixed arguments
          if (proto.variadic) args.push(...guess().slice(abi === "win64" ? proto.args.length : ni).filter((e) => !(e.k === "l" && e.loc.startsWith("xmm") && abi === "sysv")));
        } else args.push(...guess());
        written.clear();
        const fl = proto?.returns === "float" || proto?.returns === "double";
        return { e: { k: "call", target, args, w: fl && proto?.returns === "float" ? 32 : 64, ...(name ? { name } : {}), ...(fl ? { fl: true } : {}) }, proto };
      };

      const br = branchOf(insn.text);
      const last = ii === b.insns.length - 1;
      if (br) {
        if (br.kind === "ret") term = { k: "ret", v: loc("rax"), fv: loc("xmm0"), addr };
        else if (br.kind === "stop") term = { k: "stop", addr };
        else if (br.kind === "jmp") {
          const cases = b.succ.filter((e) => e.kind === "case");
          const j = succ("jump");
          if (cases.length) {
            const x = switchIndex(b.insns, ii);
            const cs: Case[] = cases.map((e) => ({ vals: (e.values ?? []).map(BigInt), to: e.to }));
            term = { k: "switch", x: x ? loc(`sw${b.id}`) : { k: "raw", text: "SWITCH_INDEX", w: 64 }, cases: cs, def: null, addr };
            if (x) {
              // the index as it was before the table load overwrote it
              const at = stmts.findIndex((s) => s.addr === b.insns[x.at].address);
              const s: Stmt = { k: "set", id: id(), dst: `sw${b.id}`, w: 64, src: regVal(x.reg, 64), addr: b.insns[x.at].address };
              if (at >= 0) stmts.splice(at, 0, s);
              else stmts.push(s);
            }
          } else if (j !== undefined) term = { k: "jump", to: j };
          else {
            const op = n.ops[0] ?? "";
            const direct = br.target !== null;
            const m = parseMem(op);
            if (direct || (m && (m.rip || m.abs))) term = { k: "tail", call: callExpr(op).e, addr };
            else term = { k: "ijump", x: rd(op, 64), addr };
          }
        } else if (br.kind === "jcc") {
          const t = succ("true");
          const fs = succ("false");
          let cond: Expr;
          if (n.mn === "jrcxz" || n.mn === "jecxz") cond = { k: "cmp", op: "==", a: loc("rcx", n.mn === "jrcxz" ? 64 : 32), b: c(0, n.mn === "jrcxz" ? 64 : 32) };
          else if (/^loop/.test(n.mn)) {
            stmts.push({ k: "set", id: id(), dst: "rcx", w: 64, src: { k: "b", op: "+", a: loc("rcx"), b: c(-1), w: 64 }, addr });
            cond = { k: "cmp", op: "!=", a: loc("rcx"), b: c(0) };
          } else cond = { k: "cc", cc: n.mn.slice(1), f: loc("flags") };
          if (t !== undefined && fs !== undefined) term = { k: "cond", c: cond, t, f: fs, addr };
          else {
            stmts.push({ k: "asm", id: id(), text: `JUMPOUT(${br.target !== null ? "0x" + br.target.toString(16) : "?"})`, uses: [cond], defs: [], addr });
            const to = t ?? fs;
            term = to !== undefined ? { k: "jump", to } : { k: "end" };
          }
        }
        frameStep(n, f);
        if (last) break;
        continue;
      }

      liftOne();
      frameStep(n, f);

      function liftOne(): void {
        const [d, s, t] = n.ops;
        const mn = n.mn;
        const dw = opWidth(d);
        const sw = opWidth(s);
        const w = (regWidth(d ?? "") || dw || regWidth(s ?? "") || sw || 64);
        if (/^nop[wlq]?$/.test(mn) || mn === "endbr64" || mn === "endbr32" || mn === "pause" || mn === "int3" || /^prefetch/.test(mn)) return;
        if (mn === "xchg" && d === s) return;
        if (isXmm(d ?? "") || isXmm(s ?? "")) return sse();
        switch (mn) {
          case "mov":
          case "movabs":
            if (n.ops.length !== 2) return asm();
            return wr(d, w, rd(s, w));
          case "movzx":
          case "movsx":
          case "movsxd": {
            const from = attExtendWidth(insn.text) ?? (sw && sw !== dw ? sw : mn === "movsxd" ? 32 : 8);
            const to = regWidth(d) || 64;
            return wr(d, to, { k: "cast", a: rd(s, from), w: to, s: mn !== "movzx" });
          }
          case "lea": {
            const m = parseMem(s);
            if (!m) return asm();
            return wr(d, regWidth(d) || 64, regWidth(d) < 64 ? { k: "cast", a: addrOf(m), w: regWidth(d) } : addrOf(m));
          }
          case "add":
          case "sub":
          case "and":
          case "or":
          case "xor":
          case "adc":
          case "sbb": {
            if (n.ops.length !== 2 || mn === "adc" || mn === "sbb") return asm();
            const a = rd(d, w);
            const b2 = rd(s, w);
            if ((mn === "xor" || mn === "sub") && d === s) {
              wr(d, w, c(0, w));
              return setFlags("res", c(0, w), c(0, w), w);
            }
            const v: Expr = { k: "b", op: mn === "add" ? "+" : mn === "sub" ? "-" : mn === "and" ? "&" : mn === "or" ? "|" : "^", a, b: b2, w };
            if (kFlagsCmp.has(mn)) {
              if (b2.k === "c" && isVar(d)) {
                // sub reg, imm: compare the new value plus the immediate, so a loop test
                // after the decrement does not need the old value
                wr(d, w, v);
                return setFlags("cmp", { k: "b", op: "+", a: rd(d, w), b: b2, w }, b2, w);
              }
              setFlags("cmp", a, b2, w);
              return wr(d, w, v);
            }
            return result(d, w, v);
          }
          case "cmp":
            return setFlags("cmp", rd(d, w), rd(s, w), w);
          case "test":
            return setFlags("test", rd(d, w), rd(s, w), w);
          case "inc":
          case "dec": {
            const v: Expr = { k: "b", op: mn === "inc" ? "+" : "-", a: rd(d, w), b: c(1, w), w };
            return result(d, w, v);
          }
          case "neg": {
            const v: Expr = { k: "u", op: "-", a: rd(d, w), w };
            return result(d, w, v);
          }
          case "not":
            return wr(d, w, { k: "u", op: "~", a: rd(d, w), w });
          case "shl":
          case "sal":
          case "shr":
          case "sar":
          case "rol":
          case "ror": {
            const cnt: Expr = s === undefined ? c(1, 8) : regWidth(s) ? loc(reg64(s), 8) : rd(s, 8);
            const op = mn === "shl" || mn === "sal" ? "<<" : mn === "shr" ? ">>" : mn === "sar" ? ">>s" : mn;
            const v: Expr = { k: "b", op: op as "<<", a: rd(d, w), b: cnt, w };
            return result(d, w, v);
          }
          case "imul": {
            if (n.ops.length === 1) return asm();
            const v: Expr = n.ops.length === 3 ? { k: "b", op: "*", a: rd(s, w), b: rd(t, w), w } : { k: "b", op: "*", a: rd(d, w), b: rd(s, w), w };
            return result(d, w, v);
          }
          case "div":
          case "idiv": {
            const xw = opWidth(d) ?? 64;
            if (xw < 32) return asm();
            const x = rd(d, xw);
            const signed = mn === "idiv";
            const num = loc("rax", xw);
            stmts.push({ k: "set", id: id(), dst: "rdx", w: xw, src: { k: "b", op: signed ? "%" : "%u", a: num, b: x, w: xw }, addr });
            stmts.push({ k: "set", id: id(), dst: "rax", w: xw, src: { k: "b", op: signed ? "/" : "/u", a: num, b: x, w: xw }, addr });
            return asmFlags();
          }
          case "cdq":
          case "cqo":
          case "cwd": {
            const xw = mn === "cqo" ? 64 : mn === "cdq" ? 32 : 16;
            const v: Expr = { k: "b", op: ">>s", a: loc("rax", xw), b: c(xw - 1, 8), w: xw };
            return xw === 16 ? asm() : void stmts.push({ k: "set", id: id(), dst: "rdx", w: xw, src: v, addr });
          }
          case "cdqe":
            return void stmts.push({ k: "set", id: id(), dst: "rax", w: 64, src: { k: "cast", a: loc("rax", 32), w: 64, s: true }, addr });
          case "cwde":
            return void stmts.push({ k: "set", id: id(), dst: "rax", w: 32, src: { k: "cast", a: loc("rax", 16), w: 32, s: true }, addr });
          case "push": {
            if (f.sp === null) return asm();
            const v = rd(d, 64);
            const so = f.sp - 8;
            if (slots.has(so)) stmts.push({ k: "set", id: id(), dst: `s${so}`, w: 64, src: v, addr, push: true });
            else stmts.push({ k: "st", id: id(), a: { k: "sa", off: so }, w: 64, v, addr });
            return;
          }
          case "pop": {
            if (f.sp === null) return asm();
            const so = f.sp;
            const v: Expr = slots.has(so) ? loc(`s${so}`) : { k: "ld", a: { k: "sa", off: so }, w: 64 };
            return wr(d, 64, v);
          }
          case "leave": {
            if (f.bp === null) return asm();
            const so = f.bp;
            const v: Expr = slots.has(so) ? loc(`s${so}`) : { k: "ld", a: { k: "sa", off: so }, w: 64 };
            stmts.push({ k: "set", id: id(), dst: "rbp", w: 64, src: v, addr });
            return;
          }
          case "xchg": {
            if (!regWidth(d) || !regWidth(s)) return asm();
            const tmp = `t${ii}_${b.id}`;
            stmts.push({ k: "set", id: id(), dst: tmp, w, src: rd(d, w), addr });
            wr(d, w, rd(s, w));
            wr(s, w, loc(tmp, w));
            return;
          }
          case "call": {
            if (n.ops.length !== 1) return asm();
            const { e, proto } = callExpr(d);
            const dst = proto?.returns === "void" ? null : e.fl ? "xmm0" : "rax";
            stmts.push({ k: "call", id: id(), dst, call: e, addr });
            stmts.push({ k: "clob", id: id(), locs: kVolatile[abi].filter((r) => r !== dst), addr });
            return;
          }
        }
        if (/^set[a-z]+$/.test(mn) && n.ops.length === 1) return wr(d, 8, { k: "cast", a: { k: "cc", cc: mn.slice(3), f: loc("flags") }, w: 8 });
        if (/^cmov[a-z]+$/.test(mn) && n.ops.length === 2) {
          return wr(d, w, { k: "sel", c: { k: "cc", cc: mn.slice(4), f: loc("flags") }, a: rd(s, w), b: rd(d, w), w });
        }
        return asm();
      }

      /** a register or promoted slot: readable again after the write */
      function isVar(op: string): boolean {
        if (regWidth(op)) return !["rsp", "rbp"].includes(reg64(op)) && regWidth(op) >= 32;
        const m = parseMem(op);
        return !!m && slotOf(m) !== null && (m.size ?? 64) === (slotMax.get(slotOf(m)!) ?? 0);
      }

      /** writes an arithmetic result; its flags are the result (re-read from the destination when it is a variable) */
      function result(d: string, w: number, v: Expr): void {
        if (isVar(d)) {
          wr(d, w, v);
          const nv = rd(d, w);
          return setFlags("res", nv, nv, w);
        }
        setFlags("res", v, v, w);
        wr(d, w, v);
      }

      function asmFlags(): void {
        stmts.push({ k: "asm", id: id(), text: "", uses: [], defs: ["flags"], addr });
      }

      function sse(): void {
        const [d, s] = n.ops;
        const mn = n.mn.replace(/^v(?=(add|sub|mul|div|min|max|sqrt|cvt|ucomi|comi|xor))/, "");
        const three = n.ops.length === 3 && n.mn.startsWith("v");
        const src = three ? n.ops[2] : s;
        const ar = kSse[mn];
        if (ar) {
          const a = three ? rd(n.ops[1], ar.w, true) : rd(d, ar.w, true);
          return wr(d, ar.w, { k: "b", op: ar.op, a, b: rd(src, ar.w, true), w: ar.w, fl: true });
        }
        if (mn === "sqrtss" || mn === "sqrtsd") {
          const fw = mn === "sqrtss" ? 32 : 64;
          return wr(d, fw, { k: "u", op: "sqrt", a: rd(src, fw, true), w: fw, fl: true });
        }
        if (kSseMov[n.mn] !== undefined && n.ops.length === 2) {
          let mw = kSseMov[n.mn];
          if (n.mn === "movq" || n.mn === "movd") mw = regWidth(d) || regWidth(s) || mw;
          const fl = /ss$|sd$|ps$|pd$/.test(n.mn);
          if (regWidth(d)) return wr(d, mw, rd(s, mw));
          return wr(d, mw, rd(s, mw, fl), { fl });
        }
        if ((mn === "xorps" || mn === "xorpd" || mn === "pxor") && d === (three ? n.ops[2] : s) && (!three || n.ops[1] === d)) {
          return wr(d, 128, { k: "c", v: 0n, w: 128, fl: true });
        }
        if (/^cvtsi2s[sd]q?$|^cvtsi2s[sd]l$/.test(mn)) {
          const fw = mn.includes("ss") ? 32 : 64;
          const iw = opWidth(src) ?? (mn.endsWith("q") ? 64 : 32);
          return wr(d, fw, { k: "cast", a: rd(src, iw), w: fw, to: fw === 32 ? "f32" : "f64" });
        }
        if (/^cvtt?s[sd]2si/.test(mn)) {
          const fw = mn.includes("ss2") ? 32 : 64;
          const iw = regWidth(d) || 32;
          return wr(d, iw, { k: "cast", a: rd(s, fw, true), w: iw, to: "int" });
        }
        if (mn === "cvtss2sd" || mn === "cvtsd2ss") {
          const to = mn === "cvtss2sd" ? 64 : 32;
          return wr(d, to, { k: "cast", a: rd(src, to === 64 ? 32 : 64, true), w: to, to: to === 64 ? "f64" : "f32" });
        }
        if (/^u?comis[sd]$/.test(mn)) {
          const fw = mn.endsWith("ss") ? 32 : 64;
          return setFlags("fcmp", rd(d, fw, true), rd(s, fw, true), fw);
        }
        return asm();
      }
    }
    if (!term) {
      const fall = succ("fall") ?? succ("jump");
      term = fall !== undefined ? { k: "jump", to: fall } : { k: "end" };
    }
    return { id: b.id, start: b.start, addr: b.insns[0]?.address ?? "0x" + b.start.toString(16), insns: b.insns, stmts, term };
  });
  return { blocks, abi, slots, nextId };
}

/** Index register of a jump-table dispatch ending at `insns[at]`, and where the table load is. */
function switchIndex(insns: readonly Insn[], at: number): { reg: string; at: number } | null {
  for (let i = at; i >= Math.max(0, at - 8); i--) {
    const n = normalize(insns[i].text);
    for (const op of n.ops) {
      const m = parseMem(op);
      if (m?.index && (m.scale === 4 || m.scale === 8)) return { reg: m.index, at: i };
    }
  }
  return null;
}

