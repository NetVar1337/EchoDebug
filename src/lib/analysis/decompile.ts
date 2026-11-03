// The decompiler pipeline behind the CFG view's Pseudocode mode:
//   structure.ts blocks -> irlift (IR, stack slots, calls with arguments)
//   -> dataflow (signature, propagation, dead code) -> [unflatten]
//   -> graph clean-up (empty blocks, && / || conditions, switch defaults,
//      constant branches) -> structuring (if / else if / while / do / for /
//      switch, break / continue, small return blocks duplicated instead of goto)
//   -> C-like text with variables (a1.., v1.., var_18), types guessed from use
//      (pointer, signed / unsigned, float) and struct fields (p->field_10, or
//      the field names of a Structs type mapped onto the variable).
// pseudocode.ts keeps the older per-instruction output (the "raw" toggle).
import { graphInfo, type Cfg } from "./structure";
import {
  hasCall, isBool, negate, retarget, simp, stmtDefs, succOf, walk, width,
  type Expr, type IrBlock, type IrFunc, type Stmt, type Term,
} from "./ir";
import { analyze, analyzeSignature, baseLoc, optimize, webs, defId, livePreds, type Flow } from "./dataflow";
import { liftFunction, type LiftOptions } from "./irlift";
import { unflatten as removeFlattening, type UnflattenReport } from "./unflatten";
import { cType, lookupPrototype, type Prototype } from "./prototypes";
import type { PseudoLine } from "./pseudocode";

export type StructField = { offset: number; size: number; name: string; type?: string };
export type DecompileOptions = LiftOptions & {
  /** remove control-flow flattening before structuring */
  unflatten?: boolean;
  /** this function's address (0x hex), for its own prototype and name */
  entry?: string;
  /** fields of a user struct type by name (Structs view) */
  fieldsOf?: (typeName: string) => StructField[] | null;
  /** variable name -> struct type name: the variable is a pointer to that struct */
  varTypes?: Record<string, string>;
  /** a C string stored at an address, when there is one (string literals in the output) */
  stringAt?: (address: bigint) => string | null;
};
export type VarInfo = { name: string; type: string; loc: string; arg: boolean; fields: { offset: number; size: number }[] };
export type Decompiled = { lines: PseudoLine[]; signature: string; vars: VarInfo[]; report: UnflattenReport | null; ir: IrFunc };

// ---------------------------------------------------------------------------
// pipeline

/** Lifts, optimizes and (optionally) unflattens; the IR the structurer and the graph view use. */
export function buildIr(cfg: Cfg, opts: DecompileOptions = {}): { ir: IrFunc; report: UnflattenReport | null } {
  const ir = liftFunction(cfg, opts);
  const own = ownPrototype(opts);
  analyzeSignature(ir, own ? { args: own.args?.length, returns: own.returns === "void" ? "void" : own.returns === "float" || own.returns === "double" ? "float" : own.returns ? "int" : undefined } : undefined);
  optimize(ir);
  let report: UnflattenReport | null = null;
  if (opts.unflatten) {
    report = removeFlattening(ir);
    if (report.flattened) optimize(ir);
  }
  cleanup(ir);
  optimize(ir);
  return { ir, report };
}

function ownPrototype(opts: DecompileOptions): Prototype | null {
  if (!opts.entry) return null;
  const name = opts.nameOf?.(opts.entry) || null;
  return (opts.prototypeOf ?? lookupPrototype)(opts.entry, name) ?? null;
}

export function decompile(cfg: Cfg, opts: DecompileOptions = {}): Decompiled {
  const { ir, report } = buildIr(cfg, opts);
  if (!ir.blocks.length) return { lines: [], signature: "", vars: [], report, ir };
  const flow = analyze(ir);
  const names = nameVars(ir, flow, opts);
  const ast = structureIr(ir);
  const body = tidy(ast, names, true);
  const pr = new Printer(ir, names, opts);
  const lines: PseudoLine[] = [];
  lines.push({ indent: 0, text: names.signature, addr: ir.blocks[0].addr });
  lines.push({ indent: 0, text: "{" });
  for (const v of names.vars) {
    if (v.arg) continue;
    lines.push({ indent: 1, text: `${decl(v.type, v.name)}; // ${locLabel(v.loc)}` });
  }
  for (const v of names.vars) {
    if (!v.fields.length || opts.varTypes?.[v.name]) continue;
    lines.push({ indent: 1, text: `// ${v.name}: fields ${v.fields.map((x) => `+0x${x.offset.toString(16)} (${x.size})`).join(", ")}` });
  }
  if (names.vars.some((v) => !v.arg) || names.vars.some((v) => v.fields.length)) lines.push({ indent: 1, text: "" });
  pr.nodes(body, 1, lines);
  lines.push({ indent: 0, text: "}" });
  return { lines, signature: names.signature, vars: names.vars, report, ir };
}

function decl(type: string, name: string): string {
  return type.endsWith("*") ? `${type}${name}` : `${type} ${name}`;
}

function locLabel(loc: string): string {
  const l = baseLoc(loc);
  if (/^s-?\d+$/.test(l)) return "stack";
  if (/^sw\d+$/.test(l) || /^t\d+_\d+$/.test(l)) return "temp";
  return l;
}

// ---------------------------------------------------------------------------
// graph clean-up

/** Removes empty jump blocks, merges short-circuit conditions and switch bounds checks, folds constant branches. */
export function cleanup(f: IrFunc): void {
  for (let changed = true, guard = 0; changed && guard < 1000; guard++) {
    changed = false;
    const preds = livePreds(f);
    for (const b of f.blocks) {
      if (b.dead) continue;
      // constant conditions (opaque predicates included)
      if (b.term.k === "cond") {
        const c = simp(b.term.c);
        if (c.k === "c") {
          b.term = { k: "jump", to: c.v !== 0n ? b.term.t : b.term.f };
          changed = true;
          continue;
        }
        if (b.term.t === b.term.f) {
          b.term = { k: "jump", to: b.term.t };
          changed = true;
          continue;
        }
      }
      // empty jump blocks
      if (b.id !== 0 && !b.stmts.length && b.term.k === "jump" && b.term.to !== b.id) {
        const to = b.term.to;
        for (const p of preds[b.id]) retarget(f.blocks[p].term, b.id, to);
        b.dead = true;
        changed = true;
        break;
      }
      if (b.term.k === "cond" && mergeShortCircuit(f, b, preds)) {
        changed = true;
        break;
      }
      if (b.term.k === "cond" && mergeSwitchBound(f, b, preds)) {
        changed = true;
        break;
      }
    }
    // blocks the entry no longer reaches
    const reach = new Set<number>();
    const st = [0];
    while (st.length) {
      const n = st.pop()!;
      if (reach.has(n) || f.blocks[n].dead) continue;
      reach.add(n);
      st.push(...succOf(f.blocks[n].term));
    }
    for (const b of f.blocks) if (!b.dead && !reach.has(b.id) && f.blocks.length) {
      b.dead = true;
      changed = true;
    }
  }
}

/** `if (a) goto T; if (b) goto T;` -> `if (a || b) goto T;` and the && forms. */
function mergeShortCircuit(f: IrFunc, a: IrBlock, preds: number[][]): boolean {
  const t = a.term as Extract<Term, { k: "cond" }>;
  for (const side of ["f", "t"] as const) {
    const bi = t[side];
    const b = f.blocks[bi];
    if (bi === a.id || bi === 0 || b.stmts.length || b.term.k !== "cond" || preds[bi].length !== 1) continue;
    const u = b.term;
    if (u.t === bi || u.f === bi) continue;
    let merged: Extract<Term, { k: "cond" }> | null = null;
    if (side === "f") {
      if (u.t === t.t) merged = { k: "cond", c: or(t.c, u.c), t: t.t, f: u.f, addr: t.addr };
      else if (u.f === t.t) merged = { k: "cond", c: or(t.c, negate(u.c)), t: t.t, f: u.t, addr: t.addr };
    } else {
      if (u.f === t.f) merged = { k: "cond", c: and(t.c, u.c), t: u.t, f: t.f, addr: t.addr };
      else if (u.t === t.f) merged = { k: "cond", c: and(t.c, negate(u.c)), t: u.f, f: t.f, addr: t.addr };
    }
    if (!merged) continue;
    a.term = merged;
    b.dead = true;
    return true;
  }
  return false;
}
const or = (a: Expr, b: Expr): Expr => ({ k: "b", op: "||", a, b, w: 1 });
const and = (a: Expr, b: Expr): Expr => ({ k: "b", op: "&&", a, b, w: 1 });

/** `if (x > N) goto D; switch (x)` -> `switch (x) { ... default: D }`. */
function mergeSwitchBound(f: IrFunc, a: IrBlock, preds: number[][]): boolean {
  const t = a.term as Extract<Term, { k: "cond" }>;
  for (const [si, di, takenIsDefault] of [[t.f, t.t, true], [t.t, t.f, false]] as const) {
    const s = f.blocks[si];
    if (s.term.k !== "switch" || s.stmts.length || preds[si].length !== 1 || s.term.def !== null) continue;
    let c = t.c;
    if (!takenIsDefault) c = negate(c);
    // c is "out of range": x > N, x >= N (unsigned)
    if (c.k !== "cmp" || !(c.op === ">u" || c.op === ">=u" || c.op === ">" || c.op === ">=")) continue;
    a.term = { ...s.term, def: di };
    s.dead = true;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// structuring

type Node =
  | { k: "s"; s: Stmt }
  | { k: "if"; c: Expr; then: Node[]; else: Node[]; addr: string }
  | { k: "while" | "do"; c: Expr; body: Node[]; addr: string }
  | { k: "loop"; body: Node[]; addr: string }
  | { k: "for"; init: Stmt | null; c: Expr; step: Stmt | null; steps?: Stmt[]; body: Node[]; addr: string }
  | { k: "switch"; x: Expr; cases: { vals: bigint[]; body: Node[] }[]; def: Node[] | null; addr: string }
  | { k: "ret"; t: Term }
  | { k: "goto" | "label"; block: number }
  | { k: "break" | "continue" };

/** `step`: a for-loop's increment block; reaching it is `continue` */
type Ctx = { kind: "loop"; header: number; exit: number | null; latch: number | null; step?: number } | { kind: "switch"; exit: number | null };

export function structureIr(f: IrFunc): Node[] {
  const n = f.blocks.length;
  const succ = (b: number) => (f.blocks[b].dead ? [] : succOf(f.blocks[b].term));
  const preds = livePreds(f);
  const info = graphInfo(n, succ, (b) => preds[b]);
  const { ipdom, loops } = info;
  const emitted = new Set<number>();
  const labels = new Set<number>();
  const blk = (b: number) => f.blocks[b];
  const term = (b: number) => blk(b).term;
  const addrOf = (b: number) => blk(b).addr;
  const isSmallExit = (b: number) => {
    const t = term(b);
    return succ(b).length === 0 && (t.k === "ret" || t.k === "tail" || t.k === "stop") && blk(b).stmts.filter((s) => s.k !== "clob").length <= 3;
  };
  const body = (b: number): Node[] => blk(b).stmts.map((s) => ({ k: "s", s }));
  const exitNodes = (b: number): Node[] => {
    const t = term(b);
    return t.k === "ret" || t.k === "tail" || t.k === "stop" || t.k === "ijump" || t.k === "end" ? [{ k: "ret", t }] : [];
  };

  const leave = (x: number, ctx: Ctx[]): Node[] | null => {
    const top = ctx[ctx.length - 1];
    const loop = [...ctx].reverse().find((c) => c.kind === "loop") as Extract<Ctx, { kind: "loop" }> | undefined;
    if (loop && (x === loop.header || x === loop.step)) return [{ k: "continue" }];
    if (top && x === top.exit) return [{ k: "break" }];
    if (isSmallExit(x) && emitted.has(x)) return [...body(x), ...exitNodes(x)];
    if (emitted.has(x)) {
      labels.add(x);
      return [{ k: "goto", block: x }];
    }
    // the exit of an enclosing loop from inside a switch
    if (ctx.some((c) => c.exit === x)) {
      if (isSmallExit(x)) return null;
      labels.add(x);
      return [{ k: "goto", block: x }];
    }
    return null;
  };

  const region = (start: number | null, follow: number | null, ctx: Ctx[], out: Node[], entering = false): void => {
    let b = start;
    let first = entering;
    while (b !== null && b !== follow) {
      if (!first) {
        const ex = leave(b, ctx);
        if (ex) {
          out.push(...ex);
          return;
        }
      }
      first = false;
      const top = ctx[ctx.length - 1];
      const loop = loops.find((l) => l.header === b);
      if (loop && !(top?.kind === "loop" && top.header === b)) {
        b = emitLoop(b, out, ctx);
        continue;
      }
      emitted.add(b);
      out.push({ k: "label", block: b }, ...body(b));
      if (top?.kind === "loop" && b === top.latch) return;
      const t = term(b);
      if (t.k === "cond") {
        const lt = t.t === follow ? null : leave(t.t, ctx);
        const lf = t.f === follow ? null : leave(t.f, ctx);
        if (lt && lf) {
          out.push({ k: "if", c: t.c, then: lt, else: [], addr: t.addr }, ...lf);
          return;
        }
        if (lt || lf) {
          out.push({ k: "if", c: lt ? t.c : negate(t.c), then: lt ?? lf!, else: [], addr: t.addr });
          b = lt ? t.f : t.t;
          continue;
        }
        const join = ipdom[b] >= 0 ? ipdom[b] : null;
        const thenS: Node[] = [];
        const elseS: Node[] = [];
        if (t.t === join) {
          region(t.f, join, ctx, thenS);
          out.push({ k: "if", c: negate(t.c), then: thenS, else: [], addr: t.addr });
        } else if (t.f === join) {
          region(t.t, join, ctx, thenS);
          out.push({ k: "if", c: t.c, then: thenS, else: [], addr: t.addr });
        } else {
          region(t.t, join, ctx, thenS);
          region(t.f, join, ctx, elseS);
          out.push({ k: "if", c: t.c, then: thenS, else: elseS, addr: t.addr });
        }
        b = join;
      } else if (t.k === "switch") {
        const join = ipdom[b] >= 0 ? ipdom[b] : null;
        const sctx: Ctx[] = [...ctx, { kind: "switch", exit: join }];
        const groups = new Map<number, bigint[]>();
        for (const cs of t.cases) groups.set(cs.to, [...(groups.get(cs.to) ?? []), ...cs.vals]);
        const cases = [...groups].map(([to, vals]) => ({ to, vals: vals.sort((x, y) => (x < y ? -1 : 1)) })).sort((x, y) => (x.vals[0] < y.vals[0] ? -1 : 1));
        const arm = (to: number): Node[] => {
          if (to === join) return [{ k: "break" }];
          const ex = leave(to, sctx);
          if (ex) return ex;
          const a: Node[] = [];
          region(to, join, sctx, a);
          if (!endsInJump(a)) a.push({ k: "break" });
          return a;
        };
        const sw: Extract<Node, { k: "switch" }> = { k: "switch", x: t.x, cases: [], def: null, addr: t.addr };
        for (const cs of cases) if (cs.to !== t.def) sw.cases.push({ vals: cs.vals, body: arm(cs.to) });
        if (t.def !== null && t.def !== join) sw.def = arm(t.def);
        out.push(sw);
        b = join;
      } else {
        out.push(...exitNodes(b));
        b = t.k === "jump" ? t.to : null;
      }
    }
  };

  const emitLoop = (h: number, out: Node[], ctx: Ctx[]): number | null => {
    const loop = loops.find((l) => l.header === h)!;
    const exits = [...new Set([...loop.body].flatMap(succ).filter((x) => !loop.body.has(x)))].sort((a, b) => a - b);
    let exit = ipdom[h] >= 0 && !loop.body.has(ipdom[h]) ? ipdom[h] : null;
    if (exit === null) exit = exits.find((x) => !isSmallExit(x)) ?? exits[0] ?? null;
    const lbody: Node[] = [];
    const t = term(h);
    if (t.k === "cond" && blk(h).stmts.length === 0) {
      if ((t.t === exit && loop.body.has(t.f)) || (t.f === exit && loop.body.has(t.t))) {
        emitted.add(h);
        const first = t.t === exit ? t.f : t.t;
        const c = t.t === exit ? negate(t.c) : t.c;
        // a single small latch that only steps and jumps back: for (...; c; step), and edges to it are continue
        const l = loop.latches.length === 1 ? loop.latches[0] : null;
        const lb = l !== null ? blk(l) : null;
        if (l !== null && lb && l !== h && l !== first && lb.term.k === "jump" && lb.stmts.length >= 1 && lb.stmts.length <= 2 && lb.stmts.every((s) => s.k === "set")) {
          region(first, l, [...ctx, { kind: "loop", header: h, exit, latch: null, step: l }], lbody);
          emitted.add(l);
          out.push({ k: "label", block: h }, { k: "for", init: null, c, step: lb.stmts.length === 1 ? lb.stmts[0] : null, steps: lb.stmts, body: trimContinue(lbody), addr: t.addr });
          return exit;
        }
        region(first, h, [...ctx, { kind: "loop", header: h, exit, latch: null }], lbody);
        out.push({ k: "label", block: h }, { k: "while", c, body: trimContinue(lbody), addr: t.addr });
        return exit;
      }
    }
    const latch = loop.latches.length === 1 ? loop.latches[0] : null;
    if (latch !== null) {
      const lt = term(latch);
      if (lt.k === "cond" && ((lt.t === h && lt.f === exit) || (lt.f === h && lt.t === exit))) {
        region(h, null, [...ctx, { kind: "loop", header: h, exit, latch }], lbody, true);
        out.push({ k: "do", c: lt.t === h ? lt.c : negate(lt.c), body: lbody, addr: lt.addr });
        return exit;
      }
    }
    region(h, null, [...ctx, { kind: "loop", header: h, exit, latch: null }], lbody, true);
    out.push({ k: "loop", body: trimContinue(lbody), addr: addrOf(h) });
    return exit;
  };

  const out: Node[] = [];
  if (n && !blk(0).dead) region(0, null, [], out);
  for (const b of f.blocks) {
    if (b.dead || emitted.has(b.id) || !info.reachable[b.id]) continue;
    labels.add(b.id);
    region(b.id, null, [], out);
  }
  return dropLabels(out, labels);
}

function dropLabels(list: Node[], keep: Set<number>): Node[] {
  const out: Node[] = [];
  for (const x of list) {
    if (x.k === "label" && !keep.has(x.block)) continue;
    out.push(mapChildren(x, (l) => dropLabels(l, keep)));
  }
  return out;
}

function mapChildren(x: Node, f: (l: Node[]) => Node[]): Node {
  switch (x.k) {
    case "if":
      return { ...x, then: f(x.then), else: f(x.else) };
    case "while":
    case "do":
    case "loop":
    case "for":
      return { ...x, body: f(x.body) };
    case "switch":
      return { ...x, cases: x.cases.map((cs) => ({ ...cs, body: f(cs.body) })), def: x.def ? f(x.def) : null };
    default:
      return x;
  }
}

function termCall(t: Term): Expr {
  return t.k === "tail" ? t.call : t.k === "ret" && t.v ? t.v : { k: "c", v: 0n, w: 1 };
}

function trimContinue(body: Node[]): Node[] {
  return body.length && body[body.length - 1].k === "continue" ? body.slice(0, -1) : body;
}

function endsInJump(list: Node[]): boolean {
  const last = list[list.length - 1];
  if (!last) return false;
  if (last.k === "ret" || last.k === "goto" || last.k === "break" || last.k === "continue") return true;
  if (last.k === "if") return last.else.length > 0 && endsInJump(last.then) && endsInJump(last.else);
  return false;
}

/** Statements an expression or node mentions, as names, for loop recognition. */
function namesIn(e: Expr, names: Names): Set<string> {
  const s = new Set<string>();
  walk(e, (x) => x.k === "l" && s.add(names.of(x)));
  return s;
}

function size(list: Node[]): number {
  let n = 0;
  for (const x of list) {
    n++;
    if (x.k === "if") n += size(x.then) + size(x.else);
    else if (x.k === "while" || x.k === "do" || x.k === "loop" || x.k === "for") n += size(x.body);
    else if (x.k === "switch") n += x.cases.reduce((a, c) => a + size(c.body), 0) + (x.def ? size(x.def) : 0);
  }
  return n;
}

/** `x == 0`, `x != 5`, `!x`: tests that read better the other way round when there is an else. */
function negativeTest(c: Expr): boolean {
  if (c.k === "u" && c.op === "!") return true;
  if (c.k !== "cmp" || c.b.k !== "c") return false;
  return (c.op === "==" && c.b.v === 0n) || (c.op === "!=" && c.b.v !== 0n);
}

function hasContinue(list: Node[]): boolean {
  for (const x of list) {
    if (x.k === "continue") return true;
    if (x.k === "if" && (hasContinue(x.then) || hasContinue(x.else))) return true;
    if (x.k === "switch" && (x.cases.some((c) => hasContinue(c.body)) || (x.def && hasContinue(x.def)))) return true;
  }
  return false;
}

/** AST clean-ups: early-exit arms lose their else, empty thens flip, while(1){if(c)break;..} becomes while(!c), while -> for. */
function tidy(list: Node[], names: Names, top = false): Node[] {
  let out: Node[] = [];
  for (const x0 of list) {
    let x = mapChildren(x0, (l) => tidy(l, names));
    // a trailing continue does nothing
    if (x.k === "while" || x.k === "for" || x.k === "loop" || x.k === "do") x = { ...x, body: trimContinue(x.body) };
    if (x.k === "if") {
      if (!x.then.length && x.else.length) x = { ...x, c: negate(x.c), then: x.else, else: [] };
      if (!x.then.length && !x.else.length && !hasCall(x.c)) continue;
      if (x.else.length) {
        const elseIf = x.else.length === 1 && x.else[0].k === "if";
        const thenIf = x.then.length === 1 && x.then[0].k === "if";
        // else-if chains read better; so do positive tests
        if ((thenIf && !elseIf) || (!elseIf && negativeTest(x.c))) x = { ...x, c: negate(x.c), then: x.else, else: x.then };
      }
      // two exits: the shorter one first, then the other one unindented
      if (x.else.length && endsInJump(x.then) && endsInJump(x.else) && size(x.then) > size(x.else)) x = { ...x, c: negate(x.c), then: x.else, else: x.then };
      if (x.else.length && endsInJump(x.then)) {
        out.push({ ...x, else: [] }, ...x.else);
        continue;
      }
    }
    if (x.k === "loop" && x.body[0]?.k === "if" && x.body[0].else.length === 0 && x.body[0].then.length === 1 && x.body[0].then[0].k === "break") {
      x = { k: "while", c: negate(x.body[0].c), body: x.body.slice(1), addr: x.body[0].addr };
    }
    if (x.k === "while") {
      const prev = out[out.length - 1];
      const last = x.body[x.body.length - 1];
      if (prev?.k === "s" && prev.s.k === "set" && last?.k === "s" && last.s.k === "set" && !hasContinue(x.body)) {
        const iv = names.def(prev.s);
        const sv = names.def(last.s);
        if (iv && iv === sv && namesIn(x.c, names).has(iv)) {
          out.pop();
          x = { k: "for", init: prev.s, c: x.c, step: last.s, body: x.body.slice(0, -1), addr: x.addr };
        }
      }
    }
    if (x.k === "for" && !x.init) {
      // the assignment right before the loop of a variable the loop steps or tests
      const prev = out[out.length - 1];
      if (prev?.k === "s" && prev.s.k === "set") {
        const iv = names.def(prev.s);
        const stepped = (x.steps ?? (x.step ? [x.step] : [])).some((st) => names.def(st) === iv);
        if (iv && stepped) {
          out.pop();
          x = { ...x, init: prev.s };
        }
      }
    }
    out.push(x);
  }
  // `if (c) { A; jump } J` with J a lone break / return / goto: `if (!c) J; A; jump`
  const n = out.length;
  const last = out[n - 1];
  const prev = out[n - 2];
  if (n >= 2 && prev.k === "if" && !prev.else.length && endsInJump(prev.then) && prev.then.length > 1 && (last.k === "break" || last.k === "goto" || (last.k === "ret" && !hasCall(termCall(last.t))))) {
    out = [...out.slice(0, -2), { ...prev, c: negate(prev.c), then: [last], else: [] }, ...prev.then];
  }
  if (top) {
    // a void function's final bare return
    const last = out[out.length - 1];
    if (last?.k === "ret" && last.t.k === "ret" && !last.t.v) out = out.slice(0, -1);
  }
  return out;
}

// ---------------------------------------------------------------------------
// names and types

type TypeInfo = { ptr: boolean; float: number; unsigned: boolean; signed: boolean; w: number; fields: Map<number, number>; bool: boolean };
type Names = {
  of: (x: Extract<Expr, { k: "l" }>) => string;
  def: (s: Stmt) => string | null;
  slot: (off: number) => string;
  info: (name: string) => TypeInfo | undefined;
  typeOf: (name: string) => string;
  vars: VarInfo[];
  signature: string;
};

function hexs(n: number | bigint): string {
  return n.toString(16);
}

function nameVars(f: IrFunc, flow: Flow, opts: DecompileOptions): Names {
  const web = webs(flow);
  const sig = f.sig ?? { args: [], ret: "int" as const };
  const own = ownPrototype(opts);
  const argName = new Map<string, string>();
  sig.args.forEach((l, i) => argName.set(l, own?.args?.[i]?.name || `a${i + 1}`));
  const slotName = (off: number): string => {
    const l = `s${off}`;
    if (argName.has(l)) return argName.get(l)!;
    return off < 0 ? `var_${hexs(-off)}` : `arg_${hexs(off - 8)}`;
  };
  const rootName = new Map<number, string>();
  let next = 1;
  const nameRoot = (root: number, loc: string): string => {
    let nm = rootName.get(root);
    if (nm) return nm;
    const ent = flow.entryDef.get(loc);
    if (/^s-?\d+$/.test(loc)) nm = slotName(Number(loc.slice(1)));
    else if (ent !== undefined && web.get(ent) === root) nm = argName.get(loc) ?? loc;
    else if (baseLoc(loc) === "flags") nm = "flags";
    else nm = `v${next++}`;
    rootName.set(root, nm);
    return nm;
  };
  // name definitions in program order so v1, v2 follow the listing
  for (const b of f.blocks) {
    if (b.dead) continue;
    for (const s of b.stmts) stmtDefs(s).forEach((l, k) => {
      if (l === "flags") return;
      const d = defId(s, k);
      nameRoot(web.get(d) ?? d, l);
    });
  }
  const of = (x: Extract<Expr, { k: "l" }>): string => {
    const d = x.rd?.[0];
    if (d === undefined) return x.loc;
    return nameRoot(web.get(d) ?? d, x.loc);
  };
  const def = (s: Stmt): string | null => {
    const ds = stmtDefs(s);
    if (!ds.length) return null;
    const d = defId(s, 0);
    return nameRoot(web.get(d) ?? d, ds[0]);
  };

  // --- type evidence
  const info = new Map<string, TypeInfo>();
  const get = (nm: string) => {
    let t = info.get(nm);
    if (!t) info.set(nm, (t = { ptr: false, float: 0, unsigned: false, signed: false, w: 0, fields: new Map(), bool: false }));
    return t;
  };
  const locOfName = new Map<string, string>();
  const mentioned = new Set<string>();
  const baseVar = (a: Expr): { name: string; off: number } | null => {
    if (a.k === "l") return { name: of(a), off: 0 };
    if (a.k === "b" && a.op === "+" && a.a.k === "l") {
      if (a.b.k === "c") return { name: of(a.a), off: Number(BigInt.asIntN(64, a.b.v)) };
      return { name: of(a.a), off: NaN };
    }
    return null;
  };
  const deref = (a: Expr, w: number) => {
    const bv = baseVar(a);
    if (!bv) return;
    const t = get(bv.name);
    t.ptr = true;
    if (!Number.isNaN(bv.off) && bv.off >= 0 && bv.off < 0x10000) t.fields.set(bv.off, Math.max(t.fields.get(bv.off) ?? 0, w / 8));
  };
  const scan = (e: Expr) => walk(e, (x) => {
    if (x.k === "l") {
      const nm = of(x);
      mentioned.add(nm);
      locOfName.set(nm, x.loc);
      const t = get(nm);
      t.w = Math.max(t.w, x.w);
      if (x.loc.startsWith("xmm")) t.float = Math.max(t.float, Math.min(64, x.w));
    } else if (x.k === "ld") deref(x.a, x.w);
    else if (x.k === "cmp") {
      const u = x.op.endsWith("u");
      const s = ["<", "<=", ">", ">="].includes(x.op);
      for (const side of [x.a, x.b]) {
        let y = side;
        while (y.k === "cast" && !y.to) y = y.a;
        if (y.k === "l") {
          const t = get(of(y));
          if (u) t.unsigned = true;
          if (s) t.signed = true;
        }
      }
    }
  });
  for (const b of f.blocks) {
    if (b.dead) continue;
    for (const s of b.stmts) {
      if (s.k === "st") deref(s.a, s.w);
      for (const e of s.k === "set" ? [s.src] : s.k === "st" ? [s.a, s.v] : s.k === "call" ? [s.call] : s.k === "asm" ? s.uses : []) scan(e);
      const nm = def(s);
      if (nm && s.k === "set" && baseLoc(s.dst) !== "flags") {
        mentioned.add(nm);
        locOfName.set(nm, s.dst);
        const t = get(nm);
        t.w = Math.max(t.w, width(s.src) === 1 ? 8 : s.w);
        if (s.dst.startsWith("xmm")) t.float = Math.max(t.float, Math.min(64, s.w));
        if (isBool(s.src) || (s.src.k === "cast" && isBool(s.src.a))) t.bool = true;
      }
      if (nm && s.k === "call" && s.dst) {
        mentioned.add(nm);
        locOfName.set(nm, s.dst);
        const t = get(nm);
        t.w = Math.max(t.w, s.call.w);
        if (s.call.fl) t.float = s.call.w;
      }
    }
    for (const e of [b.term.k === "cond" ? b.term.c : null, b.term.k === "switch" ? b.term.x : null, b.term.k === "ret" ? b.term.v : null, b.term.k === "tail" ? b.term.call : null]) if (e) scan(e);
  }
  const typeOf = (nm: string): string => {
    const mapped = opts.varTypes?.[nm];
    if (mapped) return `${mapped} *`;
    const t = info.get(nm);
    if (!t) return "__int64";
    if (t.float) return t.float <= 32 ? "float" : "double";
    if (t.ptr) return "void *";
    const u = t.unsigned && !t.signed;
    switch (t.w <= 8 ? 8 : t.w <= 16 ? 16 : t.w <= 32 ? 32 : 64) {
      case 8:
        return t.bool ? "bool" : u ? "unsigned __int8" : "char";
      case 16:
        return u ? "unsigned __int16" : "__int16";
      case 32:
        return u ? "unsigned int" : "int";
      default:
        return u ? "unsigned __int64" : "__int64";
    }
  };
  const vars: VarInfo[] = [];
  const argNames = new Set(argName.values());
  for (const nm of new Set(rootName.values())) {
    if (argNames.has(nm)) continue;
    const l = locOfName.get(nm) ?? "";
    if (!/^v\d+$/.test(nm) && !/^var_|^arg_/.test(nm)) continue; // registers read before written
    if (!mentioned.has(nm)) continue;
    vars.push({ name: nm, type: typeOf(nm), loc: l, arg: false, fields: fieldList(info.get(nm)) });
  }
  vars.sort((a, b) => (a.name.startsWith("v") === b.name.startsWith("v") ? a.name.localeCompare(b.name, undefined, { numeric: true }) : a.name.startsWith("var") ? -1 : 1));
  sig.args.forEach((l, i) => {
    const nm = argName.get(l)!;
    const pt = own?.args?.[i]?.type;
    vars.unshift({ name: nm, type: pt ? cType(pt) : typeOf(nm), loc: l, arg: true, fields: fieldList(info.get(nm)) });
  });
  vars.sort((a, b) => (a.arg === b.arg ? 0 : a.arg ? -1 : 1));
  const argVars = vars.filter((v) => v.arg).sort((a, b) => sig.args.indexOf(a.loc) - sig.args.indexOf(b.loc));
  // return type
  let ret = "void";
  if (own?.returns) ret = cType(own.returns);
  else if (sig.ret === "float") {
    const w = firstRetWidth(f);
    ret = w <= 32 ? "float" : "double";
  } else if (sig.ret === "int") {
    const w = firstRetWidth(f);
    ret = w <= 8 ? "char" : w <= 16 ? "__int16" : w <= 32 ? "int" : "__int64";
  }
  const fname = (opts.entry && (opts.nameOf?.(opts.entry) || own?.name)) || (opts.entry ? `sub_${BigInt(opts.entry).toString(16)}` : `sub_${f.blocks[0].start.toString(16)}`);
  const cc = f.abi === "win64" ? "__fastcall " : "";
  const signature = `${ret} ${cc}${fname}(${argVars.map((v) => decl(v.type, v.name)).join(", ")})`;
  return { of, def, slot: slotName, info: (nm) => info.get(nm), typeOf, vars, signature };
}

function fieldList(t: TypeInfo | undefined): { offset: number; size: number }[] {
  if (!t?.ptr) return [];
  return [...t.fields].sort((a, b) => a[0] - b[0]).map(([offset, size]) => ({ offset, size }));
}

function firstRetWidth(f: IrFunc): number {
  for (const b of f.blocks) if (!b.dead && b.term.k === "ret" && b.term.v) return width(b.term.v);
  return 64;
}

// ---------------------------------------------------------------------------
// printing

const kPrec: Record<string, number> = {
  "*": 13, "/": 13, "/u": 13, "%": 13, "%u": 13, "+": 12, "-": 12, "<<": 11, ">>": 11, ">>s": 11,
  "<": 10, "<=": 10, ">": 10, ">=": 10, "<u": 10, "<=u": 10, ">u": 10, ">=u": 10, "==": 9, "!=": 9,
  "&": 8, "^": 7, "|": 6, "&&": 5, "||": 4,
};
const kMemType: Record<number, string> = { 8: "_BYTE", 16: "_WORD", 32: "_DWORD", 64: "_QWORD", 128: "_OWORD" };
const kGlobal: Record<number, string> = { 8: "byte", 16: "word", 32: "dword", 64: "qword", 128: "xmmword" };

class Printer {
  constructor(private f: IrFunc, private names: Names, private opts: DecompileOptions) {}

  num(v: bigint, w: number, signed = true): string {
    const s = signed ? BigInt.asIntN(Math.max(1, Math.min(64, w)), v) : v;
    if (s >= -9n && s <= 9n) return s.toString();
    if (s < 0n && s > -0x10000n) return `-0x${(-s).toString(16)}`;
    return `0x${BigInt.asUintN(64, v).toString(16)}`;
  }

  private sym(a: bigint): string | null {
    return this.opts.nameOf?.("0x" + a.toString(16)) || null;
  }

  private field(nm: string, off: number, w: number): string {
    const mapped = this.opts.varTypes?.[nm];
    if (mapped) {
      const fields = this.opts.fieldsOf?.(mapped) ?? [];
      const hit = fields.find((x) => x.offset === off);
      if (hit) return `${nm}->${hit.name}`;
      const inside = fields.find((x) => x.offset < off && off < x.offset + x.size);
      if (inside) return `*(${kMemType[w] ?? "_QWORD"} *)((char *)&${nm}->${inside.name} + ${off - inside.offset})`;
    }
    return `${nm}->field_${off.toString(16)}`;
  }

  /** text and precedence */
  e(x: Expr): [string, number] {
    switch (x.k) {
      case "c":
        if (x.fl) return [x.v === 0n ? "0.0" : `0x${x.v.toString(16)}`, 16];
        if (x.w === 64 && x.v >= 0x1000n) {
          // an address: a string literal or a named symbol
          const str = this.opts.stringAt?.(x.v);
          if (str !== null && str !== undefined) return [JSON.stringify(str), 16];
          const sym = this.sym(x.v);
          if (sym) return [`&${sym}`, 14];
        }
        return [this.num(x.v, x.w), x.v !== 0n && BigInt.asIntN(Math.min(64, x.w), x.v) < 0n ? 14 : 16];
      case "l":
        return [this.names.of(x), 16];
      case "sa":
        return [`&${this.names.slot(x.off)}`, 14];
      case "raw":
        return [x.text, 16];
      case "ld":
        return this.load(x.a, x.w, !!x.fl);
      case "b": {
        if (x.op === "rol" || x.op === "ror") return [`__${x.op.toUpperCase()}${x.w / 8}__(${this.t(x.a)}, ${this.t(x.b)})`, 16];
        if (x.op === "min" || x.op === "max") return [`f${x.op}${x.w === 32 ? "f" : ""}(${this.t(x.a)}, ${this.t(x.b)})`, 16];
        let op: string = x.op;
        let b = x.b;
        if (op === "+" && b.k === "c" && !b.fl && BigInt.asIntN(Math.min(64, b.w), b.v) < 0n) {
          op = "-";
          b = { k: "c", v: BigInt.asUintN(64, -BigInt.asIntN(Math.min(64, b.w), b.v)), w: 64 };
        }
        const p = kPrec[op];
        const shown = op.replace(/u$|s$/, "");
        return [`${this.p(x.a, p)} ${shown} ${this.p(b, p + 1)}`, p];
      }
      case "u":
        if (x.op === "sqrt") return [`sqrt${x.w === 32 ? "f" : ""}(${this.t(x.a)})`, 16];
        return [`${x.op}${this.p(x.a, 14)}`, 14];
      case "cast": {
        const aw = width(x.a);
        if (x.to) return [`(${x.to === "f32" ? "float" : x.to === "f64" ? "double" : x.w <= 32 ? "int" : "__int64"})${this.p(x.a, 14)}`, 14];
        if (x.w > aw && !x.s) return this.e(x.a); // zero extension: implicit
        if (aw === 1) return this.e(x.a);
        const t = x.w <= 8 ? (x.s ? "char" : "unsigned __int8") : x.w <= 16 ? (x.s ? "__int16" : "unsigned __int16") : x.w <= 32 ? (x.s ? "int" : "unsigned int") : x.s ? "__int64" : "unsigned __int64";
        return [`(${t})${this.p(x.a, 14)}`, 14];
      }
      case "cmp": {
        const p = kPrec[x.op];
        const signed = !x.op.endsWith("u");
        const xb = x.b;
        const rhs: [string, number] = xb.k === "c" && !xb.fl ? [this.num(xb.v, xb.w, signed), 16] : this.e(xb);
        return [`${this.p(x.a, p + 1)} ${x.op.replace(/u$/, "")} ${rhs[1] > p ? rhs[0] : `(${rhs[0]})`}`, p];
      }
      case "flags":
        return [`CMP(${this.t(x.a)}, ${this.t(x.b)})`, 16];
      case "cc":
        return [`COND_j${x.cc}(${this.t(x.f)})`, 16];
      case "sel":
        return [`${this.p(x.c, 4)} ? ${this.p(x.a, 4)} : ${this.p(x.b, 3)}`, 3];
      case "part": {
        const nm = x.w === 8 ? (x.hi ? "BYTE1" : "LOBYTE") : "LOWORD";
        return [`__SET_${nm}(${this.t(x.old)}, ${this.t(x.v)})`, 16];
      }
      case "call":
        return [this.call(x), 16];
    }
  }

  /** text, parenthesized below precedence p */
  p(x: Expr, p: number): string {
    const [s, q] = this.e(x);
    return q < p ? `(${s})` : s;
  }

  t(x: Expr): string {
    return this.e(x)[0];
  }

  call(x: Extract<Expr, { k: "call" }>): string {
    let target: string;
    if (x.name) target = x.name;
    else if (x.target.k === "c") target = this.sym(x.target.v) ?? `sub_${x.target.v.toString(16)}`;
    else if (x.target.k === "ld" && x.target.a.k === "c") target = this.sym(x.target.a.v) ?? `qword_${x.target.a.v.toString(16)}`;
    else target = this.p(x.target, 16);
    return `${target}(${x.args.map((a) => this.t(a)).join(", ")})`;
  }

  load(a: Expr, w: number, fl: boolean): [string, number] {
    if (a.k === "sa") return [this.names.slot(a.off), 16];
    if (a.k === "c") {
      const s = this.sym(a.v);
      return [s ?? `${fl ? (w === 32 ? "flt" : "dbl") : kGlobal[w] ?? "qword"}_${a.v.toString(16)}`, 16];
    }
    const mt = fl ? (w === 32 ? "float" : "double") : kMemType[w] ?? "_QWORD";
    // pointer variable + constant: a field
    let base: Expr | null = null;
    let off = 0;
    if (a.k === "l") base = a;
    else if (a.k === "b" && a.op === "+" && a.a.k === "l" && a.b.k === "c") {
      base = a.a;
      off = Number(BigInt.asIntN(64, a.b.v));
    }
    if (base && base.k === "l" && off >= 0) {
      const nm = this.names.of(base);
      if (this.names.info(nm)?.ptr || this.opts.varTypes?.[nm]) return [this.field(nm, off, w), 16];
    }
    // p[i] with the element size as the scale
    if (a.k === "b" && a.op === "+" && a.a.k === "l" && a.b.k === "b" && a.b.op === "*" && a.b.b.k === "c" && Number(a.b.b.v) * 8 === w) {
      let ix = a.b.a;
      while (ix.k === "cast" && !ix.to) ix = ix.a;
      return [`((${mt} *)${this.names.of(a.a)})[${this.t(ix)}]`, 16];
    }
    return [`*(${mt} *)${this.p(a, 15)}`, 14];
  }

  stmt(s: Stmt): string | null {
    switch (s.k) {
      case "set": {
        if (baseLoc(s.dst) === "flags") return `flags = ${this.t(s.src)};`;
        const nm = this.names.def(s) ?? s.dst;
        const src = s.src;
        if (src.k === "part" && src.old.k === "l" && this.names.of(src.old) === nm) return `${src.w === 8 ? (src.hi ? "BYTE1" : "LOBYTE") : "LOWORD"}(${nm}) = ${this.t(src.v)};`;
        if (src.k === "b" && src.a.k === "l" && this.names.of(src.a) === nm && !["rol", "ror", "min", "max", "&&", "||"].includes(src.op)) {
          if (src.b.k === "c" && !src.fl && (src.op === "+" || src.op === "-")) {
            const v = BigInt.asIntN(Math.min(64, src.b.w), src.b.v) * (src.op === "-" ? -1n : 1n);
            if (v === 1n) return `++${nm};`;
            if (v === -1n) return `--${nm};`;
          }
          const [rhs] = this.e(src.b);
          const op = this.e(src)[0].includes(" - ") && src.op === "+" ? "-" : src.op.replace(/u$|s$/, "");
          if (op === "-" && src.op === "+" && src.b.k === "c") return `${nm} -= ${this.num(BigInt.asUintN(64, -BigInt.asIntN(64, src.b.v)), 64)};`;
          return `${nm} ${op}= ${rhs};`;
        }
        return `${nm} = ${this.t(src)};`;
      }
      case "st": {
        const [lhs] = this.load(s.a, s.w, !!s.fl);
        return `${lhs} = ${this.t(s.v)};`;
      }
      case "call": {
        const call = this.call(s.call);
        if (!s.dst) return `${call};`;
        return `${this.names.def(s) ?? s.dst} = ${call};`;
      }
      case "clob":
        return null;
      case "asm":
        if (!s.text) return null;
        if (s.text.startsWith("JUMPOUT")) return `if (${this.t(s.uses[0])}) ${s.text};`;
        return `__asm { ${s.text} }`;
    }
  }

  term(t: Term): string | null {
    switch (t.k) {
      case "ret":
        return t.v ? `return ${this.t(t.v)};` : "return;";
      case "tail":
        return this.f.sig?.ret === "void" ? `${this.call(t.call)}; return; // tail call` : `return ${this.call(t.call)}; // tail call`;
      case "ijump":
        return `JUMPOUT(${this.t(t.x)});`;
      case "stop":
        return "__debugbreak(); // stop";
      case "end":
        return "// (listing ends here)";
      default:
        return null;
    }
  }

  cond(x: Expr): string {
    return this.t(x);
  }

  nodes(list: Node[], indent: number, out: PseudoLine[]): void {
    for (const x of list) this.node(x, indent, out);
  }

  label(b: number): string {
    return `loc_${this.f.blocks[b].start.toString(16)}`;
  }

  node(x: Node, indent: number, out: PseudoLine[], elseIf = false): void {
    switch (x.k) {
      case "s": {
        const t = this.stmt(x.s);
        if (t !== null) out.push({ indent, text: t, addr: x.s.addr });
        return;
      }
      case "ret": {
        const t = this.term(x.t);
        if (t !== null) out.push({ indent, text: t, addr: "addr" in x.t ? x.t.addr : undefined });
        return;
      }
      case "label":
        out.push({ indent: Math.max(0, indent - 1), text: `${this.label(x.block)}:`, addr: this.f.blocks[x.block].addr });
        return;
      case "goto":
        out.push({ indent, text: `goto ${this.label(x.block)};`, addr: this.f.blocks[x.block].addr });
        return;
      case "break":
      case "continue":
        out.push({ indent, text: `${x.k};` });
        return;
      case "if": {
        out.push({ indent, text: `${elseIf ? "} else " : ""}if (${this.cond(x.c)}) {`, addr: x.addr });
        this.nodes(x.then, indent + 1, out);
        if (x.else.length === 1 && x.else[0].k === "if") {
          this.node(x.else[0], indent, out, true);
          return;
        }
        if (x.else.length) {
          out.push({ indent, text: "} else {" });
          this.nodes(x.else, indent + 1, out);
        }
        out.push({ indent, text: "}" });
        return;
      }
      case "while":
        out.push({ indent, text: `while (${this.cond(x.c)}) {`, addr: x.addr });
        this.nodes(x.body, indent + 1, out);
        out.push({ indent, text: "}" });
        return;
      case "loop":
        out.push({ indent, text: "while (1) {", addr: x.addr });
        this.nodes(x.body, indent + 1, out);
        out.push({ indent, text: "}" });
        return;
      case "do":
        out.push({ indent, text: "do {" });
        this.nodes(x.body, indent + 1, out);
        out.push({ indent, text: `} while (${this.cond(x.c)});`, addr: x.addr });
        return;
      case "for": {
        const strip = (s: Stmt | null) => (s ? (this.stmt(s) ?? "").replace(/;$/, "") : "");
        const step = (x.steps ?? (x.step ? [x.step] : [])).map(strip).filter(Boolean).join(", ");
        out.push({ indent, text: `for (${strip(x.init)}; ${this.cond(x.c)}; ${step}) {`, addr: x.addr });
        this.nodes(x.body, indent + 1, out);
        out.push({ indent, text: "}" });
        return;
      }
      case "switch": {
        // switch (x - k): show the original values
        let sx = x.x;
        while (sx.k === "cast" && !sx.to) sx = sx.a;
        let bias = 0n;
        if (sx.k === "b" && sx.op === "+" && sx.b.k === "c") {
          bias = -BigInt.asIntN(Math.min(64, sx.b.w), sx.b.v);
          sx = sx.a;
          while (sx.k === "cast" && !sx.to) sx = sx.a;
        }
        out.push({ indent, text: `switch (${this.t(sx)}) {`, addr: x.addr });
        for (const cs of x.cases) {
          for (const v of cs.vals) out.push({ indent: indent + 1, text: `case ${this.num(v + bias, 64)}:` });
          this.nodes(cs.body, indent + 2, out);
        }
        if (x.def) {
          out.push({ indent: indent + 1, text: "default:" });
          this.nodes(x.def, indent + 2, out);
        }
        out.push({ indent, text: "}" });
        return;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// the rebuilt graph, for the CFG view

export type GraphBlock = { id: number; start: bigint; addr: string; insns: IrBlock["insns"] };
export type GraphEdge = { from: number; to: number; kind: "taken" | "fallthrough" | "jump" | "case"; label?: string };

/** Live blocks and edges of an IR function (after unflattening: the recovered CFG). */
export function irGraph(f: IrFunc): { blocks: GraphBlock[]; edges: GraphEdge[] } {
  const blocks = f.blocks.filter((b) => !b.dead).map((b) => ({ id: b.id, start: b.start, addr: b.addr, insns: b.insns }));
  const edges: GraphEdge[] = [];
  for (const b of f.blocks) {
    if (b.dead) continue;
    const t = b.term;
    if (t.k === "jump") edges.push({ from: b.id, to: t.to, kind: "jump" });
    else if (t.k === "cond") {
      edges.push({ from: b.id, to: t.t, kind: "taken" });
      if (t.f !== t.t) edges.push({ from: b.id, to: t.f, kind: "fallthrough" });
    } else if (t.k === "switch") {
      for (const cs of t.cases) edges.push({ from: b.id, to: cs.to, kind: "case", label: cs.vals.map(String).join(",") });
      if (t.def !== null) edges.push({ from: b.id, to: t.def, kind: "case", label: "default" });
    }
  }
  return { blocks, edges };
}

