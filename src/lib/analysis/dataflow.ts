// Def-use analysis over the IR, SSA-equivalent for what the decompiler
// needs: reaching definitions per location give every read its definitions,
// single-definition reads take the defining expression (copy, constant and
// expression propagation; the operands must still hold the same definitions
// at the read, and loads only move within a block past no store or call),
// and definitions nobody reads are removed (dead-code elimination). Reads
// joined at a merge point form one web, which becomes one variable.
import {
  clone, hasLoad, mapStmtUses, mapTermUses, narrow, simp, stmtDefs, stmtUses, succOf, termUses, walk,
  type Expr, type IrFunc, type Stmt,
} from "./ir";
import { kArgRegs, kArgXmm, kStackArgBase } from "./irlift";

type L = Extract<Expr, { k: "l" }>;
export type DefInfo = { id: number; loc: string; block: number; index: number; stmt: Stmt | null; w: number };
export type Use = { node: L; block: number; /** statement index, -1 for the terminator */ index: number; host: Stmt | null };
export type Flow = {
  defs: Map<number, DefInfo>;
  entryDef: Map<string, number>;
  inSets: Map<string, number[]>[];
  uses: Map<number, Use[]>;
  preds: number[][];
  /** definitions of a location reaching a block's start */
  rdIn: (block: number, loc: string) => number[];
};

const kMaxDefsPerStmt = 64;
/** Definition id of the i-th location a statement defines. */
export const defId = (s: Stmt, i: number) => s.id * kMaxDefsPerStmt + i;

function union(a: number[], b: number[]): number[] {
  if (!a.length) return b;
  if (!b.length || a === b) return a;
  const out: number[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    const x = i < a.length ? a[i] : Infinity;
    const y = j < b.length ? b[j] : Infinity;
    if (x === y) {
      out.push(x);
      i++;
      j++;
    } else if (x < y) out.push(a[i++]);
    else out.push(b[j++]);
  }
  return out;
}
function sameSet(a: readonly number[] | undefined, b: readonly number[] | undefined): boolean {
  const x = a ?? [];
  const y = b ?? [];
  if (x === y) return true;
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
}

export function livePreds(f: IrFunc): number[][] {
  const preds: number[][] = f.blocks.map(() => []);
  for (const b of f.blocks) if (!b.dead) for (const s of succOf(b.term)) if (!preds[s].includes(b.id)) preds[s].push(b.id);
  return preds;
}

/**
 * Reaching definitions and the def-use chains of every read. Annotates each read's `rd`.
 * The per-block sets only hold live locations (liveness first), which keeps them small; the
 * definitions of a location that is not live at a block start are found on demand (`rdIn`).
 */
export function analyze(f: IrFunc): Flow {
  const defs = new Map<number, DefInfo>();
  const entryDef = new Map<string, number>();
  const locs = new Set<string>();
  const nb = f.blocks.length;
  const ue: Set<string>[] = f.blocks.map(() => new Set());
  const dfs: Set<string>[] = f.blocks.map(() => new Set());
  const gen = f.blocks.map(() => new Map<string, number>());
  for (const b of f.blocks) {
    if (b.dead) continue;
    const used = (e: Expr) => walk(e, (x) => {
      if (x.k !== "l") return;
      locs.add(x.loc);
      if (!dfs[b.id].has(x.loc)) ue[b.id].add(x.loc);
    });
    b.stmts.forEach((s, i) => {
      stmtUses(s).forEach(used);
      stmtDefs(s).forEach((l, k) => {
        locs.add(l);
        dfs[b.id].add(l);
        gen[b.id].set(l, defId(s, k));
        defs.set(defId(s, k), { id: defId(s, k), loc: l, block: b.id, index: i, stmt: s, w: s.k === "set" ? s.w : s.k === "call" ? s.call.w : 64 });
      });
    });
    termUses(b.term).forEach(used);
  }
  let n = -1;
  for (const l of [...locs].sort()) {
    entryDef.set(l, n);
    defs.set(n, { id: n, loc: l, block: -1, index: -1, stmt: null, w: 64 });
    n--;
  }
  const preds = livePreds(f);
  const succs = f.blocks.map((b) => (b.dead ? [] : succOf(b.term).filter((x) => !f.blocks[x].dead)));
  // reverse postorder from the entry; unreachable blocks after it (they start from entry values)
  const order: number[] = [];
  const seen = new Set<number>();
  if (nb && !f.blocks[0].dead) {
    const stack: { n: number; i: number }[] = [{ n: 0, i: 0 }];
    seen.add(0);
    while (stack.length) {
      const top = stack[stack.length - 1];
      if (top.i < succs[top.n].length) {
        const x = succs[top.n][top.i++];
        if (!seen.has(x)) {
          seen.add(x);
          stack.push({ n: x, i: 0 });
        }
      } else {
        order.push(top.n);
        stack.pop();
      }
    }
  }
  order.reverse();
  for (const b of f.blocks) if (!seen.has(b.id) && !b.dead) order.push(b.id);
  // liveness
  const liveIn: Set<string>[] = f.blocks.map((b) => new Set(ue[b.id]));
  const liveOut: Set<string>[] = f.blocks.map(() => new Set());
  for (let changed = true, iter = 0; changed && iter < 500; iter++) {
    changed = false;
    for (let k = order.length - 1; k >= 0; k--) {
      const b = order[k];
      const out = liveOut[b];
      for (const s of succs[b]) for (const l of liveIn[s]) if (!out.has(l)) out.add(l);
      const inn = liveIn[b];
      for (const l of out) if (!dfs[b].has(l) && !inn.has(l)) {
        inn.add(l);
        changed = true;
      }
    }
  }
  // reaching definitions of the live locations
  const inSets: Map<string, number[]>[] = f.blocks.map(() => new Map());
  const outSets: Map<string, number[]>[] = f.blocks.map(() => new Map());
  for (let changed = true, iter = 0; changed && iter < 500; iter++) {
    changed = false;
    for (const b of order) {
      const inn = new Map<string, number[]>();
      const root = b === 0 || !seen.has(b);
      for (const l of liveIn[b]) {
        let ds: number[] = root ? [entryDef.get(l)!] : [];
        for (const p of preds[b]) {
          const o = outSets[p].get(l);
          if (o) ds = union(ds, o);
        }
        inn.set(l, ds);
      }
      inSets[b] = inn;
      const prev = outSets[b];
      let diff = false;
      const out = new Map<string, number[]>();
      for (const l of liveOut[b]) {
        const g = gen[b].get(l);
        const ds = g !== undefined ? [g] : inn.get(l) ?? [];
        out.set(l, ds);
        if (!diff && !sameSet(prev.get(l), ds)) diff = true;
      }
      if (diff || prev.size !== out.size) {
        outSets[b] = out;
        changed = true;
      }
    }
  }
  // definitions of any location at a block start, live or not
  const memo = new Map<string, number[]>();
  const rdIn = (block: number, loc: string): number[] => {
    const known = inSets[block].get(loc);
    if (known) return known;
    const key = `${block}|${loc}`;
    const m = memo.get(key);
    if (m) return m;
    const found = new Set<number>();
    const visited = new Set<number>();
    const stack = [block];
    while (stack.length) {
      const x = stack.pop()!;
      if (visited.has(x)) continue;
      visited.add(x);
      if (x === 0 || !seen.has(x)) found.add(entryDef.get(loc) ?? entryDef.size * -1 - 1);
      for (const p of preds[x]) {
        const g = gen[p].get(loc);
        if (g !== undefined) found.add(g);
        else stack.push(p);
      }
    }
    const r = [...found].sort((a, b) => a - b);
    memo.set(key, r);
    return r;
  };
  // annotate reads
  const uses = new Map<number, Use[]>();
  const addUse = (u: Use) => {
    for (const d of u.node.rd ?? []) {
      let list = uses.get(d);
      if (!list) uses.set(d, (list = []));
      list.push(u);
    }
  };
  for (const b of f.blocks) {
    if (b.dead) continue;
    const cur = new Map(inSets[b.id]);
    const ann = (e: Expr, index: number, host: Stmt | null) => walk(e, (x) => {
      if (x.k !== "l") return;
      x.rd = cur.get(x.loc) ?? rdIn(b.id, x.loc);
      addUse({ node: x, block: b.id, index, host });
    });
    b.stmts.forEach((s, i) => {
      stmtUses(s).forEach((e) => ann(e, i, s));
      stmtDefs(s).forEach((l, k) => cur.set(l, [defId(s, k)]));
    });
    termUses(b.term).forEach((e) => ann(e, -1, null));
  }
  return { defs, entryDef, inSets, uses, preds, rdIn };
}

/** Definitions of `loc` reaching the point before statement `index` (-1: before the terminator). */
export function rdAt(f: IrFunc, flow: Flow, block: number, index: number, loc: string): number[] {
  const stmts = f.blocks[block].stmts;
  for (let i = (index < 0 ? stmts.length : index) - 1; i >= 0; i--) {
    const ds = stmtDefs(stmts[i]);
    const k = ds.indexOf(loc);
    if (k >= 0) return [defId(stmts[i], k)];
  }
  return flow.rdIn(block, loc);
}

const isBarrier = (s: Stmt) => s.k === "st" || s.k === "call" || s.k === "asm";

/** Cheap enough to copy into several reads. */
function cheap(e: Expr): boolean {
  switch (e.k) {
    case "c":
    case "l":
    case "sa":
    case "raw":
      return true;
    case "cast":
      return cheap(e.a) && e.a.k !== "cast";
    case "u":
      return e.op !== "sqrt" && (e.a.k === "l" || e.a.k === "c");
    case "b":
      return (e.op === "+" || e.op === "-") && (e.a.k === "l" || e.a.k === "sa") && e.b.k === "c";
    case "flags":
      return cheap(e.a) && cheap(e.b);
    case "cc":
      return cheap(e.f);
    case "cmp":
      return cheap(e.a) && cheap(e.b);
    default:
      return false;
  }
}

/** `e` (defined at width dw) read at width rw. */
function adapt(e: Expr, dw: number, rw: number): Expr {
  if (rw === dw || e.k === "flags") return e;
  if (rw < dw) return narrow(e, rw);
  return { k: "cast", a: e, w: rw, s: false };
}

/** Replaces `target` (by identity) inside `e`, keeping every other node. */
function replaceNode(e: Expr, target: Expr, repl: Expr): Expr {
  if (e === target) return repl;
  let changed = false;
  const kidsOf = (x: Expr): Expr => {
    const r = replaceNode(x, target, repl);
    if (r !== x) changed = true;
    return r;
  };
  let out: Expr;
  switch (e.k) {
    case "ld":
    case "u":
    case "cast":
      out = { ...e, a: kidsOf(e.a) };
      break;
    case "b":
    case "cmp":
    case "flags":
      out = { ...e, a: kidsOf(e.a), b: kidsOf(e.b) };
      break;
    case "cc":
      out = { ...e, f: kidsOf(e.f) };
      break;
    case "sel":
      out = { ...e, c: kidsOf(e.c), a: kidsOf(e.a), b: kidsOf(e.b) };
      break;
    case "part":
      out = { ...e, old: kidsOf(e.old), v: kidsOf(e.v) };
      break;
    case "call":
      out = { ...e, target: kidsOf(e.target), args: e.args.map(kidsOf) };
      break;
    default:
      return e;
  }
  return changed ? out : e;
}

/**
 * Which arguments the function reads and what it returns, from the reads of
 * the entry values (pushes of callee-saved registers excluded). Rewrites the
 * return terminators and the calls' return locations to match.
 */
export function analyzeSignature(f: IrFunc, own?: { args?: number; returns?: "void" | "int" | "float" }): void {
  let flow = analyze(f);
  const used = (l: string) => {
    const d = flow.entryDef.get(l);
    if (d === undefined) return false;
    return (flow.uses.get(d) ?? []).some((u) => !(u.host?.k === "set" && u.host.push) && !(u.host?.k === "asm" && u.host.text === "") && !(!u.host && f.blocks[u.block].term.k === "ret"));
  };
  // calls whose integer result is unused but whose xmm0 is read: a float return
  for (const b of f.blocks) {
    b.stmts.forEach((s, i) => {
      if (s.k !== "call" || s.dst !== "rax") return;
      const clob = b.stmts[i + 1];
      if (clob?.k !== "clob") return;
      const raxUses = flow.uses.get(defId(s, 0)) ?? [];
      const k = clob.locs.indexOf("xmm0");
      const xUses = k >= 0 ? flow.uses.get(defId(clob, k)) ?? [] : [];
      if (!raxUses.length && xUses.length) {
        s.dst = "xmm0";
        s.call.fl = true;
        clob.locs = [...clob.locs.filter((l) => l !== "xmm0"), "rax"];
      }
    });
  }
  flow = analyze(f);
  const abi = f.abi;
  const ints = kArgRegs[abi];
  const xmms = kArgXmm[abi];
  const args: string[] = [];
  const stackSlot = (k: number) => `s${8 + kStackArgBase[abi] + 8 * k}`;
  if (abi === "win64") {
    let n = 0;
    for (let i = 0; i < 4; i++) if (used(ints[i]) || used(xmms[i])) n = i + 1;
    let st = 0;
    for (let k = 0; k < 16; k++) if (used(stackSlot(k))) st = k + 1;
    if (st) n = 4 + st;
    if (own?.args !== undefined) n = own.args;
    for (let i = 0; i < n; i++) args.push(i < 4 ? (used(xmms[i]) && !used(ints[i]) ? xmms[i] : ints[i]) : stackSlot(i - 4));
  } else {
    let n = 0;
    for (let i = 0; i < 6; i++) if (used(ints[i])) n = i + 1;
    let st = 0;
    for (let k = 0; k < 16; k++) if (used(stackSlot(k))) st = k + 1;
    if (st) n = 6 + st;
    if (own?.args !== undefined) n = own.args;
    for (let i = 0; i < n; i++) args.push(i < 6 ? ints[i] : stackSlot(i - 6));
    if (own?.args === undefined) {
      let nf = 0;
      for (let i = 0; i < 8; i++) if (used(xmms[i])) nf = i + 1;
      for (let i = 0; i < nf; i++) args.push(xmms[i]);
    }
  }
  // return value: rax (or xmm0) written on the way to every return; a path that leaves it
  // untouched means the function returns nothing
  const written = (e: Expr | null | undefined) => !!e && e.k === "l" && !!e.rd?.length && e.rd.every((d) => d >= 0);
  const rets = f.blocks.filter((b) => !b.dead && b.term.k === "ret").map((b) => b.term as Extract<typeof b.term, { k: "ret" }>);
  let ret: "void" | "int" | "float" = "void";
  if (rets.length && rets.every((t) => written(t.v))) ret = "int";
  else if (rets.length && rets.every((t) => written(t.fv))) ret = "float";
  else if (!rets.length && f.blocks.some((b) => !b.dead && b.term.k === "tail")) ret = "int";
  if (own?.returns) ret = own.returns;
  // the return width: the widest definition that reaches a return
  let rw = 0;
  for (const b of f.blocks) {
    if (b.dead || b.term.k !== "ret") continue;
    const e = ret === "float" ? b.term.fv : b.term.v;
    for (const d of (e?.k === "l" ? e.rd : []) ?? []) if (d >= 0) rw = Math.max(rw, flow.defs.get(d)!.w);
  }
  if (!rw) rw = 64;
  for (const b of f.blocks) {
    if (b.term.k !== "ret") continue;
    if (ret === "int") b.term = { k: "ret", v: { k: "l", loc: "rax", w: rw }, fv: null, addr: b.term.addr };
    else if (ret === "float") b.term = { k: "ret", v: { k: "l", loc: "xmm0", w: rw }, fv: null, addr: b.term.addr };
    else b.term = { k: "ret", v: null, fv: null, addr: b.term.addr };
  }
  f.sig = { args, ret };
}

/** One round of propagation; returns the number of reads replaced. */
function propagateOnce(f: IrFunc, flow: Flow): number {
  const usedAsSource = new Set<number>(); // statement ids inlined somewhere this round
  const modified = new Set<number>(); // statement ids (or -1-block for terminators) changed this round
  let count = 0;
  const hostKey = (u: Use) => (u.host ? u.host.id : -1 - u.block);
  for (const b of f.blocks) {
    if (b.dead) continue;
    for (let i = 0; i < b.stmts.length; i++) {
      const s = b.stmts[i];
      if (s.k !== "set" && s.k !== "call") continue;
      if (s.k === "call" && !s.dst) continue;
      if (modified.has(s.id)) continue;
      const d = defId(s, 0);
      const info = flow.defs.get(d)!;
      const all = flow.uses.get(d) ?? [];
      if (!all.length) continue;
      const src: Expr = s.k === "set" ? s.src : s.call;
      const isCall = s.k === "call";
      if (isCall && all.length !== 1) continue;
      const multi = all.length > 1;
      if (multi && !cheap(src)) continue;
      // operands of src, with the definitions they had at the definition
      const operands: L[] = [];
      walk(src, (x) => x.k === "l" && operands.push(x));
      const mem = hasLoad(src);
      /** the operand still holds the same definitions at the read (webs are renamed apart first) */
      const valid = (o: L, u: Use): boolean => sameSet(rdAt(f, flow, u.block, u.index, o.loc), o.rd);
      for (const u of all) {
        if (u.host?.k === "asm") continue;
        if (u.host && usedAsSource.has(u.host.id)) continue;
        if (!sameSet(u.node.rd, [d])) continue;
        if (u.node.loc !== info.loc) continue;
        if (mem) {
          if (u.block !== b.id) continue;
          const end = u.index < 0 ? b.stmts.length : u.index;
          if (end <= i) continue;
          let blocked = false;
          for (let j = i + 1; j < end; j++) if (isBarrier(b.stmts[j])) blocked = true;
          if (blocked) continue;
        }
        if (!operands.every((o) => valid(o, u))) continue;
        // replace
        const repl = adapt(clone(src), info.w, u.node.w);
        const tgt = u.node;
        if (u.host) mapStmtUses(u.host, (e) => replaceNode(e, tgt, repl));
        else mapTermUses(f.blocks[u.block].term, (e) => replaceNode(e, tgt, repl));
        modified.add(hostKey(u));
        usedAsSource.add(s.id);
        count++;
        if (isCall) {
          // the call moved into its only reader
          s.dst = null;
          (s as Stmt & { moved?: boolean }).moved = true;
        }
      }
    }
  }
  // tidy what changed
  for (const b of f.blocks) {
    b.stmts = b.stmts.filter((s) => !(s as Stmt & { moved?: boolean }).moved);
    for (const s of b.stmts) if (modified.has(s.id)) mapStmtUses(s, simp);
    if (modified.has(-1 - b.id)) mapTermUses(b.term, simp);
  }
  return count;
}

/** Removes definitions nobody reads; calls keep their side effect. Returns how many were removed. */
function deadCode(f: IrFunc, flow: Flow): number {
  const count = new Map<number, number>();
  for (const [d, us] of flow.uses) count.set(d, us.length);
  let removed = 0;
  const dead = new Set<number>();
  const kill = (s: Stmt) => {
    dead.add(s.id);
    removed++;
    for (const e of stmtUses(s)) walk(e, (x) => {
      if (x.k !== "l") return;
      for (const d of x.rd ?? []) {
        const n = (count.get(d) ?? 0) - 1;
        count.set(d, n);
        if (n === 0) pending.push(d);
      }
    });
  };
  const pending: number[] = [];
  const consider = (s: Stmt) => {
    if (dead.has(s.id)) return;
    const ds = stmtDefs(s);
    const unused = ds.every((_, k) => !(count.get(defId(s, k)) ?? 0));
    if (s.k === "set" && unused) kill(s);
    else if (s.k === "clob" && unused) {
      dead.add(s.id);
      removed++;
    } else if (s.k === "call" && s.dst && unused) {
      s.dst = null;
      removed++;
    }
  };
  for (const b of f.blocks) if (!b.dead) b.stmts.forEach(consider);
  while (pending.length) {
    const d = pending.pop()!;
    const info = flow.defs.get(d);
    if (info?.stmt) consider(info.stmt);
  }
  for (const b of f.blocks) b.stmts = b.stmts.filter((s) => !dead.has(s.id));
  return removed;
}

/** The register a (possibly renamed) location belongs to: `rcx.3` -> `rcx`. */
export const baseLoc = (l: string) => l.replace(/\.\d+$/, "");

/**
 * Gives every web of a register its own location (`rcx`, `rcx.1`, ...), so a
 * value can still be read after its register was reused for another
 * variable. The web holding the entry value keeps the register's name. Stack
 * slots keep theirs: each stays one variable.
 */
export function renameWebs(f: IrFunc): void {
  const flow = analyze(f);
  const web = webs(flow);
  const entryRoots = new Set<number>();
  for (const d of flow.entryDef.values()) entryRoots.add(web.get(d) ?? d);
  const names = new Map<number, string>();
  const counter = new Map<string, number>();
  for (const l of flow.entryDef.keys()) {
    const m = /^(.*)\.(\d+)$/.exec(l);
    if (m) counter.set(m[1], Math.max(counter.get(m[1]) ?? 0, Number(m[2])));
  }
  const nameOf = (d: number): string | null => {
    const root = web.get(d) ?? d;
    const loc = flow.defs.get(root)!.loc;
    if (/^s-?\d+$/.test(loc)) return null;
    let nm = names.get(root);
    if (nm) return nm;
    if (entryRoots.has(root)) nm = loc;
    else {
      const base = baseLoc(loc);
      const k = (counter.get(base) ?? 0) + 1;
      counter.set(base, k);
      nm = `${base}.${k}`;
    }
    names.set(root, nm);
    return nm;
  };
  const rename = (e: Expr) => walk(e, (x) => {
    if (x.k !== "l" || !x.rd?.length) return;
    const nm = nameOf(x.rd[0]);
    if (nm) x.loc = nm;
  });
  for (const b of f.blocks) {
    if (b.dead) continue;
    for (const s of b.stmts) {
      stmtUses(s).forEach(rename);
      const ds = stmtDefs(s).map((l, k) => nameOf(defId(s, k)) ?? l);
      if (s.k === "set") s.dst = ds[0];
      else if (s.k === "call" && s.dst) s.dst = ds[0];
      else if (s.k === "clob") s.locs = ds;
      else if (s.k === "asm") s.defs = ds;
    }
    termUses(b.term).forEach(rename);
  }
}

/** Propagation and dead-code elimination to a fixpoint. */
export function optimize(f: IrFunc, maxRounds = 64): void {
  renameWebs(f);
  for (let r = 0; r < maxRounds; r++) {
    let flow = analyze(f);
    const p = propagateOnce(f, flow);
    flow = analyze(f);
    const d = deadCode(f, flow);
    if (!p && !d) break;
  }
  // final simplification of whatever is left
  for (const b of f.blocks) {
    for (const s of b.stmts) mapStmtUses(s, simp);
    mapTermUses(b.term, simp);
  }
}

/** Webs: definitions joined by reads that see more than one of them. Returns def id -> web root. */
export function webs(flow: Flow): Map<number, number> {
  const parent = new Map<number, number>();
  const find = (x: number): number => {
    let r = x;
    while (parent.has(r) && parent.get(r) !== r) r = parent.get(r)!;
    // path compression
    for (let y = x; y !== r; ) {
      const nx = parent.get(y)!;
      parent.set(y, r);
      y = nx;
    }
    return r;
  };
  for (const d of flow.defs.keys()) parent.set(d, d);
  const done = new Set<L>();
  for (const list of flow.uses.values()) {
    for (const u of list) {
      if (done.has(u.node)) continue; // a read is listed under each of its definitions
      done.add(u.node);
      const rd = u.node.rd ?? [];
      for (let i = 1; i < rd.length; i++) {
        const a = find(rd[0]);
        const b = find(rd[i]);
        if (a !== b) parent.set(Math.max(a, b), Math.min(a, b));
      }
    }
  }
  const out = new Map<number, number>();
  for (const d of flow.defs.keys()) out.set(d, find(d));
  return out;
}
