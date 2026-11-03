// Control-flow flattening removal (OLLVM style). A flattened function keeps
// its real blocks but sends every one of them back to a dispatcher: a block
// (or a tree of compare blocks, or a switch) that picks the next real block
// from a state variable each real block assigns before jumping back.
//
// On the optimized IR: the state variable is the location the most
// statement-free compare blocks test against constants; those blocks, the
// switch on it and the empty jump blocks leading into them are the
// dispatcher. For each edge from a real block into the dispatcher the value
// the state holds at the end of the block (a constant, or a select between
// two constants from a cmov) is run through the dispatcher by constant
// evaluation, which gives the real successor. The edges are rewired, the
// dispatcher becomes unreachable and the state assignments die.
import { analyze, baseLoc, rdAt, type Flow } from "./dataflow";
import { evalConst, simp, succOf, walk, type Expr, type IrFunc, type Term } from "./ir";

export type UnflattenReport = {
  flattened: boolean;
  /** first dispatcher block (0x address) */
  dispatcher: string | null;
  /** the state location (register or stack slot) */
  state: string | null;
  dispatcherBlocks: string[];
  /** distinct state values seen */
  states: number;
  /** real blocks and the successors they were given */
  recovered: { block: string; next: string[]; via: "const" | "select" }[];
  unresolved: { block: string; reason: string }[];
  note: string;
};

type L = Extract<Expr, { k: "l" }>;

/** The location `e` tests, when it is a comparison of one location (maybe narrowed or extended) with a constant. */
function testedLoc(e: Expr): string | null {
  if (e.k === "u" && e.op === "!") return testedLoc(e.a);
  if (e.k === "b" && (e.op === "&&" || e.op === "||")) {
    const a = testedLoc(e.a);
    return a && a === testedLoc(e.b) ? a : null;
  }
  if (e.k !== "cmp" || e.b.k !== "c") return null;
  let a = e.a;
  while (a.k === "cast" && !a.to) a = a.a;
  if (a.k === "b" && (a.op === "+" || a.op === "^" || a.op === "-") && a.b.k === "c") a = a.a;
  return a.k === "l" ? a.loc : null;
}

function switchLoc(t: Term): string | null {
  if (t.k !== "switch") return null;
  let a = t.x;
  while (a.k === "cast" && !a.to) a = a.a;
  if (a.k === "b" && (a.op === "+" || a.op === "-") && a.b.k === "c") a = a.a;
  return a.k === "l" ? a.loc : null;
}

const hex = (a: string) => "0x" + BigInt(a).toString(16);
/** How the decompiler names a location: stack slots as var_N / arg_N, registers by their name. */
function display(l: string): string {
  const m = /^s(-?\d+)$/.exec(l);
  if (m) {
    const off = Number(m[1]);
    return off < 0 ? `var_${(-off).toString(16)}` : `arg_${(off - 8).toString(16)}`;
  }
  return baseLoc(l);
}

/**
 * Detects and removes flattening in place (on an optimized IR). `f` is left
 * unchanged when no dispatcher is found. Run optimize() again afterwards so
 * the state assignments disappear.
 */
export function unflatten(f: IrFunc): UnflattenReport {
  const none = (note: string): UnflattenReport => ({ flattened: false, dispatcher: null, state: null, dispatcherBlocks: [], states: 0, recovered: [], unresolved: [], note });
  const live = f.blocks.filter((b) => !b.dead);
  // 1. the state variable: the location most empty compare blocks test
  const votes = new Map<string, number>();
  for (const b of live) {
    if (b.stmts.length) continue;
    const l = b.term.k === "cond" ? testedLoc(b.term.c) : switchLoc(b.term);
    if (l) votes.set(l, (votes.get(l) ?? 0) + (b.term.k === "switch" ? 3 : 1));
  }
  const best = [...votes].sort((a, b) => b[1] - a[1])[0];
  if (!best || best[1] < 3) return none("no dispatcher: fewer than three empty blocks compare one variable against constants");
  const S = best[0];

  // 2. dispatcher blocks: empty compares / switches on S and empty jumps into them
  const inD = new Set<number>();
  for (const b of live) {
    if (b.stmts.length) continue;
    if ((b.term.k === "cond" && testedLoc(b.term.c) === S) || switchLoc(b.term) === S) inD.add(b.id);
  }
  for (let changed = true; changed; ) {
    changed = false;
    for (const b of live) {
      if (inD.has(b.id) || b.stmts.length || b.term.k !== "jump") continue;
      if (inD.has(b.term.to)) {
        inD.add(b.id);
        changed = true;
      }
    }
  }
  // a real dispatcher is a loop: some block outside it must come back into it more than once
  const preds = new Map<number, number>();
  for (const b of live) if (!inD.has(b.id)) for (const s of succOf(b.term)) if (inD.has(s)) preds.set(s, (preds.get(s) ?? 0) + 1);
  const entries = [...preds].sort((a, b) => b[1] - a[1]);
  if (!entries.length || [...preds.values()].reduce((a, b) => a + b, 0) < 3) return none(`no dispatcher: ${display(S)} is compared but fewer than three blocks feed the compares`);
  // the dispatcher's first compare: follow the busiest entry through plain jumps
  let head = entries[0][0];
  for (let guard = 0; guard < 64 && f.blocks[head].term.k === "jump"; guard++) {
    const to = (f.blocks[head].term as Extract<Term, { k: "jump" }>).to;
    if (!inD.has(to)) break;
    head = to;
  }

  // 3. routing a state value through the dispatcher
  const route = (v: bigint, from: number): number | null => {
    const seen = new Set<number>();
    let b = from;
    while (inD.has(b)) {
      if (seen.has(b)) return null;
      seen.add(b);
      const t = f.blocks[b].term;
      const env = (x: L) => (x.loc === S ? v : null);
      if (t.k === "jump") b = t.to;
      else if (t.k === "cond") {
        const r = evalConst(t.c, env);
        if (r === null) return null;
        b = r !== 0n ? t.t : t.f;
      } else if (t.k === "switch") {
        const x = evalConst(t.x, env);
        if (x === null) return null;
        const hit = t.cases.find((cs) => cs.vals.includes(x));
        if (hit) b = hit.to;
        else if (t.def !== null) b = t.def;
        else return null;
      } else return null;
    }
    return b;
  };

  // 4. the state each real block leaves behind
  const flow: Flow = analyze(f);
  const rdEnd = (block: number, loc: string): number[] => rdAt(f, flow, block, -1, loc);
  const recovered: UnflattenReport["recovered"] = [];
  const unresolved: UnflattenReport["unresolved"] = [];
  const values = new Set<bigint>();
  type Plan = { block: number; term: Term; next: number[]; via: "const" | "select" };
  const plans: Plan[] = [];
  for (const b of live) {
    if (inD.has(b.id)) continue;
    const succ = succOf(b.term);
    const into = succ.filter((s) => inD.has(s));
    if (!into.length) continue;
    const ds = rdEnd(b.id, S);
    const addr = hex(b.addr);
    if (ds.length !== 1 || ds[0] < 0) {
      unresolved.push({ block: addr, reason: ds.some((d) => d < 0) ? "state not assigned on every path into this block" : "several assignments of the state reach this block" });
      continue;
    }
    const info = flow.defs.get(ds[0])!;
    const st = info.stmt;
    if (st?.k !== "set") {
      unresolved.push({ block: addr, reason: "the state comes from a call or an unmodelled instruction" });
      continue;
    }
    const val = simp(st.src);
    if (val.k === "c") {
      values.add(val.v);
      const term = structuredClone(b.term) as Term;
      const next: number[] = [];
      let ok = true;
      for (const t of into) {
        const r = route(val.v, t);
        if (r === null) {
          ok = false;
          break;
        }
        retargetOne(term, t, r);
        next.push(r);
      }
      if (!ok) {
        unresolved.push({ block: addr, reason: `state 0x${val.v.toString(16)} does not reach a real block through the dispatcher` });
        continue;
      }
      plans.push({ block: b.id, term, next, via: "const" });
    } else if (val.k === "sel" && val.a.k === "c" && val.b.k === "c" && b.term.k === "jump") {
      // a cmov-selected state: the block becomes a conditional branch
      const ta = route(val.a.v, b.term.to);
      const tb = route(val.b.v, b.term.to);
      const cond = val.c;
      // the condition's operands must be unchanged between the select and the end of the block
      let valid = true;
      walk(cond, (x) => {
        if (x.k !== "l") return;
        const now = rdEnd(b.id, x.loc);
        if ((x.rd ?? []).join() !== now.join()) valid = false;
      });
      if (ta === null || tb === null || !valid) {
        unresolved.push({ block: addr, reason: !valid ? "the select's condition changes before the jump" : "a selected state does not reach a real block" });
        continue;
      }
      values.add(val.a.v);
      values.add(val.b.v);
      plans.push({ block: b.id, term: ta === tb ? { k: "jump", to: ta } : { k: "cond", c: structuredClone(cond), t: ta, f: tb, addr: b.insns[b.insns.length - 1]?.address ?? b.addr }, next: [ta, tb], via: "select" });
    } else {
      unresolved.push({ block: addr, reason: "the state is not a constant here" });
    }
  }
  if (!plans.length) return { ...none(`dispatcher on ${display(S)} found, but no block's next state could be computed`), unresolved, state: display(S), dispatcher: hex(f.blocks[head].addr) };

  // 5. rewire
  for (const p of plans) {
    f.blocks[p.block].term = p.term;
    recovered.push({ block: hex(f.blocks[p.block].addr), next: p.next.map((n) => hex(f.blocks[n].addr)), via: p.via });
  }
  // dispatcher blocks nothing real reaches any more are gone
  const reach = new Set<number>();
  const stack = [0];
  while (stack.length) {
    const n = stack.pop()!;
    if (reach.has(n)) continue;
    reach.add(n);
    stack.push(...succOf(f.blocks[n].term));
  }
  const removed: string[] = [];
  for (const d of inD) {
    if (!reach.has(d)) {
      f.blocks[d].dead = true;
      removed.push(hex(f.blocks[d].addr));
    }
  }
  const dispatcherBlocks = [...inD].sort((a, b) => a - b).map((d) => hex(f.blocks[d].addr));
  return {
    flattened: true,
    dispatcher: hex(f.blocks[head].addr),
    state: display(S),
    dispatcherBlocks,
    states: values.size,
    recovered,
    unresolved,
    note: `${plans.length} block(s) rewired, ${unresolved.length} unresolved, ${removed.length} of ${inD.size} dispatcher blocks removed`,
  };
}

function retargetOne(t: Term, from: number, to: number): void {
  if (t.k === "jump" && t.to === from) t.to = to;
  else if (t.k === "cond") {
    if (t.t === from) t.t = to;
    if (t.f === from) t.f = to;
  } else if (t.k === "switch") {
    t.cases.forEach((c) => c.to === from && (c.to = to));
    if (t.def === from) t.def = to;
  }
}
