// Structural view of one function's control flow, built synchronously from a
// linear listing (Intel or AT&T text): basic blocks, true/false/jump/fall
// edges, dominators, post-dominators and natural loops. This is what the
// pseudocode structurer (pseudocode.ts) and the CFG view's loop highlighting
// work from; the graph itself is drawn from cfg.ts (recursive descent).

export type Insn = { address: string; length: number; text: string };

/** `true`/`false` leave a conditional branch, `jump` is an unconditional jmp, `fall` runs into the next block, `case` is a switch jump-table entry. */
export type EdgeKind = "true" | "false" | "jump" | "fall" | "case";

export type CfgEdge = {
  from: number;
  to: number;
  kind: EdgeKind;
  /** target dominates source: a loop back edge */
  back: boolean;
  /** `case` edges: the jump-table indices that lead here */
  values?: number[];
};

export type Block = {
  id: number;
  start: bigint;
  insns: Insn[];
  succ: CfgEdge[];
  pred: number[];
  /** header of a natural loop */
  loopHeader: boolean;
  /** inside at least one natural loop (headers included) */
  inLoop: boolean;
  /** reachable from the entry block */
  reachable: boolean;
};

export type Loop = { header: number; latches: number[]; body: Set<number> };

export type Cfg = { blocks: Block[]; edges: CfgEdge[]; loops: Loop[]; idom: number[] };

export type Branch =
  | { kind: "ret" }
  | { kind: "stop" } // int3 / ud2 / hlt: execution does not continue
  | { kind: "jmp"; target: bigint | null }
  | { kind: "jcc"; mnemonic: string; target: bigint | null }
  | null;

/** Mnemonic with branch-hint prefixes (`bnd`, `notrack`) removed, lowercased. */
export function mnemonicOf(text: string): string {
  const words = text.trim().toLowerCase().split(/\s+/);
  while (words.length > 1 && (words[0] === "bnd" || words[0] === "notrack")) words.shift();
  return words[0] ?? "";
}

/** How an instruction leaves the straight-line flow, or null when it does not. */
export function branchOf(text: string): Branch {
  const mn = mnemonicOf(text);
  if (/^ret[nqlw]?$/.test(mn) || mn === "iretq") return { kind: "ret" };
  if (mn === "int3" || mn === "ud2" || mn === "hlt") return { kind: "stop" };
  const isJmp = mn === "jmp" || mn === "jmpq";
  const isJcc = !isJmp && (/^j[a-z]+$/.test(mn) || /^loop[a-z]*$/.test(mn));
  if (!isJmp && !isJcc) return null;
  const words = text.replace(/;.*$/, "").trim().toLowerCase().split(/\s+/).filter((w) => !["bnd", "notrack", "short", "near"].includes(w));
  const m = words.length === 2 ? /^0x([0-9a-f]+)$/.exec(words[1]) : null;
  const target = m ? BigInt("0x" + m[1]) : null;
  return isJmp ? { kind: "jmp", target } : { kind: "jcc", mnemonic: mn, target };
}

/**
 * Splits a listing into basic blocks. Leaders are the first instruction,
 * every in-function branch target and every instruction after a branch or a
 * return. Branches that leave the listing (tail calls) end their block
 * without an edge; indirect jumps do the same.
 */
export function buildStructure(insns: readonly Insn[], opts: { switches?: ReadonlyMap<bigint, readonly bigint[]> } = {}): Cfg {
  if (insns.length === 0) return { blocks: [], edges: [], loops: [], idom: [] };
  const addrs = insns.map((i) => BigInt(i.address));
  const indexOf = new Map<bigint, number>();
  addrs.forEach((a, i) => indexOf.set(a, i));
  const branches = insns.map((i) => branchOf(i.text));

  const leaders = new Set<number>([0]);
  branches.forEach((b, i) => {
    if (!b) return;
    if (i + 1 < insns.length) leaders.add(i + 1);
    if ((b.kind === "jmp" || b.kind === "jcc") && b.target !== null) {
      const t = indexOf.get(b.target);
      if (t !== undefined) leaders.add(t);
    }
  });

  const starts = [...leaders].sort((a, b) => a - b);
  const blockAt = new Map<number, number>(); // insn index of a leader -> block id
  const blocks: Block[] = starts.map((s, id) => {
    blockAt.set(s, id);
    const end = id + 1 < starts.length ? starts[id + 1] : insns.length;
    return { id, start: addrs[s], insns: insns.slice(s, end), succ: [], pred: [], loopHeader: false, inLoop: false, reachable: false };
  });

  const edges: CfgEdge[] = [];
  const link = (from: number, to: number, kind: EdgeKind) => {
    const e: CfgEdge = { from, to, kind, back: false };
    edges.push(e);
    blocks[from].succ.push(e);
    if (!blocks[to].pred.includes(from)) blocks[to].pred.push(from);
  };
  const targetBlock = (t: bigint | null) => {
    const i = t === null ? undefined : indexOf.get(t);
    return i === undefined ? undefined : blockAt.get(i);
  };

  for (const b of blocks) {
    const lastIdx = starts[b.id] + b.insns.length - 1;
    const br = branches[lastIdx];
    const next = b.id + 1 < blocks.length ? b.id + 1 : undefined;
    if (!br) {
      if (next !== undefined) link(b.id, next, "fall");
    } else if (br.kind === "jmp") {
      const cases = br.target === null ? opts.switches?.get(addrs[lastIdx]) : undefined;
      if (cases) {
        // one edge per distinct target, carrying every table index that leads there
        const byTarget = new Map<number, number[]>();
        cases.forEach((c, i) => {
          const t = targetBlock(c);
          if (t !== undefined) byTarget.set(t, [...(byTarget.get(t) ?? []), i]);
        });
        for (const [t, values] of byTarget) {
          link(b.id, t, "case");
          edges[edges.length - 1].values = values;
        }
      }
      const t = targetBlock(br.target);
      if (t !== undefined) link(b.id, t, "jump");
    } else if (br.kind === "jcc") {
      const t = targetBlock(br.target);
      if (t !== undefined) link(b.id, t, "true");
      if (next !== undefined) link(b.id, next, "false");
    }
  }

  const info = graphInfo(blocks.length, (n) => blocks[n].succ.map((e) => e.to), (n) => blocks[n].pred);
  for (const b of blocks) b.reachable = info.reachable[b.id];
  for (const e of edges) e.back = info.back.has(`${e.from}>${e.to}`);
  for (const l of info.loops) {
    blocks[l.header].loopHeader = true;
    for (const n of l.body) blocks[n].inLoop = true;
  }
  return { blocks, edges, loops: info.loops, idom: info.idom };
}

export type GraphInfo = {
  /** immediate dominators; -1 for the entry and unreachable nodes */
  idom: number[];
  /** immediate post-dominators over a virtual exit; -1 is the exit (or none) */
  ipdom: number[];
  loops: Loop[];
  /** back edges as `from>to` */
  back: Set<string>;
  reachable: boolean[];
};

/**
 * Dominators, post-dominators and natural loops of any graph given by its
 * successor and predecessor lists. Used for listings (buildStructure) and for
 * rebuilt graphs (the decompiler's IR, unflattened functions).
 */
export function graphInfo(count: number, succ: (n: number) => number[], pred: (n: number) => number[], entry = 0): GraphInfo {
  if (count === 0) return { idom: [], ipdom: [], loops: [], back: new Set(), reachable: [] };
  const idom = idoms(count, entry, succ, pred);
  idom[entry] = -1;
  const reachable = Array.from({ length: count }, (_, n) => n === entry || idom[n] >= 0);
  const loops: Loop[] = [];
  const back = new Set<string>();
  for (let from = 0; from < count; from++) {
    if (!reachable[from]) continue;
    for (const to of new Set(succ(from))) {
      if (!dominates(idom, to, from)) continue;
      back.add(`${from}>${to}`);
      let loop = loops.find((l) => l.header === to);
      if (!loop) {
        loop = { header: to, latches: [], body: new Set([to]) };
        loops.push(loop);
      }
      loop.latches.push(from);
      // natural loop: everything that reaches the latch without passing the header
      const stack = [from];
      while (stack.length) {
        const n = stack.pop()!;
        if (loop.body.has(n)) continue;
        loop.body.add(n);
        stack.push(...pred(n).filter((p) => reachable[p]));
      }
    }
  }
  // the virtual exit follows every node without successors
  const exit = count;
  const exits: number[] = [];
  for (let n = 0; n < count; n++) if (succ(n).length === 0) exits.push(n);
  const revNext = (b: number) => (b === exit ? exits : pred(b));
  const revPrev = (b: number) => (b === exit ? [] : succ(b).length ? succ(b) : [exit]);
  const ipdom = idoms(count + 1, exit, revNext, revPrev).slice(0, count).map((d) => (d === exit ? -1 : d));
  return { idom, ipdom, loops, back, reachable };
}

/** Reverse postorder of the blocks reachable from `entry` over `next`. */
function reversePostorder(count: number, entry: number, next: (n: number) => number[]): number[] {
  const seen = new Uint8Array(count);
  const order: number[] = [];
  const stack: { n: number; i: number }[] = [{ n: entry, i: 0 }];
  seen[entry] = 1;
  while (stack.length) {
    const top = stack[stack.length - 1];
    const succ = next(top.n);
    if (top.i < succ.length) {
      const s = succ[top.i++];
      if (!seen[s]) {
        seen[s] = 1;
        stack.push({ n: s, i: 0 });
      }
    } else {
      order.push(top.n);
      stack.pop();
    }
  }
  return order.reverse();
}

/** Immediate dominators (Cooper-Harvey-Kennedy); `-1` for unreachable blocks, the entry is its own. */
function idoms(count: number, entry: number, next: (n: number) => number[], prev: (n: number) => number[]): number[] {
  const rpo = reversePostorder(count, entry, next);
  const rank = new Array<number>(count).fill(-1);
  rpo.forEach((n, i) => (rank[n] = i));
  const idom = new Array<number>(count).fill(-1);
  idom[entry] = entry;
  const intersect = (a: number, b: number) => {
    while (a !== b) {
      while (rank[a] > rank[b]) a = idom[a];
      while (rank[b] > rank[a]) b = idom[b];
    }
    return a;
  };
  for (let changed = true; changed; ) {
    changed = false;
    for (const n of rpo) {
      if (n === entry) continue;
      let d = -1;
      for (const p of prev(n)) if (idom[p] >= 0) d = d < 0 ? p : intersect(p, d);
      if (d !== idom[n]) {
        idom[n] = d;
        changed = true;
      }
    }
  }
  return idom;
}

/** Does `a` dominate `b`? (`idom[entry]` is -1.) */
export function dominates(idom: readonly number[], a: number, b: number): boolean {
  for (let n = b; n >= 0; n = idom[n]) if (n === a) return true;
  return false;
}

/**
 * Immediate post-dominators over a virtual exit that every block without
 * successors flows into. `-1` means the virtual exit (or no post-dominator).
 */
export function postDominators(cfg: Cfg): number[] {
  return graphInfo(cfg.blocks.length, (b) => cfg.blocks[b].succ.map((e) => e.to), (b) => cfg.blocks[b].pred).ipdom;
}
