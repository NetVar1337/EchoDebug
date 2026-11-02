// Control-flow graph of one function, built from its disassembly listing
// (Intel or AT&T text, as Echo and the local backend print it), plus a small
// layered (Sugiyama-style) layout for drawing it top-down.

export type Insn = { address: string; length: number; text: string };

/** `true`/`false` leave a conditional branch, `jump` is an unconditional jmp, `fall` runs into the next block. */
export type EdgeKind = "true" | "false" | "jump" | "fall";

export type CfgEdge = { from: number; to: number; kind: EdgeKind; /** target dominates source: a loop back edge */ back: boolean };

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
export function buildCfg(insns: readonly Insn[]): Cfg {
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
      const t = targetBlock(br.target);
      if (t !== undefined) link(b.id, t, "jump");
    } else if (br.kind === "jcc") {
      const t = targetBlock(br.target);
      if (t !== undefined) link(b.id, t, "true");
      if (next !== undefined) link(b.id, next, "false");
    }
  }

  const idom = dominators(blocks);
  for (const b of blocks) b.reachable = b.id === 0 || idom[b.id] >= 0;
  const loops: Loop[] = [];
  for (const e of edges) {
    if (!blocks[e.from].reachable || !dominates(idom, e.to, e.from)) continue;
    e.back = true;
    let loop = loops.find((l) => l.header === e.to);
    if (!loop) {
      loop = { header: e.to, latches: [], body: new Set([e.to]) };
      loops.push(loop);
    }
    loop.latches.push(e.from);
    // natural loop: everything that reaches the latch without passing the header
    const stack = [e.from];
    while (stack.length) {
      const n = stack.pop()!;
      if (loop.body.has(n)) continue;
      loop.body.add(n);
      stack.push(...blocks[n].pred);
    }
  }
  for (const l of loops) {
    blocks[l.header].loopHeader = true;
    for (const n of l.body) blocks[n].inLoop = true;
  }
  return { blocks, edges, loops, idom };
}

/**
 * The instructions of the blocks reachable from the first one: trims a
 * fixed-size disassembly window down to the function that starts it when
 * no function bound is known (whatever follows its last return is dropped).
 */
export function reachableListing<T extends Insn>(insns: readonly T[]): T[] {
  const cfg = buildCfg(insns);
  const keep = new Set(cfg.blocks.filter((b) => b.reachable).flatMap((b) => b.insns.map((i) => i.address)));
  return insns.filter((i) => keep.has(i.address));
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

function dominators(blocks: Block[]): number[] {
  const idom = idoms(blocks.length, 0, (n) => blocks[n].succ.map((e) => e.to), (n) => blocks[n].pred);
  idom[0] = -1;
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
  const n = cfg.blocks.length;
  const exit = n;
  const succ = (b: number) => cfg.blocks[b].succ.map((e) => e.to);
  const exits = cfg.blocks.filter((b) => b.succ.length === 0).map((b) => b.id);
  // dominators of the reversed graph, rooted at the virtual exit
  const revNext = (b: number) => (b === exit ? exits : cfg.blocks[b].pred);
  const revPrev = (b: number) => (b === exit ? [] : succ(b).length ? succ(b) : [exit]);
  return idoms(n + 1, exit, revNext, revPrev).slice(0, n).map((d) => (d === exit ? -1 : d));
}

// ---------------------------------------------------------------------------
// layout

export type Size = { w: number; h: number };
export type LaidNode = { id: number; x: number; y: number; w: number; h: number; layer: number };
export type LaidEdge = CfgEdge & { points: [number, number][] };
export type CfgLayout = { nodes: LaidNode[]; edges: LaidEdge[]; width: number; height: number };

const kGapX = 36;
const kGapY = 48;
const kDummyW = 12;

/**
 * Layered layout: cycles broken at DFS back edges, layers by longest path,
 * long edges split with dummy nodes, crossings reduced by barycenter sweeps,
 * x positions pulled toward the neighbours' centers. Good enough for the
 * few hundred blocks a function has; not a full Brandes-Köpf placement.
 */
export function layoutCfg(cfg: Cfg, sizes: readonly Size[]): CfgLayout {
  const n = cfg.blocks.length;
  if (n === 0) return { nodes: [], edges: [], width: 0, height: 0 };

  // 1. break cycles: edges to a node on the DFS stack are reversed for layering
  const reversed = new Set<CfgEdge>();
  const state = new Uint8Array(n); // 0 new, 1 on stack, 2 done
  const visit = (root: number) => {
    const stack: { b: number; i: number }[] = [{ b: root, i: 0 }];
    state[root] = 1;
    while (stack.length) {
      const top = stack[stack.length - 1];
      const succ = cfg.blocks[top.b].succ;
      if (top.i < succ.length) {
        const e = succ[top.i++];
        if (state[e.to] === 1) reversed.add(e);
        else if (state[e.to] === 0) {
          state[e.to] = 1;
          stack.push({ b: e.to, i: 0 });
        }
      } else {
        state[top.b] = 2;
        stack.pop();
      }
    }
  };
  visit(0);
  for (let b = 0; b < n; b++) if (!state[b]) visit(b);
  const dag = cfg.edges.filter((e) => e.from !== e.to).map((e) => (reversed.has(e) ? { e, from: e.to, to: e.from } : { e, from: e.from, to: e.to }));

  // 2. longest-path layering (Kahn order over the DAG)
  const layer = new Array<number>(n).fill(0);
  const indeg = new Array<number>(n).fill(0);
  for (const d of dag) indeg[d.to]++;
  const queue = [...Array(n).keys()].filter((b) => indeg[b] === 0);
  while (queue.length) {
    const b = queue.shift()!;
    for (const d of dag) {
      if (d.from !== b) continue;
      layer[d.to] = Math.max(layer[d.to], layer[b] + 1);
      if (--indeg[d.to] === 0) queue.push(d.to);
    }
  }

  // 3. dummy nodes for edges spanning several layers; ids >= n are dummies
  type V = { id: number; layer: number; w: number; h: number; x: number; order: number };
  const verts: V[] = [...Array(n).keys()].map((b) => ({ id: b, layer: layer[b], w: sizes[b].w, h: sizes[b].h, x: 0, order: 0 }));
  const up = new Map<number, number[]>(); // vertex -> neighbours one layer above
  const down = new Map<number, number[]>();
  const connect = (a: number, b: number) => {
    (down.get(a) ?? down.set(a, []).get(a)!).push(b);
    (up.get(b) ?? up.set(b, []).get(b)!).push(a);
  };
  const chains = new Map<CfgEdge, number[]>(); // edge -> vertex chain in layering direction
  for (const d of dag) {
    if (reversed.has(d.e)) continue; // back edges are routed around the side, see below
    const chain = [d.from];
    for (let l = layer[d.from] + 1; l < layer[d.to]; l++) {
      const v: V = { id: verts.length, layer: l, w: kDummyW, h: 0, x: 0, order: 0 };
      verts.push(v);
      chain.push(v.id);
    }
    chain.push(d.to);
    for (let i = 0; i + 1 < chain.length; i++) connect(chain[i], chain[i + 1]);
    chains.set(d.e, chain);
  }

  // 4. crossing reduction: initial order by id (address order), then barycenter sweeps
  const maxLayer = Math.max(...verts.map((v) => v.layer));
  const layers: V[][] = Array.from({ length: maxLayer + 1 }, () => []);
  for (const v of verts) layers[v.layer].push(v);
  layers.forEach((l) => l.forEach((v, i) => (v.order = i)));
  const sweep = (l: V[], nb: Map<number, number[]>) => {
    const bary = new Map<V, number>();
    for (const v of l) {
      const ns = nb.get(v.id) ?? [];
      bary.set(v, ns.length ? ns.reduce((s, x) => s + verts[x].order, 0) / ns.length : v.order);
    }
    l.sort((a, b) => bary.get(a)! - bary.get(b)! || a.order - b.order);
    l.forEach((v, i) => (v.order = i));
  };
  for (let it = 0; it < 6; it++) {
    for (let i = 1; i <= maxLayer; i++) sweep(layers[i], up);
    for (let i = maxLayer - 1; i >= 0; i--) sweep(layers[i], down);
  }

  // 5. x placement: pack, then pull toward neighbour centers keeping order and spacing
  for (const l of layers) {
    let x = 0;
    for (const v of l) {
      v.x = x;
      x += v.w + kGapX;
    }
  }
  const center = (v: V) => v.x + v.w / 2;
  const place = (l: V[], nb: Map<number, number[]>) => {
    const want = l.map((v) => {
      const ns = nb.get(v.id) ?? [];
      return ns.length ? ns.reduce((s, x) => s + center(verts[x]), 0) / ns.length - v.w / 2 : v.x;
    });
    // left-to-right then right-to-left resolution of overlaps, averaged
    const lr = want.slice();
    for (let i = 1; i < l.length; i++) lr[i] = Math.max(lr[i], lr[i - 1] + l[i - 1].w + kGapX);
    const rl = want.slice();
    for (let i = l.length - 2; i >= 0; i--) rl[i] = Math.min(rl[i], rl[i + 1] - l[i].w - kGapX);
    const mid = l.map((_, i) => (lr[i] + rl[i]) / 2);
    for (let i = 1; i < l.length; i++) mid[i] = Math.max(mid[i], mid[i - 1] + l[i - 1].w + kGapX);
    l.forEach((v, i) => (v.x = mid[i]));
  };
  for (let it = 0; it < 4; it++) {
    for (let i = 1; i <= maxLayer; i++) place(layers[i], up);
    for (let i = maxLayer - 1; i >= 0; i--) place(layers[i], down);
  }
  const minX = Math.min(...verts.map((v) => v.x));
  for (const v of verts) v.x -= minX - kGapX / 2;

  // 6. y per layer from the tallest block in it
  const layerY: number[] = [];
  let y = kGapY / 2;
  for (const l of layers) {
    layerY.push(y);
    y += Math.max(0, ...l.map((v) => v.h)) + kGapY;
  }
  const height = y - kGapY / 2;
  let width = Math.max(...verts.map((v) => v.x + v.w)) + kGapX / 2;
  let backLane = 0;

  const nodes: LaidNode[] = verts.slice(0, n).map((v) => ({ id: v.id, x: v.x, y: layerY[v.layer], w: v.w, h: v.h, layer: v.layer }));
  const bottom = (id: number): [number, number] => [center(verts[id]), layerY[verts[id].layer] + verts[id].h];
  const top = (id: number): [number, number] => [center(verts[id]), layerY[verts[id].layer]];
  const mid = (id: number): [number, number] => [center(verts[id]), layerY[verts[id].layer] + Math.max(0, ...layers[verts[id].layer].map((v) => v.h)) / 2];

  const edges: LaidEdge[] = cfg.edges.map((e) => {
    if (e.from === e.to) {
      // self loop: out of the right side and back in
      const v = verts[e.from];
      const r = v.x + v.w;
      const yy = layerY[v.layer];
      return { ...e, points: [[r, yy + v.h - 8], [r + 16, yy + v.h - 8], [r + 16, yy + 8], [r, yy + 8]] };
    }
    const chain = chains.get(e)!;
    if (!reversed.has(e)) return { ...e, points: [bottom(chain[0]), ...chain.slice(1, -1).map(mid), top(chain[chain.length - 1])] };
    // back edge: down out of the source, up along the right of every layer it spans, into the target's top
    const [sx, sy] = bottom(e.from);
    const [tx, ty] = top(e.to);
    const lo = Math.min(layer[e.from], layer[e.to]);
    const hi = Math.max(layer[e.from], layer[e.to]);
    let right = 0;
    for (let l = lo; l <= hi; l++) for (const v of layers[l]) right = Math.max(right, v.x + v.w);
    const x = right + 14 + 10 * backLane++;
    width = Math.max(width, x + kGapX / 2);
    return { ...e, points: [[sx, sy], [sx, sy + 12 + 4 * (backLane % 3)], [x, sy + 12 + 4 * (backLane % 3)], [x, ty - 14], [tx, ty - 14], [tx, ty]] };
  });

  return { nodes, edges, width, height };
}
