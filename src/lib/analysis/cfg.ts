// Control-flow graph of one function: basic blocks and the edges between them, built by
// recursive descent over the disassembly (Echo's or iced-x86's text, Intel or AT&T style, or the
// relay's AArch64 text).
//
// Blocks start at the entry, at every branch target inside the function and after every
// conditional branch; they end at a branch, a return or right before another block's start.
// Calls fall through. Switch jump tables (see jumptables.ts) add one edge per case.

export type CfgLine = { address: string; length: number; bytes: string; text: string };
export type EdgeKind = "taken" | "fallthrough" | "jump" | "case";
export type Block = { start: bigint; end: bigint; lines: CfgLine[]; terminator: "ret" | "jmp" | "jcc" | "fall" | "indirect" | "stop" };
export type CfgEdge = { from: bigint; to: bigint; kind: EdgeKind; label?: string };
/** `switches`: the case targets of each resolved indirect jmp (by its address), in table order. */
export type Cfg = { entry: bigint; blocks: Block[]; edges: CfgEdge[]; truncated: boolean; switches?: Map<bigint, bigint[]> };

export type Flow = { kind: "ret" | "jmp" | "jcc" | "call" | "indirect-jmp" | "stop" | "none"; target: bigint | null };

/**
 * AArch64 (the relay prints PC-relative targets as absolute addresses): b, bl, br, blr, ret,
 * b.cond / bc.cond, cbz / cbnz, tbz / tbnz, the pointer-authentication forms, brk / udf / hlt.
 * null when the mnemonic is not an AArch64 control-flow instruction.
 */
export function a64FlowOf(mn: string, op: string): Flow | null {
  const last = op.split(",").pop()?.trim() ?? "";
  const m = /^#?(0x[0-9a-f]+)(?: <[^>]*>)?$/.exec(last);
  const target = m ? BigInt(m[1]) : null;
  if (mn === "b") return target !== null ? { kind: "jmp", target } : { kind: "indirect-jmp", target: null };
  if (mn === "bl") return { kind: "call", target };
  if (/^(?:blr|blraaz?|blrabz?)$/.test(mn)) return { kind: "call", target: null };
  if (/^(?:br|braaz?|brabz?)$/.test(mn)) return { kind: "indirect-jmp", target: null };
  if (/^(?:retaa|retab|eret|eretaa|eretab)$/.test(mn)) return { kind: "ret", target: null };
  if (/^bc?\.[a-z]{2}$/.test(mn) || /^(?:cbz|cbnz|tbz|tbnz)$/.test(mn)) return { kind: "jcc", target };
  if (mn === "brk" || mn === "udf" || mn === ".inst") return { kind: "stop", target: null };
  return null;
}

/** What an instruction does to control flow; `target` for direct branches. x86-64 and AArch64. */
export function flowOf(text: string): Flow {
  // prefixes that do not change control flow: CET notrack, MPX bnd, branch hints
  const t = text.trim().toLowerCase().replace(/\s+/g, " ").replace(/^(?:(?:notrack|bnd|ds|cs|rep|repz|repnz|lock) )+/, "");
  const sp = t.indexOf(" ");
  const mn = sp < 0 ? t : t.slice(0, sp);
  const op = sp < 0 ? "" : t.slice(sp + 1).split(";")[0].trim();
  const direct = /^(?:qword ptr |near |short )?\$?(0x[0-9a-f]+)(?: <[^>]*>)?$/.exec(op);
  const target = direct ? BigInt(direct[1]) : null;
  if (/^ret[qnfw]?$|^iret[dq]?$|^sysret|^retf/.test(mn)) return { kind: "ret", target: null };
  const a64 = a64FlowOf(mn, op);
  if (a64) return a64;
  if (mn === "int3" || mn === "hlt" || mn === "ud2" || mn === "ud1" || mn === "int" && op === "0x29") return { kind: "stop", target: null };
  if (/^jmp[qw]?$/.test(mn)) return target !== null ? { kind: "jmp", target } : { kind: "indirect-jmp", target: null };
  if (/^call[qw]?$/.test(mn)) return { kind: "call", target };
  if (/^(j[a-z]+|loop[a-z]*|jrcxz|jecxz)$/.test(mn) && mn !== "jmp") return { kind: "jcc", target };
  return { kind: "none", target: null };
}

export type Decoder = (address: bigint) => Promise<CfgLine[]>;

/**
 * Builds the CFG starting at `entry`. `decode(a)` returns a run of instructions starting at `a`
 * (any length; the builder asks again where it needs more). `switchTargets` may resolve an
 * indirect jump to its case targets.
 */
export async function buildCfg(
  entry: bigint,
  decode: Decoder,
  opts: { maxInsns?: number; switchTargets?: (lines: CfgLine[], at: number) => bigint[] | null; bounds?: { lo: bigint; hi: bigint } } = {},
): Promise<Cfg> {
  const maxInsns = opts.maxInsns ?? 20000;
  const insns = new Map<bigint, CfgLine>();
  const order: bigint[] = [];
  const leaders = new Set<bigint>([entry]);
  const work: bigint[] = [entry];
  const caseEdges = new Map<bigint, bigint[]>();
  let truncated = false;
  const inBounds = (a: bigint) => !opts.bounds || (a >= opts.bounds.lo && a < opts.bounds.hi);

  // 1. discover every reachable instruction
  while (work.length) {
    let a = work.pop()!;
    if (insns.has(a)) continue;
    let run = await decode(a);
    let i = 0;
    const local: CfgLine[] = [];
    for (;;) {
      if (insns.size >= maxInsns) {
        truncated = true;
        break;
      }
      if (i >= run.length) {
        run = await decode(a);
        i = 0;
        if (!run.length) break;
      }
      const l = run[i++];
      const la = BigInt(l.address);
      if (la !== a) break; // decoder desync
      if (insns.has(la)) break;
      insns.set(la, l);
      order.push(la);
      local.push(l);
      const f = flowOf(l.text);
      const next = la + BigInt(l.length);
      if (f.kind === "ret" || f.kind === "stop") break;
      if (f.kind === "jmp") {
        if (f.target !== null && inBounds(f.target)) {
          leaders.add(f.target);
          work.push(f.target);
        }
        break;
      }
      if (f.kind === "indirect-jmp") {
        const cases = opts.switchTargets?.(local, local.length - 1) ?? null;
        if (cases?.length) {
          caseEdges.set(la, cases);
          for (const c of cases) {
            leaders.add(c);
            work.push(c);
          }
        }
        break;
      }
      if (f.kind === "jcc") {
        if (f.target !== null && inBounds(f.target)) {
          leaders.add(f.target);
          work.push(f.target);
        }
        leaders.add(next);
      }
      a = next;
    }
  }

  // 2. cut into blocks
  const sorted = [...order].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  const blocks: Block[] = [];
  let cur: Block | null = null;
  for (const a of sorted) {
    const l = insns.get(a)!;
    const contiguous = cur && cur.end === a;
    if (!cur || leaders.has(a) || !contiguous) {
      if (cur) blocks.push(cur);
      cur = { start: a, end: a, lines: [], terminator: "fall" };
    }
    cur.lines.push(l);
    cur.end = a + BigInt(l.length);
    const f = flowOf(l.text);
    if (f.kind === "ret" || f.kind === "jmp" || f.kind === "jcc" || f.kind === "indirect-jmp" || f.kind === "stop") {
      cur.terminator = f.kind === "indirect-jmp" ? "indirect" : f.kind;
      blocks.push(cur);
      cur = null;
    }
  }
  if (cur) blocks.push(cur);

  // 3. edges
  const starts = new Set(blocks.map((b) => b.start));
  const edges: CfgEdge[] = [];
  for (const b of blocks) {
    const last = b.lines[b.lines.length - 1];
    const f = flowOf(last.text);
    if (b.terminator === "jcc") {
      if (f.target !== null && starts.has(f.target)) edges.push({ from: b.start, to: f.target, kind: "taken" });
      if (starts.has(b.end)) edges.push({ from: b.start, to: b.end, kind: "fallthrough" });
    } else if (b.terminator === "jmp") {
      if (f.target !== null && starts.has(f.target)) edges.push({ from: b.start, to: f.target, kind: "jump" });
    } else if (b.terminator === "indirect") {
      const cases = caseEdges.get(BigInt(last.address)) ?? [];
      cases.forEach((c, i) => starts.has(c) && edges.push({ from: b.start, to: c, kind: "case", label: String(i) }));
    } else if (b.terminator === "fall" && starts.has(b.end)) {
      edges.push({ from: b.start, to: b.end, kind: "fallthrough" });
    }
  }
  // dedupe case edges that share a target
  const seen = new Set<string>();
  const unique = edges.filter((e) => {
    const k = `${e.from}>${e.to}>${e.kind}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return { entry, blocks, edges: unique, truncated, switches: caseEdges };
}

/**
 * Layered layout: blocks get a layer by longest path from the entry over forward edges (back
 * edges of loops are ignored), then are spread horizontally inside their layer.
 */
export function layoutCfg(cfg: Cfg, blockHeight: (b: Block) => number, width = 300, gapX = 40, gapY = 50): Map<bigint, { x: number; y: number; w: number; h: number }> {
  const index = new Map(cfg.blocks.map((b, i) => [b.start, i]));
  const layer = new Map<bigint, number>([[cfg.entry, 0]]);
  // DFS order for back-edge detection
  const state = new Map<bigint, number>();
  const back = new Set<string>();
  const out = new Map<bigint, CfgEdge[]>();
  for (const e of cfg.edges) out.set(e.from, [...(out.get(e.from) ?? []), e]);
  const dfs = (n: bigint) => {
    state.set(n, 1);
    for (const e of out.get(n) ?? []) {
      const s = state.get(e.to) ?? 0;
      if (s === 1) back.add(`${e.from}>${e.to}`);
      else if (s === 0) dfs(e.to);
    }
    state.set(n, 2);
  };
  if (index.has(cfg.entry)) dfs(cfg.entry);
  // longest path over forward edges (Kahn)
  const indeg = new Map<bigint, number>();
  for (const b of cfg.blocks) indeg.set(b.start, 0);
  const fwd = cfg.edges.filter((e) => !back.has(`${e.from}>${e.to}`));
  for (const e of fwd) indeg.set(e.to, (indeg.get(e.to) ?? 0) + 1);
  const q = cfg.blocks.filter((b) => (indeg.get(b.start) ?? 0) === 0).map((b) => b.start);
  for (const s of q) if (!layer.has(s)) layer.set(s, 0);
  while (q.length) {
    const n = q.shift()!;
    for (const e of fwd.filter((x) => x.from === n)) {
      layer.set(e.to, Math.max(layer.get(e.to) ?? 0, (layer.get(n) ?? 0) + 1));
      indeg.set(e.to, (indeg.get(e.to) ?? 1) - 1);
      if (indeg.get(e.to) === 0) q.push(e.to);
    }
  }
  const rows = new Map<number, Block[]>();
  for (const b of cfg.blocks) {
    const l = layer.get(b.start) ?? 0;
    rows.set(l, [...(rows.get(l) ?? []), b]);
  }
  const pos = new Map<bigint, { x: number; y: number; w: number; h: number }>();
  let y = 0;
  const maxCols = Math.max(1, ...[...rows.values()].map((r) => r.length));
  for (const l of [...rows.keys()].sort((a, b) => a - b)) {
    const row = rows.get(l)!.sort((a, b) => (a.start < b.start ? -1 : 1));
    const h = Math.max(...row.map(blockHeight));
    const offset = ((maxCols - row.length) * (width + gapX)) / 2;
    row.forEach((b, i) => pos.set(b.start, { x: offset + i * (width + gapX), y, w: width, h: blockHeight(b) }));
    y += h + gapY;
  }
  return pos;
}
