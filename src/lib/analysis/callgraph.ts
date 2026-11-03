// Call graph built from Echo's own disassembly: the backend resolves branch
// targets, so the edges are exact rather than a byte-pattern guess.
import type { Line } from "@/components/views/DisassemblyView";

export type GraphNode = {
  address: string;
  label: string;
  kind: "function" | "unknown";
  depth: number;
};

export type GraphEdge = {
  from: string;
  to: string;
  kind: "call" | "jmp" | "jcc";
};

export type CallGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** function addresses that were visited, in visit order */
  visited: string[];
};

/** `call 0x7ff600012340` / `jmp 0x401000` / `je 0x401005` -> the hex target, if any. */
export function branchTarget(text: string): { target: string; kind: GraphEdge["kind"] } | null {
  const t = text.trim().toLowerCase();
  const m = /^([a-z]+)\s+(0x[0-9a-f]+)$/.exec(t);
  if (!m) return null;
  if (m[1] === "call") return { target: m[2], kind: "call" };
  if (m[1] === "jmp") return { target: m[2], kind: "jmp" };
  if (m[1].startsWith("j")) return { target: m[2], kind: "jcc" };
  return null;
}

/**
 * Collects the direct call targets of one function's listing.
 * Indirect calls (through a register or a pointer) have no static target and
 * are skipped.
 */
export function calleesOf(lines: readonly Line[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const l of lines) {
    const b = branchTarget(l.text);
    if (!b || b.kind !== "call") continue;
    if (seen.has(b.target)) continue;
    seen.add(b.target);
    out.push(b.target);
  }
  return out;
}

/** Adds a node and its edges to the graph, keeping both deduplicated. */
export function addNode(g: CallGraph, address: string, label: string, kind: GraphNode["kind"], depth: number): void {
  if (!g.nodes.some((n) => n.address === address)) g.nodes.push({ address, label, kind, depth });
}

export function addEdge(g: CallGraph, from: string, to: string, kind: GraphEdge["kind"]): void {
  if (!g.edges.some((e) => e.from === from && e.to === to && e.kind === kind)) g.edges.push({ from, to, kind });
}

/** Lays the graph out in columns by depth: column 0 is the root. */
export function layout(g: CallGraph): Map<string, { x: number; y: number }> {
  const byDepth = new Map<number, GraphNode[]>();
  for (const n of g.nodes) {
    const list = byDepth.get(n.depth) ?? [];
    list.push(n);
    byDepth.set(n.depth, list);
  }
  const pos = new Map<string, { x: number; y: number }>();
  const depths = [...byDepth.keys()].sort((a, b) => a - b);
  for (const d of depths) {
    const list = byDepth.get(d)!;
    list.sort((a, b) => a.address.localeCompare(b.address));
    list.forEach((n, i) => pos.set(n.address, { x: d * 190, y: i * 26 }));
  }
  return pos;
}
