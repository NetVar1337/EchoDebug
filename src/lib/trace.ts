// Time-travel traces (record & replay): request helpers for the relay's trace_* verbs and the
// pure pieces of the Trace view (hex rows, sparkline geometry, the dataflow tree, base64).
import { request } from "./client";

export type TraceSummary = {
  trace_id: string;
  name: string;
  source: string;
  created_ms: number;
  steps: number;
  stop_reason: string;
  truncated?: boolean;
  keyframe?: number;
  unique_pcs?: number;
  accesses?: number;
  writes?: number;
  pid?: number | null;
  tid?: number | null;
  file_size?: number;
  unsaved?: boolean;
  initial_regs?: Record<string, string>;
  final_regs?: Record<string, string>;
};

export type StepLine = { step: number; pc: string; text: string; changes: Record<string, string>; reads: number; writes: number };
export type Access = { kind: "read" | "write"; address: string; size: number; data?: string; old?: string; new?: string };
export type StepDetail = StepLine & { bytes: string; accesses: Access[]; regs_before: Record<string, string> };
export type WriteHit = { step: number; pc: string; address: string; size: number; old: string; new: string; text?: string };
export type TaintHop = {
  id: number;
  parent: number | null;
  step: number | null;
  pc?: string;
  text?: string;
  loc: { kind: "reg"; reg: string } | { kind: "mem"; address: string; size: number };
  value: string;
  kind: "mov" | "arith" | "const" | "initial" | "unmodeled";
  sources?: TaintHop["loc"][];
};

export const kTraceRegs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "fs_base", "gs_base"];

export function traceQuery<T>(trace: string | null, kind: string, args: Record<string, unknown> = {}): Promise<T> {
  return request<T>("trace_query", { kind, ...(trace ? { trace } : {}), ...args });
}

/** "a1??ff" → [0xa1, null, 0xff] */
export function parseKnown(hex: string): (number | null)[] {
  const out: (number | null)[] = [];
  for (let i = 0; i + 1 < hex.length; i += 2) {
    const p = hex.slice(i, i + 2);
    out.push(p === "??" ? null : parseInt(p, 16));
  }
  return out;
}

/** Rows of `width` bytes for a hex view starting at `base`. */
export function hexRows(base: bigint, hex: string, width = 16): { address: bigint; bytes: (number | null)[] }[] {
  const b = parseKnown(hex);
  const rows: { address: bigint; bytes: (number | null)[] }[] = [];
  for (let i = 0; i < b.length; i += width) rows.push({ address: base + BigInt(i), bytes: b.slice(i, i + width) });
  return rows;
}

/** Offsets in base..base+len that `step` wrote. */
export function writtenBy(step: Pick<StepDetail, "accesses"> | null, base: bigint, len: number): Set<number> {
  const out = new Set<number>();
  if (!step) return out;
  for (const a of step.accesses) {
    if (a.kind !== "write") continue;
    const lo = BigInt(a.address);
    for (let i = 0; i < a.size; i++) {
      const off = Number(lo + BigInt(i) - base);
      if (off >= 0 && off < len) out.add(off);
    }
  }
  return out;
}

/**
 * SVG path of a step function through (position, value) points, scaled into w×h. Values are
 * hex strings (64-bit), so the scale works in bigint.
 */
export function sparkline(points: [number, string][], w: number, h: number): { path: string; min: bigint; max: bigint } {
  if (!points.length) return { path: "", min: 0n, max: 0n };
  const vals = points.map(([, v]) => BigInt(v));
  let min = vals[0];
  let max = vals[0];
  for (const v of vals) {
    if (v < min) min = v;
    if (v > max) max = v;
  }
  const x0 = points[0][0];
  const span = Math.max(1, points[points.length - 1][0] - x0);
  const range = max - min;
  const y = (v: bigint) => (range === 0n ? h / 2 : h - Number(((v - min) * 1000n) / range) / 1000 * h);
  const x = (p: number) => ((p - x0) / span) * w;
  let d = `M${x(points[0][0]).toFixed(1)},${y(vals[0]).toFixed(1)}`;
  for (let i = 1; i < points.length; i++) {
    d += ` H${x(points[i][0]).toFixed(1)} V${y(vals[i]).toFixed(1)}`;
  }
  return { path: d, min, max };
}

/** Taint hops as an indented list (depth-first, children after their parent). */
export function taintTree(hops: TaintHop[]): { hop: TaintHop; depth: number }[] {
  const kids = new Map<number | null, TaintHop[]>();
  for (const h of hops) kids.set(h.parent, [...(kids.get(h.parent) ?? []), h]);
  const out: { hop: TaintHop; depth: number }[] = [];
  const walk = (parent: number | null, depth: number) => {
    for (const h of kids.get(parent) ?? []) {
      out.push({ hop: h, depth });
      walk(h.id, depth + 1);
    }
  };
  walk(null, 0);
  return out;
}

export function locText(l: TaintHop["loc"]): string {
  return l.kind === "reg" ? l.reg : `[${l.address}]${l.size !== 8 ? `:${l.size}` : ""}`;
}

/** The nearest step among several seek results (forward: smallest, back: largest). */
export function nearestStep(steps: (number | null | undefined)[], forward: boolean): number | null {
  const s = steps.filter((x): x is number => typeof x === "number");
  if (!s.length) return null;
  return forward ? Math.min(...s) : Math.max(...s);
}

export function bytesToB64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

export function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
