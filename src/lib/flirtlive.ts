// Live module → FLIRT input: each function's bytes with relocated operands marked variable,
// using the same operand wildcarding as the sigmaker.
import { request } from "./client";
import { fmtAddr, hexToBytes, toBig, type Module } from "./hex";
import { pdataFunctions } from "./live";
import { insnPattern } from "./analysis/sigmaker";
import type { GenFunction } from "./analysis/flirtgen";

export type LiveFunction = { address: string; size: number; name: string };

/** Echo's function list merged with .pdata starts. */
export async function moduleFunctions(m: Module): Promise<{ address: string; size: number }[]> {
  const [echo, pdata] = await Promise.all([
    request<{ results: { address: string; size: number }[] }>("enumerate_functions", { module: m.name }).then((r) => r.results).catch(() => []),
    pdataFunctions(m).catch(() => []),
  ]);
  const by = new Map<string, { address: string; size: number }>();
  for (const f of [...echo, ...pdata]) {
    const a = fmtAddr(toBig(f.address));
    const cur = by.get(a);
    by.set(a, { address: a, size: Math.max(cur?.size ?? 0, f.size) });
  }
  return [...by.values()].sort((a, b) => (toBig(a.address) < toBig(b.address) ? -1 : 1));
}

export async function genInput(fns: readonly LiveFunction[], onProgress?: (done: number) => void, signal?: { aborted: boolean }): Promise<GenFunction[]> {
  const out: GenFunction[] = [];
  let done = 0;
  for (const f of fns) {
    if (signal?.aborted) break;
    const size = Math.min(Math.max(f.size, 1), 0x4000);
    const r = await request<{ results: { address: string; length: number; bytes: string; text: string }[]; arch?: string }>("disassemble", { address: f.address, size }, true).catch(() => null);
    const lines = r?.results ?? [];
    if (lines.length) {
      const bytes = hexToBytes(lines.map((l) => l.bytes).join(""));
      const variable = lines.flatMap((l) => insnPattern(l.bytes, l.text, r?.arch).map((b) => b === null));
      out.push({ name: f.name, bytes, variable });
    }
    onProgress?.(++done);
  }
  return out;
}
