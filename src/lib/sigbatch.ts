// Many IDA patterns in as few round trips as possible: sig_scan_batch (agent / local backend),
// falling back to one sig_scan_ida per pattern for older agents.
import { request } from "./client";

export type BatchHit = { count: number; results: string[] };

export async function scanMany(patterns: string[], module: string, maxHits = 16): Promise<BatchHit[]> {
  const out: BatchHit[] = [];
  for (let i = 0; i < patterns.length; i += 512) {
    const chunk = patterns.slice(i, i + 512);
    const r = await request<{ results: BatchHit[] }>("sig_scan_batch", { patterns: chunk, module, max_hits: maxHits }, true).catch(() => null);
    if (r?.results?.length === chunk.length) {
      out.push(...r.results);
      continue;
    }
    for (const p of chunk) {
      const one = await request<{ results: string[]; success: boolean }>("sig_scan_ida", { pattern: p, module, find_all: true }, true).catch(() => null);
      const hits = one?.success ? one.results ?? [] : [];
      out.push({ count: hits.length, results: hits.slice(0, maxHits) });
    }
  }
  return out;
}

/** scanMany over patterns that may target different modules. */
export async function scanGrouped<T extends { ida: string; module: string }>(items: T[], maxHits = 16): Promise<BatchHit[]> {
  const byMod = new Map<string, number[]>();
  items.forEach((s, i) => byMod.set(s.module, [...(byMod.get(s.module) ?? []), i]));
  const out: BatchHit[] = new Array(items.length);
  for (const [mod, idx] of byMod) {
    const r = await scanMany(idx.map((i) => items[i].ida), mod, maxHits);
    idx.forEach((i, k) => (out[i] = r[k]));
  }
  return out;
}
