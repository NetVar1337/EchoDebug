// YARA over live process memory (#18): scan every committed region with the same YARA engine used
// for files (analysis/yara.ts), streaming region by region with a cross-boundary overlap so matches
// that straddle a chunk edge are still found. Matches are reported with absolute addresses.
import { parseYara, scanYara, type YaraMatch, type YaraRule } from "./analysis/yara";
import { readChunked, type ChunkedRead } from "./chunkread";

export type Region = { base: string; size: number };

export type MemoryMatch = YaraMatch & { address: string };

export type ScanMemoryOpts = {
  read?: (addr: bigint, size: number) => Promise<Uint8Array>;
  regions?: Region[];
  chunkBytes?: number;
  maxBytesPerRegion?: number;
  maxMatches?: number;
  onProgress?: (regionsDone: number, regionsTotal: number) => void;
  onMatch?: (m: MemoryMatch) => void;
  signal?: { aborted: boolean };
};

type ReadFn = (addr: bigint, size: number) => Promise<Uint8Array>;

/** Longest string in the rule set — the overlap needed so no match straddles a chunk edge. */
export function maxStringLen(rules: readonly YaraRule[]): number {
  let m = 0;
  for (const r of rules) {
    for (const s of r.strings) {
      // text: exact; hex: source is hex chars (2 per byte); regex: unbounded, use a sane cap
      const len = s.kind === "text" ? s.source.length : s.kind === "hex" ? s.source.length / 2 : 256;
      m = Math.max(m, len);
    }
  }
  return m;
}

/** Scan one buffer in chunks with overlap; `base` is the absolute address of buf[0]. */
export function scanBuffer(rules: readonly YaraRule[], buf: Uint8Array, base: bigint, chunkBytes: number, overlap: number, onMatch?: (m: MemoryMatch) => void): MemoryMatch[] {
  const out: MemoryMatch[] = [];
  const seen = new Set<string>();
  const step = Math.max(1, chunkBytes - overlap);
  for (let off = 0; off < buf.length; off += step) {
    const end = Math.min(buf.length, off + chunkBytes);
    const matches = scanYara(rules, buf.subarray(off, end));
    for (const m of matches) {
      // a string match's absolute address; rule-level dedup by first string offset
      const at = base + BigInt(off + (m.strings[0]?.offset ?? 0));
      const key = `${m.rule}@${at}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const mm = { ...m, address: `0x${at.toString(16)}` };
      out.push(mm);
      onMatch?.(mm);
    }
    if (end >= buf.length) break;
  }
  return out;
}

/** Default region list: the relay's `regions` verb (present, committed regions only). */
export async function liveRegions(request: (t: string, f?: Record<string, unknown>) => Promise<unknown>): Promise<Region[]> {
  const r = (await request("regions", { max: 200000 }).catch(() => null)) as { regions?: { base: string; size: number; present?: boolean }[] } | null;
  return (r?.regions ?? []).filter((x) => x.present !== false).map((x) => ({ base: x.base, size: x.size }));
}

/** Scans all (or the given) live regions. Reads go through readChunked, so the 8 MiB cap applies. */
export async function yaraScanMemory(rulesSrc: string | readonly YaraRule[], opts: ScanMemoryOpts = {}): Promise<{ matches: MemoryMatch[]; regions: number; truncated: boolean }> {
  const rules = typeof rulesSrc === "string" ? parseYara(rulesSrc) : rulesSrc;
  const read: ReadFn = opts.read ?? (await import("./chunkread")).relayRead;
  const regions = opts.regions ?? (await liveRegions((t, f) => import("./client").then((c) => c.request(t, f ?? {}))));
  const chunkBytes = opts.chunkBytes ?? 1024 * 1024;
  const overlap = Math.min(maxStringLen(rules), chunkBytes - 1);
  const maxMatches = opts.maxMatches ?? 10000;
  const matches: MemoryMatch[] = [];
  let truncated = false;
  for (let i = 0; i < regions.length; i++) {
    if (opts.signal?.aborted) break;
    const r = regions[i];
    const base = BigInt(r.base);
    const size = Math.min(r.size, opts.maxBytesPerRegion ?? r.size);
    const cr: ChunkedRead = await readChunked(read, base, size, { chunk: chunkBytes, onProgress: undefined, signal: opts.signal });
    if (cr.truncated) truncated = true;
    const found = scanBuffer(rules, cr.bytes, base, chunkBytes, overlap, (m) => {
      if (matches.length < maxMatches) matches.push(m);
      opts.onMatch?.(m);
    });
    for (const m of found) if (matches.length < maxMatches && !matches.includes(m)) matches.push(m);
    opts.onProgress?.(i + 1, regions.length);
  }
  return { matches, regions: regions.length, truncated };
}
