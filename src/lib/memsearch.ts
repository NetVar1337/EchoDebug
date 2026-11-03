// Search process memory from an address, forward or backward, region by region.
import { request } from "./client";
import { readBytes } from "./memory";
import { findIn, type Needle } from "./analysis/bytes";

type Region = { base: string; size: number; present: boolean };
const kChunk = 0x100000;

async function regions(): Promise<{ lo: bigint; hi: bigint }[]> {
  const r = await request<{ regions: Region[] }>("regions", { max: 200000 }, true).catch(() => null);
  return (r?.regions ?? []).filter((x) => x.present !== false).map((x) => ({ lo: BigInt(x.base), hi: BigInt(x.base) + BigInt(x.size) })).sort((a, b) => (a.lo < b.lo ? -1 : 1));
}

/**
 * First match strictly after `from` (dir 1) or strictly before it (dir -1). Scans at most
 * `maxBytes`; `onProgress` gets the bytes scanned so far. Returns null when nothing matches.
 */
export async function searchMemory(from: bigint, n: Needle, dir: 1 | -1, opts: { maxBytes?: number; onProgress?: (done: number) => void; signal?: { aborted: boolean } } = {}): Promise<bigint | null> {
  const max = BigInt(opts.maxBytes ?? 512 * 1024 * 1024);
  const len = BigInt(n.bytes.length);
  let list = await regions();
  if (!list.length) list = [{ lo: from - (dir === -1 ? max : 0n), hi: from + (dir === 1 ? max : 0n) }];
  let done = 0n;
  if (dir === 1) {
    for (const r of list) {
      if (r.hi <= from + 1n) continue;
      let a = r.lo > from + 1n ? r.lo : from + 1n;
      while (a < r.hi && done < max && !opts.signal?.aborted) {
        const size = Number(r.hi - a < BigInt(kChunk) ? r.hi - a : BigInt(kChunk));
        const buf = await readBytes(a, size).catch(() => null);
        if (buf) {
          const i = findIn(buf, n, 0, 1);
          if (i >= 0) return a + BigInt(i);
        }
        const step = BigInt(size) - (len - 1n > 0n ? len - 1n : 0n);
        a += step > 0n ? step : BigInt(size);
        done += BigInt(size);
        opts.onProgress?.(Number(done));
      }
    }
  } else {
    for (const r of [...list].reverse()) {
      if (r.lo >= from) continue;
      let hi = r.hi < from ? r.hi : from; // exclusive: matches must start before `from`
      while (hi > r.lo && done < max && !opts.signal?.aborted) {
        const lo = hi - BigInt(kChunk) > r.lo ? hi - BigInt(kChunk) : r.lo;
        const end = hi + len - 1n < r.hi ? hi + len - 1n : r.hi; // allow a match that straddles hi
        const buf = await readBytes(lo, Number(end - lo)).catch(() => null);
        if (buf) {
          const i = findIn(buf, n, Number(hi - lo) - 1, -1);
          if (i >= 0) return lo + BigInt(i);
        }
        done += hi - lo;
        hi = lo;
        opts.onProgress?.(Number(done));
      }
    }
  }
  return null;
}
