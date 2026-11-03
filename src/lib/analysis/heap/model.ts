// Common shapes for every heap implementation (glibc malloc, NT heap, segment heap) plus the
// pure helpers the view and the MCP tools share: stats, filters, histogram, address lookup and the
// "who points here" pointer scan.

export type ChunkState =
  | "in-use" | "free" | "top" | "mmapped" | "fencepost"
  // glibc bins
  | "tcache" | "fastbin" | "unsorted" | "smallbin" | "largebin"
  // Windows
  | "lfh" | "large" | "internal";

export type HeapChunk = {
  /** chunk / block header address */
  address: bigint;
  /** first byte handed to the program */
  user: bigint;
  /** whole chunk size in bytes, header included */
  size: number;
  /** usable bytes (requested size where the allocator records it) */
  userSize: number;
  state: ChunkState;
  /** allocator flags as text, e.g. "P" (PREV_INUSE), "M" (mmapped), "busy|extra" */
  flags: string;
  /** id of the heap it belongs to (HeapInfo.id) */
  heap: string;
  /** bin or list that holds the chunk, e.g. "tcache[3]", "fastbin[1]", "lfh 0x30" */
  bin?: string;
  /** first bytes of the user data, when they were read */
  preview?: Uint8Array;
  /** extra detail, e.g. LFH subsegment occupancy */
  note?: string;
};

export type HeapInfo = {
  id: string;
  /** "glibc arena", "NT heap", "segment heap" */
  kind: string;
  address: bigint;
  label: string;
  /** bytes the heap has committed (walked range for glibc) */
  committed: number;
  reserved?: number;
  /** allocator-reported counters (system_mem, TotalFreeSize, MemStats, …) */
  counters: Record<string, number | string>;
  /** memory ranges the heap owns (segments, glibc heaps) */
  ranges: { base: bigint; size: number; label: string }[];
  notes: string[];
};

export type BinList = {
  heap: string;
  kind: "tcache" | "fastbin" | "unsorted" | "smallbin" | "largebin" | "lfh";
  index: number;
  /** chunk size the bin holds (exact for tcache/fastbins/smallbins, lower bound for large bins) */
  chunkSize: number;
  /** chunk header addresses in list order */
  entries: bigint[];
  /** allocator's own count (tcache counts, LFH busy blocks) */
  count?: number;
  /** blocks in the bucket (LFH) */
  total?: number;
  /** owner of the list (tcache_perthread_struct, LFH subsegment) */
  owner?: bigint;
  error?: string;
};

export type HeapError = { heap: string; address: bigint; message: string };

export type HeapReport = {
  platform: "glibc" | "windows";
  /** how the heaps were located, e.g. "main_arena from the symbol table", "PEB->ProcessHeaps" */
  source: string;
  version?: string;
  heaps: HeapInfo[];
  /** sorted by address */
  chunks: HeapChunk[];
  bins: BinList[];
  /** corrupted chunks / lists: where the walk stopped and why */
  errors: HeapError[];
  notes: string[];
  truncated: boolean;
};

export type HeapStats = {
  chunks: number;
  committed: number;
  inUse: number;
  inUseCount: number;
  free: number;
  freeCount: number;
  largestFree: number;
  /** 1 - largest free / total free (0 = one free block, → 1 = many small holes) */
  fragmentation: number;
};

const kFreeStates: ReadonlySet<ChunkState> = new Set(["free", "tcache", "fastbin", "unsorted", "smallbin", "largebin"]);
export const isFree = (s: ChunkState): boolean => kFreeStates.has(s);
export const isInUse = (s: ChunkState): boolean => s === "in-use" || s === "mmapped" || s === "large" || s === "lfh" || s === "internal";

export function heapStats(r: HeapReport, heap?: string): HeapStats {
  const list = heap ? r.chunks.filter((c) => c.heap === heap) : r.chunks;
  const committed = (heap ? r.heaps.filter((h) => h.id === heap) : r.heaps).reduce((a, h) => a + h.committed, 0);
  let inUse = 0, inUseCount = 0, free = 0, freeCount = 0, largestFree = 0;
  for (const c of list) {
    if (isInUse(c.state)) {
      inUse += c.size;
      inUseCount++;
    } else if (isFree(c.state)) {
      free += c.size;
      freeCount++;
      if (c.size > largestFree) largestFree = c.size;
    }
  }
  return { chunks: list.length, committed, inUse, inUseCount, free, freeCount, largestFree, fragmentation: free ? 1 - largestFree / free : 0 };
}

export type ChunkFilter = { heap?: string; state?: string; minSize?: number; maxSize?: number; text?: string };

/** state: a ChunkState, "free" (every free kind) or "used" (every in-use kind). */
export function filterChunks(chunks: readonly HeapChunk[], f: ChunkFilter, typeOf?: (c: HeapChunk) => string | undefined): HeapChunk[] {
  const t = f.text?.trim().toLowerCase() ?? "";
  return chunks.filter((c) => {
    if (f.heap && c.heap !== f.heap) return false;
    if (f.state && f.state !== "all") {
      if (f.state === "free" ? !isFree(c.state) : f.state === "used" ? !isInUse(c.state) : c.state !== f.state) return false;
    }
    if (f.minSize !== undefined && c.size < f.minSize) return false;
    if (f.maxSize !== undefined && c.size > f.maxSize) return false;
    if (t) {
      const hay = `0x${c.address.toString(16)} 0x${c.user.toString(16)} ${c.bin ?? ""} ${typeOf?.(c) ?? ""}`.toLowerCase();
      if (!hay.includes(t)) return false;
    }
    return true;
  });
}

/** The chunk whose [address, address+size) holds `a` (chunks sorted by address). */
export function findChunk(chunks: readonly HeapChunk[], a: bigint): HeapChunk | null {
  let lo = 0, hi = chunks.length - 1, best = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (chunks[mid].address <= a) {
      best = mid;
      lo = mid + 1;
    } else hi = mid - 1;
  }
  // overlapping entries (an LFH subsegment and its backend block) resolve to the innermost one
  for (let i = best; i >= 0 && i >= best - 4; i--) {
    const c = chunks[i];
    if (a >= c.address && a < c.address + BigInt(c.size)) return c;
  }
  return null;
}

export type HistBucket = { lo: number; hi: number; count: number; bytes: number };

/** Power-of-two size buckets from 16 bytes up to `top`, the last one open-ended. */
export function sizeHistogram(chunks: readonly HeapChunk[], top = 1 << 20): HistBucket[] {
  const out: HistBucket[] = [];
  for (let lo = 16; lo < top; lo *= 2) out.push({ lo, hi: lo * 2, count: 0, bytes: 0 });
  out.push({ lo: top, hi: Infinity, count: 0, bytes: 0 });
  for (const c of chunks) {
    const i = c.size < 32 ? 0 : Math.min(out.length - 1, Math.floor(Math.log2(c.size)) - 4);
    out[i].count++;
    out[i].bytes += c.size;
  }
  return out;
}

/**
 * Every 8-aligned qword in `buf` (read at `base`) whose value lies in [lo, hi): the pointers into
 * a chunk. Returns the addresses of the qwords, at most `limit`.
 */
export function scanForPointers(buf: Uint8Array, base: bigint, lo: bigint, hi: bigint, limit = 1000): bigint[] {
  const out: bigint[] = [];
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const skew = Number((8n - (base & 7n)) & 7n);
  // compare the high and low dwords separately: much faster than building a BigInt per qword
  const loHi = Number(lo >> 32n), loLo = Number(lo & 0xffffffffn);
  const hiHi = Number((hi - 1n) >> 32n), hiLo = Number((hi - 1n) & 0xffffffffn);
  for (let o = skew; o + 8 <= buf.length && out.length < limit; o += 8) {
    const h = dv.getUint32(o + 4, true);
    if (h < loHi || h > hiHi) continue;
    const l = dv.getUint32(o, true);
    if ((h === loHi && l < loLo) || (h === hiHi && l > hiLo)) continue;
    out.push(base + BigInt(o));
  }
  return out;
}

export const hex = (a: bigint | number): string => `0x${a.toString(16)}`;
