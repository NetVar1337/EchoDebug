// glibc malloc (ptmalloc2), x86-64: arenas, heaps, chunks and bins read from process memory.
//
// Finding main_arena:
//   1. the symbol, when the caller has it (`main_arena` is a local symbol: only unstripped libcs or
//      a separate debug file have it; the relay's `resolve_export` also searches .symtab);
//   2. otherwise a signature over libc's writable data: once malloc is initialised, every empty
//      bin of an arena points at itself (fd == bk == &bins[2*(i-1)] - 0x10). Each such pair votes
//      for the arena bases it can belong to; the winner must also close its `next` ring (the main
//      arena's `next` is itself, or a chain of thread arenas that leads back to it).
// Struct layouts are those of malloc/malloc.c and malloc/arena.c (glibc 2.26 to 2.40):
//   - malloc_state gained `have_fastchunks` in 2.27 (fastbinsY moves from +0x08 to +0x10);
//   - heap_info gained `pagesize` in 2.35 (0x20 → 0x30 bytes); we measure it from the first heap;
//   - tcache counts are u8 up to 2.29 (struct 0x240 bytes) and u16 from 2.30 (0x280 bytes);
//   - fastbin and tcache `next` pointers are safe-linked from 2.32 ((pos >> 12) ^ ptr); when the
//     version is unknown each pointer is decoded whichever way lands inside a heap.
// Per-thread tcaches are found as the tcache_perthread_struct chunk (the first allocation an
// arena hands a thread, validated by its counts/entries); which thread owns one is not knowable
// without the thread's TLS, so they are labelled by arena and address.

import { HeapMem, u64At } from "./reader";
import { hex, type BinList, type ChunkState, type HeapChunk, type HeapError, type HeapReport } from "./model";

export type GlibcVersion = { major: number; minor: number };
export type Region = { base: bigint; size: number; writable?: boolean };

export type GlibcEnv = {
  mem: HeapMem;
  /** the process's mapped regions (any order) */
  regions: Region[];
  /** the libc module (all of its mappings) */
  libc: { name: string; base: bigint; size: number };
  /** other modules: their writable data is never taken for an mmapped chunk */
  modules?: { base: bigint; size: number }[];
  version?: GlibcVersion | null;
  /** main_arena from symbols, when the caller found it */
  mainArena?: bigint | null;
  mainArenaSource?: string;
  /** cap on chunks over all heaps (default 1,000,000) */
  maxChunks?: number;
};

export type ArenaLayout = {
  name: string; fastbins: number; top: number; lastRemainder: number; bins: number;
  next: number; nextFree: number; attached: number; systemMem: number; maxSystemMem: number; size: number;
};

/** struct malloc_state, x86-64. */
export const kArenaLayouts: Record<"2.27+" | "2.26", ArenaLayout> = {
  "2.27+": { name: "2.27+", fastbins: 0x10, top: 0x60, lastRemainder: 0x68, bins: 0x70, next: 0x870, nextFree: 0x878, attached: 0x880, systemMem: 0x888, maxSystemMem: 0x890, size: 0x898 },
  "2.26": { name: "2.26", fastbins: 0x08, top: 0x58, lastRemainder: 0x60, bins: 0x68, next: 0x868, nextFree: 0x870, attached: 0x878, systemMem: 0x880, maxSystemMem: 0x888, size: 0x890 },
};

const NFASTBINS = 10;
const NBINS = 128;
const TCACHE_BINS = 64;
/** HEAP_MAX_SIZE on x86-64: 2 * DEFAULT_MMAP_THRESHOLD_MAX (32 MiB) */
export const HEAP_MAX = 0x4000000n;
const kListCap = 100_000;

/** "GNU C Library (…) stable release version 2.39." in libc's .rodata. */
export function glibcVersion(img: Uint8Array): GlibcVersion | null {
  const needle = "release version 2.";
  const n = Array.from(needle, (c) => c.charCodeAt(0));
  outer: for (let i = 0; i + n.length + 2 < img.length; i++) {
    for (let j = 0; j < n.length; j++) if (img[i + j] !== n[j]) continue outer;
    let k = i + n.length, minor = 0, digits = 0;
    while (img[k] >= 0x30 && img[k] <= 0x39 && digits < 3) minor = minor * 10 + (img[k++] - 0x30), digits++;
    if (digits) return { major: 2, minor };
  }
  return null;
}

export const atLeast = (v: GlibcVersion | null | undefined, minor: number): boolean | undefined => (v ? v.major > 2 || (v.major === 2 && v.minor >= minor) : undefined);

/** Bin index → smallest chunk size it holds (x86-64 smallbin_index / largebin_index_64). */
export function binChunkSize(b: number): number {
  if (b < 64) return b * 16;
  return kLargeLo[b] ?? 0;
}
const largebinIndex = (s: number): number =>
  s >> 6 <= 48 ? 48 + (s >> 6) : s >> 9 <= 20 ? 91 + (s >> 9) : s >> 12 <= 10 ? 110 + (s >> 12) : s >> 15 <= 4 ? 119 + (s >> 15) : s >> 18 <= 2 ? 124 + (s >> 18) : 126;
const kLargeLo: Record<number, number> = (() => {
  const t: Record<number, number> = {};
  for (let s = 0x400; s <= 0x100000; s += 16) {
    const i = largebinIndex(s);
    if (t[i] === undefined) t[i] = s;
  }
  return t;
})();

/** Bin index (1-based, as glibc numbers them) → state and display name. */
function binKind(b: number): { kind: "unsorted" | "smallbin" | "largebin"; name: string } {
  if (b === 1) return { kind: "unsorted", name: "unsorted" };
  if (b < 64) return { kind: "smallbin", name: `smallbin[${b}]` };
  return { kind: "largebin", name: `largebin[${b}]` };
}

// ---- locating main_arena ------------------------------------------------------------------------

export type ArenaGuess = { address: bigint; layout: ArenaLayout; votes: number };

/**
 * main_arena by the empty-bin signature over `ranges` (libc's writable mappings). Returns the
 * best candidate whose `next` ring closes, or null (malloc not initialised, or not glibc).
 */
export async function findMainArena(mem: HeapMem, ranges: Region[], version?: GlibcVersion | null): Promise<ArenaGuess | null> {
  const layouts = version ? [atLeast(version, 27) ? kArenaLayouts["2.27+"] : kArenaLayouts["2.26"]] : [kArenaLayouts["2.27+"], kArenaLayouts["2.26"]];
  const votes = new Map<string, number>(); // `${layout}:${base}`
  for (const r of ranges) {
    const end = r.base + BigInt(r.size);
    for (let a = r.base; a < end; a += 0x1000n) {
      const pg = await mem.bytes(a, Number(end - a < 0x1000n ? end - a : 0x1000n));
      if (!pg) continue;
      for (let o = 0; o + 16 <= pg.length; o += 8) {
        const p = a + BigInt(o);
        const v = u64At(pg, o);
        if (v !== p - 16n || u64At(pg, o + 8) !== v) continue;
        for (const L of layouts) {
          for (let k = 0; k < NBINS - 1; k++) {
            const base = p - BigInt(L.bins + 16 * k);
            const key = `${L.name}:${base}`;
            votes.set(key, (votes.get(key) ?? 0) + 1);
          }
        }
      }
    }
  }
  const ranked = [...votes].filter(([, n]) => n >= 16).sort((x, y) => y[1] - x[1]).slice(0, 16);
  for (const [key, n] of ranked) {
    const [name, b] = key.split(":");
    const layout = name === "2.26" ? kArenaLayouts["2.26"] : kArenaLayouts["2.27+"];
    const base = BigInt(b);
    if (await ringCloses(mem, base, layout)) return { address: base, layout, votes: n };
  }
  return null;
}

/** Follows arena->next up to 64 hops: true when it comes back to `base`. */
async function ringCloses(mem: HeapMem, base: bigint, L: ArenaLayout): Promise<boolean> {
  let a = base;
  for (let i = 0; i < 64; i++) {
    const n = await mem.u64(a + BigInt(L.next));
    if (n === null || n === 0n || n & 7n) return false;
    if (n === base) return true;
    a = n;
  }
  return false;
}

/** Layout of a known main_arena address: the one whose ring closes (prefers the version's). */
export async function layoutAt(mem: HeapMem, base: bigint, version?: GlibcVersion | null): Promise<ArenaLayout | null> {
  const order = atLeast(version, 27) === false ? [kArenaLayouts["2.26"], kArenaLayouts["2.27+"]] : [kArenaLayouts["2.27+"], kArenaLayouts["2.26"]];
  for (const L of order) if (await ringCloses(mem, base, L)) return L;
  return null;
}

// ---- arenas ---------------------------------------------------------------------------------------

export type Arena = {
  address: bigint;
  layout: ArenaLayout;
  main: boolean;
  top: bigint;
  lastRemainder: bigint;
  next: bigint;
  attached: bigint;
  systemMem: bigint;
  maxSystemMem: bigint;
  fastbins: bigint[];
  /** fd, bk of bins 1..127 */
  bins: [bigint, bigint][];
};

export async function readArena(mem: HeapMem, address: bigint, layout: ArenaLayout, main: boolean): Promise<Arena | null> {
  const b = await mem.bytes(address, layout.size);
  if (!b) return null;
  const q = (o: number) => u64At(b, o);
  return {
    address, layout, main,
    top: q(layout.top), lastRemainder: q(layout.lastRemainder), next: q(layout.next), attached: q(layout.attached),
    systemMem: q(layout.systemMem), maxSystemMem: q(layout.maxSystemMem),
    fastbins: Array.from({ length: NFASTBINS }, (_, i) => q(layout.fastbins + 8 * i)),
    bins: Array.from({ length: NBINS - 1 }, (_, i) => [q(layout.bins + 16 * i), q(layout.bins + 16 * i + 8)] as [bigint, bigint]),
  };
}

/** Address of bin `b`'s fake chunk header (bin_at). */
export const binHeader = (a: Arena, b: number): bigint => a.address + BigInt(a.layout.bins + (b - 1) * 16) - 16n;

/** A contiguous run of chunks: the main heap, or one heap_info heap of a thread arena. */
export type HeapRange = { base: bigint; start: bigint; end: bigint; label: string };

/** heap_info chain of a thread arena, top heap first (ar_ptr, prev, size, mprotect_size[, pagesize]). */
export async function threadHeaps(mem: HeapMem, a: Arena): Promise<{ heaps: HeapRange[]; error?: string }> {
  const heaps: HeapRange[] = [];
  let h = a.top & ~(HEAP_MAX - 1n);
  const seen = new Set<bigint>();
  const raw: { h: bigint; size: bigint }[] = [];
  while (h && raw.length < 4096) {
    if (seen.has(h)) return { heaps, error: `heap_info loop at ${hex(h)}` };
    seen.add(h);
    const hi = await mem.bytes(h, 0x20);
    if (!hi) return { heaps, error: `heap_info at ${hex(h)} is not readable` };
    if (u64At(hi, 0) !== a.address) return { heaps, error: `heap_info at ${hex(h)} belongs to ${hex(u64At(hi, 0))}, not this arena` };
    const size = u64At(hi, 0x10);
    if (size === 0n || size > HEAP_MAX) return { heaps, error: `heap_info at ${hex(h)} has a bad size ${hex(size)}` };
    raw.push({ h, size });
    h = u64At(hi, 8);
  }
  // sizeof(heap_info): the first heap holds the arena right behind it (0x20 before 2.35, 0x30 after)
  const first = raw.find((x) => a.address > x.h && a.address < x.h + x.size);
  const hiSize = first ? a.address - first.h : 0x20n;
  for (const x of raw) {
    const start = x === first ? alignChunk(a.address + BigInt(a.layout.size)) : x.h + hiSize;
    heaps.push({ base: x.h, start, end: x.h + x.size, label: `heap ${hex(x.h)}` });
  }
  return { heaps };
}

/** First chunk at or after p whose user pointer (p + 0x10) is 16-aligned. */
export const alignChunk = (p: bigint): bigint => (p + 15n) & ~15n;

// ---- chunk walk ---------------------------------------------------------------------------------------

export const flagText = (f: bigint): string => [f & 1n ? "P" : "", f & 2n ? "M" : "", f & 4n ? "A" : ""].join("") || "-";

/**
 * Walks chunks from `start` (a chunk header) to `end` by their size fields. Stops at the arena's top
 * chunk, at an end-of-heap fencepost, at the cap, or at the first corrupt header (recorded in
 * `errors`). The state comes from the next chunk's PREV_INUSE bit; bins refine it later.
 */
export async function walkChunks(mem: HeapMem, heap: string, start: bigint, end: bigint, top: bigint, out: HeapChunk[], errors: HeapError[], max: number): Promise<"done" | "error" | "cap"> {
  let p = start;
  while (p < end) {
    if (out.length >= max || mem.exhausted) return "cap";
    const hdr = await mem.bytes(p, 0x20);
    if (!hdr) {
      errors.push({ heap, address: p, message: "chunk header not readable" });
      return "error";
    }
    const field = u64At(hdr, 8);
    const size = field & ~7n;
    const flags = field & 7n;
    if (p === top) {
      if (p + size > end + 0x10n && size !== 0n) errors.push({ heap, address: p, message: `top size ${hex(size)} runs past the heap end ${hex(end)}` });
      out.push({ address: p, user: p + 16n, size: Number(size), userSize: Number(size), state: "top", flags: flagText(flags), heap, preview: hdr.slice(16, 32) });
      return "done";
    }
    if (size === 0n && p + 0x30n >= end) return "done"; // trailing fencepost of a thread heap
    if (size === 0x10n) {
      // fencepost pair left behind when a heap is extended non-contiguously
      out.push({ address: p, user: p + 16n, size: 16, userSize: 0, state: "fencepost", flags: flagText(flags), heap });
      p += 16n;
      continue;
    }
    if (size < 0x20n || size & 0xfn || p + size > end) {
      errors.push({ heap, address: p, message: `corrupt chunk: size field ${hex(field)}${p + size > end ? ` runs past ${hex(end)}` : ""}` });
      return "error";
    }
    const next = p + size === end ? null : await mem.u64(p + size + 8n);
    if (next === null && p + size !== end) {
      errors.push({ heap, address: p + size, message: "next chunk header not readable" });
      return "error";
    }
    const inUse = next === null ? true : (next & 1n) === 1n;
    out.push({ address: p, user: p + 16n, size: Number(size), userSize: Number(size) - 8, state: inUse ? "in-use" : "free", flags: flagText(flags), heap, preview: hdr.slice(16, 32) });
    p += size;
  }
  if (top && p !== end && top >= start && top < end) errors.push({ heap, address: p, message: `walk missed the top chunk ${hex(top)}` });
  return "done";
}

// ---- bins -----------------------------------------------------------------------------------------------

type LinkMode = "plain" | "safe" | "auto";

/** Decodes a singly-linked next pointer stored at `pos` (safe-linking from glibc 2.32). */
export function revealPtr(pos: bigint, v: bigint, mode: LinkMode, valid: (a: bigint) => boolean): bigint {
  if (mode === "plain") return v;
  const d = (pos >> 12n) ^ v;
  if (mode === "safe") return d;
  if (v === 0n || valid(v)) return v;
  return d === 0n || valid(d) ? d : v;
}

export async function fastbins(mem: HeapMem, a: Arena, heap: string, mode: LinkMode, inHeap: (x: bigint) => boolean): Promise<BinList[]> {
  const out: BinList[] = [];
  const valid = (x: bigint) => (x & 15n) === 0n && inHeap(x);
  for (let i = 0; i < NFASTBINS; i++) {
    const want = BigInt((i + 2) * 16);
    const list: BinList = { heap, kind: "fastbin", index: i, chunkSize: Number(want), entries: [] };
    const seen = new Set<bigint>();
    let c = a.fastbins[i];
    while (c) {
      if (list.entries.length >= kListCap) { list.error = "list too long"; break; }
      if (seen.has(c)) { list.error = `loop at ${hex(c)}`; break; }
      if (!valid(c)) { list.error = `bad pointer ${hex(c)}`; break; }
      const hdr = await mem.bytes(c, 0x18);
      if (!hdr) { list.error = `${hex(c)} not readable`; break; }
      if ((u64At(hdr, 8) & ~7n) !== want) { list.error = `${hex(c)} has size ${hex(u64At(hdr, 8) & ~7n)}, bin holds ${hex(want)}`; break; }
      seen.add(c);
      list.entries.push(c);
      c = revealPtr(c + 16n, u64At(hdr, 16), mode, valid);
    }
    if (list.entries.length || list.error) out.push(list);
  }
  return out;
}

/** Unsorted, small and large bins: circular doubly-linked lists through the arena's bin headers. */
export async function arenaBins(mem: HeapMem, a: Arena, heap: string): Promise<BinList[]> {
  const out: BinList[] = [];
  for (let b = 1; b < NBINS; b++) {
    const [fd] = a.bins[b - 1];
    const head = binHeader(a, b);
    if (fd === 0n || fd === head) continue;
    const k = binKind(b);
    const list: BinList = { heap, kind: k.kind, index: b, chunkSize: binChunkSize(b), entries: [] };
    const seen = new Set<bigint>();
    let prev = head, c = fd;
    while (c !== head) {
      if (list.entries.length >= kListCap) { list.error = "list too long"; break; }
      if (seen.has(c) || c & 15n) { list.error = seen.has(c) ? `loop at ${hex(c)}` : `bad pointer ${hex(c)}`; break; }
      const hdr = await mem.bytes(c, 0x20);
      if (!hdr) { list.error = `${hex(c)} not readable`; break; }
      if (u64At(hdr, 0x18) !== prev) { list.error = `${hex(c)}->bk is ${hex(u64At(hdr, 0x18))}, expected ${hex(prev)}`; break; }
      seen.add(c);
      list.entries.push(c);
      prev = c;
      c = u64At(hdr, 0x10);
    }
    out.push(list);
  }
  return out;
}

/** tcache_perthread_struct layout by chunk size: 0x290 (u16 counts, 2.30+) or 0x250 (u8 counts). */
export function tcacheLayout(chunkSize: number): { counts: 1 | 2; entries: number } | null {
  if (chunkSize === 0x290) return { counts: 2, entries: 0x80 };
  if (chunkSize === 0x250) return { counts: 1, entries: 0x40 };
  return null;
}

/**
 * Reads and validates a tcache_perthread_struct at the chunk `c` (counts[i] == 0 exactly when
 * entries[i] == NULL, entries inside a heap). An all-empty struct is accepted only when `first`.
 */
export async function readTcache(mem: HeapMem, c: HeapChunk, heap: string, mode: LinkMode, inHeap: (x: bigint) => boolean, first: boolean): Promise<BinList[] | null> {
  const L = tcacheLayout(c.size);
  if (!L) return null;
  const b = await mem.bytes(c.user, L.entries + 8 * TCACHE_BINS);
  if (!b) return null;
  const dv = new DataView(b.buffer);
  const counts = Array.from({ length: TCACHE_BINS }, (_, i) => (L.counts === 2 ? dv.getUint16(2 * i, true) : b[i]));
  const heads = Array.from({ length: TCACHE_BINS }, (_, i) => dv.getBigUint64(L.entries + 8 * i, true));
  let used = 0;
  for (let i = 0; i < TCACHE_BINS; i++) {
    if ((counts[i] === 0) !== (heads[i] === 0n)) return null;
    if (heads[i] && ((heads[i] & 15n) !== 0n || !inHeap(heads[i] - 16n))) return null;
    if (counts[i]) used++;
  }
  if (!used && !first) return null;
  const valid = (x: bigint) => (x & 15n) === 0n && inHeap(x - 16n);
  const out: BinList[] = [];
  for (let i = 0; i < TCACHE_BINS; i++) {
    if (!heads[i]) continue;
    const want = BigInt(0x20 + 16 * i);
    const list: BinList = { heap, kind: "tcache", index: i, chunkSize: Number(want), entries: [], count: counts[i], owner: c.address };
    const seen = new Set<bigint>();
    let e = heads[i];
    while (e) {
      if (list.entries.length >= Math.min(kListCap, counts[i] + 64)) { list.error = "longer than its count"; break; }
      if (seen.has(e)) { list.error = `loop at ${hex(e)}`; break; }
      if (!valid(e)) { list.error = `bad pointer ${hex(e)}`; break; }
      const hdr = await mem.bytes(e - 16n, 0x18);
      if (!hdr) { list.error = `${hex(e)} not readable`; break; }
      if ((u64At(hdr, 8) & ~7n) !== want) { list.error = `${hex(e - 16n)} has size ${hex(u64At(hdr, 8) & ~7n)}, bin holds ${hex(want)}`; break; }
      seen.add(e);
      list.entries.push(e - 16n);
      e = revealPtr(e, u64At(hdr, 16), mode, valid);
    }
    if (!list.error && list.entries.length !== counts[i]) list.error = `count says ${counts[i]}, list has ${list.entries.length}`;
    out.push(list);
  }
  // keep a marker for an empty tcache so the owner still shows up
  if (!out.length) out.push({ heap, kind: "tcache", index: -1, chunkSize: 0, entries: [], count: 0, owner: c.address });
  return out;
}

// ---- mmapped chunks ----------------------------------------------------------------------------------

/** IS_MMAPPED chunks at the start of anonymous writable regions (adjacent mmaps merge, so walk on). */
export async function mmappedChunks(mem: HeapMem, regions: Region[], skip: (a: bigint) => boolean, max: number): Promise<HeapChunk[]> {
  const out: HeapChunk[] = [];
  for (const r of regions) {
    if (!r.writable || r.size < 0x1000 || skip(r.base)) continue;
    const end = r.base + BigInt(r.size);
    let p = r.base;
    while (p < end && out.length < max) {
      const hdr = await mem.bytes(p, 0x20);
      if (!hdr) break;
      const prev = u64At(hdr, 0), field = u64At(hdr, 8), size = field & ~7n;
      if ((field & 7n) !== 2n || prev >= 0x1000n || size < 0x1000n || (size & 0xfffn) !== 0n || p + size > end) break;
      out.push({ address: p, user: p + 16n, size: Number(size), userSize: Number(size) - 16, state: "mmapped", flags: flagText(field & 7n), heap: "glibc:mmap", preview: hdr.slice(16, 32) });
      p += size;
    }
  }
  return out;
}

// ---- the whole explorer ---------------------------------------------------------------------------

const inRange = (rs: HeapRange[]) => (x: bigint) => rs.some((r) => x >= r.start && x < r.end);

export async function exploreGlibc(env: GlibcEnv): Promise<HeapReport> {
  const { mem } = env;
  const max = env.maxChunks ?? 1_000_000;
  const regions = [...env.regions].sort((a, b) => (a.base < b.base ? -1 : 1));
  const notes: string[] = [];
  const errors: HeapError[] = [];
  const version = env.version ?? null;
  const report: HeapReport = { platform: "glibc", source: "", version: version ? `${version.major}.${version.minor}` : undefined, heaps: [], chunks: [], bins: [], errors, notes, truncated: false };

  let mainAddr: bigint | null = null;
  let layout: ArenaLayout | null = null;
  if (env.mainArena) {
    layout = await layoutAt(mem, env.mainArena, version);
    if (layout) {
      mainAddr = env.mainArena;
      report.source = `main_arena ${hex(mainAddr)} from ${env.mainArenaSource ?? "symbols"}`;
    } else notes.push(`symbol main_arena ${hex(env.mainArena)} does not look like an arena; trying the signature`);
  }
  if (!mainAddr) {
    const libEnd = env.libc.base + BigInt(env.libc.size);
    const data = regions.filter((r) => r.writable !== false && r.base < libEnd && r.base + BigInt(r.size) > env.libc.base);
    const g = await findMainArena(mem, data, version);
    if (!g) {
      report.source = `main_arena not found in ${env.libc.name}`;
      notes.push("No arena signature in libc's writable data: malloc may not have run yet, or the C library is not glibc (musl, jemalloc and tcmalloc are not supported).");
      return report;
    }
    mainAddr = g.address;
    layout = g.layout;
    report.source = `main_arena ${hex(mainAddr)} by signature in ${env.libc.name} (empty-bin self-pointers, ${g.votes} votes, malloc_state ${g.layout.name} layout)`;
  }
  if (!layout) return report;

  const mode: LinkMode = atLeast(version, 32) === undefined ? "auto" : atLeast(version, 32) ? "safe" : "plain";
  const tcacheSizes = atLeast(version, 30) === undefined ? [0x290, 0x250] : atLeast(version, 30) ? [0x290] : atLeast(version, 26) ? [0x250] : [];

  // arenas: main_arena, then its next ring
  const arenas: Arena[] = [];
  for (let a: bigint = mainAddr, i = 0; i < 64; i++) {
    const ar = await readArena(mem, a, layout, a === mainAddr);
    if (!ar) {
      errors.push({ heap: `glibc:${hex(a)}`, address: a, message: "arena not readable" });
      break;
    }
    arenas.push(ar);
    if (ar.next === mainAddr || !ar.next) break;
    a = ar.next;
  }

  const ranges = new Map<bigint, HeapRange[]>();
  for (const ar of arenas) {
    const id = `glibc:${hex(ar.address)}`;
    let rs: HeapRange[] = [];
    if (ar.main) {
      if (ar.top) {
        const reg = regions.find((r) => ar.top >= r.base && ar.top < r.base + BigInt(r.size));
        const topSize = ((await mem.u64(ar.top + 8n)) ?? 0n) & ~7n;
        if (reg) rs = [{ base: reg.base, start: reg.base, end: ar.top + topSize, label: "main heap (brk)" }];
        else errors.push({ heap: id, address: ar.top, message: "top chunk is outside every mapped region" });
      } else notes.push("main_arena has no top chunk yet");
    } else {
      const th = await threadHeaps(mem, ar);
      rs = th.heaps;
      if (th.error) errors.push({ heap: id, address: ar.address, message: th.error });
    }
    ranges.set(ar.address, rs);
  }
  const allRanges = [...ranges.values()].flat();
  const inHeap = inRange(allRanges);

  for (const [n, ar] of arenas.entries()) {
    const id = `glibc:${hex(ar.address)}`;
    const rs = ranges.get(ar.address) ?? [];
    const before = report.chunks.length;
    for (const r of rs) {
      const st = await walkChunks(mem, id, r.start, r.end, ar.top, report.chunks, errors, max);
      if (st === "cap") report.truncated = true;
    }
    const mine = report.chunks.slice(before);
    // tcache_perthread_structs handed out by this arena
    const firsts = new Set(rs.map((r) => r.start));
    for (const c of mine) {
      if (c.state !== "in-use" || !tcacheSizes.includes(c.size)) continue;
      const t = await readTcache(mem, c, id, mode, inHeap, firsts.has(c.address));
      if (t) {
        c.state = "internal";
        c.bin = "tcache_perthread_struct";
        report.bins.push(...t);
      }
    }
    report.bins.push(...(await fastbins(mem, ar, id, mode, inHeap)), ...(await arenaBins(mem, ar, id)));
    const topChunk = mine.find((c) => c.state === "top");
    report.heaps.push({
      id, kind: "glibc arena", address: ar.address, label: ar.main ? "main_arena" : `arena #${n}`,
      committed: rs.reduce((s, r) => s + Number(r.end - r.base), 0),
      counters: { system_mem: Number(ar.systemMem), max_system_mem: Number(ar.maxSystemMem), attached_threads: Number(ar.attached), top: hex(ar.top), top_size: topChunk?.size ?? 0, last_remainder: hex(ar.lastRemainder) },
      ranges: rs.map((r) => ({ base: r.base, size: Number(r.end - r.base), label: r.label })),
      notes: [],
    });
  }

  // bins → chunk states
  const byAddr = new Map(report.chunks.map((c) => [c.address, c]));
  for (const b of report.bins) {
    const state: ChunkState = b.kind === "lfh" ? "lfh" : b.kind;
    const name = b.kind === "tcache" || b.kind === "fastbin" ? `${b.kind}[${b.index}]` : binKind(b.index).name;
    for (const e of b.entries) {
      const c = byAddr.get(e);
      if (!c) continue;
      if ((b.kind === "unsorted" || b.kind === "smallbin" || b.kind === "largebin") && c.state === "in-use") errors.push({ heap: b.heap, address: e, message: `${name} holds a chunk whose next chunk says it is in use` });
      c.state = state;
      c.bin = name;
    }
  }

  // mmapped chunks: anonymous writable regions outside heaps and modules
  const mods = [env.libc, ...(env.modules ?? [])];
  const skip = (a: bigint) => inHeap(a) || allRanges.some((r) => a >= r.base && a < r.end) || mods.some((m) => a >= m.base && a < m.base + BigInt(m.size));
  const mm = await mmappedChunks(mem, regions, skip, Math.max(0, max - report.chunks.length));
  if (mm.length) {
    report.chunks.push(...mm);
    report.heaps.push({ id: "glibc:mmap", kind: "mmapped chunks", address: mm[0].address, label: "mmapped (heuristic)", committed: mm.reduce((s, c) => s + c.size, 0), counters: { chunks: mm.length }, ranges: mm.map((c) => ({ base: c.address, size: c.size, label: "mmap" })), notes: ["IS_MMAPPED chunk headers found at the start of anonymous writable mappings"] });
  }
  report.chunks.sort((x, y) => (x.address < y.address ? -1 : x.address > y.address ? 1 : 0));
  if (mode === "auto") notes.push("glibc version unknown: safe-linked pointers decoded per pointer");
  return report;
}
