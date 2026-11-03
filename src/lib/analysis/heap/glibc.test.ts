import { describe, expect, it } from "vitest";
import { HeapMem } from "./reader";
import { FakeMem } from "./testmem";
import { alignChunk, arenaLayoutFor, binChunkSize, binHeader, exploreGlibc, findMainArena, glibcVersion, kArenaLayouts, layoutAt, revealPtr, tcacheBinSizes, tcacheLayout, type ArenaLayout, type GlibcVersion } from "./glibc";
import { filterChunks, findChunk, heapStats, sizeHistogram } from "./model";

const L = kArenaLayouts["2.27+"];
const LIBC = 0x7f0000000000n;
const ARENA = LIBC + 0x1c00n;
const HEAP = 0x555555559000n;
const safe = (pos: bigint, p: bigint) => (pos >> 12n) ^ p;

/** An initialised malloc_state: every bin empty (pointing at itself), `next` = `next`. */
function arena(m: FakeMem, a: bigint, next: bigint, top: bigint, layout: ArenaLayout = L) {
  for (let b = 1; b < 128; b++) {
    const h = a + BigInt(layout.bins + (b - 1) * 16) - 16n;
    m.q(a + BigInt(layout.bins + (b - 1) * 16), h).q(a + BigInt(layout.bins + (b - 1) * 16 + 8), h);
  }
  m.q(a + BigInt(layout.top), top).q(a + BigInt(layout.next), next).q(a + BigInt(layout.attached), 1n).q(a + BigInt(layout.systemMem), 0x21000n);
}
const chunk = (m: FakeMem, p: bigint, size: number, prevInUse = true, prevSize = 0) => m.q(p, BigInt(prevSize)).q(p + 8n, BigInt(size | (prevInUse ? 1 : 0)));

/** tcache_perthread_struct chunk size and default fill of a version */
const tcSizeOf = (v: GlibcVersion) => (v.minor >= 42 ? 0x300 : 0x290);
const fillOf = (v: GlibcVersion) => (v.minor >= 43 ? 16 : 7);

/**
 * Writes tcache counts: counts[i] before 2.42, num_slots[i] = fill - count from 2.42 (every bin,
 * empty ones included, starts at the fill).
 */
function tcacheCounts(m: FakeMem, tc: bigint, v: GlibcVersion, counts: Record<number, number>) {
  const T = tcacheLayout(tcSizeOf(v))!;
  for (let i = 0; i < T.bins; i++) {
    const n = counts[i] ?? 0;
    if (T.slots) m.w(tc + 16n + BigInt(2 * i), fillOf(v) - n);
    else if (n) m.w(tc + 16n + BigInt(2 * i), n);
  }
  return T;
}

/**
 * main heap: tcache struct, 2 tcache 0x20 chunks, an in-use 0x40, a fastbin 0x30 (a smallbin 0x30
 * from 2.43, which has no fastbins), an unsorted 0x110, an in-use 0x30 after it, then top.
 */
function mainImage(version: GlibcVersion = { major: 2, minor: 35 }) {
  const A = arenaLayoutFor(version);
  const m = new FakeMem().map(LIBC, 0x1000, false).map(LIBC + 0x1000n, 0x2000).map(HEAP, 0x21000);
  const tcSize = tcSizeOf(version);
  const tc = HEAP, t1 = HEAP + BigInt(tcSize), t2 = t1 + 0x20n, obj = t2 + 0x20n, fb = obj + 0x40n, us = fb + 0x30n, after = us + 0x110n, top = after + 0x30n;
  arena(m, ARENA, ARENA, top, A);
  chunk(m, tc, tcSize);
  chunk(m, t1, 0x20);
  chunk(m, t2, 0x20);
  chunk(m, obj, 0x40);
  m.q(obj + 16n, 0x401020n);
  chunk(m, fb, 0x30);
  chunk(m, us, 0x110, A.fastbins !== null, A.fastbins !== null ? 0 : 0x30);
  chunk(m, after, 0x30, false, 0x110);
  chunk(m, top, Number(HEAP + 0x21000n - top));
  const lk = (pos: bigint, p: bigint) => (version.minor >= 32 ? safe(pos, p) : p);
  // tcache[0]: t2 -> t1 -> NULL (entries hold user pointers)
  const T = tcacheCounts(m, tc, version, { 0: 2 });
  m.q(tc + 16n + BigInt(T.entries), t2 + 16n);
  m.q(t2 + 16n, lk(t2 + 16n, t1 + 16n)).q(t1 + 16n, lk(t1 + 16n, 0n));
  if (A.fastbins !== null) {
    // fastbin[1] (0x30): fb -> NULL
    m.q(ARENA + BigInt(A.fastbins + 8), fb).q(fb + 16n, lk(fb + 16n, 0n));
  } else {
    // smallbin[3] (0x30): header <-> fb
    const sh = ARENA + BigInt(A.bins + 2 * 16) - 16n;
    m.q(ARENA + BigInt(A.bins + 2 * 16), fb).q(ARENA + BigInt(A.bins + 2 * 16 + 8), fb).q(fb + 16n, sh).q(fb + 24n, sh);
  }
  // unsorted: header <-> us
  const uh = ARENA + BigInt(A.bins) - 16n;
  m.q(ARENA + BigInt(A.bins), us).q(ARENA + BigInt(A.bins + 8), us).q(us + 16n, uh).q(us + 24n, uh);
  // version banner in .rodata
  m.put(LIBC + 0x100n, Array.from(`GNU C Library (Ubuntu GLIBC 2.${version.minor}-0ubuntu3) stable release version 2.${version.minor}.`, (c) => c.charCodeAt(0)));
  return { m, tc, t1, t2, obj, fb, us, after, top };
}

const env = (m: FakeMem, version?: GlibcVersion | null) => ({ mem: new HeapMem(m.read), regions: m.list(), libc: { name: "libc.so.6", base: LIBC, size: 0x3000 }, version });

describe("glibc heap", () => {
  it("reads the version banner", () => {
    const { m } = mainImage();
    expect(glibcVersion(m.regions[0].bytes)).toEqual({ major: 2, minor: 35 });
    expect(glibcVersion(new Uint8Array(64))).toBeNull();
  });

  it("finds main_arena by its empty-bin signature", async () => {
    const { m } = mainImage();
    const g = await findMainArena(new HeapMem(m.read), [{ base: LIBC + 0x1000n, size: 0x2000 }]);
    expect(g?.address).toBe(ARENA);
    expect(g?.layout.name).toBe("2.27+");
    expect(binHeader({ address: ARENA, layout: L } as never, 1)).toBe(ARENA + 0x60n);
  });

  it("finds a 2.26 layout arena", async () => {
    const m = new FakeMem().map(LIBC + 0x1000n, 0x2000);
    arena(m, ARENA, ARENA, 0n, kArenaLayouts["2.26"]);
    const g = await findMainArena(new HeapMem(m.read), [{ base: LIBC + 0x1000n, size: 0x2000 }]);
    expect(g?.address).toBe(ARENA);
    expect(g?.layout.name).toBe("2.26");
  });

  const cases: [number, boolean][] = [[35, true], [31, false], [42, true], [42, false], [43, true], [43, false], [44, true]];
  for (const [minor, known] of cases) {
    it(`walks chunks and bins (glibc 2.${minor}, ${minor >= 32 ? "safe-linked" : "plain"} pointers, version ${known ? "known" : "unknown"})`, async () => {
      const v = { major: 2, minor };
      const { m, tc, t1, t2, obj, fb, us, after, top } = mainImage(v);
      const r = await exploreGlibc(env(m, known ? v : null));
      expect(r.errors).toEqual([]);
      expect(r.notes.filter((n) => /layout/.test(n))).toEqual([]);
      expect(r.source).toMatch(/signature/);
      expect(r.source).toContain(`malloc_state ${arenaLayoutFor(v).name} layout`);
      const noFast = minor >= 43;
      expect(r.heaps.map((h) => h.label)).toEqual(["main_arena"]);
      const st = Object.fromEntries(r.chunks.map((c) => [c.address.toString(16), [c.state, c.bin ?? ""]]));
      expect(st).toEqual({
        [tc.toString(16)]: ["internal", "tcache_perthread_struct"],
        [t1.toString(16)]: ["tcache", "tcache[0]"],
        [t2.toString(16)]: ["tcache", "tcache[0]"],
        [obj.toString(16)]: ["in-use", ""],
        [fb.toString(16)]: noFast ? ["smallbin", "smallbin[3]"] : ["fastbin", "fastbin[1]"],
        [us.toString(16)]: ["unsorted", "unsorted"],
        [after.toString(16)]: ["in-use", ""],
        [top.toString(16)]: ["top", ""],
      });
      const tl = r.bins.find((b) => b.kind === "tcache" && b.index === 0);
      expect(tl?.entries).toEqual([t2, t1]);
      expect(tl?.count).toBe(2);
      expect(tl?.owner).toBe(tc);
      expect(r.chunks.find((c) => c.address === tc)?.size).toBe(tcSizeOf(v));
      expect(r.bins.some((b) => b.kind === "fastbin")).toBe(!noFast);
      expect(r.chunks.find((c) => c.address === obj)?.preview?.[1]).toBe(0x10);
      const s = heapStats(r);
      expect(s.inUseCount).toBe(3); // tcache struct, obj, after
      expect(s.freeCount).toBe(4);
      expect(s.largestFree).toBe(0x110);
      expect(s.fragmentation).toBeCloseTo(1 - 0x110 / (0x20 * 2 + 0x30 + 0x110));
      expect(findChunk(r.chunks, obj + 0x18n)?.address).toBe(obj);
      expect(findChunk(r.chunks, 0x1000n)).toBeNull();
      expect(filterChunks(r.chunks, { state: "free" }).length).toBe(4);
      expect(filterChunks(r.chunks, { minSize: 0x100, maxSize: 0x200 }).map((c) => c.address)).toEqual([us]);
      expect(sizeHistogram(r.chunks).find((b) => b.lo === 32)?.count).toBe(4); // 0x20 x2, 0x30 x2
    });
  }

  it("finds a 2.43+ layout arena (no fastbins) with the version known, unknown or wrong", async () => {
    const v43 = { major: 2, minor: 43 };
    for (const v of [v43, null, { major: 2, minor: 39 }, { major: 2, minor: 26 }]) {
      const { m } = mainImage(v43);
      const g = await findMainArena(new HeapMem(m.read), [{ base: LIBC + 0x1000n, size: 0x2000 }], v);
      expect(g?.address).toBe(ARENA);
      expect(g?.layout.name).toBe("2.43+");
    }
    const { m } = mainImage(v43);
    const mem = new HeapMem(m.read);
    expect((await layoutAt(mem, ARENA, v43))?.name).toBe("2.43+");
    expect((await layoutAt(mem, ARENA, null))?.name).toBe("2.43+");
    expect((await layoutAt(mem, ARENA, { major: 2, minor: 35 }))?.name).toBe("2.43+");
    expect(binHeader({ address: ARENA, layout: kArenaLayouts["2.43+"] } as never, 1)).toBe(ARENA + 0x08n);
    // and the older layouts are still told apart from it
    const { m: m35 } = mainImage({ major: 2, minor: 35 });
    expect((await layoutAt(new HeapMem(m35.read), ARENA, v43))?.name).toBe("2.27+");
    expect((await findMainArena(new HeapMem(m35.read), [{ base: LIBC + 0x1000n, size: 0x2000 }], v43))?.layout.name).toBe("2.27+");
  });

  it("falls back to the other layouts when the version's finds nothing, and says so", async () => {
    const { m, t1 } = mainImage({ major: 2, minor: 43 });
    const r = await exploreGlibc(env(m, { major: 2, minor: 41 }));
    expect(r.heaps.map((h) => h.label)).toEqual(["main_arena"]);
    expect(r.source).toContain("2.43+ layout");
    expect(r.notes.some((n) => /2\.41 normally uses the 2\.27\+ malloc_state layout; this arena matched the 2\.43\+ layout/.test(n))).toBe(true);
    expect(r.chunks.some((c) => c.address === t1)).toBe(true);
    const s = await exploreGlibc({ ...env(m, { major: 2, minor: 41 }), mainArena: ARENA, mainArenaSource: "symbols" });
    expect(s.source).toMatch(/from symbols/);
    expect(s.notes.some((n) => /matched the 2\.43\+ layout/.test(n))).toBe(true);
  });

  it("maps tcache bins to chunk sizes (64 small bins, 12 large bins from 2.42)", () => {
    expect(tcacheBinSizes(0)).toEqual({ lo: 0x20, hi: 0x30 });
    expect(tcacheBinSizes(63)).toEqual({ lo: 0x410, hi: 0x420 });
    expect(tcacheBinSizes(64)).toEqual({ lo: 0x400, hi: 0x800 });
    expect(tcacheBinSizes(65)).toEqual({ lo: 0x800, hi: 0x1000 });
    expect(tcacheBinSizes(75)).toEqual({ lo: 0x200000, hi: 0x400000 });
    expect(tcacheLayout(0x300)).toEqual({ bins: 76, counts: 2, entries: 0x98, slots: true });
    expect(tcacheLayout(0x290)).toEqual({ bins: 64, counts: 2, entries: 0x80, slots: false });
    expect(tcacheLayout(0x250)).toEqual({ bins: 64, counts: 1, entries: 0x40, slots: false });
    expect(tcacheLayout(0x2a0)).toBeNull();
  });

  it("walks a large tcache bin (2.43, sorted by size) and flags one out of order", async () => {
    const v = { major: 2, minor: 43 };
    const A = kArenaLayouts["2.43+"];
    const { m, tc, top } = mainImage(v);
    const b1 = top, b2 = b1 + 0x500n, nt = b2 + 0x600n;
    chunk(m, b1, 0x500);
    chunk(m, b2, 0x600);
    chunk(m, nt, Number(HEAP + 0x21000n - nt));
    m.q(ARENA + BigInt(A.top), nt);
    const T = tcacheCounts(m, tc, v, { 0: 2, 64: 2 });
    m.q(tc + 16n + BigInt(T.entries + 8 * 64), b1 + 16n);
    m.q(b1 + 16n, safe(b1 + 16n, b2 + 16n)).q(b2 + 16n, safe(b2 + 16n, 0n));
    const r = await exploreGlibc(env(m, v));
    expect(r.errors).toEqual([]);
    const big = r.bins.find((b) => b.kind === "tcache" && b.index === 64);
    expect(big).toMatchObject({ chunkSize: 0x400, entries: [b1, b2], count: 2 });
    expect(big?.error).toBeUndefined();
    expect(r.chunks.find((c) => c.address === b2)?.bin).toBe("tcache[64]");
    // swap the order: b2 (0x600) first, then b1 (0x500)
    m.q(tc + 16n + BigInt(T.entries + 8 * 64), b2 + 16n);
    m.q(b2 + 16n, safe(b2 + 16n, b1 + 16n)).q(b1 + 16n, safe(b1 + 16n, 0n));
    const r2 = await exploreGlibc(env(m, v));
    expect(r2.bins.find((b) => b.kind === "tcache" && b.index === 64)?.error).toMatch(/out of order/);
    // a 0x900 chunk does not belong in bin 64
    chunk(m, b2, 0x900);
    const r3 = await exploreGlibc(env(m, v));
    expect(r3.bins.find((b) => b.kind === "tcache" && b.index === 64)?.error).toMatch(/bin holds 0x400\.\.0x7f0/);
  });

  it("rejects a 2.42+ tcache struct whose empty bins disagree on num_slots", async () => {
    const v = { major: 2, minor: 42 };
    const { m, tc, t1 } = mainImage(v);
    m.w(tc + 16n + 2n * 5n, 3); // bin 5 is empty (NULL) but has 3 free slots, the others 7
    const r = await exploreGlibc(env(m, v));
    expect(r.chunks.find((c) => c.address === tc)?.state).toBe("in-use");
    expect(r.chunks.find((c) => c.address === t1)?.state).toBe("in-use");
    // a full bin (num_slots 0) is fine
    const { m: m2, tc: tc2 } = mainImage(v);
    m2.w(tc2 + 16n, 0);
    const r2 = await exploreGlibc(env(m2, v));
    expect(r2.bins.find((b) => b.kind === "tcache" && b.index === 0)).toMatchObject({ count: 7, error: "count says 7, list has 2" });
  });

  it("walks a 2.43 thread arena (0x840-byte malloc_state, empty 0x300 tcache)", async () => {
    const v = { major: 2, minor: 43 };
    const A = kArenaLayouts["2.43+"];
    const { m } = mainImage(v);
    const h = 0x7f1000000000n, a2 = h + 0x30n;
    m.map(h, 0x21000);
    const first = alignChunk(a2 + BigInt(A.size));
    expect(first).toBe(h + 0x870n);
    const tc = first, c1 = tc + 0x300n, top = c1 + 0x50n;
    arena(m, a2, ARENA, top, A);
    m.q(ARENA + BigInt(A.next), a2);
    m.q(h, a2).q(h + 8n, 0n).q(h + 0x10n, 0x21000n).q(h + 0x18n, 0x21000n).q(h + 0x20n, 0x1000n);
    chunk(m, tc, 0x300 | 4);
    tcacheCounts(m, tc, v, {});
    chunk(m, c1, 0x50 | 4);
    chunk(m, top, Number(h + 0x21000n - top) | 4);
    const r = await exploreGlibc(env(m, v));
    expect(r.errors).toEqual([]);
    const th = r.heaps.find((x) => x.label === "arena #1");
    const mine = r.chunks.filter((c) => c.heap === th?.id);
    expect(mine.map((c) => [c.state, c.size])).toEqual([["internal", 0x300], ["in-use", 0x50], ["top", Number(h + 0x21000n - top)]]);
    expect(r.bins.filter((b) => b.heap === th?.id)).toEqual([{ heap: th?.id, kind: "tcache", index: -1, chunkSize: 0, entries: [], count: 0, owner: tc }]);
  });

  it("uses a main_arena symbol when given", async () => {
    const { m } = mainImage();
    const r = await exploreGlibc({ ...env(m), mainArena: ARENA, mainArenaSource: "libc.so.6 .symtab" });
    expect(r.source).toBe(`main_arena 0x${ARENA.toString(16)} from libc.so.6 .symtab`);
    expect(r.chunks.length).toBe(8);
  });

  it("stops at a corrupt chunk with an error marker", async () => {
    const { m, obj } = mainImage();
    m.q(obj + 8n, 0x7fffffffn);
    const r = await exploreGlibc(env(m, { major: 2, minor: 35 }));
    expect(r.chunks.map((c) => c.address).every((a) => a < obj)).toBe(true);
    expect(r.errors[0].address).toBe(obj);
    expect(r.errors[0].message).toMatch(/corrupt chunk/);
  });

  it("reports corrupt bin lists without looping", async () => {
    const { m, t1, t2, fb } = mainImage();
    m.q(t1 + 16n, safe(t1 + 16n, t2 + 16n)); // tcache loop t2 -> t1 -> t2
    m.q(fb + 8n, 0x41n); // fastbin chunk with the wrong size
    const r = await exploreGlibc(env(m, { major: 2, minor: 35 }));
    expect(r.bins.find((b) => b.kind === "tcache" && b.index === 0)?.error).toMatch(/loop|longer|count/);
    expect(r.bins.find((b) => b.kind === "fastbin")?.error).toMatch(/size/);
  });

  it("walks a thread arena through heap_info and finds its tcache", async () => {
    const { m } = mainImage();
    const h = 0x7f1000000000n, a2 = h + 0x30n; // 2.35+: heap_info is 0x30 bytes
    m.map(h, 0x21000);
    const first = alignChunk(a2 + BigInt(L.size));
    expect(first).toBe(h + 0x8d0n);
    const tc = first, c1 = tc + 0x290n, top = c1 + 0x50n;
    arena(m, a2, ARENA, top);
    m.q(ARENA + BigInt(L.next), a2);
    m.q(h, a2).q(h + 8n, 0n).q(h + 0x10n, 0x21000n).q(h + 0x18n, 0x21000n).q(h + 0x20n, 0x1000n);
    chunk(m, tc, 0x290 | 4);
    chunk(m, c1, 0x50 | 4);
    chunk(m, top, Number(h + 0x21000n - top) | 4);
    const r = await exploreGlibc(env(m, { major: 2, minor: 35 }));
    expect(r.errors).toEqual([]);
    const th = r.heaps.find((x) => x.label === "arena #1");
    expect(th?.ranges[0].base).toBe(h);
    const mine = r.chunks.filter((c) => c.heap === th?.id);
    expect(mine.map((c) => [c.state, c.size])).toEqual([["internal", 0x290], ["in-use", 0x50], ["top", Number(h + 0x21000n - top)]]);
    expect(mine[1].flags).toBe("PA");
    expect(r.bins.some((b) => b.heap === th?.id && b.kind === "tcache" && b.owner === tc)).toBe(true);
  });

  it("lists mmapped chunks outside the heaps", async () => {
    const { m } = mainImage();
    const mm = 0x7f2000000000n;
    m.map(mm, 0x22000);
    m.q(mm + 8n, 0x22000n | 2n);
    m.q(mm + 16n, 0x4142434445464748n);
    const r = await exploreGlibc(env(m, { major: 2, minor: 35 }));
    const c = r.chunks.find((x) => x.state === "mmapped");
    expect(c?.address).toBe(mm);
    expect(c?.size).toBe(0x22000);
    expect(r.heaps.some((x) => x.id === "glibc:mmap")).toBe(true);
  });

  it("decodes safe-linked pointers and bin sizes", () => {
    const pos = 0x55555555a2a0n, p = 0x55555555a2c0n;
    const inHeap = (x: bigint) => x >= 0x555555559000n && x < 0x55555557a000n;
    expect(revealPtr(pos, safe(pos, p), "safe", inHeap)).toBe(p);
    expect(revealPtr(pos, safe(pos, p), "auto", inHeap)).toBe(p);
    expect(revealPtr(pos, p, "auto", inHeap)).toBe(p);
    expect(revealPtr(pos, safe(pos, 0n), "auto", inHeap)).toBe(0n);
    expect(binChunkSize(2)).toBe(0x20);
    expect(binChunkSize(63)).toBe(0x3f0);
    expect(binChunkSize(64)).toBe(0x400);
    expect(binChunkSize(97)).toBe(0xc40);
  });

  it("reports when malloc has not run", async () => {
    const m = new FakeMem().map(LIBC, 0x3000);
    const r = await exploreGlibc({ mem: new HeapMem(m.read), regions: m.list(), libc: { name: "libc.so.6", base: LIBC, size: 0x3000 } });
    expect(r.heaps).toEqual([]);
    expect(r.source).toMatch(/not found/);
  });
});
