import { describe, expect, it } from "vitest";
import { HeapMem } from "./reader";
import { FakeMem } from "./testmem";
import { alignChunk, binChunkSize, binHeader, exploreGlibc, findMainArena, glibcVersion, kArenaLayouts, revealPtr, type GlibcVersion } from "./glibc";
import { filterChunks, findChunk, heapStats, sizeHistogram } from "./model";

const L = kArenaLayouts["2.27+"];
const LIBC = 0x7f0000000000n;
const ARENA = LIBC + 0x1c00n;
const HEAP = 0x555555559000n;
const safe = (pos: bigint, p: bigint) => (pos >> 12n) ^ p;

/** An initialised malloc_state: every bin empty (pointing at itself), `next` = `next`. */
function arena(m: FakeMem, a: bigint, next: bigint, top: bigint, layout = L) {
  for (let b = 1; b < 128; b++) {
    const h = a + BigInt(layout.bins + (b - 1) * 16) - 16n;
    m.q(a + BigInt(layout.bins + (b - 1) * 16), h).q(a + BigInt(layout.bins + (b - 1) * 16 + 8), h);
  }
  m.q(a + BigInt(layout.top), top).q(a + BigInt(layout.next), next).q(a + BigInt(layout.attached), 1n).q(a + BigInt(layout.systemMem), 0x21000n);
}
const chunk = (m: FakeMem, p: bigint, size: number, prevInUse = true, prevSize = 0) => m.q(p, BigInt(prevSize)).q(p + 8n, BigInt(size | (prevInUse ? 1 : 0)));

/**
 * main heap: tcache struct, 2 tcache 0x20 chunks, an in-use 0x40, a fastbin 0x30, an unsorted 0x110,
 * an in-use 0x30 after it, then top.
 */
function mainImage(version: GlibcVersion = { major: 2, minor: 35 }) {
  const m = new FakeMem().map(LIBC, 0x1000, false).map(LIBC + 0x1000n, 0x2000).map(HEAP, 0x21000);
  const tc = HEAP, t1 = HEAP + 0x290n, t2 = t1 + 0x20n, obj = t2 + 0x20n, fb = obj + 0x40n, us = fb + 0x30n, after = us + 0x110n, top = after + 0x30n;
  arena(m, ARENA, ARENA, top);
  chunk(m, tc, 0x290);
  chunk(m, t1, 0x20);
  chunk(m, t2, 0x20);
  chunk(m, obj, 0x40);
  m.q(obj + 16n, 0x401020n);
  chunk(m, fb, 0x30);
  chunk(m, us, 0x110);
  chunk(m, after, 0x30, false, 0x110);
  chunk(m, top, Number(HEAP + 0x21000n - top));
  const lk = (pos: bigint, p: bigint) => (version.minor >= 32 ? safe(pos, p) : p);
  // tcache[0]: t2 -> t1 -> NULL (entries hold user pointers)
  m.w(tc + 16n, 2).q(tc + 16n + 0x80n, t2 + 16n);
  m.q(t2 + 16n, lk(t2 + 16n, t1 + 16n)).q(t1 + 16n, lk(t1 + 16n, 0n));
  // fastbin[1] (0x30): fb -> NULL
  m.q(ARENA + BigInt(L.fastbins + 8), fb).q(fb + 16n, lk(fb + 16n, 0n));
  // unsorted: header <-> us
  const uh = ARENA + BigInt(L.bins) - 16n;
  m.q(ARENA + BigInt(L.bins), us).q(ARENA + BigInt(L.bins + 8), us).q(us + 16n, uh).q(us + 24n, uh);
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

  for (const minor of [35, 31]) {
    it(`walks chunks and bins (glibc 2.${minor}, ${minor >= 32 ? "safe-linked" : "plain"} pointers, version ${minor === 35 ? "known" : "unknown"})`, async () => {
      const v = { major: 2, minor };
      const { m, tc, t1, t2, obj, fb, us, after, top } = mainImage(v);
      const r = await exploreGlibc(env(m, minor === 35 ? v : null));
      expect(r.errors).toEqual([]);
      expect(r.source).toMatch(/signature/);
      expect(r.heaps.map((h) => h.label)).toEqual(["main_arena"]);
      const st = Object.fromEntries(r.chunks.map((c) => [c.address.toString(16), [c.state, c.bin ?? ""]]));
      expect(st).toEqual({
        [tc.toString(16)]: ["internal", "tcache_perthread_struct"],
        [t1.toString(16)]: ["tcache", "tcache[0]"],
        [t2.toString(16)]: ["tcache", "tcache[0]"],
        [obj.toString(16)]: ["in-use", ""],
        [fb.toString(16)]: ["fastbin", "fastbin[1]"],
        [us.toString(16)]: ["unsorted", "unsorted"],
        [after.toString(16)]: ["in-use", ""],
        [top.toString(16)]: ["top", ""],
      });
      const tl = r.bins.find((b) => b.kind === "tcache" && b.index === 0);
      expect(tl?.entries).toEqual([t2, t1]);
      expect(tl?.count).toBe(2);
      expect(tl?.owner).toBe(tc);
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
