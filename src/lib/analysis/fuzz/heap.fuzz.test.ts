// Fuzz / property tests for the heap walkers (glibc arenas, NT and segment heaps) over hostile
// target memory: every qword is attacker-chosen (sizes, links and pointers into and out of the
// mapped regions), so chunk walks, bin lists and tcache chains must stay bounded.
import { describe, it } from "vitest";
import { cleanAsync, fc, kTimeout, params } from "./harness";
import { FakeMem } from "../heap/testmem";
import { HeapMem } from "../heap/reader";
import { exploreGlibc } from "../heap/glibc";
import { exploreWindows } from "../heap/nt";
import { scanForPointers } from "../heap/model";

const LIBC = 0x7f00_0000_0000n;
const HEAP = 0x5555_0000_0000n;
const PEB = 0x7ff0_0000_0000n;

/** Qwords that break heap metadata: sizes with odd flag bits, links into each region, self-links. */
const word = (bases: bigint[]) =>
  fc.oneof(
    fc.constantFrom(0n, 1n, 0x21n, 0x31n, 0x411n, 0x20d51n, 0xffff_ffff_ffff_fff1n, 2n ** 63n, 0x1000n),
    fc.tuple(fc.constantFrom(...bases), fc.nat({ max: 0x2000 })).map(([b, o]) => b + BigInt(o & ~7)),
    fc.bigUintN(64),
  );

function fill(m: FakeMem, base: bigint, words: bigint[], size: number) {
  for (let o = 0; o + 8 <= size; o += 8) m.q(base + BigInt(o), words[(o / 8) % words.length]);
}

describe("heap walkers over hostile memory", () => {
  const bases = [LIBC, HEAP, PEB];

  it("exploreGlibc", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(word(bases), { minLength: 1, maxLength: 48 }), fc.array(word(bases), { minLength: 1, maxLength: 48 }), fc.constantFrom(null, { major: 2, minor: 31 }, { major: 2, minor: 35 }, { major: 2, minor: 43 }), async (lw, hw, version) => {
        const m = new FakeMem().map(LIBC, 0x3000).map(HEAP, 0x4000);
        fill(m, LIBC, lw, 0x3000);
        fill(m, HEAP, hw, 0x4000);
        await cleanAsync(() => exploreGlibc({ mem: new HeapMem(m.read), regions: m.list(), libc: { name: "libc.so.6", base: LIBC, size: 0x3000 }, version, maxChunks: 50_000 }), 2000);
      }),
      params(),
    );
  }, kTimeout);

  it("exploreWindows (NT and segment heaps from the PEB)", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(word(bases), { minLength: 1, maxLength: 48 }), fc.array(word(bases), { minLength: 1, maxLength: 48 }), async (pw, hw) => {
        const m = new FakeMem().map(PEB, 0x2000).map(HEAP, 0x4000);
        fill(m, PEB, pw, 0x2000);
        fill(m, HEAP, hw, 0x4000);
        await cleanAsync(() => exploreWindows(new HeapMem(m.read), PEB, { maxChunks: 50_000 }), 2000);
      }),
      params(),
    );
  }, kTimeout);

  it("scanForPointers", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 4096 }), fc.bigUintN(64), fc.bigUintN(64), async (b, lo, hi) => {
        await cleanAsync(async () => scanForPointers(b, HEAP, lo, hi));
      }),
      params(),
    );
  }, kTimeout);
});
