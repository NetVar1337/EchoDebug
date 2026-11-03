import { describe, expect, it } from "vitest";
import { HeapMem } from "./reader";
import { FakeMem } from "./testmem";
import { decodeEntry, encodeEntry, exploreWindows, kNt, NT_HEAP_SIGNATURE, SEGMENT_HEAP_SIGNATURE, SEGMENT_SIGNATURE, USERBLOCKS_SIGNATURE } from "./nt";
import { findChunk, heapStats } from "./model";

const PEB = 0x7ff000000000n;
const H = 0x20000000n; // NT heap
const SH = 0x30000000n; // segment heap
const KEY = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
const FIRST = H + 0x740n, UCR_AT = H + 0x8000n, LAST = H + 0x10000n;
const SUB = 0x20200000n, LFH = 0x20400000n, VA = 0x20300000n, UCRD = 0x20100000n;
const H_ = kNt.heap, S_ = kNt.segment;

function image() {
  const m = new FakeMem().map(PEB, 0x1000).map(H, 0x8000).map(UCRD, 0x1000).map(SUB, 0x1000).map(VA, 0x1000).map(LFH, 0x1000).map(SH, 0x1000).map(0x40000000n, 0x4000);
  // PEB: two heaps, the first is the process heap
  m.q(PEB + 0x30n, H).d(PEB + 0xe8n, 2).q(PEB + 0xf0n, PEB + 0x800n).q(PEB + 0x800n, H).q(PEB + 0x808n, SH);
  // _HEAP + its own segment
  m.d(H + BigInt(S_.signature), SEGMENT_SIGNATURE).d(H + BigInt(H_.signature), NT_HEAP_SIGNATURE).d(H + BigInt(H_.encodeFlagMask), 0x100000).put(H + BigInt(H_.encoding + 8), KEY);
  m.q(H + BigInt(S_.baseAddress), H).d(H + BigInt(S_.numberOfPages), 0x10).d(H + BigInt(S_.unCommittedPages), 8).q(H + BigInt(S_.firstEntry), FIRST).q(H + BigInt(S_.lastValidEntry), LAST);
  const seglist = H + BigInt(H_.segmentList), segEntry = H + BigInt(S_.listEntry);
  m.q(seglist, segEntry).q(seglist + 8n, segEntry).q(segEntry, seglist).q(segEntry + 8n, seglist);
  // one uncommitted range: [H+0x8000, H+0x10000)
  const ucrHead = H + BigInt(S_.ucrSegmentList), d = UCRD;
  m.q(ucrHead, d + 0x10n).q(d + 0x10n, ucrHead).q(d + 0x20n, UCR_AT).q(d + 0x28n, 0x8000n);
  // front end: LFH whose Heap points back
  m.q(H + BigInt(H_.frontEndHeap), LFH).put(H + BigInt(H_.frontEndHeapType), [2]).q(LFH + 0x18n, H);
  // entries: busy 0x30 (0x18 requested), free 0x100, busy 0x1000 LFH UserBlocks, free rest
  const busy = FIRST, free = busy + 0x30n, ub = free + 0x100n, rest = ub + 0x1000n;
  m.put(busy, encodeEntry({ size: 0x30, flags: 1, unusedBytes: 0x18 }, KEY)).q(busy + 16n, 0x7ff612340000n);
  m.put(free, encodeEntry({ size: 0x100, flags: 0, prevSize: 0x30 }, KEY));
  m.put(ub, encodeEntry({ size: 0x1000, flags: 1, unusedBytes: 0x10 }, KEY));
  const ud = ub + 16n;
  m.q(ud, SUB).d(ud + 0x14n, USERBLOCKS_SIGNATURE).q(ud + 0x20n, 64n).q(ud + 0x28n, ud + 0x30n).q(ud + 0x30n, 0x0003ffffffffffffn); // 50 busy
  m.q(SUB + 8n, ud).w(SUB + 0x20n, 14).w(SUB + 0x28n, 3).w(SUB + 0x2cn, 64).put(SUB + 0x2en, [2]);
  m.put(rest, encodeEntry({ size: Number(UCR_AT - rest), flags: 0 }, KEY));
  // one VirtualAlloc block
  const vaHead = H + BigInt(H_.virtualAllocdBlocks);
  m.q(vaHead, VA).q(vaHead + 8n, VA).q(VA, vaHead).q(VA + 8n, vaHead).q(VA + 0x20n, 0x100000n).q(VA + 0x28n, 0x101000n).q(VA + 0x40n, 0xabcdn);
  // segment heap: MemStats and a two-node large-alloc tree (root with a left child)
  const G = kNt.segHeap;
  m.d(SH + BigInt(G.signature), SEGMENT_HEAP_SIGNATURE);
  m.q(SH + BigInt(G.memStats), 0x400n).q(SH + BigInt(G.memStats + 8), 0x80n).q(SH + BigInt(G.memStats + 0x10), 0x10n).q(SH + BigInt(G.memStats + 0x18), 0x4n);
  m.q(SH + BigInt(G.largeReservedPages), 6n).q(SH + BigInt(G.largeCommittedPages), 6n);
  const root = SH + 0x800n, left = SH + 0x900n;
  m.q(SH + BigInt(G.largeAllocMetadata), root);
  m.q(root, left).q(root + 0x18n, 0x40010000n | 0x20n).q(root + 0x20n, 2n << 12n);
  m.q(left + 0x18n, 0x40000000n | 0x10n).q(left + 0x20n, 2n << 12n);
  return { m, busy, free, ub, rest };
}

describe("NT heap entries", () => {
  it("decode with the Encoding key and check the checksum", () => {
    const raw = encodeEntry({ size: 0x30, flags: 1, prevSize: 0x20, unusedBytes: 0x18, segmentOffset: 2 }, KEY);
    expect(raw[8]).not.toBe(3);
    const e = decodeEntry(raw, KEY);
    expect(e).toEqual({ size: 0x30, flags: 1, smallTagIndex: 3 ^ 0 ^ 1, prevSize: 0x20, segmentOffset: 2, unusedBytes: 0x18, checksumOk: true });
    expect(decodeEntry(raw, null).checksumOk).toBe(false);
    expect(decodeEntry(encodeEntry({ size: 0x1230, flags: 0x11 }, null), null)).toMatchObject({ size: 0x1230, flags: 0x11, checksumOk: true });
  });
});

describe("Windows heaps", () => {
  it("walks PEB->ProcessHeaps: NT heap segments, LFH, virtual allocs and the segment heap", async () => {
    const { m, busy, free, ub, rest } = image();
    const r = await exploreWindows(new HeapMem(m.read), PEB);
    expect(r.errors).toEqual([]);
    expect(r.source).toMatch(/ProcessHeaps \(2 heaps\)/);
    expect(r.heaps.map((h) => [h.kind, h.label])).toEqual([["NT heap", `process heap 0x${H.toString(16)}`], ["segment heap", `heap 1 0x${SH.toString(16)}`]]);
    const nt = r.heaps[0];
    expect(nt.reserved).toBe(0x10000 + 0x101000);
    expect(nt.committed).toBe(0x8000 + 0x100000);
    expect(nt.counters.front_end).toBe("LFH");
    expect(nt.notes[0]).toMatch(/LFH front end/);
    const mine = r.chunks.filter((c) => c.heap === nt.id);
    expect(mine.map((c) => [c.address, c.size, c.state])).toEqual([
      [busy, 0x30, "in-use"], [free, 0x100, "free"], [ub, 0x1000, "lfh"], [rest, Number(UCR_AT - rest), "free"], [VA, 0x100000, "large"],
    ]);
    expect(mine[0].userSize).toBe(0x18);
    expect(mine[0].flags).toBe("busy");
    expect(mine[0].preview?.[2]).toBe(0x34);
    expect(mine[2].note).toMatch(/50\/64 blocks of 0x30 busy/);
    expect(r.bins).toEqual([{ heap: nt.id, kind: "lfh", index: 2, chunkSize: 0x30, entries: [ub], count: 50, total: 64, owner: SUB }]);
    const seg = r.chunks.filter((c) => c.heap === r.heaps[1].id);
    expect(seg.map((c) => [c.address, c.size, c.userSize])).toEqual([[0x40000000n, 0x2000, 0x2000 - 0x10], [0x40010000n, 0x2000, 0x2000 - 0x20]]);
    expect(r.heaps[1].committed).toBe(0x80 * 0x1000);
    expect(r.heaps[1].counters.lfh_free_committed_pages).toBe(4);
    expect(findChunk(r.chunks, busy + 0x20n)?.address).toBe(busy);
    expect(heapStats(r, nt.id).freeCount).toBe(2);
  });

  it("stops a segment walk at a corrupted entry", async () => {
    const { m, free } = image();
    const raw = (await m.read(free + 8n, 1))!;
    m.put(free + 8n, [raw[0] ^ 0x40]); // size byte flipped: checksum no longer matches
    const r = await exploreWindows(new HeapMem(m.read), PEB);
    const e = r.errors.find((x) => x.address === free);
    expect(e?.message).toMatch(/checksum/);
    expect(r.chunks.some((c) => c.address > free && c.address < UCR_AT)).toBe(false);
  });

  it("flags a heap with an unknown signature and an LFH subsegment that does not point back", async () => {
    const { m } = image();
    m.d(SH + 0x10n, 0x12345678);
    m.q(SUB + 8n, 0n);
    const r = await exploreWindows(new HeapMem(m.read), PEB);
    expect(r.heaps.length).toBe(1);
    expect(r.errors.some((e) => /neither an NT heap/.test(e.message))).toBe(true);
    expect(r.errors.some((e) => /does not point back/.test(e.message))).toBe(true);
  });
});
