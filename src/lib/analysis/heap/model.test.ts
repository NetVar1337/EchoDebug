import { describe, expect, it } from "vitest";
import { filterChunks, findChunk, heapStats, scanForPointers, sizeHistogram, type HeapChunk, type HeapReport } from "./model";

const ch = (address: bigint, size: number, state: HeapChunk["state"], heap = "h1", bin?: string): HeapChunk => ({ address, user: address + 16n, size, userSize: size - 8, state, flags: "P", heap, bin });

describe("heap model helpers", () => {
  const chunks = [ch(0x1000n, 0x20, "in-use"), ch(0x1020n, 0x40, "tcache", "h1", "tcache[2]"), ch(0x1060n, 0x400, "free"), ch(0x1460n, 0x100, "in-use", "h2"), ch(0x1560n, 0x2000, "top")];
  const report: HeapReport = { platform: "glibc", source: "", heaps: [{ id: "h1", kind: "k", address: 0n, label: "a", committed: 0x1460, counters: {}, ranges: [], notes: [] }, { id: "h2", kind: "k", address: 0n, label: "b", committed: 0x2100, counters: {}, ranges: [], notes: [] }], chunks, bins: [], errors: [], notes: [], truncated: false };

  it("computes stats per heap (top is neither used nor free)", () => {
    expect(heapStats(report, "h1")).toEqual({ chunks: 4, committed: 0x1460, inUse: 0x20, inUseCount: 1, free: 0x440, freeCount: 2, largestFree: 0x400, fragmentation: 1 - 0x400 / 0x440 });
    expect(heapStats(report).committed).toBe(0x1460 + 0x2100);
    expect(heapStats({ ...report, chunks: [] }).fragmentation).toBe(0);
  });

  it("filters by heap, state class, size and text", () => {
    expect(filterChunks(chunks, { heap: "h2" }).length).toBe(1);
    expect(filterChunks(chunks, { state: "used" }).map((c) => c.address)).toEqual([0x1000n, 0x1460n]);
    expect(filterChunks(chunks, { state: "tcache" }).length).toBe(1);
    expect(filterChunks(chunks, { text: "tcache[2]" }).length).toBe(1);
    expect(filterChunks(chunks, { text: "0x1470" }).length).toBe(1); // user pointer
    expect(filterChunks(chunks, { text: "Player" }, (c) => (c.address === 0x1000n ? "class Player" : undefined)).length).toBe(1);
  });

  it("finds the owning chunk by address", () => {
    expect(findChunk(chunks, 0x1000n)?.address).toBe(0x1000n);
    expect(findChunk(chunks, 0x105fn)?.address).toBe(0x1020n);
    expect(findChunk(chunks, 0x3560n)).toBeNull();
    expect(findChunk(chunks, 0xfffn)).toBeNull();
    expect(findChunk([], 0x1000n)).toBeNull();
  });

  it("buckets sizes by powers of two", () => {
    const h = sizeHistogram(chunks);
    expect(h[0]).toEqual({ lo: 16, hi: 32, count: 0, bytes: 0 });
    expect(h.find((b) => b.lo === 32)?.count).toBe(1);
    expect(h.find((b) => b.lo === 1024)?.count).toBe(1);
    expect(h.find((b) => b.lo === 8192)?.bytes).toBe(0x2000);
    expect(sizeHistogram([ch(0n, 1 << 24, "in-use")]).at(-1)?.count).toBe(1);
  });

  it("scans a buffer for aligned pointers into a range", () => {
    const buf = new Uint8Array(0x40);
    const dv = new DataView(buf.buffer);
    dv.setBigUint64(0x00, 0x7f0000001010n, true); // inside
    dv.setBigUint64(0x08, 0x7f0000002000n, true); // == hi: outside
    dv.setBigUint64(0x10, 0x7f0000001000n, true); // == lo: inside
    dv.setBigUint64(0x18, 0x7e0000001010n, true); // high dword differs
    dv.setBigUint64(0x20, 0x00000000ffffffffn, true);
    dv.setBigUint64(0x28, 0x7f0000001ff8n, true);
    expect(scanForPointers(buf, 0x5000n, 0x7f0000001000n, 0x7f0000002000n)).toEqual([0x5000n, 0x5010n, 0x5028n]);
    expect(scanForPointers(buf, 0x5000n, 0x7f0000001000n, 0x7f0000002000n, 1)).toEqual([0x5000n]);
    // an unaligned buffer base starts at the first aligned qword
    expect(scanForPointers(buf.subarray(4), 0x5004n, 0x7f0000001000n, 0x7f0000002000n)).toEqual([0x5010n, 0x5028n]);
    // a range that crosses a 4 GiB boundary
    const b2 = new Uint8Array(16);
    new DataView(b2.buffer).setBigUint64(0, 0x1_00000010n, true);
    new DataView(b2.buffer).setBigUint64(8, 0x0_fffffff0n, true);
    expect(scanForPointers(b2, 0n, 0xfffffff8n, 0x1_00000020n)).toEqual([0n]);
  });
});
