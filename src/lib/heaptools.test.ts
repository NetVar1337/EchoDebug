import { describe, expect, it, vi } from "vitest";
import tools from "./tools.json";
import type { HeapChunk, HeapReport } from "./analysis/heap/model";

const { report, explore } = vi.hoisted(() => {
  const ch = (address: bigint, size: number, state: HeapChunk["state"], bin?: string): HeapChunk => ({ address, user: address + 16n, size, userSize: size - 8, state, flags: "P", heap: "glibc:0x1", bin, preview: new Uint8Array(16).fill(0x41) });
  const report: HeapReport = {
    platform: "glibc", source: "main_arena 0x1 by signature", version: "2.39", truncated: false, notes: [],
    heaps: [{ id: "glibc:0x1", kind: "glibc arena", address: 1n, label: "main_arena", committed: 0x21000, counters: { system_mem: 0x21000 }, ranges: [{ base: 0x1000n, size: 0x21000, label: "main heap" }], notes: [] }],
    chunks: [ch(0x1000n, 0x290, "internal"), ch(0x1290n, 0x20, "tcache", "tcache[0]"), ch(0x12b0n, 0x40, "in-use"), ch(0x12f0n, 0x20d10, "top")],
    bins: [{ heap: "glibc:0x1", kind: "tcache", index: 0, chunkSize: 0x20, entries: [0x1290n], count: 1, owner: 0x1000n }, { heap: "glibc:0x1", kind: "fastbin", index: 3, chunkSize: 0x50, entries: [] }],
    errors: [{ heap: "glibc:0x1", address: 0x5000n, message: "corrupt chunk" }],
  };
  return { report, explore: vi.fn(async () => report) };
});
vi.mock("./heaplive", () => ({ cachedReport: () => report, exploreHeaps: explore, resolveTypes: async () => 0, typeOf: (c: HeapChunk) => (c.address === 0x12b0n ? "Player" : undefined) }));
vi.mock("@/store/conn", () => ({ useConn: { getState: () => ({ modules: [] }) } }));

const { heapHandlers } = await import("./heaptools");

describe("heap MCP tools", () => {
  it("are ui_* verbs declared in tools.json (read-only: none is in the relay's gated lists)", () => {
    const byVerb = new Map((tools as { name: string; verb: string }[]).map((t) => [t.verb, t.name]));
    expect(Object.keys(heapHandlers).map((v) => byVerb.get(v))).toEqual(["heaps", "heap_chunks", "heap_find"]);
  });

  it("summarises heaps with stats, non-empty bins and errors", async () => {
    const r = await heapHandlers.ui_heaps({});
    expect(r.platform).toBe("glibc");
    const h = (r.heaps as Record<string, unknown>[])[0];
    expect(h).toMatchObject({ id: "glibc:0x1", address: "0x1", in_use: 0x290 + 0x40, in_use_count: 2, free: 0x20, free_count: 1, fragmentation: 0 });
    expect(r.bins).toEqual([{ heap: "glibc:0x1", kind: "tcache", index: 0, chunk_size: 0x20, length: 1, count: 1, total: undefined, owner: "0x1000", error: undefined }]);
    expect(r.errors).toEqual([{ heap: "glibc:0x1", address: "0x5000", message: "corrupt chunk" }]);
    await heapHandlers.ui_heaps({ refresh: true });
    expect(explore).toHaveBeenCalledWith({ refresh: true });
  });

  it("pages and filters chunks", async () => {
    const p = await heapHandlers.ui_heap_chunks({ state: "used", limit: 1 });
    expect(p.total).toBe(2);
    expect(p.next_offset).toBe(1);
    expect((p.chunks as Record<string, unknown>[])[0]).toMatchObject({ address: "0x1000", user: "0x1010", state: "internal", preview: "41".repeat(16) });
    const q = await heapHandlers.ui_heap_chunks({ state: "used", offset: 1, limit: 5 });
    expect((q.chunks as Record<string, unknown>[])[0]).toMatchObject({ address: "0x12b0", type: "Player" });
    expect(q.next_offset).toBeNull();
    expect((await heapHandlers.ui_heap_chunks({ min_size: "0x100" })).total).toBe(2);
    await expect(heapHandlers.ui_heap_chunks({ min_size: -1 })).rejects.toThrow(/min_size/);
  });

  it("finds the owning chunk and its bins", async () => {
    const r = await heapHandlers.ui_heap_find({ address: "0x12a0" });
    expect(r).toMatchObject({ found: true, offset_in_chunk: 0x10, offset_in_user: 0, heap: { label: "main_arena" }, bins: [{ kind: "tcache", index: 0, position: 0, length: 1 }] });
    expect(await heapHandlers.ui_heap_find({ address: "0x900" })).toMatchObject({ found: false, heap: null });
    await expect(heapHandlers.ui_heap_find({})).rejects.toThrow(/address/);
  });
});
