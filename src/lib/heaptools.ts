// MCP tools of the heap explorer (all read-only): heaps, heap_chunks (paged), heap_find.
// Registered by provider.ts like the annotation verbs; the relay routes them to the app window.
import { bytesToHex, fmtAddr, parseAddress } from "./hex";
import { cachedReport, exploreHeaps, resolveTypes, typeOf } from "./heaplive";
import { filterChunks, findChunk, heapStats, type HeapChunk, type HeapReport } from "./analysis/heap/model";
import { useConn } from "@/store/conn";

type Args = Record<string, unknown>;

const n = (args: Args, k: string): number | undefined => {
  const v = args[k];
  if (v === undefined || v === null || v === "") return undefined;
  const x = typeof v === "string" ? Number(v.startsWith("0x") ? parseInt(v, 16) : v) : Number(v);
  if (!Number.isFinite(x) || x < 0) throw new Error(`'${k}' must be a non-negative number`);
  return x;
};

async function report(args: Args): Promise<HeapReport> {
  return args.refresh ? exploreHeaps({ refresh: true }) : (cachedReport() ?? exploreHeaps());
}

function chunkJson(c: HeapChunk) {
  return {
    address: fmtAddr(c.address), user: fmtAddr(c.user), size: c.size, user_size: c.userSize, state: c.state, flags: c.flags, heap: c.heap,
    bin: c.bin, note: c.note, preview: c.preview ? bytesToHex(c.preview) : undefined, type: typeOf(c) || undefined,
  };
}

export const heapHandlers: Record<string, (args: Args) => Promise<Record<string, unknown>>> = {
  ui_heaps: async (args) => {
    const r = await report(args);
    return {
      platform: r.platform, source: r.source, version: r.version, truncated: r.truncated, chunks: r.chunks.length,
      heaps: r.heaps.map((h) => {
        const s = heapStats(r, h.id);
        return {
          id: h.id, kind: h.kind, label: h.label, address: fmtAddr(h.address), committed: h.committed, reserved: h.reserved,
          in_use: s.inUse, in_use_count: s.inUseCount, free: s.free, free_count: s.freeCount, largest_free: s.largestFree,
          fragmentation: Number(s.fragmentation.toFixed(4)), chunks: s.chunks, counters: h.counters,
          ranges: h.ranges.slice(0, 64).map((x) => ({ base: fmtAddr(x.base), size: x.size, label: x.label })), notes: h.notes,
        };
      }),
      bins: r.bins.filter((b) => b.entries.length || b.error || b.count).slice(0, 1000).map((b) => ({
        heap: b.heap, kind: b.kind, index: b.index, chunk_size: b.chunkSize, length: b.entries.length, count: b.count, total: b.total,
        owner: b.owner === undefined ? undefined : fmtAddr(b.owner), error: b.error,
      })),
      errors: r.errors.slice(0, 200).map((e) => ({ heap: e.heap, address: fmtAddr(e.address), message: e.message })),
      notes: r.notes,
    };
  },

  ui_heap_chunks: async (args) => {
    const r = await report(args);
    const list = filterChunks(r.chunks, { heap: typeof args.heap === "string" ? args.heap : undefined, state: typeof args.state === "string" ? args.state : undefined, minSize: n(args, "min_size"), maxSize: n(args, "max_size") });
    const offset = Math.floor(n(args, "offset") ?? 0);
    const limit = Math.min(2000, Math.max(1, Math.floor(n(args, "limit") ?? 200)));
    const page = list.slice(offset, offset + limit);
    if (args.rtti) await resolveTypes(page, useConn.getState().modules);
    return { total: list.length, offset, limit, next_offset: offset + page.length < list.length ? offset + page.length : null, chunks: page.map(chunkJson) };
  },

  ui_heap_find: async (args) => {
    const raw = args.address;
    if (typeof raw !== "string" && typeof raw !== "number") throw new Error("missing 'address'");
    const a = parseAddress(String(raw), useConn.getState().modules);
    if (a === null) throw new Error(`cannot parse address: ${raw}`);
    const r = await report(args);
    const c = findChunk(r.chunks, a);
    if (!c) return { address: fmtAddr(a), found: false, heap: r.heaps.find((h) => h.ranges.some((x) => a >= x.base && a < x.base + BigInt(x.size)))?.id ?? null };
    await resolveTypes([c], useConn.getState().modules);
    const h = r.heaps.find((x) => x.id === c.heap);
    return {
      address: fmtAddr(a), found: true, chunk: chunkJson(c), offset_in_chunk: Number(a - c.address), offset_in_user: Number(a - c.user),
      heap: h ? { id: h.id, kind: h.kind, label: h.label } : c.heap,
      bins: r.bins.filter((b) => b.entries.includes(c.address)).map((b) => ({ kind: b.kind, index: b.index, position: b.entries.indexOf(c.address), length: b.entries.length })),
    };
  },
};
