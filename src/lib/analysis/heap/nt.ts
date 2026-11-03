// Windows process heaps (x64): PEB->ProcessHeaps, then per heap either the NT heap (backend
// segments walked entry by entry, LFH subsegments summarised) or the segment heap (large
// allocations and the runtime memory counters).
//
// Coverage:
//   NT heap      - every segment (SegmentList) walked from FirstEntry to LastValidEntry, entries
//                  decoded with the heap's Encoding key and checked by their SmallTagIndex checksum,
//                  uncommitted ranges skipped through UCRSegmentList, VirtualAllocdBlocks listed;
//                  LFH: every backend block that is an LFH UserBlocks (signature 0xF0E0D0C0) is
//                  reported with its subsegment's block size, block count and busy count (from the
//                  busy bitmap). Individual LFH blocks are not listed: their offsets inside the
//                  UserBlocks are encoded with the process-wide LFH key.
//   segment heap - the large-allocation tree (LargeAllocMetadata) as chunks, and the VS / LFH
//                  summary from MemStats (reserved, committed, free committed, LFH free committed).
//                  VS and LFH blocks themselves are not walked.
// Offsets are from the public ntdll symbols of Windows 10 2004/20H2/21H2/22H2 (build 19041-19045)
// and Windows 11 21H2-24H2 (builds 22000-26100), where these fields did not move. Each parser
// checks what it reads (signatures, checksums, back-pointers) and reports an error instead of
// guessing when a build does not match.

import { HeapMem, u16At, u32At, u64At } from "./reader";
import { hex, type BinList, type HeapChunk, type HeapError, type HeapInfo, type HeapReport } from "./model";

/** Struct offsets, x64. See the header comment for the builds they come from. */
export const kNt = {
  peb: { processHeap: 0x30, numberOfHeaps: 0xe8, processHeaps: 0xf0 },
  /** _HEAP_SEGMENT (also the start of _HEAP) */
  segment: { signature: 0x10, listEntry: 0x18, heap: 0x28, baseAddress: 0x30, numberOfPages: 0x38, firstEntry: 0x40, lastValidEntry: 0x48, unCommittedPages: 0x50, ucrSegmentList: 0x60 },
  /** _HEAP */
  heap: { flags: 0x70, forceFlags: 0x74, encodeFlagMask: 0x7c, encoding: 0x80, signature: 0x98, totalFreeSize: 0xc0, virtualAllocdBlocks: 0x110, segmentList: 0x120, frontEndHeap: 0x198, frontEndHeapType: 0x1a2 },
  /** _HEAP_UCR_DESCRIPTOR: ListEntry 0x0, SegmentEntry 0x10 */
  ucr: { segmentEntry: 0x10, address: 0x20, size: 0x28 },
  /** _HEAP_VIRTUAL_ALLOC_ENTRY */
  virtualAlloc: { commitSize: 0x20, reserveSize: 0x28, busyBlock: 0x30, user: 0x40 },
  /** _LFH_HEAP */
  lfh: { heap: 0x18 },
  /** _HEAP_USERDATA_HEADER */
  userBlocks: { subSegment: 0x0, signature: 0x14, bitmapSize: 0x20, bitmapBuffer: 0x28 },
  /** _HEAP_SUBSEGMENT: AggregateExchg.Depth is the free count */
  subSegment: { userBlocks: 0x8, depth: 0x20, blockSize: 0x28, blockCount: 0x2c, sizeIndex: 0x2e },
  /** _SEGMENT_HEAP */
  segHeap: { signature: 0x10, largeAllocMetadata: 0x48, largeReservedPages: 0x58, largeCommittedPages: 0x60, memStats: 0x80 },
  /** _HEAP_LARGE_ALLOC_DATA: TreeNode (Left 0x0, Right 0x8), VirtualAddress (64 KiB aligned; low 16 bits: UnusedBytes), AllocatedPages (bits 12..63) */
  largeAlloc: { left: 0x0, right: 0x8, virtualAddress: 0x18, pages: 0x20 },
  /** _HEAP_RUNTIME_MEMORY_STATS */
  memStats: { totalReserved: 0x0, totalCommitted: 0x8, freeCommitted: 0x10, lfhFreeCommitted: 0x18 },
} as const;

export const NT_HEAP_SIGNATURE = 0xeeffeeff;
export const SEGMENT_SIGNATURE = 0xffeeffee;
export const SEGMENT_HEAP_SIGNATURE = 0xddeeddee;
export const USERBLOCKS_SIGNATURE = 0xf0e0d0c0;
const HEAP_ENTRY_BUSY = 0x01, HEAP_ENTRY_EXTRA = 0x02, HEAP_ENTRY_FILL = 0x04, HEAP_ENTRY_VIRTUAL = 0x08, HEAP_ENTRY_LAST = 0x10;
/** HEAP_ENCODE_ENTRIES in _HEAP.EncodeFlagMask */
const kEncodeEntries = 0x100000;

export type NtEntry = {
  /** block size in bytes (Size * 16) */
  size: number;
  flags: number;
  smallTagIndex: number;
  prevSize: number;
  segmentOffset: number;
  unusedBytes: number;
  checksumOk: boolean;
};

/**
 * Decodes a 16-byte _HEAP_ENTRY. The second qword is XOR-ed with the heap's Encoding (the 8 bytes
 * at _HEAP+0x88) when `key` is given; SmallTagIndex must equal Size.lo ^ Size.hi ^ Flags.
 */
export function decodeEntry(raw: Uint8Array, key: Uint8Array | null): NtEntry {
  const b = raw.slice(8, 16);
  if (key) for (let i = 0; i < 8; i++) b[i] ^= key[i];
  const size = b[0] | (b[1] << 8);
  return { size: size * 16, flags: b[2], smallTagIndex: b[3], prevSize: (b[4] | (b[5] << 8)) * 16, segmentOffset: b[6], unusedBytes: b[7], checksumOk: (b[0] ^ b[1] ^ b[2]) === b[3] };
}

/** Encodes an entry the way ntdll stores it (used by the tests to build heap images). */
export function encodeEntry(e: { size: number; flags: number; prevSize?: number; segmentOffset?: number; unusedBytes?: number }, key: Uint8Array | null): Uint8Array {
  const out = new Uint8Array(16);
  const s = e.size / 16, p = (e.prevSize ?? 0) / 16;
  const b = [s & 0xff, (s >> 8) & 0xff, e.flags, 0, p & 0xff, (p >> 8) & 0xff, e.segmentOffset ?? 0, e.unusedBytes ?? 0];
  b[3] = b[0] ^ b[1] ^ b[2];
  for (let i = 0; i < 8; i++) out[8 + i] = b[i] ^ (key ? key[i] : 0);
  return out;
}

export function entryFlags(f: number): string {
  const parts = [f & HEAP_ENTRY_BUSY ? "busy" : "free"];
  if (f & HEAP_ENTRY_EXTRA) parts.push("extra");
  if (f & HEAP_ENTRY_FILL) parts.push("fill");
  if (f & HEAP_ENTRY_VIRTUAL) parts.push("virtual");
  if (f & HEAP_ENTRY_LAST) parts.push("last");
  return parts.join("|");
}

/** Walks a LIST_ENTRY ring from its head; yields each Flink (at most `cap`). */
async function listLinks(mem: HeapMem, head: bigint, cap: number): Promise<{ links: bigint[]; error?: string }> {
  const links: bigint[] = [];
  const seen = new Set<bigint>();
  let cur = await mem.u64(head);
  while (cur !== null && cur !== head) {
    if (!cur || seen.has(cur) || links.length >= cap) return { links, error: !cur ? `null link after ${links.length} entries` : seen.has(cur) ? `list loop at ${hex(cur)}` : "list too long" };
    seen.add(cur);
    links.push(cur);
    cur = await mem.u64(cur);
  }
  return cur === null ? { links, error: `list link not readable after ${links.length} entries` } : { links };
}

export type NtHeapResult = { info: HeapInfo; chunks: HeapChunk[]; bins: BinList[]; errors: HeapError[]; truncated: boolean };

export async function exploreNtHeap(mem: HeapMem, heap: bigint, max: number): Promise<NtHeapResult> {
  const id = `nt:${hex(heap)}`;
  const H = kNt.heap, S = kNt.segment;
  const errors: HeapError[] = [];
  const chunks: HeapChunk[] = [];
  const bins: BinList[] = [];
  const info: HeapInfo = { id, kind: "NT heap", address: heap, label: `heap ${hex(heap)}`, committed: 0, reserved: 0, counters: {}, ranges: [], notes: [] };
  const hb = await mem.bytes(heap, 0x1b0);
  if (!hb) {
    errors.push({ heap: id, address: heap, message: "_HEAP not readable" });
    return { info, chunks, bins, errors, truncated: false };
  }
  const encoded = (u32At(hb, H.encodeFlagMask) & kEncodeEntries) !== 0;
  const key = encoded ? hb.slice(H.encoding + 8, H.encoding + 16) : null;
  info.counters = { flags: hex(u32At(hb, H.flags)), force_flags: hex(u32At(hb, H.forceFlags)), encoded: encoded ? "yes" : "no", total_free: u64At(hb, H.totalFreeSize) <= 0xffffffffffn ? Number(u64At(hb, H.totalFreeSize)) * 16 : "?" };

  // front end
  const feType = hb[H.frontEndHeapType], fe = u64At(hb, H.frontEndHeap);
  if (feType === 2 && fe) {
    const back = await mem.u64(fe + BigInt(kNt.lfh.heap));
    info.notes.push(back === heap ? `LFH front end at ${hex(fe)}` : `front end type 2 at ${hex(fe)} (its Heap field ${back === null ? "is unreadable" : hex(back)} does not point back: offsets may not match this build)`);
    info.counters.front_end = "LFH";
  } else info.counters.front_end = feType === 0 ? "none" : `type ${feType}`;

  // segments
  const segHead = heap + BigInt(H.segmentList);
  const sl = await listLinks(mem, segHead, 1024);
  if (sl.error) errors.push({ heap: id, address: segHead, message: `SegmentList: ${sl.error}` });
  const segs = sl.links.map((l) => l - BigInt(S.listEntry));
  if (!segs.includes(heap)) segs.unshift(heap);
  let truncated = false;
  for (const seg of segs) {
    const sb = await mem.bytes(seg, 0x70);
    if (!sb || u32At(sb, S.signature) !== SEGMENT_SIGNATURE) {
      errors.push({ heap: id, address: seg, message: sb ? `segment signature ${hex(u32At(sb, S.signature))}, expected 0xffeeffee` : "segment not readable" });
      continue;
    }
    const pages = u32At(sb, S.numberOfPages), uncommitted = u32At(sb, S.unCommittedPages);
    const base = u64At(sb, S.baseAddress), first = u64At(sb, S.firstEntry), last = u64At(sb, S.lastValidEntry);
    info.reserved = (info.reserved ?? 0) + pages * 0x1000;
    info.committed += Math.max(0, pages - uncommitted) * 0x1000;
    info.ranges.push({ base, size: pages * 0x1000, label: `segment ${hex(seg)}` });
    // uncommitted ranges of this segment
    const ucr = new Map<bigint, bigint>();
    const ul = await listLinks(mem, seg + BigInt(S.ucrSegmentList), 4096);
    for (const l of ul.links) {
      const d = l - BigInt(kNt.ucr.segmentEntry);
      const a = await mem.u64(d + BigInt(kNt.ucr.address)), n = await mem.u64(d + BigInt(kNt.ucr.size));
      if (a !== null && n !== null && n > 0n) ucr.set(a, n);
    }
    const st = await walkSegment(mem, id, first, last, key, ucr, chunks, errors, max);
    if (st === "cap") truncated = true;
  }

  // LFH subsegments inside backend blocks
  for (const c of chunks) {
    if (c.state !== "in-use" || c.size < 0x40) continue;
    const ub = await mem.bytes(c.user, 0x30);
    if (!ub || u32At(ub, kNt.userBlocks.signature) !== USERBLOCKS_SIGNATURE) continue;
    const sub = u64At(ub, kNt.userBlocks.subSegment);
    const sb = sub ? await mem.bytes(sub, 0x30) : null;
    if (!sb || u64At(sb, kNt.subSegment.userBlocks) !== c.user) {
      errors.push({ heap: id, address: c.user, message: `LFH UserBlocks whose subsegment ${hex(sub)} does not point back` });
      continue;
    }
    const blockSize = u16At(sb, kNt.subSegment.blockSize) * 16, count = u16At(sb, kNt.subSegment.blockCount), depth = u16At(sb, kNt.subSegment.depth);
    let busy = Math.max(0, count - depth);
    const bmBits = u64At(ub, kNt.userBlocks.bitmapSize), bmBuf = u64At(ub, kNt.userBlocks.bitmapBuffer);
    if (bmBits === BigInt(count) && count > 0 && bmBuf) {
      const bm = await mem.bytes(bmBuf, Math.ceil(count / 8));
      if (bm) busy = popcount(bm, count);
    }
    c.state = "lfh";
    c.bin = `lfh 0x${blockSize.toString(16)}`;
    c.note = `LFH subsegment ${hex(sub)}: ${busy}/${count} blocks of 0x${blockSize.toString(16)} busy`;
    bins.push({ heap: id, kind: "lfh", index: sb[kNt.subSegment.sizeIndex], chunkSize: blockSize, entries: [c.address], count: busy, total: count, owner: sub });
  }

  // VirtualAlloc'd blocks
  const vaHead = heap + BigInt(H.virtualAllocdBlocks);
  const va = await listLinks(mem, vaHead, 100_000);
  if (va.error) errors.push({ heap: id, address: vaHead, message: `VirtualAllocdBlocks: ${va.error}` });
  for (const e of va.links) {
    const v = await mem.bytes(e, 0x60);
    if (!v) continue;
    const commit = Number(u64At(v, kNt.virtualAlloc.commitSize));
    const reserve = Number(u64At(v, kNt.virtualAlloc.reserveSize));
    chunks.push({ address: e, user: e + BigInt(kNt.virtualAlloc.user), size: commit, userSize: Math.max(0, commit - kNt.virtualAlloc.user), state: "large", flags: "virtual", heap: id, preview: v.slice(0x40, 0x50), note: `VirtualAlloc block, reserve 0x${reserve.toString(16)}` });
    info.committed += commit;
    info.reserved = (info.reserved ?? 0) + reserve;
    info.ranges.push({ base: e, size: reserve, label: "virtual alloc" });
  }
  info.counters.segments = segs.length;
  info.counters.virtual_allocs = va.links.length;
  return { info, chunks, bins, errors, truncated };
}

function popcount(b: Uint8Array, bits: number): number {
  let n = 0;
  for (let i = 0; i < bits; i++) if (b[i >> 3] & (1 << (i & 7))) n++;
  return n;
}

/** Backend entries of one segment, FirstEntry → LastValidEntry, skipping uncommitted ranges. */
export async function walkSegment(mem: HeapMem, heap: string, first: bigint, last: bigint, key: Uint8Array | null, ucr: Map<bigint, bigint>, out: HeapChunk[], errors: HeapError[], max: number): Promise<"done" | "error" | "cap"> {
  let p = first;
  while (p < last) {
    if (out.length >= max || mem.exhausted) return "cap";
    const skip = ucr.get(p);
    if (skip) {
      p += skip;
      continue;
    }
    const raw = await mem.bytes(p, 0x20);
    if (!raw) {
      errors.push({ heap, address: p, message: "heap entry not readable" });
      return "error";
    }
    const e = decodeEntry(raw, key);
    if (!e.checksumOk || e.size === 0 || p + BigInt(e.size) > last) {
      errors.push({ heap, address: p, message: !e.checksumOk ? "heap entry checksum mismatch (corrupt, or a different Encoding key)" : `bad entry size 0x${e.size.toString(16)}` });
      return "error";
    }
    const busy = (e.flags & HEAP_ENTRY_BUSY) !== 0;
    const userSize = busy ? (e.unusedBytes >= 0x10 && e.unusedBytes <= e.size ? e.size - e.unusedBytes : e.size - 16) : e.size - 16;
    out.push({ address: p, user: p + 16n, size: e.size, userSize, state: busy ? "in-use" : "free", flags: entryFlags(e.flags), heap, preview: raw.slice(16, 32) });
    p += BigInt(e.size);
  }
  return "done";
}

export type SegmentHeapResult = NtHeapResult;

/** Segment heap: large allocations (red-black tree, in order) and the MemStats summary. */
export async function exploreSegmentHeap(mem: HeapMem, heap: bigint, max: number): Promise<SegmentHeapResult> {
  const id = `seg:${hex(heap)}`;
  const G = kNt.segHeap, A = kNt.largeAlloc, M = kNt.memStats;
  const errors: HeapError[] = [];
  const chunks: HeapChunk[] = [];
  const info: HeapInfo = { id, kind: "segment heap", address: heap, label: `segment heap ${hex(heap)}`, committed: 0, counters: {}, ranges: [], notes: ["VS and LFH blocks are summarised from MemStats, not walked"] };
  const hb = await mem.bytes(heap, 0xd8);
  if (!hb) {
    errors.push({ heap: id, address: heap, message: "_SEGMENT_HEAP not readable" });
    return { info, chunks, bins: [], errors, truncated: false };
  }
  const pages = (o: number) => u64At(hb, o);
  const reserved = pages(G.memStats + M.totalReserved), committed = pages(G.memStats + M.totalCommitted);
  const sane = committed <= reserved && reserved < 1n << 36n;
  if (sane) {
    info.reserved = Number(reserved) * 0x1000;
    info.committed = Number(committed) * 0x1000;
    info.counters = {
      reserved_pages: Number(reserved), committed_pages: Number(committed),
      free_committed_pages: Number(pages(G.memStats + M.freeCommitted)), lfh_free_committed_pages: Number(pages(G.memStats + M.lfhFreeCommitted)),
      large_reserved_pages: Number(pages(G.largeReservedPages)), large_committed_pages: Number(pages(G.largeCommittedPages)),
    };
  } else errors.push({ heap: id, address: heap + BigInt(G.memStats), message: "MemStats do not look sane (offsets may not match this build)" });

  // LargeAllocMetadata: RTL_RB_TREE { Root, Encoded:1 | Min }
  const root = u64At(hb, G.largeAllocMetadata);
  const encodedTree = (u64At(hb, G.largeAllocMetadata + 8) & 1n) === 1n;
  const child = (node: bigint, v: bigint) => (encodedTree && v ? v ^ node : v);
  const stack: bigint[] = [];
  const seen = new Set<bigint>();
  let n = root, truncated = false;
  while ((n || stack.length) && !truncated) {
    while (n) {
      if (seen.has(n) || n & 7n) {
        errors.push({ heap: id, address: n, message: seen.has(n) ? "large-alloc tree loop" : `bad tree node ${hex(n)}` });
        n = 0n;
        break;
      }
      seen.add(n);
      stack.push(n);
      const l = await mem.u64(n + BigInt(A.left));
      n = l === null ? 0n : child(n, l);
    }
    const cur = stack.pop();
    if (cur === undefined) break;
    const d = await mem.bytes(cur, 0x28);
    if (!d) {
      errors.push({ heap: id, address: cur, message: "large-alloc node not readable" });
      break;
    }
    const vaRaw = u64At(d, A.virtualAddress);
    const addr = vaRaw & ~0xffffn, unused = Number(vaRaw & 0xffffn);
    const size = Number(u64At(d, A.pages) >> 12n) * 0x1000;
    if (addr & 0xfffn || size <= 0) errors.push({ heap: id, address: cur, message: `large-alloc node with address ${hex(addr)} size 0x${size.toString(16)}` });
    else chunks.push({ address: addr, user: addr, size, userSize: Math.max(0, size - unused), state: "large", flags: "large", heap: id, note: `large alloc (node ${hex(cur)})` });
    if (chunks.length >= max) truncated = true;
    n = child(cur, u64At(d, A.right));
  }
  info.counters.large_allocs = chunks.length;
  for (const c of chunks) info.ranges.push({ base: c.address, size: c.size, label: "large alloc" });
  return { info, chunks, bins: [], errors, truncated };
}

export type HeapKind = "nt" | "segment" | "unknown";

export async function heapKind(mem: HeapMem, heap: bigint): Promise<HeapKind> {
  const s = await mem.u32(heap + BigInt(kNt.segHeap.signature));
  if (s === SEGMENT_HEAP_SIGNATURE) return "segment";
  const n = await mem.u32(heap + BigInt(kNt.heap.signature));
  return n === NT_HEAP_SIGNATURE ? "nt" : "unknown";
}

/** Every heap of PEB->ProcessHeaps. */
export async function exploreWindows(mem: HeapMem, peb: bigint, opts: { maxChunks?: number } = {}): Promise<HeapReport> {
  const P = kNt.peb;
  const max = opts.maxChunks ?? 1_000_000;
  const report: HeapReport = { platform: "windows", source: "", heaps: [], chunks: [], bins: [], errors: [], notes: [], truncated: false };
  const count = await mem.u32(peb + BigInt(P.numberOfHeaps));
  const arr = await mem.u64(peb + BigInt(P.processHeaps));
  const def = await mem.u64(peb + BigInt(P.processHeap));
  if (count === null || arr === null || !arr) {
    report.source = `PEB ${hex(peb)} not readable`;
    return report;
  }
  const n = Math.min(count, 1024);
  report.source = `PEB ${hex(peb)} → ProcessHeaps (${count} heaps)`;
  const list = await mem.bytes(arr, n * 8);
  if (!list) {
    report.errors.push({ heap: "peb", address: arr, message: "ProcessHeaps array not readable" });
    return report;
  }
  for (let i = 0; i < n; i++) {
    const h = u64At(list, i * 8);
    if (!h) continue;
    const kind = await heapKind(mem, h);
    const left = Math.max(0, max - report.chunks.length);
    if (kind === "unknown") {
      report.errors.push({ heap: `heap:${hex(h)}`, address: h, message: "neither an NT heap (0xEEFFEEFF at +0x98) nor a segment heap (0xDDEEDDEE at +0x10)" });
      continue;
    }
    const r = kind === "nt" ? await exploreNtHeap(mem, h, left) : await exploreSegmentHeap(mem, h, left);
    r.info.label = `${h === def ? "process heap" : `heap ${i}`} ${hex(h)}`;
    report.heaps.push(r.info);
    report.chunks.push(...r.chunks);
    report.bins.push(...r.bins);
    report.errors.push(...r.errors);
    if (r.truncated) report.truncated = true;
  }
  report.chunks.sort((x, y) => (x.address < y.address ? -1 : x.address > y.address ? 1 : 0));
  return report;
}
