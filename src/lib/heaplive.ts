// Heap explorer against the attached process: picks the allocator from the module list (ntdll.dll →
// Windows NT/segment heaps via the PEB, libc → glibc malloc), feeds the parsers in
// analysis/heap through the relay's `read` verb, and adds the live extras (RTTI type guesses,
// "who points here"). One report is cached per process until refreshed.
import { request } from "./client";
import { fmtAddr, moduleOf, toBig, type Module } from "./hex";
import { loadImage, readBytes } from "./memory";
import { HeapMem } from "./analysis/heap/reader";
import { exploreGlibc, glibcVersion } from "./analysis/heap/glibc";
import { exploreWindows } from "./analysis/heap/nt";
import { scanForPointers, type HeapChunk, type HeapReport } from "./analysis/heap/model";
import { useConn } from "@/store/conn";

type Region = { base: string; size: number; present?: boolean; writable?: boolean };

let cache: { pid: number; report: HeapReport } | null = null;
let running: { pid: number; p: Promise<HeapReport> } | null = null;
const types = new Map<bigint, string>();

export function cachedReport(): HeapReport | null {
  const pid = useConn.getState().target?.pid;
  return cache && cache.pid === pid ? cache.report : null;
}

async function regions(): Promise<Region[]> {
  const r = await request<{ regions: Region[] }>("regions", { max: 200000 }, true).catch(() => null);
  return (r?.regions ?? []).filter((x) => x.present !== false);
}

export const isLibc = (name: string): boolean => /^libc(\.so|-[\d.]+\.so)/i.test(name);

/** Walks every heap of the attached process (cached per pid unless `refresh`; concurrent calls share one walk). */
export async function exploreHeaps(opts: { refresh?: boolean; onStatus?: (s: string) => void } = {}): Promise<HeapReport> {
  const { target } = useConn.getState();
  if (!target) throw new Error("attach to a process first");
  if (!opts.refresh && cache && cache.pid === target.pid) return cache.report;
  if (running && running.pid === target.pid) return running.p;
  const p = walk(target, opts.onStatus);
  running = { pid: target.pid, p };
  try {
    return await p;
  } finally {
    if (running?.p === p) running = null;
  }
}

async function walk(target: { pid: number; peb?: string }, onStatus?: (s: string) => void): Promise<HeapReport> {
  const opts = { onStatus };
  const { modules } = useConn.getState();
  types.clear();
  const mem = new HeapMem((a, n) => readBytes(a, n), { maxRead: 1 << 30 });
  const ntdll = modules.find((m) => m.name.toLowerCase() === "ntdll.dll");
  const libc = modules.find((m) => isLibc(m.name));
  let report: HeapReport;
  if (ntdll) {
    if (!target.peb || toBig(target.peb) === 0n) throw new Error("the backend did not report the PEB address of this process");
    opts.onStatus?.("walking PEB->ProcessHeaps…");
    report = await exploreWindows(mem, toBig(target.peb));
  } else if (libc) {
    opts.onStatus?.(`reading ${libc.name}…`);
    const version = glibcVersion(await loadImage(libc));
    const sym = await request<{ address?: string; success?: boolean }>("resolve_export", { module: libc.name, name: "main_arena" }, true).catch(() => null);
    const mainArena = sym?.success && sym.address ? toBig(sym.address) : null;
    const regs = await regions();
    opts.onStatus?.("walking arenas…");
    report = await exploreGlibc({
      mem, version, mainArena, mainArenaSource: `${libc.name} symbols`,
      regions: regs.map((r) => ({ base: toBig(r.base), size: r.size, writable: r.writable })),
      libc: { name: libc.name, base: toBig(libc.base), size: libc.size },
      modules: modules.filter((m) => m !== libc).map((m) => ({ base: toBig(m.base), size: m.size })),
    });
  } else throw new Error("no heap allocator recognised: ntdll.dll (Windows) or glibc's libc.so.6 (Linux) must be loaded");
  if (mem.exhausted) report.notes.push("stopped after reading 1 GiB of heap memory");
  cache = { pid: target.pid, report };
  return report;
}

/** RTTI class name of a chunk whose first qword points into a module (a vtable), cached. */
export function typeOf(c: HeapChunk): string | undefined {
  return types.get(c.user);
}

/**
 * Resolves RTTI names for the chunks that start with a module pointer (a vtable candidate), in
 * batches of 256 through `rtti_resolve_batch`; at most `max` chunks per call.
 */
export async function resolveTypes(chunks: readonly HeapChunk[], modules: readonly Module[], opts: { max?: number; onBatch?: (named: number) => void; live?: () => boolean } = {}): Promise<number> {
  const want = chunks.filter((c) => {
    if (types.has(c.user) || !c.preview || c.preview.length < 8 || c.state === "free" || c.state === "top") return false;
    const q = new DataView(c.preview.buffer, c.preview.byteOffset, 8).getBigUint64(0, true);
    return q !== 0n && moduleOf(q, modules) !== undefined;
  }).slice(0, opts.max ?? 256);
  let n = 0;
  for (let i = 0; i < want.length && (opts.live?.() ?? true); i += 256) {
    const batch = want.slice(i, i + 256);
    for (const c of batch) types.set(c.user, "");
    const r = await request<{ results: { success: boolean; name?: string }[] }>("rtti_resolve_batch", { addresses: batch.map((c) => fmtAddr(c.user)) }, true).catch(() => null);
    let got = 0;
    r?.results?.forEach((x, j) => {
      if (x.success && x.name && batch[j]) {
        types.set(batch[j].user, x.name);
        got++;
      }
    });
    n += got;
    if (got) opts.onBatch?.(n);
  }
  return n;
}

export type PointerHit = { address: bigint; inside: boolean };

/**
 * "Who points here": every 8-aligned qword in readable memory whose value lies inside the chunk.
 * Bounded by `maxBytes` scanned and `limit` hits; `signal.aborted` stops it.
 */
export async function whoPointsHere(c: HeapChunk, opts: { maxBytes?: number; limit?: number; signal?: { aborted: boolean }; onProgress?: (scanned: number) => void } = {}): Promise<{ hits: PointerHit[]; scanned: number; truncated: boolean }> {
  const max = opts.maxBytes ?? 512 * 1024 * 1024, limit = opts.limit ?? 200;
  const lo = c.address, hi = c.address + BigInt(Math.max(c.size, 1));
  const hits: PointerHit[] = [];
  let scanned = 0;
  for (const r of await regions()) {
    const end = toBig(r.base) + BigInt(r.size);
    for (let a = toBig(r.base); a < end; a += 0x100000n) {
      if (scanned >= max || hits.length >= limit || opts.signal?.aborted) return { hits, scanned, truncated: true };
      const n = Number(end - a < 0x100000n ? end - a : 0x100000n);
      const buf = await readBytes(a, n).catch(() => null);
      scanned += n;
      opts.onProgress?.(scanned);
      if (!buf) continue;
      for (const p of scanForPointers(buf, a, lo, hi, limit - hits.length)) hits.push({ address: p, inside: p >= lo && p < hi });
    }
  }
  return { hits, scanned, truncated: false };
}
