// Live unpacking and batch decryption on top of the emulate verb.
import { request } from "./client";
import { fmtAddr, moduleOf, toBig, type Module } from "./hex";
import { loadImage } from "./memory";
import { pdataFunctions, xrefsTo } from "./live";
import { moduleFunctions } from "./flirtlive";
import { buildExports } from "./analysis/exports";
import { parsePe } from "./analysis/pe";
import { findOep, type ExportIndex, type OepCandidate } from "./analysis/unpack";
import { bestString, buffersFromLog, type Decoded, type LogEntry } from "./analysis/decrypt";

type Emu = { error_name: string; regs: Record<string, string>; trace: string[]; mem_log?: LogEntry[]; instructions: number; reached_end: boolean };

/** Emulates the module from its entry point and proposes original entry points. */
export async function oepCandidates(m: Module, maxInsns = 2_000_000): Promise<{ candidates: OepCandidate[]; instructions: number; stop: string }> {
  const img = await loadImage(m);
  const pe = parsePe(img);
  const base = toBig(m.base);
  const r = await request<Emu>("emulate", { start: fmtAddr(base + BigInt(pe.entryRva)), end: "0x1", max_insns: maxInsns, timeout_us: 5_000_000, trace: true, trace_limit: 100000, mem_log: true, mem_log_limit: 20000 });
  const writes = (r.mem_log ?? []).filter((e) => e.access.includes("w")).map((e) => ({ address: BigInt(e.address), size: e.size }));
  const sections = pe.sections.map((s) => ({ start: base + BigInt(s.rva), end: base + BigInt(s.rva + Math.max(s.vsize, s.rawSize)), name: s.name }));
  return { candidates: findOep(r.trace.map((t) => BigInt(t)), writes, sections), instructions: r.instructions, stop: r.error_name };
}

/** Export address → name for every loaded module except `skip`. */
export async function exportIndex(modules: readonly Module[], skip: Module, onProgress?: (done: number, total: number) => void): Promise<ExportIndex> {
  const idx: ExportIndex = new Map();
  const list = modules.filter((x) => x.base !== skip.base);
  for (const [i, x] of list.entries()) {
    const img = await loadImage(x).catch(() => null);
    if (img) {
      try {
        const ex = buildExports(img, toBig(x.base));
        for (const e of ex.entries) if (!e.forwarder) idx.set(BigInt(e.address), { dll: x.name, name: e.name, ...(e.ordinal !== undefined ? { ordinal: e.ordinal } : {}) });
      } catch { /* not a PE */ }
    }
    onProgress?.(i + 1, list.length);
  }
  return idx;
}

export type DecryptRow = { site: string; fn: string | null; result: Decoded | null; stop: string; error?: string };

/**
 * Runs `routine` at each of its call sites: emulate from the enclosing function's start to the
 * instruction after the call, then decode the most string-like buffer the run wrote.
 */
export async function batchDecrypt(routine: bigint, modules: readonly Module[], opts: { limit?: number; onProgress?: (done: number, total: number) => void; signal?: { aborted: boolean } } = {}): Promise<DecryptRow[]> {
  const m = moduleOf(routine, modules);
  if (!m) throw new Error("the routine is outside every module");
  const sites = (await xrefsTo(fmtAddr(routine), modules)).filter((x) => x.kind === "call").slice(0, opts.limit ?? 200);
  const fns = [...(await pdataFunctions(m).catch(() => [])), ...(await moduleFunctions(m).catch(() => []))].map((f) => ({ start: toBig(f.address), end: toBig(f.address) + BigInt(Math.max(1, f.size)) }));
  const out: DecryptRow[] = [];
  for (const [i, s] of sites.entries()) {
    if (opts.signal?.aborted) break;
    const site = s.address;
    const fn = fns.filter((f) => f.start <= site && site < f.end).sort((a, b) => (a.end - a.start < b.end - b.start ? -1 : 1))[0];
    const row: DecryptRow = { site: fmtAddr(site), fn: fn ? fmtAddr(fn.start) : null, result: null, stop: "" };
    try {
      const call = await request<{ results: { length: number }[] }>("disassemble", { address: fmtAddr(site), size: 16 });
      const end = site + BigInt(call.results[0]?.length ?? 5);
      const r = await request<Emu>("emulate", { start: fmtAddr(fn?.start ?? site), end: fmtAddr(end), max_insns: 500_000, timeout_us: 2_000_000, mem_log: true, mem_log_limit: 20000 });
      row.stop = r.reached_end ? "returned" : r.error_name;
      const rsp = r.regs.rsp ? BigInt(r.regs.rsp) : 0n;
      const onStack = (a: bigint) => rsp !== 0n && a >= rsp - 0x10000n && a < rsp + 0x10000n;
      row.result = bestString(buffersFromLog(r.mem_log ?? [], onStack)) ?? bestString(buffersFromLog(r.mem_log ?? []));
    } catch (e) {
      row.error = String(e instanceof Error ? e.message : e);
    }
    out.push(row);
    opts.onProgress?.(i + 1, sites.length);
  }
  return out;
}
