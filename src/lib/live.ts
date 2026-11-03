// analysis that combines module images with the pure analysers
import { moduleOf, toBig, type Module } from "./hex";
import { loadImage } from "./memory";
import { parseRuntimeFunctions } from "./analysis/pe";
import { buildXrefIndex, executableRanges, type XrefIndex } from "./analysis/xrefindex";
import { request } from "./client";
import { findXrefs, type Xref } from "./analysis/xrefs";

export type LiveXref = Xref & { address: bigint };

export async function xrefsTo(address: string, modules: readonly Module[]): Promise<LiveXref[]> {
  const a = toBig(address);
  const m = moduleOf(a, modules);
  if (!m) throw new Error("address is outside every module");
  const img = await loadImage(m);
  let ranges = [{ rva: 0x1000, size: Math.max(0, m.size - 0x1000) }];
  const x = executableRanges(img); // PE sections or ELF PT_LOAD segments
  if (x.length) ranges = x;
  const base = toBig(m.base);
  return findXrefs(img, ranges, Number(a - base)).map((x) => ({ ...x, address: base + BigInt(x.rva) }));
}


const xrefIndexes = new Map<string, Promise<XrefIndex>>();

/** The module's whole reference index, built once per module. */
export function moduleXrefIndex(m: Module): Promise<XrefIndex> {
  const key = `${m.name}@${m.base}`;
  let p = xrefIndexes.get(key);
  if (!p) {
    p = loadImage(m).then((img) => buildXrefIndex(img, executableRanges(img)));
    xrefIndexes.set(key, p);
    p.catch(() => xrefIndexes.delete(key));
  }
  return p;
}

/** Function starts from the x64 exception directory, as absolute {address, size}. */
export async function pdataFunctions(m: Module): Promise<{ address: string; size: number }[]> {
  const img = await loadImage(m);
  try {
    const base = toBig(m.base);
    return parseRuntimeFunctions(img).filter((f) => !f.chained).map((f) => ({ address: "0x" + (base + BigInt(f.begin)).toString(16), size: f.end - f.begin }));
  } catch {
    return [];
  }
}

export type CodeHit = { address: string; text: string };

/**
 * Disassembles the module's executable ranges in 64 KiB windows and returns the instructions whose
 * text matches `re`. Stops at `limit` hits or when `signal.aborted`.
 */
export async function searchModuleCode(m: Module, re: RegExp, opts: { limit?: number; onProgress?: (f: number) => void; signal?: { aborted: boolean } } = {}): Promise<CodeHit[]> {
  const img = await loadImage(m);
  let ranges = [{ rva: 0x1000, size: Math.max(0, m.size - 0x1000) }];
  const x = executableRanges(img); // PE sections or ELF PT_LOAD segments; else the whole image
  if (x.length) ranges = x;
  const base = toBig(m.base);
  const total = ranges.reduce((n, r) => n + r.size, 0) || 1;
  let done = 0;
  const hits: CodeHit[] = [];
  const limit = opts.limit ?? 500;
  for (const r of ranges) {
    let a = base + BigInt(r.rva);
    const end = a + BigInt(r.size);
    while (a < end && hits.length < limit && !opts.signal?.aborted) {
      const size = Number(end - a < 0x10000n ? end - a : 0x10000n);
      const res = await request<{ results: { address: string; length: number; text: string }[] }>("disassemble", { address: "0x" + a.toString(16), size }, true).catch(() => null);
      const lines = res?.results ?? [];
      for (const l of lines) if (re.test(l.text)) hits.push({ address: l.address, text: l.text });
      const last = lines[lines.length - 1];
      const next = last ? BigInt(last.address) + BigInt(last.length) : a + BigInt(size);
      done += Number(next - a);
      a = next > a ? next : a + 1n; // undecodable byte: skip it
      opts.onProgress?.(Math.min(1, done / total));
    }
  }
  return hits.slice(0, limit);
}
