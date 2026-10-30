// analysis that combines module images with the pure analysers
import { moduleOf, toBig, type Module } from "./hex";
import { loadImage } from "./memory";
import { parsePe } from "./analysis/pe";
import { findXrefs, type Xref } from "./analysis/xrefs";

export type LiveXref = Xref & { address: bigint };

export async function xrefsTo(address: string, modules: readonly Module[]): Promise<LiveXref[]> {
  const a = toBig(address);
  const m = moduleOf(a, modules);
  if (!m) throw new Error("address is outside every module");
  const img = await loadImage(m);
  let ranges = [{ rva: 0x1000, size: Math.max(0, m.size - 0x1000) }];
  try {
    const x = parsePe(img).sections.filter((s) => s.x);
    if (x.length) ranges = x.map((s) => ({ rva: s.rva, size: s.vsize }));
  } catch { /* headers unreadable: scan the whole image */ }
  const base = toBig(m.base);
  return findXrefs(img, ranges, Number(a - base)).map((x) => ({ ...x, address: base + BigInt(x.rva) }));
}
