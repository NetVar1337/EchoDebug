// Classifies pointer values for the struct guesser: into a module's code, read-only data or
// writable data, or into some other mapped region (heap/stack).
import { request } from "./client";
import { toBig, type Module } from "./hex";
import { loadImage } from "./memory";
import { parsePe } from "./analysis/pe";
import { elfExecutableRanges } from "./analysis/xrefindex";
import { isElf } from "./analysis/elf";
import type { PtrKind } from "./analysis/structguess";

type Range = { lo: bigint; hi: bigint; kind: PtrKind };

export async function pointerClassifier(modules: readonly Module[]): Promise<(v: bigint) => PtrKind | null> {
  const ranges: Range[] = [];
  for (const m of modules) {
    const base = toBig(m.base);
    const img = await loadImage(m).catch(() => null);
    let added = false;
    if (img) {
      try {
        if (isElf(img)) {
          for (const r of elfExecutableRanges(img)) ranges.push({ lo: base + BigInt(r.rva), hi: base + BigInt(r.rva + r.size), kind: "code" });
        } else {
          for (const s of parsePe(img).sections) {
            const kind: PtrKind = s.x ? "code" : s.w ? "data" : "rdata";
            ranges.push({ lo: base + BigInt(s.rva), hi: base + BigInt(s.rva + Math.max(s.vsize, s.rawSize)), kind });
          }
        }
        added = true;
      } catch { /* headers unreadable */ }
    }
    ranges.push({ lo: base, hi: base + BigInt(m.size), kind: added ? "rdata" : "data" });
  }
  const r = await request<{ regions: { base: string; size: number; present?: boolean }[] }>("regions", { max: 200000 }, true).catch(() => null);
  for (const x of r?.regions ?? []) if (x.present !== false) ranges.push({ lo: BigInt(x.base), hi: BigInt(x.base) + BigInt(x.size), kind: "heap" });
  // first match wins: section ranges before whole-module and region fallbacks
  return (v) => ranges.find((x) => v >= x.lo && v < x.hi)?.kind ?? null;
}
