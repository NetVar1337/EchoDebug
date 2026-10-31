// Code caves: runs of a repeated filler byte inside executable sections that
// can hold injected code (0xCC padding, 0x90 nops, 0x00 slack).
import { parsePe } from "./pe";

export type CodeCave = {
  rva: number;
  address: string;
  size: number;
  fill: number;
  section: string;
};

export type CaveOptions = {
  /** smallest run worth reporting, in bytes */
  minSize?: number;
  /** filler bytes to look for */
  fills?: number[];
};

export function findCodeCaves(img: Uint8Array, base?: bigint, opts: CaveOptions = {}): CodeCave[] {
  const minSize = opts.minSize ?? 16;
  const fills = opts.fills ?? [0xcc, 0x90, 0x00];
  let pe;
  try {
    pe = parsePe(img);
  } catch {
    return [];
  }
  const out: CodeCave[] = [];
  for (const s of pe.sections) {
    if (!s.x) continue;
    const start = s.rva;
    const end = Math.min(img.length, s.rva + s.vsize);
    let i = start;
    while (i < end) {
      const fill = img[i];
      if (!fills.includes(fill)) {
        i++;
        continue;
      }
      let j = i + 1;
      while (j < end && img[j] === fill) j++;
      const size = j - i;
      if (size >= minSize) {
        out.push({
          rva: i,
          address: "0x" + ((base ?? 0n) + BigInt(i)).toString(16),
          size,
          fill,
          section: s.name.trim(),
        });
      }
      i = j;
    }
  }
  // Big caves first, then by address.
  return out.sort((a, b) => b.size - a.size || a.rva - b.rva);
}
