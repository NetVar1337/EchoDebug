import { parsePe } from "./pe";

export type CodeCave = {
  rva: number;
  address: string;
  size: number;
  fill: number;
  section: string;
};

const kDefaultMinSize = 16;
const kDefaultFills = [0xcc, 0x90, 0x00];

function formatAddress(rva: number, base?: bigint): string {
  if (base === undefined) return `0x${rva.toString(16)}`;
  return `0x${(base + BigInt(rva)).toString(16)}`;
}

/**
 * Finds runs of a single repeated fill byte inside executable PE sections.
 *
 * `img` is a mapped image indexed by RVA.  Only sections marked executable are
 * considered; the mapped extent of a section is `max(virtualSize, rawSize)`
 * clamped to the image length.  Zero-filled runs are reported as well, but they
 * rank behind non-zero fills of the same size because they are usually plain
 * data padding rather than intentional code caves.
 */
export function findCodeCaves(
  img: Uint8Array,
  base?: bigint,
  opts?: { minSize?: number; fills?: number[] },
): CodeCave[] {
  const minSize = Math.max(1, opts?.minSize ?? kDefaultMinSize);
  const fills = new Set<number>((opts?.fills ?? kDefaultFills).map((f) => f & 0xff));

  let pe;
  try {
    pe = parsePe(img);
  } catch {
    return [];
  }

  const caves: CodeCave[] = [];

  for (const section of pe.sections) {
    if (!section.x) continue;
    const start = section.rva;
    const extent = Math.max(section.vsize, section.rawSize);
    const end = Math.min(img.length, start + extent);
    if (end <= start) continue;

    let runStart = start;
    let runFill = img[start];

    for (let i = start + 1; i <= end; i++) {
      const byte = i < end ? img[i] : -1;
      if (byte !== runFill) {
        const length = i - runStart;
        if (length >= minSize && fills.has(runFill)) {
          caves.push({
            rva: runStart,
            address: formatAddress(runStart, base),
            size: length,
            fill: runFill,
            section: section.name,
          });
        }
        runStart = i;
        runFill = byte;
      }
    }
  }

  caves.sort(
    (a, b) =>
      b.size - a.size ||
      (a.fill === 0 ? 1 : 0) - (b.fill === 0 ? 1 : 0) ||
      a.rva - b.rva,
  );

  return caves;
}
