// A full cross-reference index over a module image: every direct branch and
// every RIP-relative data reference, with the direction (to / from).
//
// The byte-pattern finder in xrefs.ts answers "what points at this address";
// this builds the whole graph in one pass so the UI can list both directions
// and draw the callers of a function.
import { parsePe, type PeInfo } from "./pe";

export type XrefKind = "call" | "jmp" | "jcc" | "rip";

export type Xref = {
  /** RVA of the instruction that holds the reference */
  fromRva: number;
  /** RVA the reference points at */
  toRva: number;
  kind: XrefKind;
};

export type XrefIndex = {
  /** target RVA -> references to it */
  to: Map<number, Xref[]>;
  /** source RVA -> references made from it */
  from: Map<number, Xref[]>;
  all: Xref[];
};

/**
 * Builds the index. `ranges` are the RVA ranges to scan (normally the
 * executable sections). `base` is only used for the reported addresses.
 */
export function buildXrefIndex(img: Uint8Array, ranges: readonly { rva: number; size: number }[]): XrefIndex {
  const to = new Map<number, Xref[]>();
  const from = new Map<number, Xref[]>();
  const all: Xref[] = [];
  if (img.length < 8) return { to, from, all };

  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const push = (x: Xref) => {
    all.push(x);
    const list = to.get(x.toRva);
    if (list) list.push(x);
    else to.set(x.toRva, [x]);
    const src = from.get(x.fromRva);
    if (src) src.push(x);
    else from.set(x.fromRva, [x]);
  };

  for (const r of ranges) {
    const start = r.rva;
    const end = Math.min(img.length, r.rva + r.size);
    for (let i = start; i + 5 <= end; i++) {
      const b = img[i];
      // call rel32 / jmp rel32
      if (b === 0xe8 || b === 0xe9) {
        const rel = dv.getInt32(i + 1, true);
        push({ fromRva: i, toRva: (i + 5 + rel) >>> 0, kind: b === 0xe8 ? "call" : "jmp" });
        continue;
      }
      // jcc rel32 (0F 80..8F)
      if (b === 0x0f && (img[i + 1] & 0xf0) === 0x80 && i + 6 <= end) {
        const rel = dv.getInt32(i + 2, true);
        push({ fromRva: i, toRva: (i + 6 + rel) >>> 0, kind: "jcc" });
        continue;
      }
      // ModRM mod=00 rm=101 -> [rip+disp32]. The ModRM byte sits at i-1 and the
      // displacement at i; the instruction ends four bytes later.
      if (i >= 2 && i + 4 <= end && (img[i - 1] & 0xc7) === 0x05) {
        const disp = dv.getInt32(i, true);
        // Layout: [REX] opcode ModRM disp32. The displacement is relative to
        // the end of the instruction, which is four bytes after it.
        const rex = i >= 3 && img[i - 3] >= 0x40 && img[i - 3] <= 0x4f;
        push({ fromRva: i - 1 - (rex ? 2 : 1), toRva: (i + 4 + disp) >>> 0, kind: "rip" });
      }
    }
  }
  return { to, from, all };
}

/** The executable ranges of a module, for buildXrefIndex. */
export function executableRanges(img: Uint8Array, pe?: PeInfo): { rva: number; size: number }[] {
  let info = pe;
  if (!info) {
    try {
      info = parsePe(img);
    } catch {
      return [];
    }
  }
  return info.sections.filter((s) => s.x && s.vsize > 0).map((s) => ({ rva: s.rva, size: s.vsize }));
}
