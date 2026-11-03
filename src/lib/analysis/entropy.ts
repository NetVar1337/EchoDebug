// Section entropy and packer heuristics.
// High-entropy executable sections usually mean packed or encrypted code;
// this is the same signal Reverse-Slap's packer analysis looks at.
import { parsePe, type PeInfo } from "./pe";

export type SectionEntropy = {
  name: string;
  rva: number;
  size: number;
  entropy: number;
  executable: boolean;
};

export type PackerVerdict = {
  packed: boolean;
  confidence: number;
  reasons: string[];
};

/** Shannon entropy of a byte range, 0..8. */
export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const b of bytes) counts[b]++;
  let h = 0;
  for (const c of counts) {
    if (!c) continue;
    const p = c / bytes.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function sectionEntropies(img: Uint8Array, pe?: PeInfo): SectionEntropy[] {
  let info = pe;
  if (!info) {
    try {
      info = parsePe(img);
    } catch {
      return [];
    }
  }
  const out: SectionEntropy[] = [];
  for (const s of info.sections) {
    const start = s.rva;
    const end = Math.min(img.length, s.rva + Math.max(s.vsize, s.rawSize));
    if (end <= start) continue;
    out.push({
      name: s.name.trim(),
      rva: s.rva,
      size: end - start,
      entropy: shannonEntropy(img.subarray(start, end)),
      executable: s.x,
    });
  }
  return out;
}

/** Section names commonly produced by protectors. */
const kPackerNames = [
  "upx", "vmp", "vmprotect", "themida", "aspack", "asprotect", "nspack", "enigma",
  "mpress", "pecompact", "petite", "upack", "y0da", "rlpack", "exe32pack", "fsg",
  "mew", "molebox", "obsidium", "armadillo", "execryptor",
];

/**
 * Heuristic verdict: a packed image has either a known protector section
 * name, a very high-entropy executable section, or an import table with
 * almost no entries next to a large executable section.
 */
export function detectPacker(img: Uint8Array, pe?: PeInfo): PackerVerdict {
  let info = pe;
  if (!info) {
    try {
      info = parsePe(img);
    } catch {
      return { packed: false, confidence: 0, reasons: [] };
    }
  }
  const reasons: string[] = [];
  let score = 0;

  for (const s of info.sections) {
    const n = s.name.toLowerCase();
    if (kPackerNames.some((p) => n.includes(p))) {
      score += 0.6;
      reasons.push(`section "${s.name.trim()}" matches a known packer`);
    }
  }

  const ent = sectionEntropies(img, info);
  for (const e of ent) {
    if (e.executable && e.entropy > 7.2) {
      score += 0.35;
      reasons.push(`section "${e.name}" has entropy ${e.entropy.toFixed(2)} (encrypted or compressed?)`);
    }
  }

  const importCount = info.imports.reduce((n, d) => n + d.funcs.length, 0);
  const execSize = info.sections.filter((s) => s.x).reduce((n, s) => n + s.vsize, 0);
  if (importCount <= 2 && execSize > 0x2000) {
    score += 0.25;
    reasons.push(`only ${importCount} import${importCount === 1 ? "" : "s"} for ${(execSize / 1024) | 0} KiB of code`);
  }

  // The entry point should sit inside an executable section.
  const entrySec = info.sections.find((s) => info!.entryRva >= s.rva && info!.entryRva < s.rva + s.vsize);
  if (!entrySec) {
    score += 0.2;
    reasons.push("entry point is not inside any section");
  }

  const confidence = Math.min(1, score);
  return { packed: confidence >= 0.5, confidence, reasons };
}
