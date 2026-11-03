// API-hash / indirect-call resolution (#12): recognize the hash algorithm compiled into a
// resolver routine from its constants and rotate instructions, and name the resulting API-hash
// scheme (ror13-add, rol8-ror4, …) so the matched hash values can be looked up in a hash DB.
// Works on plain disassembly text lines, so it is usable on any listing (target or file).

export type HashAlgo = {
  id: string;
  name: string;
  /** distinguishing immediates that appear in the routine */
  constants: number[];
  bits: 32 | 64;
};

export const kHashAlgos: HashAlgo[] = [
  { id: "crc32", name: "CRC32 (reflected)", constants: [0xedb88320], bits: 32 },
  { id: "fnv1a-32", name: "FNV-1a 32", constants: [0x01000193], bits: 32 },
  { id: "djb2", name: "djb2", constants: [0x1505, 33], bits: 32 },
  { id: "sdbm", name: "sdbm", constants: [0x1000f, 65599], bits: 32 },
  { id: "md5", name: "MD5 (constants)", constants: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], bits: 32 },
  { id: "sha1", name: "SHA-1 (constants)", constants: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], bits: 32 },
  { id: "sha256", name: "SHA-256 (constants)", constants: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a], bits: 32 },
  { id: "murmur3-32", name: "MurmurHash3 32 (constants)", constants: [0xcc9e2d51, 0x1b873593], bits: 32 },
];

export type Line = { address?: string; text: string };

const kImm = /0x([0-9a-fA-F]+)\b/g;

/** All hex immediates appearing in a line's text (decimal rotate counts handled separately). */
export function hexImmediates(line: string): number[] {
  const out: number[] = [];
  for (const m of line.matchAll(kImm)) {
    const v = Number(BigInt(`0x${m[1]}`));
    if (Number.isSafeInteger(v)) out.push(v);
  }
  return out;
}

export type AlgoDetection = { algo: HashAlgo; evidence: string[]; score: number };

/** Detects which hash algorithms a routine implements, best first. */
export function detectHashAlgo(lines: readonly Line[]): AlgoDetection[] {
  const immCount = new Map<number, number>();
  for (const l of lines) {
    for (const v of hexImmediates(l.text)) immCount.set(v, (immCount.get(v) ?? 0) + 1);
    // decimal immediates like "add eax, 33" catch the djb2/sdbm add forms
    for (const m of l.text.matchAll(/,\s*(\d+)\b/g)) {
      const v = Number(m[1]);
      if (v < 0x100000000) immCount.set(v, (immCount.get(v) ?? 0) + 1);
    }
  }
  const out: AlgoDetection[] = [];
  for (const algo of kHashAlgos) {
    const hits = algo.constants.filter((c) => (immCount.get(c) ?? 0) > 0);
    if (!hits.length) continue;
    const evidence = hits.map((c) => `constant 0x${c.toString(16)}`);
    out.push({ algo, evidence, score: hits.length });
  }
  out.sort((a, b) => b.score - a.score);
  return out;
}

export type HashScheme = {
  algo: string;
  algoName: string;
  /** e.g. ["ror13", "add"] — the per-character mixing ops seen in the routine, in order */
  mixing: string[];
  bits: 32 | 64;
};

/** Names the API-hash scheme from detected rotates + add/xor mixing in the routine. */
export function nameHashScheme(lines: readonly Line[], detected: readonly AlgoDetection[]): HashScheme | null {
  const ops: string[] = [];
  const push = (op: string) => {
    if (!ops.includes(op)) ops.push(op);
  };
  for (const l of lines) {
    const t = l.text.toLowerCase();
    const m = t.match(/\b(rol|ror|rcl|rcr)\s+[a-z0-9]+\s*,\s*(?:0x([0-9a-f]+)|(\d+))/);
    if (m) push(`${m[1]}${Number(m[2] !== undefined ? BigInt(`0x${m[2]}`) : m[3])}`);
    if (/\badd\s+[a-z0-9]+\s*,\s*[a-z0-9]+/.test(t)) push("add");
    if (/\bxor\s+[a-z0-9]+\s*,\s*[a-z0-9]+/.test(t)) push("xor");
  }
  const algo = detected[0]?.algo;
  if (!ops.length && !algo) return null;
  return { algo: algo?.id ?? "unknown", algoName: algo?.name ?? "unknown", mixing: ops, bits: algo?.bits ?? 32 };
}
