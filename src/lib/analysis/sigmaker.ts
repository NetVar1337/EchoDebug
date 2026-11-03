// IDA-style signature maker: wildcard position-dependent operands, grow until unique

import { hexToBytes } from "../hex";
import { a64Wildcards } from "./a64";
import { parseArch, type Arch } from "./arch";

export type Insn = { address: string; length: number; bytes: string; text: string };
export type Pattern = (number | null)[];

const kPrefixes = new Set([0x66, 0x67, 0xf2, 0xf3, 0x2e, 0x3e, 0x26, 0x64, 0x65, 0x36, 0xf0]);

/**
 * Pattern for one instruction: rel32 branch targets and [rip+disp32] displacements become
 * wildcards. On arm64 the branch / adr / adrp / literal immediates do, and the imm12 of an add or
 * load/store that completes an adrp pair (the relay annotates those with `; 0x...`).
 */
export function insnPattern(bytesHex: string, text: string, arch: Arch | string | null = "x86_64"): Pattern {
  const b = hexToBytes(bytesHex);
  const p: Pattern = Array.from(b);
  if (parseArch(arch) === "arm64") {
    const afterAdrp = text.includes(";");
    for (let o = 0; o + 4 <= b.length; o += 4) {
      const w = (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
      a64Wildcards(w, afterAdrp).forEach((x, k) => x && (p[o + k] = null));
    }
    return p;
  }
  let i = 0;
  while (i < b.length && kPrefixes.has(b[i])) i++;
  if (i < b.length && b[i] >= 0x40 && b[i] <= 0x4f) i++; // REX
  let modrm = -1;
  const op = b[i];
  if (op === 0xe8 || op === 0xe9) {
    wild(p, i + 1, 4);
    return p;
  }
  if (op === 0xc5) modrm = i + 3; // 2-byte VEX: c5 xx op modrm
  else if (op === 0xc4) modrm = i + 4; // 3-byte VEX: c4 xx xx op modrm
  else if (op === 0x0f) {
    const op2 = b[i + 1];
    if (op2 >= 0x80 && op2 <= 0x8f) {
      wild(p, i + 2, 4);
      return p;
    }
    modrm = op2 === 0x38 || op2 === 0x3a ? i + 3 : i + 2;
  } else modrm = i + 1;
  if (text.includes("[") && modrm < b.length && (b[modrm] & 0xc7) === 0x05) wild(p, modrm + 1, 4);
  return p;
}

function wild(p: Pattern, at: number, n: number): void {
  for (let k = at; k < at + n && k < p.length; k++) p[k] = null;
}

export function toIda(p: Pattern): string {
  return p.map((x) => (x === null ? "?" : x.toString(16).toUpperCase().padStart(2, "0"))).join(" ");
}

export function toCode(p: Pattern): { bytes: string; mask: string } {
  return {
    bytes: p.map((x) => "\\x" + (x ?? 0).toString(16).toUpperCase().padStart(2, "0")).join(""),
    mask: p.map((x) => (x === null ? "?" : "x")).join(""),
  };
}

export function toByteArray(p: Pattern): string {
  return "{ " + p.map((x) => (x === null ? "0x??" : "0x" + x.toString(16).toUpperCase().padStart(2, "0"))).join(", ") + " }";
}

/** Strip trailing wildcards, they never help uniqueness. */
export function trim(p: Pattern): Pattern {
  let n = p.length;
  while (n > 0 && p[n - 1] === null) n--;
  return p.slice(0, n);
}

/**
 * Add one instruction at a time until countHits(pattern) === 1.
 * Returns null if the instructions run out or a pattern stops matching at all.
 */
export async function makeSignature(
  insns: readonly Insn[],
  countHits: (ida: string) => Promise<number>,
  minBytes = 5,
  /** the listing's architecture (a disassemble reply's `arch`); x86-64 by default */
  arch: Arch | string | null = "x86_64",
): Promise<{ pattern: Pattern; hits: number } | null> {
  let p: Pattern = [];
  for (const insn of insns) {
    p = p.concat(insnPattern(insn.bytes, insn.text, arch));
    const t = trim(p);
    if (t.filter((x) => x !== null).length < minBytes) continue;
    const hits = await countHits(toIda(t));
    if (hits === 1) return { pattern: t, hits };
    if (hits === 0) return null;
  }
  return null;
}
