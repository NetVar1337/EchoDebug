// Emulation-assisted key extraction (#24): when a module carries a crypto constant table (found by
// analysis/crypto.ts) near a decrypt routine, the key is usually sitting in the same neighborhood.
// This module pulls candidate key windows around the hit, emulates the routine once per candidate
// against the ciphertext, and keeps the one whose output is most printable.
import { scanCrypto, type CryptoHit } from "./analysis/crypto";

export type KeyCandidate = { key: Uint8Array; source: string; score: number };

/** 16/32-byte windows in `radius` bytes around the hit's RVA — where the key usually sits. */
export function candidateKeys(img: Uint8Array, hit: CryptoHit, opts: { radius?: number; sizes?: number[] } = {}): KeyCandidate[] {
  const radius = opts.radius ?? 0x100;
  const sizes = opts.sizes ?? [16, 32];
  const rva = Math.max(0, Math.min(hit.rva, img.length - 1));
  const out: KeyCandidate[] = [];
  const seen = new Set<number>();
  for (const size of sizes) {
    for (let off = Math.max(0, rva - radius); off < Math.min(img.length - size, rva + radius); off += 8) {
      if (seen.has(off)) continue;
      seen.add(off);
      const key = img.slice(off, off + size);
      if (key.every((b) => b === 0)) continue;
      out.push({ key, source: `rva 0x${off.toString(16)} (${off - rva >= 0 ? "+" : "-"}0x${Math.abs(off - rva).toString(16)} from ${hit.name})`, score: entropy(key) });
    }
  }
  return out;
}

/** Shannon entropy per byte, 0..8 — keys are high-entropy, tables are structured. */
export function entropy(b: Uint8Array): number {
  if (!b.length) return 0;
  const counts = new Map<number, number>();
  for (const x of b) counts.set(x, (counts.get(x) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / b.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Printable-ratio of a buffer, 0..1 — decrypted text scores high, random bytes low. */
export function printableRatio(b: Uint8Array): number {
  if (!b.length) return 0;
  let n = 0;
  for (const x of b) if (x === 0 || (x >= 0x20 && x < 0x7f) || x === 9 || x === 10 || x === 13) n++;
  return n / b.length;
}

export type EmulateDecrypt = (args: { start: string; end: string; regs: Record<string, string>; write: { address: string; data: string }[]; read: { address: string; size: number }[] }) => Promise<{ reads?: { address: string; bytes: string }[] }>;

/**
 * Tries each candidate key: emulates [start,end) with the key written at `keyAddr` and the
 * ciphertext at `ctAddr`, reads `outSize` bytes at `outAddr`, and returns the best-scoring
 * (key, plaintext) pair. `emulate` is injectable for tests.
 */
export async function extractKey(
  start: bigint,
  end: bigint,
  keys: readonly KeyCandidate[],
  buffers: { keyAddr: bigint; ctAddr: bigint; ct: Uint8Array; outAddr: bigint; outSize: number },
  emulate: EmulateDecrypt,
): Promise<{ key: KeyCandidate; plaintext: Uint8Array; score: number } | null> {
  let best: { key: KeyCandidate; plaintext: Uint8Array; score: number } | null = null;
  for (const key of keys) {
    const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    const r = await emulate({
      start: `0x${start.toString(16)}`,
      end: `0x${end.toString(16)}`,
      regs: { rcx: `0x${buffers.ctAddr.toString(16)}`, rdx: `0x${buffers.keyAddr.toString(16)}` },
      write: [
        { address: `0x${buffers.keyAddr.toString(16)}`, data: hex(key.key) },
        { address: `0x${buffers.ctAddr.toString(16)}`, data: hex(buffers.ct) },
      ],
      read: [{ address: `0x${buffers.outAddr.toString(16)}`, size: buffers.outSize }],
    }).catch(() => null);
    const bytesHex = r?.reads?.[0]?.bytes;
    if (!bytesHex) continue;
    const plaintext = Uint8Array.from(bytesHex.match(/../g)?.map((h) => parseInt(h, 16)) ?? []);
    const score = printableRatio(plaintext);
    if (!best || score > best.score) best = { key, plaintext, score };
  }
  return best && best.score > 0.8 ? best : null;
}

export { scanCrypto };
