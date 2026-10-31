import { describe, expect, it } from "vitest";
import {
  findCryptoConstants,
  kCryptoSignatures,
  scanCrypto,
  type CryptoKind,
} from "./crypto";

/** First 16 bytes of the standard AES forward substitution box. */
const kAesSbox = Uint8Array.from([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
]);

/** SHA-256 initial hash value H[0..7], big endian. */
const kSha256H = Uint8Array.from([
  0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
  0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
  0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
  0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
]);

const kBase64 = Uint8Array.from(
  Array.from(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    (c) => c.charCodeAt(0),
  ),
);

function withBytesAt(size: number, at: number, bytes: Uint8Array): Uint8Array {
  const img = new Uint8Array(size);
  img.set(bytes, at);
  return img;
}

describe("crypto", () => {
  it("exposes well-known signature tables", () => {
    const kinds = new Set<CryptoKind>(kCryptoSignatures.map((s) => s.kind));
    for (const kind of [
      "aes-sbox",
      "aes-inv-sbox",
      "aes-rcon",
      "sha256-k",
      "sha256-h",
      "md5-t",
      "crc32-table",
      "blowfish-p",
      "blowfish-s",
      "chacha-const",
      "tea-delta",
      "rc4-state",
      "base64-alphabet",
      "rijndael-mix",
      "salsa-const",
    ] as CryptoKind[]) {
      expect(kinds.has(kind)).toBe(true);
    }
    for (const sig of kCryptoSignatures) {
      expect(sig.bytes.length).toBeGreaterThan(0);
      expect(sig.confidence).toBeGreaterThan(0);
      expect(sig.confidence).toBeLessThanOrEqual(1);
    }
  });

  it("finds the AES S-box at the right rva", () => {
    const img = withBytesAt(0x2000, 0x1000, kAesSbox);
    const hits = scanCrypto(img);
    const hit = hits.find((h) => h.kind === "aes-sbox");
    expect(hit).toBeDefined();
    expect(hit?.rva).toBe(0x1000);
    expect(hit?.address).toBe("0x1000");
    expect(hit?.confidence).toBeGreaterThan(0.5);
    expect(hit?.name.length).toBeGreaterThan(0);
    expect(hit?.note.length).toBeGreaterThan(0);
  });

  it("uses the module base for hit addresses", () => {
    const img = withBytesAt(0x2000, 0x40, kAesSbox);
    const base = 0x7ff600000000n;
    const hits = scanCrypto(img, base);
    const hit = hits.find((h) => h.kind === "aes-sbox");
    expect(hit?.rva).toBe(0x40);
    expect(hit?.address).toBe(`0x${(base + 0x40n).toString(16)}`);
  });

  it("finds every occurrence and sorts hits by rva", () => {
    const img = new Uint8Array(0x3000);
    img.set(kAesSbox, 0x100);
    img.set(kAesSbox, 0x800);
    img.set(kAesSbox, 0x2000);
    const hits = scanCrypto(img).filter((h) => h.kind === "aes-sbox");
    expect(hits.map((h) => h.rva)).toEqual([0x100, 0x800, 0x2000]);
    const all = scanCrypto(img);
    const rvAs = all.map((h) => h.rva);
    expect([...rvAs].sort((a, b) => a - b)).toEqual(rvAs);
  });

  it("returns no hits for an all-zero image", () => {
    expect(scanCrypto(new Uint8Array(0x4000))).toEqual([]);
    expect(findCryptoConstants(new Uint8Array(0x4000))).toEqual([]);
  });

  it("recognizes the SHA-256 initial hash and the Base64 alphabet", () => {
    const img = new Uint8Array(0x4000);
    img.set(kSha256H, 0x100);
    img.set(kBase64, 0x1000);
    const hits = scanCrypto(img);
    expect(hits.some((h) => h.kind === "sha256-h" && h.rva === 0x100)).toBe(true);
    expect(hits.some((h) => h.kind === "base64-alphabet" && h.rva === 0x1000)).toBe(true);
  });

  it("filters hits by confidence", () => {
    const img = withBytesAt(0x2000, 0x10, kAesSbox);
    const strict = findCryptoConstants(img, undefined, 0.99);
    expect(strict.every((h) => h.confidence >= 0.99)).toBe(true);
    expect(strict.some((h) => h.kind === "aes-sbox")).toBe(true);
    expect(findCryptoConstants(img, undefined, 1.1)).toEqual([]);
  });
});
