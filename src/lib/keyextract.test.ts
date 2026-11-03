import { describe, expect, it } from "vitest";
import { candidateKeys, entropy, extractKey, printableRatio, type EmulateDecrypt } from "./keyextract";
import type { CryptoHit } from "./analysis/crypto";

const hit: CryptoHit = { kind: "aes-sbox", name: "AES forward S-box", rva: 0x100, address: "0x140000100", confidence: 0.99, note: "" };

/** 1 KiB fake image: sbox marker at 0x100, a 16-byte key at 0x140, zeros elsewhere. */
const img = new Uint8Array(0x400);
img[0x100] = 0x63;
img[0x101] = 0x7c;
const keyBytes = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
img.set(keyBytes, 0x140);

describe("key candidates (#24)", () => {
  it("entropy ranks the real key above zero runs", () => {
    expect(entropy(keyBytes)).toBeGreaterThan(entropy(new Uint8Array(16)));
    expect(entropy(new Uint8Array(16))).toBe(0);
  });

  it("printableRatio scores text over random", () => {
    expect(printableRatio(new TextEncoder().encode("hello world"))).toBe(1);
    expect(printableRatio(Uint8Array.from([0x41, 0x42, 1, 200]))).toBe(0.5);
  });

  it("finds the key window near the crypto hit and skips zero runs", () => {
    const keys = candidateKeys(img, hit, { radius: 0x80, sizes: [16] });
    expect(keys.some((k) => k.source.includes("+0x40") && k.key[0] === 0xa0)).toBe(true);
    expect(keys.every((k) => !k.key.every((b) => b === 0))).toBe(true);
  });
});

describe("extractKey", () => {
  it("picks the candidate whose decrypted output is most printable", async () => {
    const ct = new Uint8Array(11);
    for (let i = 0; i < 11; i++) ct[i] = "hello world".charCodeAt(i) ^ 0x5a;
    // fake "decryptor": xor with the key written at keyAddr; correct key yields "hello world"
    const emulate: EmulateDecrypt = async ({ write, read }) => {
      const keyHex = write.find((w) => w.address === "0x9000")?.data ?? "00";
      const key = Uint8Array.from(keyHex.match(/../g)!.map((h) => parseInt(h, 16)));
      const ctHex = write.find((w) => w.address === "0x8000")?.data ?? "";
      const ct = Uint8Array.from(ctHex.match(/../g)!.map((h) => parseInt(h, 16)));
      const out = ct.map((b, i) => b ^ key[i % key.length]);
      return { reads: [{ address: read[0].address, bytes: [...out].map((x) => x.toString(16).padStart(2, "0")).join("") }] };
    };
    const realKey = { key: new Uint8Array(16).fill(0x5a), source: "known", score: 0 };
    const wrong = { key: new Uint8Array(16).fill(0xff), source: "wrong", score: 0 }; // yields non-printable output
    const best = await extractKey(0x1000n, 0x1100n, [wrong, realKey], { keyAddr: 0x9000n, ctAddr: 0x8000n, ct, outAddr: 0xa000n, outSize: ct.length }, emulate);
    expect(best).not.toBeNull();
    expect(new TextDecoder().decode(best!.plaintext)).toBe("hello world");
    expect(best!.key.source).toBe("known");
  });

  it("returns null when no candidate produces printable output", async () => {
    const emulate: EmulateDecrypt = async () => ({ reads: [{ address: "0xa000", bytes: "0102feff" }] });
    const r = await extractKey(0x1000n, 0x1100n, [{ key: new Uint8Array(16), source: "x", score: 0 }], { keyAddr: 0x9000n, ctAddr: 0x8000n, ct: new Uint8Array(4), outAddr: 0xa000n, outSize: 4 }, emulate);
    expect(r).toBeNull();
  });
});
