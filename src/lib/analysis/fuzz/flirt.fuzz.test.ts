// Fuzz / property tests for the FLIRT .sig reader (plain and compressed), the matcher and the
// .pat reader.
import * as zlib from "node:zlib";
import { describe, expect, it } from "vitest";
import { clean, cleanAsync, fc, inputs, kTimeout, params, randomBytes } from "./harness";
import { FlirtError, matchFlirt, parseFlirt, parseFlirtFile, parseFlirtHeader } from "../flirt";
import { parsePat, toPatEntry, toPatFile, writeSig, type PatEntry } from "../flirtgen";

/** A version 10 .sig with a few patterns sharing prefixes, so the tree has several levels. */
function sigEntries(): PatEntry[] {
  const fn = (name: string, bytes: number[]) => toPatEntry({ name, bytes: new Uint8Array(bytes), variable: bytes.map((_, i) => i % 11 === 5) })!;
  const body = (k: number) => Array.from({ length: 48 }, (_, i) => (i * 7 + k) & 0xff);
  return [
    fn("_alpha", [0x55, 0x48, 0x89, 0xe5, ...body(1)]),
    fn("_beta", [0x55, 0x48, 0x89, 0xe5, ...body(2)]),
    fn("_gamma", [0x48, 0x83, 0xec, 0x28, ...body(3)]),
    fn("_delta", [0x48, 0x83, 0xec, 0x28, ...body(3)]),
  ];
}

/** `sig` with its body replaced by `body` (header kept), optionally flagged as compressed. */
function withBody(sig: Uint8Array, body: Uint8Array, flag: boolean): Uint8Array {
  const at = 37 + 8 + parseFlirtHeader(sig).libraryName.length;
  const out = new Uint8Array([...sig.subarray(0, at), ...body]);
  if (flag) out[16] |= 0x10; // features: compressed
  return out;
}

const bodyOf = (sig: Uint8Array) => sig.subarray(37 + 8 + parseFlirtHeader(sig).libraryName.length);

/** The same body, zlib-compressed with the "compressed" feature bit, the way IDA writes it. */
const compressed = (sig: Uint8Array) => withBody(sig, zlib.deflateSync(bodyOf(sig)), true);

/** zstd-compressed, as IDA 9 writes it (needs a Node with zstd). */
const zstd = (sig: Uint8Array): Uint8Array | null => {
  const z = (zlib as unknown as { zstdCompressSync?: (b: Uint8Array) => Uint8Array }).zstdCompressSync;
  return z ? withBody(sig, new Uint8Array(z(bodyOf(sig))), false) : null;
};

describe("FLIRT under random and mutated input", () => {
  const entries = sigEntries();
  const plain = writeSig(entries, { libraryName: "fuzz" });
  const seeds = [
    { name: "plain", bytes: plain, regions: [[0, 64]] as [number, number][] },
    { name: "zlib", bytes: compressed(plain), regions: [[0, 48]] as [number, number][] },
    ...(zstd(plain) ? [{ name: "zstd", bytes: zstd(plain)!, regions: [[0, 64]] as [number, number][] }] : []),
  ];
  const image = new Uint8Array(0x400);
  entries.forEach((e, i) => e.pattern.forEach((b, k) => { image[i * 0x100 + k] = b < 0 ? 0 : b; }));

  it("seeds parse and match", async () => {
    const sig = parseFlirt(plain);
    expect(matchFlirt(sig, image).map((m) => m.name)).toContain("_alpha");
    const z = await parseFlirtFile(seeds[1].bytes);
    expect(z.root?.children.length).toBe(sig.root?.children.length);
  });

  it("parseFlirt + matchFlirt", () => {
    fc.assert(
      fc.property(inputs(seeds), (b) => {
        const sig = clean(() => parseFlirt(b));
        if (sig) clean(() => matchFlirt(sig, image, 0x140000000n));
      }),
      params(),
    );
  }, kTimeout);

  it("parseFlirtFile (decompression paths)", async () => {
    await fc.assert(fc.asyncProperty(inputs(seeds), async (b) => { await cleanAsync(() => parseFlirtFile(b)); }), params());
  }, kTimeout);

  it("matchFlirt of a parsed signature over random images", () => {
    const sig = parseFlirt(plain);
    fc.assert(fc.property(randomBytes(4096), (img) => { clean(() => matchFlirt(sig, img)); }), params());
  }, kTimeout);

  it("parsePat on mutated .pat text", () => {
    const text = toPatFile(entries);
    fc.assert(
      fc.property(fc.string({ maxLength: 400 }), fc.nat({ max: text.length }), (junk, at) => {
        clean(() => parsePat(text.slice(0, at) + junk + text.slice(at)));
      }),
      params(),
    );
  }, kTimeout);
});

describe("FLIRT regressions", () => {
  const plain = writeSig(sigEntries(), { libraryName: "fuzz" });

  it("a tree of 100000 one-child levels is a FlirtError, not a stack overflow", () => {
    const body = [1, ...Array.from({ length: 100000 }, () => [0, 0, 1]).flat()];
    expect(() => clean(() => parseFlirt(withBody(plain, new Uint8Array(body), false)))).not.toThrow();
    expect(() => parseFlirt(withBody(plain, new Uint8Array(body), false))).toThrow(FlirtError);
  });

  it("a zstd frame that declares 2 GiB is refused before anything is allocated", async () => {
    // magic, FHD = single segment + 4 byte content size, size 0x7f000000, one empty raw last block
    const frame = new Uint8Array([0x28, 0xb5, 0x2f, 0xfd, 0xa0, 0x00, 0x00, 0x00, 0x7f, 0x01, 0x00, 0x00]);
    await expect(cleanAsync(() => parseFlirtFile(withBody(plain, frame, false)), 1000)).resolves.toBeUndefined();
    await expect(parseFlirtFile(withBody(plain, frame, false))).rejects.toThrow(FlirtError);
    // an RLE block can claim 2 MiB from 4 bytes: 100 of them in a frame without a content size
    const rle = [0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58, ...Array.from({ length: 100 }, (_, i) => [((0x1fffff << 3) | (1 << 1) | (i === 99 ? 1 : 0)) & 0xff, ((0x1fffff << 3) >> 8) & 0xff, ((0x1fffff << 3) >> 16) & 0xff, 0x41]).flat()];
    await expect(parseFlirtFile(withBody(plain, new Uint8Array(rle), false))).rejects.toThrow(/more than/);
  });

  it("a deflate bomb stops at the size cap", async () => {
    const bomb = zlib.deflateSync(new Uint8Array(129 << 20));
    await expect(parseFlirtFile(withBody(plain, new Uint8Array(bomb), true))).rejects.toThrow(/inflates to more than/);
  }, 60_000);
});
