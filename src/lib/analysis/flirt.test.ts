import { describe, expect, it } from "vitest";
import { deflateSync } from "zlib";
import { crc16, flirtArchName, matchFlirt, parseFlirt, parseFlirtFile, parseFlirtHeader, FlirtError } from "./flirt";

/**
 * Builds a FLIRT signature file for one pattern with one named function.
 *
 * The tree is a single root child: a node whose pattern covers `pattern`
 * bytes, with a leaf module holding the function name and the CRC of the
 * bytes that follow the pattern.
 */
function buildSig(opts: {
  pattern: number[];
  wildcardAt?: number;
  name: string;
  functionLength: number;
  tail?: number[];
  version?: number;
  compress?: boolean;
  libraryName?: string;
}): Uint8Array {
  const version = opts.version ?? 9;
  const pattern = opts.pattern;
  const tail = opts.tail ?? [];
  const crc = crc16(new Uint8Array(tail));
  const nameBytes = Array.from(new TextEncoder().encode(opts.name));

  const out: number[] = [];
  const push = (...b: number[]) => out.push(...b);
  const u16 = (v: number) => push(v & 0xff, (v >> 8) & 0xff);
  const u32 = (v: number) => push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff);

  // Header
  push(...Array.from(new TextEncoder().encode("IDASGN")));
  push(version); // version
  push(0); // arch: x86
  u32(0x800); // file types: PE
  u16(2); // os types: win
  u16(0x208); // app types
  u16(opts.compress ? 0x10 : 0); // features
  u16(0); // old n functions
  u16(0); // crc16
  push(...new Array(12).fill(0)); // ctype
  const lib = opts.libraryName ?? "msvc";
  push(lib.length);
  u16(0); // ctypes crc
  if (version >= 6) u32(1); // function count
  if (version >= 8) u16(16); // pattern size
  if (version >= 10) u16(0); // unknown
  push(...Array.from(new TextEncoder().encode(lib)));

  // Tree: root with one child.
  const body: number[] = [];
  const bpush = (...b: number[]) => body.push(...b);
  const bMultiple = (v: number) => {
    if (v < 0x80) bpush(v);
    else if (v < 0x4000) bpush(0x80 | (v >> 8), v & 0xff);
    else bpush(0xc0 | (v >> 24), (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
  };
  // Root: node count = 1
  bMultiple(1);
  // Child node: length, variant mask, pattern bytes
  const length = pattern.length;
  bpush(length);
  // The variant mask says which bytes are wildcards: a set bit marks a byte
  // that is not stored, an unset bit marks one that is.
  let mask = 0;
  for (let i = 0; i < length; i++) if (i === opts.wildcardAt) mask |= 1 << (length - i - 1);
  if (length < 0x10) {
    bMultiple(mask);
  } else {
    bMultiple(mask >>> 0);
  }
  for (let i = 0; i < length; i++) if (i !== opts.wildcardAt) bpush(pattern[i]);
  // Child is a leaf: node count = 0
  bMultiple(0);
  // Module: crc length, crc (big endian)
  bpush(Math.max(1, tail.length));
  bpush((crc >> 8) & 0xff, crc & 0xff);
  // Module length
  bMultiple(opts.functionLength);
  // Public function: offset, then the name. The first name byte doubles as
  // the flags byte when it is >= 0x20; the byte that ends the name carries
  // the module parse flags.
  bMultiple(0);
  for (const b of nameBytes) bpush(b);
  bpush(0); // terminates the name: no more names, no tail bytes, no references

  const bodyBytes = new Uint8Array(body);
  if (opts.compress) {
    const z = new Uint8Array(deflateSync(bodyBytes));
    return new Uint8Array([...out, ...z]);
  }
  return new Uint8Array([...out, ...body]);
}

describe("flirt signature files", () => {
  it("parses the header", () => {
    const sig = parseFlirtHeader(buildSig({ pattern: [1, 2, 3, 4], name: "_fn", functionLength: 16 }));
    expect(sig.version).toBe(9);
    expect(sig.arch).toBe(0);
    expect(sig.libraryName).toBe("msvc");
    expect(sig.functionCount).toBe(1);
  });

  it("rejects a file that is not a signature file", () => {
    expect(() => parseFlirtHeader(new Uint8Array([1, 2, 3, 4, 5, 6, 7]))).toThrow(FlirtError);
  });

  it("parses the tree and the named function", () => {
    const sig = parseFlirt(buildSig({ pattern: [0x55, 0x8b, 0xec], name: "_memcpy", functionLength: 32 }));
    expect(sig.root).not.toBeNull();
    const leaf = sig.root!.children[0];
    expect(leaf.length).toBe(3);
    expect(leaf.pattern).toEqual([0x55, 0x8b, 0xec]);
    expect(leaf.module?.functions[0].name).toBe("_memcpy");
    expect(leaf.module?.length).toBe(32);
  });

  it("matches a pattern in an image", () => {
    const sig = parseFlirt(buildSig({ pattern: [0x55, 0x8b, 0xec], name: "_memcpy", functionLength: 32 }));
    const img = new Uint8Array(0x100);
    img.set([0x90, 0x90, 0x55, 0x8b, 0xec, 0x11, 0x22], 0x10);
    const hits = matchFlirt(sig, img, 0x140000000n);
    expect(hits).toHaveLength(1);
    expect(hits[0].rva).toBe(0x12);
    expect(hits[0].name).toBe("_memcpy");
    expect(hits[0].address).toBe("0x140000012");
  });

  it("does not match a different byte sequence", () => {
    const sig = parseFlirt(buildSig({ pattern: [0x55, 0x8b, 0xec], name: "_memcpy", functionLength: 32 }));
    const img = new Uint8Array(0x100).fill(0x90);
    expect(matchFlirt(sig, img)).toHaveLength(0);
  });

  it("matches a wildcard byte", () => {
    const sig = parseFlirt(buildSig({ pattern: [0x55, 0x8b, 0xec], wildcardAt: 2, name: "_wild", functionLength: 16 }));
    const img = new Uint8Array(0x100);
    img.set([0x55, 0x8b, 0xcc], 0x20);
    const hits = matchFlirt(sig, img);
    expect(hits).toHaveLength(1);
    expect(hits[0].rva).toBe(0x20);
  });

  it("verifies the CRC of the function tail", () => {
    const tail = [1, 2, 3, 4, 5, 6, 7, 8];
    const sig = parseFlirt(buildSig({ pattern: [0x55, 0x8b, 0xec], name: "_crc", functionLength: 11, tail }));
    const img = new Uint8Array(0x100);
    img.set([0x55, 0x8b, 0xec], 0x30);
    img.set(tail, 0x33);
    const hits = matchFlirt(sig, img);
    expect(hits).toHaveLength(1);
    expect(hits[0].crcVerified).toBe(true);
  });

  it("reports a wrong CRC as unverified", () => {
    const sig = parseFlirt(buildSig({ pattern: [0x55, 0x8b, 0xec], name: "_crc", functionLength: 11, tail: [1, 2, 3, 4] }));
    const img = new Uint8Array(0x100);
    img.set([0x55, 0x8b, 0xec], 0x30);
    img.set([9, 9, 9, 9], 0x33);
    const hits = matchFlirt(sig, img);
    expect(hits).toHaveLength(1);
    expect(hits[0].crcVerified).toBe(false);
  });

  it("reads a compressed signature file", async () => {
    const sig = await parseFlirtFile(buildSig({ pattern: [0x55, 0x8b, 0xec], name: "_zipped", functionLength: 16, compress: true }));
    const img = new Uint8Array(0x100);
    img.set([0x55, 0x8b, 0xec], 0x05);
    expect(matchFlirt(sig, img)).toHaveLength(1);
  });

  it("names the architecture", () => {
    expect(flirtArchName(0)).toBe("x86");
    expect(flirtArchName(99)).toContain("99");
  });

  it("computes the CRC-16 the way FLIRT does", () => {
    // FLAIR's crc16.cpp is CRC-16/X-25 (check value 0x906E for "123456789") with the two
    // bytes swapped, as radare2's flirt.c carries it.
    expect(crc16(new TextEncoder().encode("123456789"))).toBe(0x6e90);
    expect(crc16(new Uint8Array())).toBe(0);
  });
});
