import { describe, expect, it } from "vitest";
import { findCodeCaves } from "./code-caves";
import { branchTarget, calleesOf, layout, addEdge, addNode, type CallGraph } from "./callgraph";
import { shannonEntropy, sectionEntropies, detectPacker } from "./entropy";
import { scanCrypto } from "./crypto";
import { parsePe } from "./pe";

/** Builds a minimal mapped PE image with one executable section. */
function buildPe(sectionBytes: Uint8Array, sectionName = ".text"): Uint8Array {
  const image = new Uint8Array(0x1000 + sectionBytes.length);
  const dv = new DataView(image.buffer);
  image[0] = 0x4d; image[1] = 0x5a; // MZ
  dv.setUint32(0x3c, 0x80, true); // e_lfanew
  dv.setUint32(0x80, 0x4550, true); // PE\0\0
  const fh = 0x84;
  dv.setUint16(fh, 0x8664, true); // machine x64
  dv.setUint16(fh + 2, 1, true); // one section
  dv.setUint16(fh + 16, 0xf0, true); // optional header size
  const oh = fh + 20;
  dv.setUint16(oh, 0x20b, true); // PE32+
  dv.setUint32(oh + 16, 0x1000, true); // entry rva
  dv.setBigUint64(oh + 24, 0x140000000n, true); // image base
  dv.setUint32(oh + 56, image.length, true); // size of image
  dv.setUint16(oh + 68, 3, true); // subsystem console
  const dd = oh + 112;
  dv.setUint32(dd, 16, true); // number of data directories
  const st = oh + 0xf0;
  image.set(new TextEncoder().encode(sectionName), st);
  dv.setUint32(st + 8, sectionBytes.length, true); // virtual size
  dv.setUint32(st + 12, 0x1000, true); // rva
  dv.setUint32(st + 16, sectionBytes.length, true); // raw size
  dv.setUint32(st + 36, 0x60000020, true); // code, execute, read
  image.set(sectionBytes, 0x1000);
  return image;
}

describe("code caves", () => {
  it("finds runs of filler bytes inside executable sections", () => {
    const body = new Uint8Array(0x200).fill(0xff);
    body.fill(0x90, 0x40, 0x40 + 0x40); // 64 nops
    body.fill(0xcc, 0xc0, 0xc0 + 0x20); // 32 int3s
    const img = buildPe(body);
    const caves = findCodeCaves(img, 0x140000000n, { minSize: 16 });
    expect(caves.length).toBe(2);
    const nop = caves.find((c) => c.fill === 0x90)!;
    expect(nop.size).toBe(64);
    expect(nop.rva).toBe(0x1040);
    expect(nop.address).toBe("0x140001040");
    expect(nop.section).toBe(".text");
  });

  it("ignores sections that are not executable", () => {
    const body = new Uint8Array(0x100).fill(0x90);
    const img = buildPe(body);
    // flip the characteristics to data-only
    const dv = new DataView(img.buffer);
    dv.setUint32(0x84 + 20 + 0xf0 + 36, 0x40000040, true);
    expect(findCodeCaves(img, undefined, { minSize: 16 })).toHaveLength(0);
  });
});

describe("call graph", () => {
  it("reads direct branch targets out of the listing", () => {
    expect(branchTarget("call 0x7ff600012340")).toEqual({ target: "0x7ff600012340", kind: "call" });
    expect(branchTarget("jmp 0x401000")).toEqual({ target: "0x401000", kind: "jmp" });
    expect(branchTarget("je 0x401005")).toEqual({ target: "0x401005", kind: "jcc" });
    expect(branchTarget("call qword ptr [rip+0x10]")).toBeNull();
    expect(branchTarget("nop")).toBeNull();
  });

  it("collects the distinct callees of a function", () => {
    const lines = [
      { address: "0x1000", length: 5, bytes: "e8000000", text: "call 0x2000" },
      { address: "0x1005", length: 5, bytes: "e8000000", text: "call 0x2000" },
      { address: "0x100a", length: 5, bytes: "e8000000", text: "call 0x3000" },
      { address: "0x100f", length: 1, bytes: "90", text: "nop" },
    ];
    expect(calleesOf(lines)).toEqual(["0x2000", "0x3000"]);
  });

  it("lays nodes out in depth columns", () => {
    const g: CallGraph = { nodes: [], edges: [], visited: [] };
    addNode(g, "0x1000", "root", "function", 0);
    addNode(g, "0x2000", "a", "function", 1);
    addNode(g, "0x3000", "b", "function", 1);
    addEdge(g, "0x1000", "0x2000", "call");
    addEdge(g, "0x1000", "0x2000", "call"); // duplicate is ignored
    expect(g.edges).toHaveLength(1);
    const pos = layout(g);
    expect(pos.get("0x1000")!.x).toBe(0);
    expect(pos.get("0x2000")!.x).toBe(190);
    expect(pos.get("0x3000")!.y).toBeGreaterThan(pos.get("0x2000")!.y);
  });
});

describe("entropy and packer detection", () => {
  it("computes shannon entropy", () => {
    expect(shannonEntropy(new Uint8Array(0))).toBe(0);
    expect(shannonEntropy(new Uint8Array(256).fill(0))).toBe(0);
    const uniform = new Uint8Array(256);
    for (let i = 0; i < 256; i++) uniform[i] = i;
    expect(shannonEntropy(uniform)).toBeCloseTo(8, 5);
  });

  it("reports per-section entropy", () => {
    const img = buildPe(new Uint8Array(0x100));
    const ent = sectionEntropies(img);
    expect(ent).toHaveLength(1);
    expect(ent[0].name).toBe(".text");
    expect(ent[0].executable).toBe(true);
  });

  it("flags a high-entropy executable section as packed", () => {
    const body = new Uint8Array(0x400);
    for (let i = 0; i < body.length; i++) body[i] = (i * 167 + 13) & 0xff;
    const img = buildPe(body);
    const verdict = detectPacker(img);
    expect(verdict.confidence).toBeGreaterThan(0);
  });

  it("does not flag a plain section", () => {
    const img = buildPe(new Uint8Array(0x100));
    const verdict = detectPacker(img);
    expect(verdict.packed).toBe(false);
  });
});

describe("crypto constants", () => {
  it("finds the AES S-box at the right rva", () => {
    const sbox = [
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
      0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ];
    const img = new Uint8Array(0x400);
    img.set(sbox, 0x100);
    const hits = scanCrypto(img, 0x140000000n);
    const hit = hits.find((h) => h.kind === "aes-sbox");
    expect(hit).toBeDefined();
    expect(hit!.rva).toBe(0x100);
    expect(hit!.address).toBe("0x140000100");
  });

  it("returns nothing for an all-zero image", () => {
    expect(scanCrypto(new Uint8Array(0x400))).toHaveLength(0);
  });
});

describe("pe parser reuse", () => {
  it("parses the synthetic image", () => {
    const img = buildPe(new Uint8Array(0x40));
    const pe = parsePe(img);
    expect(pe.is64).toBe(true);
    expect(pe.sections).toHaveLength(1);
    expect(pe.entryRva).toBe(0x1000);
  });
});
