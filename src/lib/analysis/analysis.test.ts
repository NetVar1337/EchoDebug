import { describe, expect, it } from "vitest";
import { parsePe } from "./pe";
import { extractStrings } from "./strings";
import { findXrefs } from "./xrefs";
import { insnPattern, makeSignature, toByteArray, toCode, toIda } from "./sigmaker";
import { decode, encode } from "./values";

/** Minimal PE32+ image: 1 section, 1 export (named), 1 import (named + ordinal). */
function fakePe(): Uint8Array {
  const img = new Uint8Array(0x3000);
  const dv = new DataView(img.buffer);
  const str = (o: number, s: string) => { for (let i = 0; i < s.length; i++) img[o + i] = s.charCodeAt(i); };
  dv.setUint16(0, 0x5a4d, true);
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x4550, true);
  const fh = 0x84;
  dv.setUint16(fh, 0x8664, true);
  dv.setUint16(fh + 2, 1, true);
  dv.setUint16(fh + 16, 240, true);
  const oh = fh + 20;
  dv.setUint16(oh, 0x20b, true);
  dv.setUint32(oh + 16, 0x1000, true);
  dv.setBigUint64(oh + 24, 0x140000000n, true);
  dv.setUint32(oh + 56, 0x3000, true);
  dv.setUint32(oh + 108, 16, true);
  const dd = oh + 112;
  dv.setUint32(dd, 0x2000, true); dv.setUint32(dd + 4, 0x100, true); // export
  dv.setUint32(dd + 8, 0x2200, true); dv.setUint32(dd + 12, 0x40, true); // import
  const st = oh + 240;
  str(st, ".text");
  dv.setUint32(st + 8, 0x1000, true); dv.setUint32(st + 12, 0x1000, true); dv.setUint32(st + 36, 0x60000020, true);
  // export dir
  dv.setUint32(0x2000 + 16, 1, true); dv.setUint32(0x2000 + 20, 1, true); dv.setUint32(0x2000 + 24, 1, true);
  dv.setUint32(0x2000 + 28, 0x2080, true); dv.setUint32(0x2000 + 32, 0x2090, true); dv.setUint32(0x2000 + 36, 0x20a0, true);
  dv.setUint32(0x2080, 0x1010, true); dv.setUint32(0x2090, 0x20b0, true); dv.setUint16(0x20a0, 0, true); str(0x20b0, "DoThing");
  // import descriptor
  dv.setUint32(0x2200, 0x2300, true); dv.setUint32(0x2200 + 12, 0x2400, true); dv.setUint32(0x2200 + 16, 0x2500, true);
  dv.setBigUint64(0x2300, 0x2410n, true); dv.setBigUint64(0x2308, (1n << 63n) | 7n, true);
  str(0x2400, "KERNEL32.dll"); str(0x2412, "Sleep");
  return img;
}

describe("pe", () => {
  it("parses headers, sections, exports, imports", () => {
    const pe = parsePe(fakePe());
    expect(pe.is64).toBe(true);
    expect(pe.imageBase).toBe(0x140000000n);
    expect(pe.sections[0]).toMatchObject({ name: ".text", rva: 0x1000, x: true, w: false });
    expect(pe.exports).toEqual([{ name: "DoThing", ordinal: 1, rva: 0x1010 }]);
    expect(pe.imports[0].dll).toBe("KERNEL32.dll");
    expect(pe.imports[0].funcs).toEqual([{ name: "Sleep", iatRva: 0x2500 }, { ordinal: 7, iatRva: 0x2508 }]);
  });
  it("rejects non-PE", () => expect(() => parsePe(new Uint8Array(0x100))).toThrow());
});

describe("strings", () => {
  it("finds ascii and utf16", () => {
    const b = new Uint8Array(64);
    "hello world".split("").forEach((c, i) => (b[4 + i] = c.charCodeAt(0)));
    "WIDE!".split("").forEach((c, i) => (b[32 + i * 2] = c.charCodeAt(0)));
    const s = extractStrings(b, 5);
    expect(s).toContainEqual({ rva: 4, text: "hello world", wide: false });
    expect(s).toContainEqual({ rva: 32, text: "WIDE!", wide: true });
  });
});

describe("xrefs", () => {
  it("finds call and rip refs", () => {
    const b = new Uint8Array(0x100);
    const dv = new DataView(b.buffer);
    b[0x10] = 0xe8; dv.setInt32(0x11, 0x80 - 0x15, true); // call 0x80
    b[0x20] = 0x48; b[0x21] = 0x8b; b[0x22] = 0x05; dv.setInt32(0x23, 0x80 - 0x27, true); // mov rax,[rip->0x80]
    const x = findXrefs(b, [{ rva: 0, size: 0x60 }], 0x80);
    expect(x).toContainEqual({ rva: 0x10, kind: "call" });
    expect(x).toContainEqual({ rva: 0x20, kind: "rip" });
  });
});

describe("sigmaker", () => {
  it("wildcards rel32 and rip disp", () => {
    expect(toIda(insnPattern("e812345678", "call 0x1"))).toBe("E8 ? ? ? ?");
    expect(toIda(insnPattern("488b0510203040", "mov rax, [rip+0x40302010]"))).toBe("48 8B 05 ? ? ? ?");
    expect(toIda(insnPattern("0f8412345678", "jz 0x1"))).toBe("0F 84 ? ? ? ?");
    expect(toIda(insnPattern("4883ec28", "sub rsp, 0x28"))).toBe("48 83 EC 28");
  });
  it("formats", () => {
    expect(toCode([0x48, null])).toEqual({ bytes: "\\x48\\x00", mask: "x?" });
    expect(toByteArray([0x48, null])).toBe("{ 0x48, 0x?? }");
  });
  it("grows until unique", async () => {
    const insns = [
      { address: "0x1", length: 4, bytes: "4883ec28", text: "sub rsp, 0x28" },
      { address: "0x5", length: 5, bytes: "e800000000", text: "call 0x0" },
      { address: "0xa", length: 1, bytes: "c3", text: "ret" },
    ];
    const seen: string[] = [];
    const r = await makeSignature(insns, async (p) => (seen.push(p), p.endsWith("C3") ? 1 : 3));
    expect(r && toIda(r.pattern)).toBe("48 83 EC 28 E8 ? ? ? ? C3");
    expect(seen).toEqual(["48 83 EC 28 E8", "48 83 EC 28 E8 ? ? ? ? C3"]);
  });
});

describe("values", () => {
  it("decodes and encodes", () => {
    const b = encode("-2", "i32");
    expect(decode(b, 0, "i32")).toBe("-2");
    expect(decode(b, 0, "u32")).toBe("4294967294");
    expect(decode(encode("1.5", "f32"), 0, "f32")).toBe("1.5");
    expect(decode(encode("0x10", "u64"), 0, "ptr")).toBe("0x10");
    expect(() => encode("256", "u8")).toThrow();
    expect(decode(new Uint8Array(2), 0, "u32")).toBe("??");
  });
});
