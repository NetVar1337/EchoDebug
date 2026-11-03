import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { a64Adrp, a64Branch, a64Indirect, a64LdrLiteral, a64Refs, a64Wildcards } from "./a64";
import { archLabel, detectArch, parseArch, registerNames } from "./arch";
import { flowOf } from "./cfg";
import { elfFunctions, parseElf, relocTypeName } from "./elf";
import { mapPeFile, parsePe, parseRuntimeFunctions } from "./pe";
import { insnPattern, toIda } from "./sigmaker";
import { buildTestPe } from "./testpe";
import { findXrefs } from "./xrefs";
import { buildXrefIndex, elfExecutableRanges, executableRanges } from "./xrefindex";

// fixtures/fix-a64.c (+ fix-a64-seh.s for the PE), see fixtures/README.md
const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));
const peFile = fixture("fix-a64.exe");
const pe = mapPeFile(peFile);
const elfFile = fixture("fix-a64.elf");

/** Lays the ELF's PT_LOAD segments out from the lowest vaddr, as the loader maps them. */
function mapElf(file: Uint8Array): Uint8Array {
  const info = parseElf(file);
  const loads = info.segments.filter((s) => s.typeName === "LOAD");
  const lo = Number(loads.reduce((m, s) => (s.vaddr < m ? s.vaddr : m), loads[0].vaddr)) & ~0xfff;
  const hi = Math.max(...loads.map((s) => Number(s.vaddr) + s.memsz));
  const img = new Uint8Array(hi - lo);
  for (const s of loads) img.set(file.subarray(s.offset, s.offset + s.filesz), Number(s.vaddr) - lo);
  return img;
}
const elf = mapElf(elfFile); // base 0x200000

const words = (...w: number[]) => {
  const b = new Uint8Array(w.length * 4);
  const dv = new DataView(b.buffer);
  w.forEach((x, i) => dv.setUint32(i * 4, x >>> 0, true));
  return b;
};

describe("architecture detection", () => {
  it("reads PE Machine and ELF e_machine from the fixtures", () => {
    expect(detectArch(peFile, false)).toEqual({ arch: "arm64", format: "pe", machine: 0xaa64 });
    expect(detectArch(pe)?.arch).toBe("arm64");
    expect(detectArch(fixture("fix.exe"), false)).toMatchObject({ arch: "x86_64", machine: 0x8664 });
    expect(detectArch(elfFile)).toEqual({ arch: "arm64", format: "elf", machine: 183 });
    expect(detectArch(new Uint8Array(64))).toBeNull();
  });

  it("recognises ARM64EC / ARM64X machines and the CHPE hybrid flag", () => {
    const hdr = (machine: number) => {
      const b = new Uint8Array(0x200);
      const dv = new DataView(b.buffer);
      b.set([0x4d, 0x5a]);
      dv.setUint32(0x3c, 0x80, true);
      dv.setUint32(0x80, 0x4550, true);
      dv.setUint16(0x84, machine, true);
      return b;
    };
    expect(detectArch(hdr(0xa641), false)).toMatchObject({ arch: "arm64", hybrid: "arm64ec" });
    expect(detectArch(hdr(0xa64e), false)).toMatchObject({ arch: "arm64", hybrid: "arm64x" });
    expect(detectArch(hdr(0x1c4), false)).toBeNull(); // ARMNT is not supported

    // an x64-header image with CHPE metadata in its load config is ARM64EC code behind x64
    const lc = new Uint8Array(0x100);
    const ldv = new DataView(lc.buffer);
    ldv.setUint32(0, 0x100, true);
    ldv.setBigUint64(200, 0x140005000n, true);
    const ec = buildTestPe([{ name: ".rdata", rva: 0x2000, bytes: lc, chars: 0x40000040 }], { 10: { rva: 0x2000, size: 0x100 } });
    expect(detectArch(ec)).toMatchObject({ arch: "x86_64", hybrid: "arm64ec" });
    expect(detectArch(ec, false)?.hybrid).toBeUndefined();
  });

  it("names and registers", () => {
    expect(parseArch("AArch64")).toBe("arm64");
    expect(parseArch("amd64")).toBe("x86_64");
    expect(parseArch("mips")).toBeNull();
    expect(archLabel("arm64")).toBe("ARM64");
    expect(registerNames("arm64").slice(0, 2)).toEqual(["x0", "x1"]);
    expect(registerNames("arm64")).toContain("nzcv");
    expect(registerNames("x86_64")[0]).toBe("rax");
    expect(relocTypeName(183, 1027)).toBe("RELATIVE");
  });
});

describe("AArch64 branch classification", () => {
  // [word, pc, expected]
  const table: [number, number, ReturnType<typeof a64Branch>][] = [
    [0x97ffffee, 0x2101b0, { kind: "call", target: 0x210168 }], // bl
    [0x17ffffff, 0x1000, { kind: "jmp", target: 0xffc }], // b
    [0x14000010, 0x1000, { kind: "jmp", target: 0x1040 }], // b
    [0x54ffff63, 0x210190, { kind: "jcc", target: 0x21017c }], // b.lo
    [0xb40000a9, 0x210180, { kind: "jcc", target: 0x210194 }], // cbz x9
    [0x350000a9, 0x1000, { kind: "jcc", target: 0x1014 }], // cbnz w9
    [0x36180041, 0x1000, { kind: "jcc", target: 0x1008 }], // tbz w1, #3
    [0xb7f80041, 0x1000, { kind: "jcc", target: 0x1008 }], // tbnz x1, #63
    [0xd65f03c0, 0x1000, null], // ret
    [0x8b010428, 0x1000, null], // add
  ];
  it.each(table)("word %s at %s", (w, pc, want) => expect(a64Branch(w, pc)).toEqual(want));

  it("register branches", () => {
    expect(a64Indirect(0xd61f0200)).toBe("indirect-jmp"); // br x16
    expect(a64Indirect(0xd63f0100)).toBe("indirect-call"); // blr x8
    expect(a64Indirect(0xd65f03c0)).toBe("ret");
    expect(a64Indirect(0xd65f0bff)).toBe("ret"); // retaa
    expect(a64Indirect(0x8b010428)).toBeNull();
  });

  // the relay's text for each, through the CFG builder's classifier
  const flows: [string, ReturnType<typeof flowOf>][] = [
    ["b 0x1040", { kind: "jmp", target: 0x1040n }],
    ["bl 0x210168", { kind: "call", target: 0x210168n }],
    ["br x16", { kind: "indirect-jmp", target: null }],
    ["blr x8", { kind: "call", target: null }],
    ["ret", { kind: "ret", target: null }],
    ["retaa", { kind: "ret", target: null }],
    ["b.ne 0x2000", { kind: "jcc", target: 0x2000n }],
    ["b.lo 0x21017c", { kind: "jcc", target: 0x21017cn }],
    ["bc.eq 0x2000", { kind: "jcc", target: 0x2000n }],
    ["cbz x9, 0x210194", { kind: "jcc", target: 0x210194n }],
    ["cbnz w0, 0x10", { kind: "jcc", target: 0x10n }],
    ["tbz w1, #0x3, 0x1008", { kind: "jcc", target: 0x1008n }],
    ["tbnz x1, #0x3f, 0x1008", { kind: "jcc", target: 0x1008n }],
    ["brk #0x3e8", { kind: "stop", target: null }],
    ["udf #0x0", { kind: "stop", target: null }],
    ["add x0, x0, #0x0  ; 0x140002000", { kind: "none", target: null }],
    ["ldr x0, [x20, #0x1d8]", { kind: "none", target: null }],
    // x86-64 is unchanged
    ["call 0x1000", { kind: "call", target: 0x1000n }],
    ["jne 0x1000", { kind: "jcc", target: 0x1000n }],
    ["bt eax, 3", { kind: "none", target: null }],
  ];
  it.each(flows)("flowOf(%s)", (text, want) => expect(flowOf(text)).toEqual(want));
});

describe("AArch64 references", () => {
  it("resolves adrp+add and adrp+ldr in the PE fixture", () => {
    const text = parsePe(pe).sections.filter((s) => s.x).map((s) => ({ rva: s.rva, size: s.vsize }));
    // g_msg in .rdata: adrp x0 (0x104c) + add x0, x0, #0
    expect(findXrefs(pe, text, 0x2000)).toEqual([{ rva: 0x104c, kind: "rip" }]);
    // g_counter in .data: adrp x20 (0x1038) + ldr w0, [x20] (and the str after the bl)
    expect(findXrefs(pe, text, 0x3000)).toEqual([{ rva: 0x1038, kind: "rip" }]);
    // calls: entry -> add_scaled, walk; with_handler -> entry
    expect(findXrefs(pe, text, 0x1000)).toEqual([{ rva: 0x1044, kind: "call" }]);
    expect(findXrefs(pe, text, 0x1030)).toEqual([{ rva: 0x1074, kind: "call" }]);
    const idx = buildXrefIndex(pe, executableRanges(pe));
    expect(idx.to.get(0x100c)?.map((x) => [x.fromRva, x.kind])).toEqual([[0x1054, "call"]]);
    expect(idx.from.get(0x1018)?.[0]).toEqual({ fromRva: 0x1018, toRva: 0x102c, kind: "jcc" }); // cbz
  });

  it("resolves adr, adrp+ldr/str and branches in the ELF fixture", () => {
    const ranges = elfExecutableRanges(elf);
    expect(ranges).toEqual([{ rva: 0x10168, size: 0x70 }]);
    const idx = buildXrefIndex(elf, ranges);
    // adr x0, g_msg
    expect(idx.to.get(0x158)).toEqual([{ fromRva: 0x101bc, toRva: 0x158, kind: "rip" }]);
    // adrp x20 + ldr / str [x20, #0x1d8] -> g_counter (reported once, at the adrp)
    expect(idx.to.get(0x201d8)).toEqual([{ fromRva: 0x101a0, toRva: 0x201d8, kind: "rip" }]);
    expect(idx.to.get(0x10174)?.map((x) => x.kind)).toEqual(["call"]); // walk
    expect(idx.to.get(0x1017c)?.map((x) => x.kind)).toEqual(["jcc"]); // the loop
  });

  it("forgets a register when it is overwritten", () => {
    // adrp x0, +0 ; mov x0, x1 ; add x0, x0, #8
    expect(a64Refs(words(0x90000000, 0xaa0103e0, 0x91002000), [{ rva: 0, size: 12 }]).filter((r) => r.kind === "rip")).toEqual([]);
    // adrp x0, +0 ; add x0, x0, #8
    expect(a64Refs(words(0x90000000, 0x91002000), [{ rva: 0, size: 8 }])).toEqual([{ fromRva: 0, toRva: 8, kind: "rip" }]);
    // ldr x1, literal +0x10
    expect(a64LdrLiteral(0x58000081, 0x2000)).toBe(0x2010);
    expect(a64Adrp(0x90000094, 0x2101a0)).toEqual({ rd: 20, page: 0x220000 });
  });
});

describe("ARM64 function discovery", () => {
  it("reads packed and .xdata .pdata entries from the PE fixture", () => {
    const fns = parseRuntimeFunctions(pe);
    expect(fns.map((f) => [f.begin, f.end - f.begin, f.unwindKind, f.chained])).toEqual([
      [0x1030, 60, "packed", false], // entry: packed unwind data
      [0x106c, 20, "xdata", false], // with_handler: names a handler, so .xdata
    ]);
  });

  it("decodes synthetic entries (Flag 1, 2, 0 and reserved 3)", () => {
    const pdata = new Uint8Array(32);
    const dv = new DataView(pdata.buffer);
    const put = (i: number, begin: number, unwind: number) => { dv.setUint32(i * 8, begin, true); dv.setUint32(i * 8 + 4, unwind, true); };
    put(0, 0x1000, 1 | (16 << 2)); // packed, 16 instructions
    put(1, 0x1100, 2 | (2 << 2)); // packed, no prologue, 2 instructions
    put(2, 0x1200, 0x3000); // .xdata
    put(3, 0x1300, 3); // reserved
    const xdata = new Uint8Array(8);
    new DataView(xdata.buffer).setUint32(0, 0x40 | (1 << 20), true); // FunctionLength 0x40 words, X bit
    const img = buildTestPe(
      [{ name: ".text", rva: 0x1000, bytes: new Uint8Array(0x400) }, { name: ".pdata", rva: 0x2000, bytes: pdata, chars: 0x40000040 }, { name: ".xdata", rva: 0x3000, bytes: xdata, chars: 0x40000040 }],
      { 3: { rva: 0x2000, size: 32 } },
      { headerBytes: (b) => new DataView(b.buffer).setUint16(0x84, 0xaa64, true) },
    );
    expect(parseRuntimeFunctions(img).map((f) => [f.begin, f.end, f.unwindKind])).toEqual([
      [0x1000, 0x1040, "packed"],
      [0x1100, 0x1108, "packed"],
      [0x1200, 0x1300, "xdata"],
    ]);
  });

  it("lists ELF FUNC symbols", () => {
    expect(elfFunctions(parseElf(elfFile)).map((f) => [f.name, f.address, f.size])).toEqual([
      ["add_scaled", 0x210168n, 12],
      ["walk", 0x210174n, 0x24],
      ["entry", 0x210198n, 0x40],
    ]);
  });
});

describe("AArch64 signature wildcards", () => {
  const hex = (w: number) => [...words(w)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const pat = (w: number, text = "") => toIda(insnPattern(hex(w), text, "arm64"));
  it("wildcards branch, adrp and paired immediates only", () => {
    expect(pat(0x97ffffee)).toBe("? ? ? ?"); // bl
    expect(pat(0x14000010)).toBe("? ? ? ?"); // b
    expect(pat(0xb0000000)).toBe("? ? ? ?"); // adrp
    expect(pat(0x10f7fce0)).toBe("? ? ? ?"); // adr
    expect(pat(0xb40000a9)).toBe("? ? ? B4"); // cbz
    expect(pat(0x54ffff63)).toBe("? ? ? 54"); // b.lo
    expect(pat(0x36180041)).toBe("? ? ? 36"); // tbz
    expect(pat(0x58000081)).toBe("? ? ? 58"); // ldr literal
    expect(pat(0x91000000, "add x0, x0, #0x0  ; 0x140002000")).toBe("00 ? ? 91"); // add after adrp
    expect(pat(0x91000508, "add x8, x8, #0x1")).toBe("08 05 00 91"); // a plain add stays exact
    expect(pat(0xd65f03c0)).toBe("C0 03 5F D6"); // ret
    expect(a64Wildcards(0xf940ee80, true)).toEqual([false, true, true, false]); // ldr after adrp
  });
  it("x86-64 stays the default", () => {
    expect(toIda(insnPattern("e800000000", "call 0x1000"))).toBe("E8 ? ? ? ?");
  });
});
