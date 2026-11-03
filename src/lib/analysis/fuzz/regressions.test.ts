// Regression tests for the crashes, hangs and unbounded allocations the fuzz properties (and the
// review that went with them) found in the PE / .NET / ELF / IL / engine readers. Each failing
// input is inlined or built by a few lines; the YARA and FLIRT ones live next to their properties.
import { describe, expect, it } from "vitest";
import { clean } from "./harness";
import { buildTestPe } from "../testpe";
import { buildMetadata, buildStrings, buildTables, type TableDef } from "../testdotnet";
import { il2cppMetadata } from "../engines/testengines";
import { mapPeFile, parsePe } from "../pe";
import { resourceTree, buildIco, parseDialog, summarizeResources } from "../resources";
import { buildRtti, findVftables } from "../rtti";
import { authenticodeHash, certificateTable } from "../authenticode";
import { buildDumpPe } from "../unpack";
import { sectionEntropies } from "../entropy";
import { scanAntiDebug } from "../antidebug";
import { buildXrefIndex, executableRanges } from "../xrefindex";
import { openMetadata, parseDotnet } from "../dotnet";
import { disassembleIl, IlError, userStringRefs } from "../cil";
import { ElfError, parseElf } from "../elf";
import { parseMetadata } from "../engines/il2cpp";
import { findNamePools } from "../engines/unreal";
import { resolveSwitch } from "../jumptables";

/** A mapped PE32+ of `size` bytes with no sections, for tests that write their own tables. */
function blankPe(size: number, dirs: Record<number, { rva: number; size: number }> = {}): { img: Uint8Array; dv: DataView } {
  const img = buildTestPe([{ name: ".text", rva: size - 0x10, bytes: new Uint8Array(0x10) }], dirs);
  return { img, dv: new DataView(img.buffer) };
}

const kOh = 0x84 + 20;
const kSections = kOh + 0xf0;

describe("PE regressions", () => {
  it("a PE header cut inside the optional header is an Error, not a DataView RangeError", () => {
    // fuzz counterexample: MZ stub + "PE\0\0" + file header, 136 bytes, optional header missing
    const b = Uint8Array.from([77,90,120,0,1,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,64,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,120,0,0,0,14,31,186,14,0,180,9,205,33,184,1,76,205,33,84,104,105,115,32,112,114,111,103,114,97,109,32,99,97,110,110,111,116,32,98,101,32,114,117,110,32,105,110,32,68,79,83,32,109,111,100,101,46,36,0,0,80,69,0,0,100,134,6,0,208,179,232,106,0,0,0,0,0,0,0,0,240,0,34,0]);
    expect(() => parsePe(b)).toThrow(/truncated optional header/);
    expect(() => mapPeFile(b)).toThrow(/truncated optional header/);
    expect(certificateTable(b)).toBeNull();
  });

  it("authenticodeHash of an empty or cut file is an Error, not a RangeError", async () => {
    await expect(authenticodeHash(new Uint8Array(0))).rejects.toThrow(/not a PE file/);
    await expect(authenticodeHash(Uint8Array.from([0x4d, 0x5a, ...new Array(0x3a).fill(0), 0xff, 0xff, 0, 0]))).rejects.toThrow(/not a PE file/);
  });

  it("mapPeFile does not allocate a SizeOfImage far beyond the file (was up to 1 GiB from 0x200 bytes)", () => {
    const { img, dv } = blankPe(0x1000);
    dv.setUint32(kOh + 56, 0x3fff0000, true);
    dv.setUint16(0x84 + 2, 0, true);
    expect(() => clean(() => mapPeFile(img.subarray(0, 0x200)))).not.toThrow();
    expect(() => mapPeFile(img.subarray(0, 0x200))).toThrow(/implausibly large/);
    dv.setUint32(kOh + 56, 0x2000, true);
    expect(mapPeFile(img.subarray(0, 0x200)).length).toBe(0x2000);
  });

  it("4096 import descriptors sharing one 100000-entry thunk array stay bounded (was 4e8 entries)", () => {
    const { img, dv } = blankPe(0x100000, { 1: { rva: 0x1000, size: 4096 * 20 } });
    for (let d = 0; d < 4096; d++) {
      dv.setUint32(0x1000 + d * 20, 0x20000, true); // OriginalFirstThunk
      dv.setUint32(0x1000 + d * 20 + 12, 0xf0000, true); // Name
      dv.setUint32(0x1000 + d * 20 + 16, 0x20000, true); // FirstThunk
    }
    for (let i = 0; i < 100_000; i++) dv.setBigUint64(0x20000 + i * 8, 0xf0000n, true);
    const pe = clean(() => parsePe(img), 2000)!;
    expect(pe.imports.reduce((n, d) => n + d.funcs.length, 0)).toBe(100_000);
  });

  it("a resource directory whose 4096 entries all point back at the root finishes (was 4096^4 steps)", () => {
    const { img, dv } = blankPe(0x10000, { 2: { rva: 0x2000, size: 0x8010 } });
    dv.setUint16(0x2000 + 14, 4096, true); // id entries
    for (let i = 0; i < 4096; i++) {
      dv.setUint32(0x2010 + i * 8, i + 1, true);
      dv.setUint32(0x2010 + i * 8 + 4, 0x80000000, true); // subdirectory at offset 0: the root
    }
    expect(clean(() => resourceTree(img, parsePe(img)), 500)).toEqual([]);
  });

  it("thousands of resource leaves pointing at one big blob decode a bounded amount (was 4000 x 256 KiB)", () => {
    const { img, dv } = blankPe(0x50000, { 2: { rva: 0x2000, size: 0x9000 } });
    // root: one STRING type entry -> a directory of 4000 leaves, all naming one data entry
    dv.setUint16(0x2000 + 14, 1, true);
    dv.setUint32(0x2010, 6, true);
    dv.setUint32(0x2014, 0x80000000 | 0x20, true);
    dv.setUint16(0x2020 + 14, 4000, true);
    for (let i = 0; i < 4000; i++) {
      dv.setUint32(0x2030 + i * 8, i + 1, true);
      dv.setUint32(0x2030 + i * 8 + 4, 0x8000, true); // data entry at root + 0x8000
    }
    dv.setUint32(0xa000, 0x10000, true); // blob rva
    dv.setUint32(0xa004, 0x40000, true); // blob size
    img.fill(0x7f, 0x10000, 0x50000); // every "string" is 0x7f7f chars long
    const r = clean(() => summarizeResources(img, parsePe(img)), 1000)!;
    expect(r.leaves.length).toBe(4000);
    expect(r.strings.length).toBeLessThan(200);
  });

  it("a GROUP_ICON naming one icon 65535 times builds one entry (was a 65535 x icon allocation)", () => {
    const group = new Uint8Array(6 + 65535 * 14);
    const dv = new DataView(group.buffer);
    dv.setUint16(4, 65535, true);
    for (let i = 0; i < 65535; i++) dv.setUint16(6 + i * 14 + 12, 1, true);
    const ico = clean(() => buildIco(group, new Map([[1, new Uint8Array(0x100000)]])))!;
    expect(ico.length).toBe(6 + 16 + 0x100000);
  });

  it("an extended DIALOG of 18-25 bytes is null, not a RangeError", () => {
    expect(parseDialog(Uint8Array.from([1, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 0, 1, 0]))).toBeNull();
  });

  it("40000 overlapping image-sized sections do not multiply the section scans (was 40000 x 2 MiB each)", () => {
    const size = 0x200000;
    const { img, dv } = blankPe(size);
    dv.setUint16(0x84 + 2, 40000, true);
    for (let i = 0; i < 40000; i++) {
      const o = kSections + i * 40;
      dv.setUint32(o + 8, size, true);
      dv.setUint32(o + 12, 0, true);
      dv.setUint32(o + 16, size, true);
      dv.setUint32(o + 36, i & 1 ? 0x40000040 : 0x60000020, true);
    }
    const pe = parsePe(img);
    expect(pe.sections.length).toBe(40000);
    clean(() => sectionEntropies(img, pe), 2000);
    clean(() => scanAntiDebug(img, 0n, pe), 2000);
    clean(() => buildRtti(img, 0n, pe), 2000);
    clean(() => buildXrefIndex(img, executableRanges(img, pe)), 2000);
  });

  it("findVftables counts slots in linear time (was quadratic over a section of locator pointers)", () => {
    // .text holds the locator (signature 1, type descriptor at +16); every .data qword points at it
    const img = buildTestPe([{ name: ".text", rva: 0x1000, bytes: new Uint8Array(0x100) }, { name: ".data", rva: 0x2000, bytes: new Uint8Array(0x80000), chars: 0x40000040 }]);
    const dv = new DataView(img.buffer);
    dv.setUint32(0x1000, 1, true);
    dv.setBigUint64(0x1010, 0x3000n, true);
    for (let o = 0x2000; o < 0x82000; o += 8) dv.setBigUint64(o, 0x1000n, true);
    const cls = { mangled: "", name: "", base: "", address: "0x3000", rva: 0x3000, vftables: [] };
    const v = clean(() => findVftables(img, 0n, cls), 2000)!;
    expect(v.length).toBe(0x80000 / 8 - 1);
    expect(v[0].slots).toBe(0x80000 / 8);
    expect(v[v.length - 1].slots).toBe(2);
  });

  it("buildDumpPe refuses a SectionAlignment that would size a 2 GiB output", () => {
    const { img, dv } = blankPe(0x2000);
    dv.setUint32(kOh + 32, 0x80000000, true);
    dv.setUint32(kOh + 60, 0x400, true);
    expect(() => buildDumpPe(img, 0x140000000n, 0x1000, [])).toThrow(/SectionAlignment/);
  });
});

/** A mapped managed image around `tables` / `strings` (any size), CLI header at 0x1000, metadata at 0x2000. */
function managed(tables: TableDef[], strings: number[], heapSizes = 0): Uint8Array {
  const meta = buildMetadata([{ name: "#~", data: buildTables(tables, heapSizes) }, { name: "#Strings", data: strings }]);
  const cli = new Uint8Array(0x48);
  const dv = new DataView(cli.buffer);
  dv.setUint32(0, 0x48, true);
  dv.setUint32(8, 0x2000, true);
  dv.setUint32(12, meta.length, true);
  return buildTestPe([{ name: ".cli", rva: 0x1000, bytes: cli }, { name: ".meta", rva: 0x2000, bytes: meta }], { 14: { rva: 0x1000, size: 0x48 } });
}

const typeDef = (name: number, fieldList: number, methodList: number) => [0, name, 0, 0, fieldList, methodList];
const methodDef = (name: number) => [0, 0, 0, name, 0, 1];
const kTypeDef = (rows: number[][]): TableDef => ({ id: 2, widths: [4, 2, 2, 2, 2, 2], rows });
const kMethodDef = (rows: number[][]): TableDef => ({ id: 6, widths: [4, 2, 2, 2, 2, 2], rows });

describe(".NET regressions", () => {
  const strs = buildStrings(["T", "M"]);

  it("alternating MethodList starts (1, N, 1, N...) no longer give every other type all N methods (was 1.3e8 method entries)", () => {
    const n = 16000; // below 2^14 rows, so coded indexes stay 2 bytes wide;
    const types = Array.from({ length: n }, (_, i) => typeDef(strs.at.T!, 1, i % 2 ? n : 1));
    const img = managed([kTypeDef(types), kMethodDef(Array.from({ length: n }, () => methodDef(strs.at.M!)))], strs.data);
    const info = clean(() => parseDotnet(img), 3000)!;
    expect(info.types.reduce((k, t) => k + t.methods.length, 0)).toBe(n);
    const md = clean(() => openMetadata(img), 3000)!; // owner lookup was types x methods
    expect(md.methods.length).toBe(n);
  });

  it("rows naming one unterminated #Strings run decode it once and at most 4 KiB of it", () => {
    const heap = [0, ...new Array(0xfff0).fill(0x41)];
    const types = Array.from({ length: 16000 }, () => typeDef(1, 1, 1));
    const img = managed([kTypeDef(types)], heap);
    const info = clean(() => parseDotnet(img), 3000)!;
    expect(info.types[0].name.length).toBe(4096);
  });

  it("a 16000-deep NestedClass chain names types instead of overflowing the stack (parseDotnet returned null)", () => {
    const n = 16000;
    const types = Array.from({ length: n }, () => typeDef(strs.at.T!, 1, 1));
    const nested: TableDef = { id: 41, widths: [2, 2], rows: Array.from({ length: n - 1 }, (_, i) => [i + 1, i + 2]) };
    const info = clean(() => parseDotnet(managed([kTypeDef(types), nested], strs.data)), 3000);
    expect(info?.types.length).toBe(n);
  });

  it("a fat method header at the last byte is an IlError (fuzz counterexample [0, 0, 0x7f] at 2)", () => {
    expect(() => disassembleIl(Uint8Array.from([0, 0, 0x7f]), 2)).toThrow(IlError);
    // an operand cut off by the end of the body: ldc.i4 with 1 of its 4 bytes
    const body = disassembleIl(Uint8Array.from([0, (2 << 2) | 2, 0x20, 0x01]), 1);
    expect(body.code[0]).toMatchObject({ opcode: "ldc.i4", operand: "<truncated>" });
    // an exception section claiming far more clauses than the image holds
    const fat = Uint8Array.from([0, 0x1b, 0x30, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x2a, 0, 0, 0, 0x41, 0xff, 0xff, 0xff]);
    expect(() => clean(() => disassembleIl(fat, 1))).not.toThrow();
  });

  it("thousands of methods sharing one huge body are disassembled once", () => {
    const img = new Uint8Array(0x10100);
    const dv = new DataView(img.buffer);
    dv.setUint16(0x100, 0x3003, true); // fat header, 12 bytes
    dv.setUint32(0x104, 0x10000 - 12, true); // code size: 65524 nops
    const methods = Array.from({ length: 5000 }, (_, i) => ({ token: 0x06000001 + i, rva: 0x100, name: "m", type: "T" }));
    expect(clean(() => userStringRefs(img, methods), 3000)!.size).toBe(0);
  });
});

describe("ELF regressions", () => {
  it("an ELF identity without the rest of the header is an ElfError (fuzz counterexample)", () => {
    expect(() => parseElf(Uint8Array.from([127, 69, 76, 70, 2, 1]))).toThrow(ElfError);
  });

  it("20000 symbols naming one unterminated 4 KiB run decode it once", () => {
    const b = new Uint8Array(0x2000 + 24 * 20001);
    const dv = new DataView(b.buffer);
    b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    dv.setBigUint64(40, 0x40n, true); // shoff
    dv.setUint16(60, 3, true); // shnum
    const sh = (i: number, type: number, off: number, size: number, link: number) => {
      const o = 0x40 + i * 64;
      dv.setUint32(o + 4, type, true);
      dv.setBigUint64(o + 24, BigInt(off), true);
      dv.setBigUint64(o + 32, BigInt(size), true);
      dv.setUint32(o + 40, link, true);
    };
    sh(1, 2, 0x2000, 24 * 20001, 2);
    sh(2, 3, 0x1000, 0x1000, 0);
    b.fill(0x41, 0x1000, 0x2000);
    const info = clean(() => parseElf(b), 2000)!;
    expect(info.symbols.length).toBe(20000);
    expect(info.symbols[0].name.length).toBe(0x1000);
  });
});

describe("engine regressions", () => {
  it("IL2CPP: an empty type table with a huge type count is an error (was a 2^31 iteration loop)", () => {
    const b = il2cppMetadata();
    const dv = new DataView(b.buffer);
    dv.setUint32(0x80c, 0x7fffffff, true); // image typeCount
    dv.setUint32(0xa4, 0, true); // type table size
    expect(() => clean(() => parseMetadata(b), 500)).not.toThrow();
    expect(() => parseMetadata(b)).toThrow(/type table/);
  });

  it("Unreal: a section of block-pointer-like qwords is scanned in linear time (was 8191 reads per offset)", () => {
    const img = new Uint8Array(0x100000);
    const dv = new DataView(img.buffer);
    for (let o = 0; o < img.length; o += 8) dv.setBigUint64(o, 0x2_00001ffen, true); // cursor 2, current block 8190
    expect(clean(() => findNamePools(img, 0n, [{ rva: 0, size: img.length }]), 2000)).toEqual([]);
  });

  it("jump tables: a `cmp eax, 0xffffffff` bound is capped", () => {
    const lines = [
      { address: "0x140001000", length: 3, text: "cmp eax, 0xffffffff" },
      { address: "0x140001003", length: 2, text: "ja 0x140001100" },
      { address: "0x140001005", length: 7, text: "lea rdx, [rip+0x0]" },
      { address: "0x14000100c", length: 4, text: "movsxd rax, dword ptr [rdx+rax*4]" },
      { address: "0x140001010", length: 3, text: "add rax, rdx" },
      { address: "0x140001013", length: 2, text: "jmp rax" },
    ];
    const t = clean(() => resolveSwitch(lines, 5, new Uint8Array(0x100000), 0x140000000n))!;
    expect(t.count).toBe(1 << 16);
  });
});
