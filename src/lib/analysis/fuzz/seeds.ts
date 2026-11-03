// Test-only seed inputs for the fuzz tests: the real PE fixtures (files and mapped images) and
// small synthetic images that reach the parts the fixtures do not (exports with a forwarder, RTTI,
// .pdata, a switch table, an ELF with every table the parser reads).
import { readFileSync } from "node:fs";
import { mapPeFile } from "../pe";
import { buildTestPe } from "../testpe";
import { buildManagedImage, kCliRva, kMetaRva } from "../testdotnet";
import { peRegions, type Regions } from "./harness";

export const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`../fixtures/${n}`, import.meta.url)));

export type Seed = { name: string; bytes: Uint8Array; regions: Regions };

const enc = (s: string) => new TextEncoder().encode(s);

/** Mapped PE32+ with an export directory: two named exports, one ordinal-only, one forwarder. */
export function exportPe(): Uint8Array {
  return buildTestPe(
    [{ name: ".text", rva: 0x1000, bytes: new Uint8Array(0x100).fill(0xc3) }, { name: ".rdata", rva: 0x2000, bytes: new Uint8Array(0x600), chars: 0x40000040 }],
    { 0: { rva: 0x2000, size: 0x500 } },
    {
      headerBytes: (img) => {
        const dv = new DataView(img.buffer);
        const ed = 0x2000;
        dv.setUint32(ed + 12, 0x2480, true); // dll name
        dv.setUint32(ed + 16, 1, true); // ordinal base
        dv.setUint32(ed + 20, 4, true); // functions
        dv.setUint32(ed + 24, 3, true); // names
        dv.setUint32(ed + 28, 0x2100, true);
        dv.setUint32(ed + 32, 0x2200, true);
        dv.setUint32(ed + 36, 0x2300, true);
        [0x1000, 0x1010, 0x2400, 0x1020].forEach((r, i) => dv.setUint32(0x2100 + i * 4, r, true));
        [0x2380, 0x2390, 0x23a0].forEach((r, i) => dv.setUint32(0x2200 + i * 4, r, true));
        [0, 1, 2].forEach((o, i) => dv.setUint16(0x2300 + i * 2, o, true));
        img.set(enc("Alpha\0"), 0x2380);
        img.set(enc("Beta\0"), 0x2390);
        img.set(enc("Fwd\0"), 0x23a0);
        img.set(enc("NTDLL.RtlFoo\0"), 0x2400); // forwarder string inside the directory
        img.set(enc("test.dll\0"), 0x2480);
      },
    },
  );
}

/** Mapped PE32+ with RTTI: two type descriptors, a base class descriptor, a COL and a vftable. */
export function rttiPe(): Uint8Array {
  return buildTestPe(
    [{ name: ".text", rva: 0x1000, bytes: new Uint8Array(0x100).fill(0xc3) }, { name: ".data", rva: 0x2000, bytes: new Uint8Array(0x1000), chars: 0x40000040 }],
    {},
    {
      headerBytes: (img) => {
        const dv = new DataView(img.buffer);
        img.set(enc(".?AVPlayer@@\0"), 0x2800);
        img.set(enc(".?AVObject@@\0"), 0x2840);
        dv.setBigUint64(0x2040 + 8, 0x2800n, true); // type descriptor A
        dv.setBigUint64(0x2060 + 8, 0x2840n, true); // type descriptor B
        dv.setBigUint64(0x2040 - 0x10, 0x2060n, true); // A's base class descriptor -> B
        dv.setUint32(0x2100, 1, true); // complete object locator for A
        dv.setBigUint64(0x2100 + 16, 0x2040n, true);
        dv.setBigUint64(0x2200, 0x2100n, true);
        dv.setBigUint64(0x2208, 0x140001000n, true);
        dv.setBigUint64(0x2210, 0x140001040n, true);
      },
    },
  );
}

/** Mapped PE32+ with an exception directory (three RUNTIME_FUNCTIONs, one chained). */
export function pdataPe(): Uint8Array {
  const pdata = new Uint8Array(36);
  const dv = new DataView(pdata.buffer);
  [[0x1000, 0x1040, 0x3000], [0x1040, 0x1080, 0x3010], [0x1100, 0x1180, 0x3020]].forEach(([b, e, u], i) => {
    dv.setUint32(i * 12, b, true);
    dv.setUint32(i * 12 + 4, e, true);
    dv.setUint32(i * 12 + 8, u, true);
  });
  const unwind = new Uint8Array(0x30);
  unwind[0] = 1;
  unwind[0x10] = 1 | (4 << 3);
  unwind[0x20] = 1;
  return buildTestPe(
    [{ name: ".text", rva: 0x1000, bytes: new Uint8Array(0x200) }, { name: ".pdata", rva: 0x2000, bytes: pdata, chars: 0x40000040 }, { name: ".rdata", rva: 0x3000, bytes: unwind, chars: 0x40000040 }],
    { 3: { rva: 0x2000, size: 36 } },
  );
}

/** A small ELF64 file: PT_LOAD/PT_DYNAMIC/PT_INTERP, .symtab/.strtab/.dynamic/.dynstr/.rela/.note.gnu.build-id/.shstrtab. */
export function elfFile(): Uint8Array {
  const b = new Uint8Array(0x800);
  const dv = new DataView(b.buffer);
  b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1], 0);
  dv.setUint16(16, 3, true); // ET_DYN
  dv.setUint16(18, 62, true); // x86-64
  dv.setBigUint64(24, 0x1000n, true);
  dv.setBigUint64(32, 64n, true); // phoff
  dv.setBigUint64(40, 0x400n, true); // shoff
  dv.setUint16(56, 3, true); // phnum
  dv.setUint16(60, 9, true); // shnum
  dv.setUint16(62, 8, true); // shstrndx
  const ph = (i: number, type: number, flags: number, off: number, vaddr: number, size: number) => {
    const o = 64 + i * 56;
    dv.setUint32(o, type, true);
    dv.setUint32(o + 4, flags, true);
    dv.setBigUint64(o + 8, BigInt(off), true);
    dv.setBigUint64(o + 16, BigInt(vaddr), true);
    dv.setBigUint64(o + 32, BigInt(size), true);
    dv.setBigUint64(o + 40, BigInt(size), true);
    dv.setBigUint64(o + 48, 0x1000n, true);
  };
  ph(0, 1, 5, 0, 0, 0x800);
  ph(1, 2, 6, 0x300, 0x300, 0x40);
  ph(2, 3, 4, 0x1f0, 0x1f0, 16);
  b.set(enc("/lib/ld.so\0"), 0x1f0);
  // .strtab at 0x200, .symtab at 0x240 (3 symbols), .dynstr at 0x2c0, .dynamic at 0x300, .rela at 0x340, note at 0x380, .shstrtab at 0x3a0
  b.set(enc("\0main\0helper\0"), 0x200);
  const sym = (i: number, name: number, info: number, value: number) => {
    const o = 0x240 + i * 24;
    dv.setUint32(o, name, true);
    b[o + 4] = info;
    dv.setUint16(o + 6, 1, true);
    dv.setBigUint64(o + 8, BigInt(value), true);
    dv.setBigUint64(o + 16, 16n, true);
  };
  sym(1, 1, 0x12, 0x1000);
  sym(2, 6, 0x12, 0x1010);
  b.set(enc("\0libc.so.6\0libx.so\0"), 0x2c0);
  const dyn = (i: number, tag: number, v: number) => { dv.setBigInt64(0x300 + i * 16, BigInt(tag), true); dv.setBigUint64(0x308 + i * 16, BigInt(v), true); };
  dyn(0, 1, 1);
  dyn(1, 14, 11);
  dyn(2, 5, 0x2c0);
  dv.setBigUint64(0x340, 0x2000n, true);
  dv.setBigUint64(0x348, (1n << 32n) | 7n, true);
  dv.setUint32(0x380, 4, true);
  dv.setUint32(0x384, 8, true);
  dv.setUint32(0x388, 3, true);
  b.set(enc("GNU\0"), 0x38c);
  b.set([1, 2, 3, 4, 5, 6, 7, 8], 0x390);
  const names = "\0.symtab\0.strtab\0.dynstr\0.dynamic\0.rela.dyn\0.note.gnu.build-id\0.shstrtab\0.text\0";
  b.set(enc(names), 0x3a0);
  const at = (n: string) => names.indexOf(n);
  const sh = (i: number, name: number, type: number, off: number, size: number, link = 0, entsize = 0) => {
    const o = 0x400 + i * 64;
    dv.setUint32(o, name, true);
    dv.setUint32(o + 4, type, true);
    dv.setBigUint64(o + 24, BigInt(off), true);
    dv.setBigUint64(o + 32, BigInt(size), true);
    dv.setUint32(o + 40, link, true);
    dv.setBigUint64(o + 56, BigInt(entsize), true);
  };
  sh(1, at(".symtab"), 2, 0x240, 72, 2, 24);
  sh(2, at(".strtab"), 3, 0x200, 0x20);
  sh(3, at(".dynstr"), 3, 0x2c0, 0x20);
  sh(4, at(".dynamic"), 6, 0x300, 0x40, 3, 16);
  sh(5, at(".rela.dyn"), 4, 0x340, 24, 1, 24);
  sh(6, at(".note.gnu.build-id"), 7, 0x380, 24);
  sh(7, at(".text"), 1, 0x100, 0x40);
  sh(8, at(".shstrtab"), 3, 0x3a0, names.length);
  return b;
}

export function elfRegions(): Regions {
  return [[0, 64], [64, 64 + 3 * 56], [0x400, 0x400 + 9 * 64], [0x240, 0x2c0], [0x300, 0x3a0]];
}

let cache: { files: Seed[]; images: Seed[] } | null = null;

/** PE seeds: the fixtures as files and mapped, plus the synthetic images (mapped). */
export function peSeeds(): { files: Seed[]; images: Seed[] } {
  if (cache) return cache;
  const files = ["fix.exe", "fix-res.exe", "fix-signed.exe"].map((n) => {
    const bytes = fixture(n);
    return { name: n, bytes, regions: peRegions(bytes, false) };
  });
  const mapped = files.map((f) => ({ name: `${f.name} (mapped)`, bytes: mapPeFile(f.bytes) }));
  const synthetic = [{ name: "exports", bytes: exportPe() }, { name: "rtti", bytes: rttiPe() }, { name: "pdata", bytes: pdataPe() }];
  const images = [...mapped, ...synthetic].map((s) => ({ ...s, regions: peRegions(s.bytes, true) }));
  cache = { files, images };
  return cache;
}

/** Managed images (narrow and wide heap indexes) with a #US heap and a tiny and a fat method body. */
export function dotnetSeeds(): Seed[] {
  const us = [0, 11, ...Array.from("hello").flatMap((c) => [c.charCodeAt(0), 0]), 0, 3, 0x78, 0, 0];
  const tinyCode = [0x72, 0x01, 0, 0, 0x70, 0x6f, 0x01, 0, 0, 0x0a, 0x26, 0x03, 0x1f, 0x05, 0x58, 0x2d, 0x01, 0x00, 0x2a];
  const tiny = [(tinyCode.length << 2) | 2, ...tinyCode];
  const fatCode = [0x45, 0x02, 0, 0, 0, 0x00, 0, 0, 0, 0x01, 0, 0, 0, 0xde, 0x00, 0xdc, 0x2a];
  const fatHeader = [0x1b, 0x30, 0x02, 0x00, fatCode.length, 0, 0, 0, 0, 0, 0, 0];
  const pad = Array((4 - ((12 + fatCode.length) % 4)) % 4).fill(0);
  const eh = [0x01, 16, 0, 0, 0x02, 0x00, 0x00, 0x00, 15, 0x0f, 0x00, 1, 0, 0, 0, 0];
  const bodies = [{ rva: 0x2250, bytes: tiny }, { rva: 0x2300, bytes: [...fatHeader, ...fatCode, ...pad, ...eh] }];
  const regions: Regions = [[kCliRva, kCliRva + 0x48], [kMetaRva, kMetaRva + 0x200], [0x2250, 0x2270], [0x2300, 0x2340]];
  return [false, true].map((wide) => ({ name: wide ? "managed (wide)" : "managed", bytes: buildManagedImage(wide, { us, bodies }), regions: [...regions, ...peRegions(buildManagedImage(wide), true)] }));
}
