// ELF64 (little-endian) parser for the Linux module browser: header, program headers, sections,
// symbols (.symtab + .dynsym), the dynamic section, relocations and the GNU build-id.
// Works on a module *file* (section headers and symbol tables are usually not mapped).

export type ElfHeader = {
  class: 32 | 64;
  type: number;
  typeName: string;
  machine: number;
  machineName: string;
  entry: bigint;
  phoff: number;
  shoff: number;
  phnum: number;
  shnum: number;
  shstrndx: number;
};
export type ElfSegment = { type: number; typeName: string; flags: string; offset: number; vaddr: bigint; filesz: number; memsz: number; align: number };
export type ElfSection = { index: number; name: string; type: number; typeName: string; flags: string; addr: bigint; offset: number; size: number; link: number; info: number; entsize: number };
export type ElfSymbol = { name: string; value: bigint; size: number; type: string; bind: string; section: number; dynamic: boolean };
export type ElfDynamic = { tag: number; tagName: string; value: bigint; text?: string };
export type ElfReloc = { section: string; offset: bigint; type: number; symbol: string; addend: bigint };
export type ElfInfo = {
  header: ElfHeader;
  segments: ElfSegment[];
  sections: ElfSection[];
  symbols: ElfSymbol[];
  dynamic: ElfDynamic[];
  relocs: ElfReloc[];
  needed: string[];
  soname: string;
  interp: string;
  buildId: string;
};

const kTypes: Record<number, string> = { 0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE" };
const kMachines: Record<number, string> = { 3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V" };
const kPt: Record<number, string> = {
  0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB", 6: "PHDR", 7: "TLS",
  0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY",
};
const kSht: Record<number, string> = {
  0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS",
  9: "REL", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 0x6ffffff6: "GNU_HASH",
  0x6ffffffe: "VERNEED", 0x6fffffff: "VERSYM", 0x6ffffffd: "VERDEF",
};
const kDt: Record<number, string> = {
  0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH", 5: "STRTAB", 6: "SYMTAB", 7: "RELA", 8: "RELASZ",
  9: "RELAENT", 10: "STRSZ", 11: "SYMENT", 12: "INIT", 13: "FINI", 14: "SONAME", 15: "RPATH", 16: "SYMBOLIC",
  17: "REL", 18: "RELSZ", 19: "RELENT", 20: "PLTREL", 21: "DEBUG", 22: "TEXTREL", 23: "JMPREL", 24: "BIND_NOW",
  25: "INIT_ARRAY", 26: "FINI_ARRAY", 27: "INIT_ARRAYSZ", 28: "FINI_ARRAYSZ", 29: "RUNPATH", 30: "FLAGS",
  0x6ffffef5: "GNU_HASH", 0x6ffffffb: "FLAGS_1", 0x6ffffffe: "VERNEED", 0x6fffffff: "VERNEEDNUM", 0x6ffffff0: "VERSYM",
};
const kStt = ["NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE", "COMMON", "TLS"];
const kStb = ["LOCAL", "GLOBAL", "WEAK"];
/** x86-64 relocation types worth naming */
const kRelX64: Record<number, string> = { 1: "64", 2: "PC32", 6: "GLOB_DAT", 7: "JUMP_SLOT", 8: "RELATIVE", 37: "IRELATIVE", 16: "DTPMOD64", 17: "DTPOFF64", 18: "TPOFF64" };

/** AArch64 relocation types worth naming */
const kRelA64: Record<number, string> = {
  257: "ABS64", 1024: "COPY", 1025: "GLOB_DAT", 1026: "JUMP_SLOT", 1027: "RELATIVE", 1028: "TLS_DTPMOD64",
  1029: "TLS_DTPREL64", 1030: "TLS_TPREL64", 1031: "TLSDESC", 1032: "IRELATIVE",
};

export class ElfError extends Error {}

export function isElf(b: Uint8Array): boolean {
  return b.length >= 4 && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46;
}

function cstr(b: Uint8Array, off: number, max = 4096): string {
  let s = "";
  for (let i = off; i >= 0 && i < b.length && i < off + max && b[i] !== 0; i++) s += String.fromCharCode(b[i]);
  return s;
}

function segFlags(f: number): string {
  return `${f & 4 ? "R" : "-"}${f & 2 ? "W" : "-"}${f & 1 ? "X" : "-"}`;
}

function secFlags(f: bigint): string {
  let s = "";
  if (f & 1n) s += "W";
  if (f & 2n) s += "A";
  if (f & 4n) s += "X";
  if (f & 0x10n) s += "M";
  if (f & 0x20n) s += "S";
  if (f & 0x400n) s += "T";
  return s;
}

export function relocTypeName(machine: number, type: number): string {
  return machine === 62 ? (kRelX64[type] ?? String(type)) : machine === 183 ? (kRelA64[type] ?? String(type)) : String(type);
}

/** FUNC symbols with an address as {address, size} file vaddrs (add the load bias), deduplicated. */
export function elfFunctions(info: ElfInfo): { address: bigint; size: number; name: string }[] {
  const byAddr = new Map<bigint, { address: bigint; size: number; name: string }>();
  for (const s of info.symbols) {
    if (s.type !== "FUNC" || !s.value || s.section === 0) continue;
    const cur = byAddr.get(s.value);
    if (!cur || (!s.dynamic && cur.size < s.size)) byAddr.set(s.value, { address: s.value, size: Math.max(s.size, cur?.size ?? 0), name: s.name || cur?.name || "" });
  }
  return [...byAddr.values()].sort((a, b) => (a.address < b.address ? -1 : 1));
}

export function parseElf(buf: Uint8Array): ElfInfo {
  if (!isElf(buf)) throw new ElfError("not an ELF file");
  if (buf.length < 64) throw new ElfError("truncated ELF header");
  if (buf[4] !== 2) throw new ElfError("only ELF64 is supported");
  if (buf[5] !== 1) throw new ElfError("only little-endian ELF is supported");
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (o: number) => dv.getUint16(o, true);
  const u32 = (o: number) => dv.getUint32(o, true);
  const u64 = (o: number) => dv.getBigUint64(o, true);
  const i64 = (o: number) => dv.getBigInt64(o, true);
  const n = (o: number) => Number(u64(o));
  const inside = (o: number, len: number) => o >= 0 && len >= 0 && o + len <= buf.length;
  // symbol / reloc / dynamic names, decoded once per string-table offset: half a million symbols
  // all naming one unterminated 4 KiB run would otherwise build 2 GB of strings
  const nameCache = new Map<number, string>();
  const name = (o: number) => {
    let v = nameCache.get(o);
    if (v === undefined) nameCache.set(o, (v = cstr(buf, o)));
    return v;
  };

  const type = u16(16);
  const machine = u16(18);
  const header: ElfHeader = {
    class: 64, type, typeName: kTypes[type] ?? `0x${type.toString(16)}`, machine, machineName: kMachines[machine] ?? String(machine),
    entry: u64(24), phoff: n(32), shoff: n(40), phnum: u16(56), shnum: u16(60), shstrndx: u16(62),
  };

  const segments: ElfSegment[] = [];
  for (let i = 0; i < header.phnum && i < 256; i++) {
    const o = header.phoff + i * 56;
    if (!inside(o, 56)) break;
    const t = u32(o);
    segments.push({ type: t, typeName: kPt[t] ?? `0x${t.toString(16)}`, flags: segFlags(u32(o + 4)), offset: n(o + 8), vaddr: u64(o + 16), filesz: n(o + 32), memsz: n(o + 40), align: n(o + 48) });
  }

  const raw: Omit<ElfSection, "name">[] = [];
  const names: number[] = [];
  for (let i = 0; i < header.shnum && i < 65535; i++) {
    const o = header.shoff + i * 64;
    if (!inside(o, 64)) break;
    names.push(u32(o));
    const t = u32(o + 4);
    raw.push({ index: i, type: t, typeName: kSht[t] ?? `0x${t.toString(16)}`, flags: secFlags(u64(o + 8)), addr: u64(o + 16), offset: n(o + 24), size: n(o + 32), link: u32(o + 40), info: u32(o + 44), entsize: n(o + 56) });
  }
  const shstr = raw[header.shstrndx];
  const sections: ElfSection[] = raw.map((s, i) => ({ ...s, name: shstr ? name(shstr.offset + names[i]) : "" }));
  const byName = (nm: string) => sections.find((s) => s.name === nm);

  const symbols: ElfSymbol[] = [];
  for (const s of sections.filter((x) => x.type === 2 || x.type === 11)) {
    const strtab = sections[s.link];
    if (!strtab || !inside(s.offset, s.size)) continue;
    for (let o = s.offset + 24; o + 24 <= s.offset + s.size && symbols.length < 500_000; o += 24) {
      const info = buf[o + 4];
      symbols.push({
        name: name(strtab.offset + u32(o)), value: u64(o + 8), size: n(o + 16),
        type: kStt[info & 0xf] ?? String(info & 0xf), bind: kStb[info >> 4] ?? String(info >> 4), section: u16(o + 6), dynamic: s.type === 11,
      });
    }
  }

  // dynamic section: from the section header, else PT_DYNAMIC
  const dynSec = sections.find((s) => s.type === 6);
  const dynSeg = segments.find((s) => s.type === 2);
  const dynOff = dynSec?.offset ?? dynSeg?.offset ?? -1;
  const dynSize = dynSec?.size ?? dynSeg?.filesz ?? 0;
  const dynamic: ElfDynamic[] = [];
  const dynstr = dynSec ? sections[dynSec.link] : byName(".dynstr");
  if (dynOff >= 0 && inside(dynOff, dynSize)) {
    for (let o = dynOff; o + 16 <= dynOff + dynSize; o += 16) {
      const tag = Number(i64(o));
      const value = u64(o + 8);
      if (tag === 0) break;
      const d: ElfDynamic = { tag, tagName: kDt[tag] ?? `0x${tag.toString(16)}`, value };
      if ((tag === 1 || tag === 14 || tag === 15 || tag === 29) && dynstr) d.text = name(dynstr.offset + Number(value));
      dynamic.push(d);
    }
  }

  const relocs: ElfReloc[] = [];
  for (const s of sections.filter((x) => x.type === 4)) {
    const symtab = sections[s.link];
    const strtab = symtab ? sections[symtab.link] : undefined;
    if (!inside(s.offset, s.size)) continue;
    for (let o = s.offset; o + 24 <= s.offset + s.size && relocs.length < 500_000; o += 24) {
      const info = u64(o + 8);
      const symIdx = Number(info >> 32n);
      let symbol = "";
      if (symIdx && symtab && strtab && inside(symtab.offset + symIdx * 24, 24)) symbol = name(strtab.offset + u32(symtab.offset + symIdx * 24));
      relocs.push({ section: s.name, offset: u64(o), type: Number(info & 0xffffffffn), symbol, addend: i64(o + 16) });
    }
  }

  const interpSeg = segments.find((s) => s.type === 3);
  const interp = interpSeg && inside(interpSeg.offset, interpSeg.filesz) ? cstr(buf, interpSeg.offset, interpSeg.filesz) : "";

  let buildId = "";
  const note = byName(".note.gnu.build-id");
  if (note && inside(note.offset, note.size) && note.size >= 16) {
    const namesz = u32(note.offset);
    const descsz = u32(note.offset + 4);
    const desc = note.offset + 12 + ((namesz + 3) & ~3);
    if (inside(desc, descsz)) buildId = Array.from(buf.subarray(desc, desc + descsz), (x) => x.toString(16).padStart(2, "0")).join("");
  }

  return {
    header, segments, sections, symbols, dynamic, relocs,
    needed: dynamic.filter((d) => d.tag === 1).map((d) => d.text ?? ""),
    soname: dynamic.find((d) => d.tag === 14)?.text ?? "",
    interp, buildId,
  };
}

/** Load bias for a module mapped at `base`: lowest PT_LOAD vaddr maps to base. */
export function elfBias(info: ElfInfo, base: bigint): bigint {
  const loads = info.segments.filter((s) => s.type === 1);
  const lowest = loads.length ? loads.reduce((m, s) => (s.vaddr < m ? s.vaddr : m), loads[0].vaddr) & ~0xfffn : 0n;
  return base - lowest;
}
