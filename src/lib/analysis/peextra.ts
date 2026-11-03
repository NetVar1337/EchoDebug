// PE details beyond headers/sections/imports/exports: Rich header, TLS callbacks, base
// relocations, debug directory (CodeView/PDB), imphash.
// All functions take a *mapped* image (indexed by RVA); TLS callback pointers in a loaded image are
// already relocated, so `base` is the address the image is mapped at.
import { md5 } from "./md5";
import { parsePe, type PeInfo } from "./pe";

export type RichEntry = { prodId: number; build: number; count: number };
export type RichHeader = { offset: number; key: number; entries: RichEntry[]; checksumValid: boolean };

const rol = (v: number, n: number) => ((v << (n & 31)) | (v >>> (32 - (n & 31)))) >>> 0;

/** The "Rich" block the Microsoft linker writes between the DOS stub and the PE header. */
export function parseRich(img: Uint8Array): RichHeader | null {
  if (img.length < 0x40) return null;
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const lfanew = dv.getUint32(0x3c, true);
  const end = Math.min(lfanew, img.length - 8);
  let rich = -1;
  for (let o = 0x80; o + 8 <= end; o += 4) if (dv.getUint32(o, true) === 0x68636952) { rich = o; break; } // "Rich"
  if (rich < 0) return null;
  const key = dv.getUint32(rich + 4, true);
  let dans = -1;
  for (let o = rich - 4; o >= 0x40; o -= 4) if ((dv.getUint32(o, true) ^ key) === 0x536e6144) { dans = o; break; } // "DanS"
  if (dans < 0) return null;
  const entries: RichEntry[] = [];
  for (let o = dans + 16; o + 8 <= rich; o += 8) {
    const id = dv.getUint32(o, true) ^ key;
    const count = dv.getUint32(o + 4, true) ^ key;
    entries.push({ prodId: id >>> 16, build: id & 0xffff, count });
  }
  // checksum: offset of DanS + every DOS-header byte rotated by its position (e_lfanew skipped)
  // + every comp.id rotated by its count
  let csum = dans;
  for (let i = 0; i < dans; i++) {
    if (i >= 0x3c && i < 0x40) continue;
    csum = (csum + rol(img[i], i)) >>> 0;
  }
  for (const e of entries) csum = (csum + rol(((e.prodId << 16) | e.build) >>> 0, e.count)) >>> 0;
  return { offset: dans, key, entries, checksumValid: csum === key };
}

export type TlsInfo = { startRaw: bigint; endRaw: bigint; indexAddress: bigint; callbacksAddress: bigint; callbacks: bigint[]; zeroFill: number; characteristics: number };

export function parseTls(img: Uint8Array, base: bigint, pe?: PeInfo): TlsInfo | null {
  const info = pe ?? parsePe(img);
  const dir = info.dirs.find((d) => d.name === "TLS");
  if (!dir?.rva || dir.rva + (info.is64 ? 40 : 24) > img.length) return null;
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const ptr = (o: number) => (info.is64 ? dv.getBigUint64(o, true) : BigInt(dv.getUint32(o, true)));
  const w = info.is64 ? 8 : 4;
  const t: TlsInfo = {
    startRaw: ptr(dir.rva), endRaw: ptr(dir.rva + w), indexAddress: ptr(dir.rva + 2 * w), callbacksAddress: ptr(dir.rva + 3 * w),
    zeroFill: dv.getUint32(dir.rva + 4 * w, true), characteristics: dv.getUint32(dir.rva + 4 * w + 4, true), callbacks: [],
  };
  if (t.callbacksAddress) {
    const rva = Number(t.callbacksAddress - base);
    for (let i = 0; i < 64 && rva >= 0 && rva + (i + 1) * w <= img.length; i++) {
      const cb = ptr(rva + i * w);
      if (!cb) break;
      t.callbacks.push(cb);
    }
  }
  return t;
}

export type RelocBlock = { page: number; entries: { offset: number; type: number }[] };
export type RelocInfo = { blocks: RelocBlock[]; total: number; byType: Record<string, number> };
const kRelocTypes: Record<number, string> = { 0: "ABSOLUTE", 1: "HIGH", 2: "LOW", 3: "HIGHLOW", 4: "HIGHADJ", 10: "DIR64" };

export function parseRelocs(img: Uint8Array, pe?: PeInfo, maxBlocks = 100000): RelocInfo {
  const info = pe ?? parsePe(img);
  const dir = info.dirs.find((d) => d.name === "BaseReloc");
  const out: RelocInfo = { blocks: [], total: 0, byType: {} };
  if (!dir?.rva) return out;
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  let o = dir.rva;
  const end = Math.min(img.length, dir.rva + dir.size);
  while (o + 8 <= end && out.blocks.length < maxBlocks) {
    const page = dv.getUint32(o, true);
    const size = dv.getUint32(o + 4, true);
    if (size < 8 || o + size > end) break;
    const entries: RelocBlock["entries"] = [];
    for (let e = o + 8; e + 2 <= o + size; e += 2) {
      const v = dv.getUint16(e, true);
      const type = v >> 12;
      const name = kRelocTypes[type] ?? String(type);
      out.byType[name] = (out.byType[name] ?? 0) + 1;
      if (type !== 0) {
        entries.push({ offset: v & 0xfff, type });
        out.total++;
      }
    }
    out.blocks.push({ page, entries });
    o += size;
  }
  return out;
}

export type DebugEntry = { type: number; typeName: string; timestamp: number; size: number; rva: number; codeview?: { format: "RSDS" | "NB10"; guid: string; age: number; path: string; symbolKey: string } };
const kDebugTypes: Record<number, string> = { 1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC", 5: "EXCEPTION", 6: "FIXUP", 9: "BORLAND", 10: "RESERVED10", 11: "CLSID", 12: "VC_FEATURE", 13: "POGO", 14: "ILTCG", 15: "MPX", 16: "REPRO", 20: "EX_DLLCHARACTERISTICS" };

function guidString(b: Uint8Array, o: number): { text: string; key: string } {
  const dv = new DataView(b.buffer, b.byteOffset + o, 16);
  const h = (v: number, n: number) => v.toString(16).toUpperCase().padStart(n, "0");
  const d4 = Array.from(b.subarray(o + 8, o + 16), (x) => h(x, 2));
  const p1 = h(dv.getUint32(0, true), 8), p2 = h(dv.getUint16(4, true), 4), p3 = h(dv.getUint16(6, true), 4);
  return { text: `${p1}-${p2}-${p3}-${d4.slice(0, 2).join("")}-${d4.slice(2).join("")}`, key: `${p1}${p2}${p3}${d4.join("")}` };
}

export function parseDebug(img: Uint8Array, pe?: PeInfo): DebugEntry[] {
  const info = pe ?? parsePe(img);
  const dir = info.dirs.find((d) => d.name === "Debug");
  if (!dir?.rva) return [];
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const out: DebugEntry[] = [];
  for (let o = dir.rva; o + 28 <= dir.rva + dir.size && o + 28 <= img.length; o += 28) {
    const type = dv.getUint32(o + 12, true);
    const e: DebugEntry = { type, typeName: kDebugTypes[type] ?? String(type), timestamp: dv.getUint32(o + 4, true), size: dv.getUint32(o + 16, true), rva: dv.getUint32(o + 20, true) };
    if (type === 2 && e.rva && e.rva + 24 <= img.length) {
      const sig = dv.getUint32(e.rva, true);
      const path = (at: number) => {
        let s = "";
        for (let i = at; i < img.length && img[i] && s.length < 1024; i++) s += String.fromCharCode(img[i]);
        return s;
      };
      if (sig === 0x53445352) { // RSDS
        const g = guidString(img, e.rva + 4);
        const age = dv.getUint32(e.rva + 20, true);
        e.codeview = { format: "RSDS", guid: g.text, age, path: path(e.rva + 24), symbolKey: `${g.key}${age.toString(16).toUpperCase()}` };
      } else if (sig === 0x3031424e) { // NB10
        const stamp = dv.getUint32(e.rva + 8, true);
        const age = dv.getUint32(e.rva + 12, true);
        e.codeview = { format: "NB10", guid: stamp.toString(16).toUpperCase(), age, path: path(e.rva + 16), symbolKey: `${stamp.toString(16).toUpperCase()}${age.toString(16).toUpperCase()}` };
      }
    }
    out.push(e);
  }
  return out;
}

/**
 * imphash (Mandiant): md5 of "dll.function" pairs in import order, lowercased, with .dll/.ocx/.sys
 * removed and ordinals as "ord<n>". pefile resolves a few ws2_32/oleaut32 ordinals to names first;
 * those few imports hash differently here.
 */
export function imphash(pe: PeInfo): string {
  const parts: string[] = [];
  for (const d of pe.imports) {
    let lib = d.dll.toLowerCase();
    const dot = lib.lastIndexOf(".");
    if (dot >= 0 && ["dll", "ocx", "sys"].includes(lib.slice(dot + 1))) lib = lib.slice(0, dot);
    for (const f of d.funcs) parts.push(`${lib}.${(f.name ?? `ord${f.ordinal}`).toLowerCase()}`);
  }
  return parts.length ? md5(parts.join(",")) : "";
}

export type CodeView = NonNullable<DebugEntry["codeview"]>;

/** The RSDS record of an image read piecemeal (`read(rva, size)`): headers, the debug directory and
 *  the CodeView blob only, so a live module's PDB identity costs three small reads. */
export async function readCodeView(read: (rva: number, size: number) => Promise<Uint8Array | null>): Promise<CodeView | null> {
  const hdr = await read(0, 0x400);
  if (!hdr || hdr.length < 0x40 || hdr[0] !== 0x4d || hdr[1] !== 0x5a) return null;
  const dv = new DataView(hdr.buffer, hdr.byteOffset, hdr.byteLength);
  const nt = dv.getUint32(0x3c, true);
  if (nt + 24 + 2 > hdr.length || dv.getUint32(nt, true) !== 0x4550) return null;
  const opt = nt + 24;
  const magic = dv.getUint16(opt, true);
  const dirs = opt + (magic === 0x20b ? 112 : 96);
  const count = dv.getUint32(opt + (magic === 0x20b ? 108 : 92), true);
  if (count <= 6 || dirs + 7 * 8 > hdr.length) return null;
  const dirRva = dv.getUint32(dirs + 6 * 8, true);
  const dirSize = Math.min(dv.getUint32(dirs + 6 * 8 + 4, true), 28 * 32);
  if (!dirRva || dirSize < 28) return null;
  const dir = await read(dirRva, dirSize);
  if (!dir) return null;
  const dd = new DataView(dir.buffer, dir.byteOffset, dir.byteLength);
  for (let o = 0; o + 28 <= dir.length; o += 28) {
    if (dd.getUint32(o + 12, true) !== 2) continue;
    const rva = dd.getUint32(o + 20, true);
    const size = Math.min(dd.getUint32(o + 16, true), 0x1000);
    if (!rva || size < 24) continue;
    const blob = await read(rva, size);
    if (!blob || blob.length < 24) continue;
    const bv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
    if (bv.getUint32(0, true) !== 0x53445352) continue; // RSDS
    const g = guidString(blob, 4);
    const age = bv.getUint32(20, true);
    let path = "";
    for (let i = 24; i < blob.length && blob[i]; i++) path += String.fromCharCode(blob[i]);
    return { format: "RSDS", guid: g.text, age, path, symbolKey: `${g.key}${age.toString(16).toUpperCase()}` };
  }
  return null;
}
