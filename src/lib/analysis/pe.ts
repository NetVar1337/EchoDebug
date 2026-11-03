// PE parser over an in-memory image (offsets are RVAs, the loader already mapped sections)

export type Section = { name: string; rva: number; vsize: number; rawSize: number; chars: number; r: boolean; w: boolean; x: boolean };
export type DataDir = { name: string; rva: number; size: number };
export type Export = { name: string; ordinal: number; rva: number; forwarder?: string };
export type ImportFn = { name?: string; ordinal?: number; iatRva: number };
export type ImportDll = { dll: string; funcs: ImportFn[] };
export type PeInfo = {
  is64: boolean;
  machine: number;
  timestamp: number;
  entryRva: number;
  imageBase: bigint;
  sizeOfImage: number;
  subsystem: number;
  characteristics: number;
  dllCharacteristics: number;
  sections: Section[];
  dirs: DataDir[];
  exports: Export[];
  imports: ImportDll[];
};

const kDirNames = [
  "Export", "Import", "Resource", "Exception", "Security", "BaseReloc", "Debug", "Architecture",
  "GlobalPtr", "TLS", "LoadConfig", "BoundImport", "IAT", "DelayImport", "CLR", "Reserved",
];
const kMaxNames = 100_000;
/** Cap on imported functions across all descriptors (descriptors may share one thunk array). */
const kMaxImports = 100_000;
/** mapPeFile refuses a SizeOfImage above this, and above kImageRatio x the file size (min. kImageFloor). */
const kMaxImage = 1 << 30;
const kImageRatio = 16;
const kImageFloor = 16 << 20;

/**
 * Budget for scans that walk every section (or every range derived from them) of a `len`-byte
 * buffer. Section headers can overlap, and a hostile table repeats one image-sized section
 * thousands of times; `take(start, end)` is false once the ranges handed out would cover more
 * than twice the buffer, so such scans stay linear. Valid images never overlap and never hit it.
 */
export function scanBudget(len: number): (start: number, end: number) => boolean {
  let left = 2 * len + 0x10000;
  return (start, end) => {
    const n = Math.max(0, end - start);
    if (n > left) return false;
    left -= n;
    return true;
  };
}

function cstr(b: Uint8Array, off: number, max = 512): string {
  let s = "";
  for (let i = off; i < b.length && i < off + max && b[i] !== 0; i++) s += String.fromCharCode(b[i]);
  return s;
}

export function parsePe(img: Uint8Array): PeInfo {
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const u16 = (o: number) => dv.getUint16(o, true);
  const u32 = (o: number) => dv.getUint32(o, true);
  const inRange = (o: number, n = 1) => o >= 0 && o + n <= img.length;

  if (img.length < 0x40 || u16(0) !== 0x5a4d) throw new Error("no MZ header");
  const nt = u32(0x3c);
  if (!inRange(nt, 0x18) || u32(nt) !== 0x4550) throw new Error("no PE signature");
  const fh = nt + 4;
  const machine = u16(fh);
  const nsec = u16(fh + 2);
  const timestamp = u32(fh + 4);
  const optSize = u16(fh + 16);
  const characteristics = u16(fh + 18);
  const oh = fh + 20;
  if (!inRange(oh, 2)) throw new Error("truncated optional header");
  const magic = u16(oh);
  const is64 = magic === 0x20b;
  if (!is64 && magic !== 0x10b) throw new Error(`bad optional header magic 0x${magic.toString(16)}`);
  if (!inRange(oh, is64 ? 112 : 96)) throw new Error("truncated optional header");
  const entryRva = u32(oh + 16);
  const imageBase = is64 ? dv.getBigUint64(oh + 24, true) : BigInt(u32(oh + 28));
  const sizeOfImage = u32(oh + 56);
  const subsystem = u16(oh + 68);
  const dllCharacteristics = u16(oh + 70);
  const ddOff = oh + (is64 ? 112 : 96);
  const nDirs = Math.min(16, u32(oh + (is64 ? 108 : 92)));
  const dirs: DataDir[] = [];
  for (let i = 0; i < nDirs && inRange(ddOff + i * 8, 8); i++) dirs.push({ name: kDirNames[i], rva: u32(ddOff + i * 8), size: u32(ddOff + i * 8 + 4) });

  const sections: Section[] = [];
  const st = oh + optSize;
  for (let i = 0; i < nsec && inRange(st + i * 40, 40); i++) {
    const o = st + i * 40;
    const chars = u32(o + 36);
    sections.push({
      name: cstr(img, o, 8),
      vsize: u32(o + 8),
      rva: u32(o + 12),
      rawSize: u32(o + 16),
      chars,
      r: (chars & 0x40000000) !== 0,
      w: (chars & 0x80000000) !== 0,
      x: (chars & 0x20000000) !== 0,
    });
  }

  const exports: Export[] = [];
  const ed = dirs[0];
  if (ed && ed.rva && inRange(ed.rva, 40)) {
    const ordBase = u32(ed.rva + 16);
    const nFuncs = Math.min(u32(ed.rva + 20), kMaxNames);
    const nNames = Math.min(u32(ed.rva + 24), kMaxNames);
    const fAddr = u32(ed.rva + 28);
    const nAddr = u32(ed.rva + 32);
    const oAddr = u32(ed.rva + 36);
    const named = new Map<number, string>();
    for (let i = 0; i < nNames && inRange(nAddr + i * 4, 4) && inRange(oAddr + i * 2, 2); i++) {
      named.set(u16(oAddr + i * 2), cstr(img, u32(nAddr + i * 4)));
    }
    for (let i = 0; i < nFuncs && inRange(fAddr + i * 4, 4); i++) {
      const rva = u32(fAddr + i * 4);
      if (!rva) continue;
      const e: Export = { name: named.get(i) ?? "", ordinal: ordBase + i, rva };
      if (rva >= ed.rva && rva < ed.rva + ed.size) e.forwarder = cstr(img, rva);
      exports.push(e);
    }
  }

  const imports: ImportDll[] = [];
  const id = dirs[1];
  let budget = kMaxImports;
  if (id && id.rva) {
    for (let d = id.rva; inRange(d, 20) && imports.length < 4096 && budget > 0; d += 20) {
      const oft = u32(d);
      const nameRva = u32(d + 12);
      const ft = u32(d + 16);
      if (!nameRva && !ft) break;
      const dll: ImportDll = { dll: cstr(img, nameRva), funcs: [] };
      const thunks = oft || ft;
      const step = is64 ? 8 : 4;
      for (let i = 0; i < kMaxNames && budget > 0; i++, budget--) {
        const t = thunks + i * step;
        if (!inRange(t, step)) break;
        const v = is64 ? dv.getBigUint64(t, true) : BigInt(u32(t));
        if (v === 0n) break;
        const byOrd = is64 ? (v >> 63n) === 1n : (v >> 31n) === 1n;
        const iatRva = ft + i * step;
        if (byOrd) dll.funcs.push({ ordinal: Number(v & 0xffffn), iatRva });
        else dll.funcs.push({ name: cstr(img, Number(v & 0x7fffffffn) + 2), iatRva });
      }
      imports.push(dll);
    }
  }

  return { is64, machine, timestamp, entryRva, imageBase, sizeOfImage, subsystem, characteristics, dllCharacteristics, sections, dirs, exports, imports };
}

export type RuntimeFunction = { begin: number; end: number; unwind: number; chained: boolean };

/**
 * x64 exception directory (.pdata): one RUNTIME_FUNCTION {begin, end, unwind} per function or
 * function fragment. Fragments whose UNWIND_INFO has UNW_FLAG_CHAININFO continue the function
 * before them, so they are flagged `chained` and are not function starts.
 */
export function parseRuntimeFunctions(img: Uint8Array, pe?: PeInfo): RuntimeFunction[] {
  const info = pe ?? parsePe(img);
  const dir = info.dirs.find((d) => d.name === "Exception");
  if (!dir || !dir.rva || dir.size < 12) return [];
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const out: RuntimeFunction[] = [];
  for (let o = dir.rva; o + 12 <= dir.rva + dir.size && o + 12 <= img.length; o += 12) {
    const begin = dv.getUint32(o, true);
    const end = dv.getUint32(o + 4, true);
    const unwind = dv.getUint32(o + 8, true);
    if (!begin || end <= begin || end > img.length) continue;
    const flags = unwind > 0 && unwind < img.length ? img[unwind & ~1] >> 3 : 0;
    out.push({ begin, end, unwind, chained: (unwind & 1) === 0 && (flags & 4) !== 0 });
  }
  return out.sort((a, b) => a.begin - b.begin);
}

/** Lays a PE *file* out like the loader does (headers + each section at its RVA), unrelocated. */
export function mapPeFile(file: Uint8Array): Uint8Array {
  const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
  if (file.length < 0x40 || dv.getUint16(0, true) !== 0x5a4d) throw new Error("no MZ header");
  const nt = dv.getUint32(0x3c, true);
  if (nt + 24 > file.length || dv.getUint32(nt, true) !== 0x4550) throw new Error("no PE signature");
  const fh = nt + 4;
  const nsec = dv.getUint16(fh + 2, true);
  const optSize = dv.getUint16(fh + 16, true);
  const oh = fh + 20;
  if (oh + 64 > file.length) throw new Error("truncated optional header");
  const sizeOfImage = dv.getUint32(oh + 56, true);
  const sizeOfHeaders = dv.getUint32(oh + 60, true);
  if (sizeOfImage > kMaxImage || sizeOfImage > Math.max(kImageFloor, file.length * kImageRatio)) {
    throw new Error(`SizeOfImage 0x${sizeOfImage.toString(16)} is implausibly large for a ${file.length} byte file`);
  }
  const img = new Uint8Array(sizeOfImage);
  img.set(file.subarray(0, Math.min(sizeOfHeaders, file.length, sizeOfImage)));
  const st = oh + optSize;
  for (let i = 0; i < nsec; i++) {
    const o = st + i * 40;
    if (o + 40 > file.length) break;
    const vsize = dv.getUint32(o + 8, true);
    const rva = dv.getUint32(o + 12, true);
    const rawSize = dv.getUint32(o + 16, true);
    const rawPtr = dv.getUint32(o + 20, true);
    const n = Math.min(rawSize, vsize || rawSize, file.length - rawPtr, sizeOfImage - rva);
    if (n > 0 && rawPtr < file.length && rva < sizeOfImage) img.set(file.subarray(rawPtr, rawPtr + n), rva);
  }
  return img;
}
