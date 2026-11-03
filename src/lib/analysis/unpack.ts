// Unpacking helpers: find the original entry point from an emulator trace, recover the import
// address table from a dumped image, and write the dump back out as a runnable PE whose imports
// point at the recovered IAT.
import { parsePe, type PeInfo } from "./pe";

export type MemWrite = { address: bigint; size: number };
export type OepCandidate = { address: bigint; step: number; reason: "written-then-executed" | "section-change" };

/**
 * OEP candidates from a trace (instruction addresses in order) and the emulator's write log:
 *  - the first instruction executed from bytes the run itself wrote (classic unpack-then-jump)
 *  - the first jump that leaves the entry point's section for another section of the image
 */
export function findOep(trace: readonly bigint[], writes: readonly MemWrite[], sections: readonly { start: bigint; end: bigint; name: string }[]): OepCandidate[] {
  const out: OepCandidate[] = [];
  const written = (a: bigint) => writes.some((w) => a >= w.address && a < w.address + BigInt(w.size));
  const sectionOf = (a: bigint) => sections.find((s) => a >= s.start && a < s.end);
  const first = trace[0] !== undefined ? sectionOf(trace[0]) : undefined;
  let sawWrite = false;
  let sawSection = false;
  for (let i = 0; i < trace.length; i++) {
    const a = trace[i];
    if (!sawWrite && written(a)) {
      out.push({ address: a, step: i, reason: "written-then-executed" });
      sawWrite = true;
    }
    if (!sawSection && i > 0 && first) {
      const s = sectionOf(a);
      if (s && s !== first && sectionOf(trace[i - 1]) === first) {
        out.push({ address: a, step: i, reason: "section-change" });
        sawSection = true;
      }
    }
    if (sawWrite && sawSection) break;
  }
  return out.sort((x, y) => x.step - y.step);
}

export type ExportIndex = Map<bigint, { dll: string; name: string; ordinal?: number }>;
export type IatThunk = { rva: number; dll: string; name: string; ordinal?: number };
export type IatBlock = { rva: number; dll: string; thunks: IatThunk[] };

/**
 * Scans a dumped image (indexed by RVA) for IAT runs: aligned pointers that resolve to exports
 * of loaded modules. A run continues through zero separators and ends at the first pointer that
 * is neither zero nor an export; each DLL becomes its own block (the loader needs one descriptor
 * per DLL, and its thunks must be contiguous).
 */
export function findIat(img: Uint8Array, exportsAt: ExportIndex, minRun = 2): IatBlock[] {
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const blocks: IatBlock[] = [];
  let o = 0;
  while (o + 8 <= img.length) {
    const first = exportsAt.get(dv.getBigUint64(o, true));
    if (!first) { o += 8; continue; }
    // collect the run
    const run: (IatThunk | null)[] = [];
    let p = o;
    for (; p + 8 <= img.length; p += 8) {
      const v = dv.getBigUint64(p, true);
      if (v === 0n) { run.push(null); continue; }
      const e = exportsAt.get(v);
      if (!e) break;
      run.push({ rva: p, ...e });
    }
    const thunks = run.filter((t): t is IatThunk => t !== null);
    if (thunks.length >= minRun) {
      let cur: IatBlock | null = null;
      for (const t of run) {
        if (t === null) { cur = null; continue; }
        if (!cur || cur.dll !== t.dll) {
          cur = { rva: t.rva, dll: t.dll, thunks: [] };
          blocks.push(cur);
        }
        cur.thunks.push(t);
      }
    }
    o = p > o ? p : o + 8;
  }
  return blocks;
}

const align = (v: number, a: number) => Math.ceil(v / a) * a;

/**
 * A runnable PE from a dump of a loaded image: raw layout = virtual layout, entry = OEP, a new
 * `.edimp` section holding import descriptors + lookup tables + names whose FirstThunk arrays are
 * the recovered IAT blocks (so the code's existing references keep working), ImageBase = the dump
 * base (no relocations needed to load it there). The thunks in the IAT are rewritten to point at
 * the hint/name entries, as an unbound file needs.
 */
export function buildDumpPe(dump: Uint8Array, base: bigint, oepRva: number, blocks: readonly IatBlock[], pe?: PeInfo): Uint8Array {
  const info = pe ?? parsePe(dump);
  if (!info.is64) throw new Error("only PE32+ dumps are rebuilt");
  const dv0 = new DataView(dump.buffer, dump.byteOffset, dump.byteLength);
  const nt = dv0.getUint32(0x3c, true);
  const fh = nt + 4;
  const oh = fh + 20;
  const optSize = dv0.getUint16(fh + 16, true);
  const nsec = dv0.getUint16(fh + 2, true);
  const st = oh + optSize;
  const sectAlign = dv0.getUint32(oh + 32, true) || 0x1000;
  // the output is align(dump, SectionAlignment) + the new section: a hostile 0x80000000 asked
  // for a 2 GiB buffer. PE section alignment is a power of two; 64 KiB is the largest in use.
  if (sectAlign & (sectAlign - 1) || sectAlign > 0x10000) throw new Error(`implausible SectionAlignment 0x${sectAlign.toString(16)}`);
  const sizeOfHeaders = dv0.getUint32(oh + 60, true) || 0x400;
  if (st + (nsec + 1) * 40 > sizeOfHeaders) throw new Error("no room in the headers for another section");

  // .edimp contents
  const parts: number[] = [];
  const pad = (n: number) => { while (parts.length % n) parts.push(0); };
  const secRva = align(dump.length, sectAlign);
  const descriptors = 0;
  const descSize = (blocks.length + 1) * 20;
  for (let i = 0; i < descSize; i++) parts.push(0);
  const put32 = (off: number, v: number) => { parts[off] = v & 0xff; parts[off + 1] = (v >>> 8) & 0xff; parts[off + 2] = (v >>> 16) & 0xff; parts[off + 3] = (v >>> 24) & 0xff; };
  const put64 = (off: number, v: bigint) => { for (let k = 0; k < 8; k++) parts[off + k] = Number((v >> BigInt(8 * k)) & 0xffn); };
  const iatRewrites: { rva: number; value: bigint }[] = [];
  blocks.forEach((b, i) => {
    pad(8);
    const ilt = parts.length;
    for (let k = 0; k < (b.thunks.length + 1) * 8; k++) parts.push(0);
    b.thunks.forEach((t, k) => {
      let entry: bigint;
      if (t.ordinal !== undefined && !t.name) entry = (1n << 63n) | BigInt(t.ordinal);
      else {
        pad(2);
        const hn = parts.length;
        parts.push(0, 0, ...Array.from(new TextEncoder().encode(t.name)), 0);
        entry = BigInt(secRva + hn);
      }
      put64(ilt + k * 8, entry);
      iatRewrites.push({ rva: t.rva, value: entry });
    });
    const nameOff = parts.length;
    parts.push(...Array.from(new TextEncoder().encode(b.dll)), 0);
    const d = descriptors + i * 20;
    put32(d, secRva + ilt); // OriginalFirstThunk
    put32(d + 12, secRva + nameOff); // Name
    put32(d + 16, b.rva); // FirstThunk: the existing IAT
  });
  pad(16);
  const secSize = Math.max(parts.length, 16);
  const total = secRva + align(secSize, sectAlign);
  const out = new Uint8Array(total);
  out.set(dump.subarray(0, Math.min(dump.length, total)));
  out.set(parts, secRva);
  const dv = new DataView(out.buffer);
  for (const r of iatRewrites) dv.setBigUint64(r.rva, r.value, true);

  // headers: file alignment = section alignment, raw = virtual
  dv.setUint32(oh + 16, oepRva, true);
  dv.setBigUint64(oh + 24, base, true);
  dv.setUint32(oh + 36, sectAlign, true); // FileAlignment
  dv.setUint32(oh + 56, total, true); // SizeOfImage
  dv.setUint32(oh + 64, 0, true); // CheckSum
  const dd = oh + 112;
  dv.setUint32(dd + 1 * 8, secRva + descriptors, true); // Import
  dv.setUint32(dd + 1 * 8 + 4, descSize, true);
  const iatLo = Math.min(...blocks.map((b) => b.rva));
  const iatHi = Math.max(...blocks.map((b) => b.rva + b.thunks.length * 8 + 8));
  if (blocks.length) {
    dv.setUint32(dd + 12 * 8, iatLo, true); // IAT
    dv.setUint32(dd + 12 * 8 + 4, iatHi - iatLo, true);
  }
  dv.setUint32(dd + 11 * 8, 0, true); // BoundImport
  dv.setUint32(dd + 11 * 8 + 4, 0, true);
  for (let i = 0; i < nsec; i++) {
    const o = st + i * 40;
    const vsize = dv.getUint32(o + 8, true);
    const rva = dv.getUint32(o + 12, true);
    const next = i + 1 < nsec ? dv.getUint32(st + (i + 1) * 40 + 12, true) : dump.length;
    const size = align(Math.max(vsize, next - rva), sectAlign);
    dv.setUint32(o + 8, size, true);
    dv.setUint32(o + 16, size, true); // SizeOfRawData
    dv.setUint32(o + 20, rva, true); // PointerToRawData
    dv.setUint32(o + 36, dv.getUint32(o + 36, true) | 0x80000000 | 0x40000000, true); // + read/write (unpackers write their sections)
  }
  const ns = st + nsec * 40;
  out.set(new TextEncoder().encode(".edimp\0\0"), ns);
  dv.setUint32(ns + 8, align(secSize, sectAlign), true);
  dv.setUint32(ns + 12, secRva, true);
  dv.setUint32(ns + 16, align(secSize, sectAlign), true);
  dv.setUint32(ns + 20, secRva, true);
  dv.setUint32(ns + 36, 0xc0000040, true); // initialized data, read, write
  dv.setUint16(fh + 2, nsec + 1, true);
  return out;
}
