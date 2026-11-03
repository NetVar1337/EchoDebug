// Dumping loaded images and whole targets from memory, x64dbg / Scylla style, as pure functions
// over bytes (the live side reads them through the backend, so the same code dumps over Echo, the
// local /proc backend or anything else that serves `read_batch`):
//
// * fixDump: a module image read from memory (indexed by RVA) turned back into a loadable PE.
//   ImageBase becomes the address it was dumped at (absolute addresses in the dump are already
//   relocated for it), the section table is rewritten for the chosen layout — "virtual" (raw =
//   virtual, Scylla's dump: runs and maps 1:1) or "file" (sections packed at FileAlignment with
//   trailing zeros trimmed, the shape IDA and disk tools expect) — file-offset directories are
//   fixed up (debug directory entries) or dropped (the certificate table, which is not in
//   memory), the entry point can be set to an OEP, and the PE checksum is recomputed (drivers
//   need a valid one to load).
// * recoverHeaders: anti-dump code wipes or corrupts the headers in memory; take them from the
//   module's file on disk instead.
// * findImages: PE images in memory that the loader's module list does not show (manually mapped
//   DLLs, unpacked payloads), and executable memory outside every module with no headers at all.
// * minidumpPrefix / elfCorePrefix: the headers of a full-memory MINIDUMP (WinDbg, x64dbg, the
//   Open Dump panel) or an ELF core file (gdb) whose region data the caller streams after them,
//   so a multi-gigabyte target never has to fit in memory at once.

export type DumpLayout = "virtual" | "file";

export type Hdr = {
  is64: boolean;
  machine: number;
  nt: number;
  fh: number;
  oh: number;
  nsec: number;
  st: number;
  sectAlign: number;
  fileAlign: number;
  sizeOfHeaders: number;
  sizeOfImage: number;
  entryRva: number;
  imageBase: bigint;
  timestamp: number;
  checksumOff: number;
  dirOff: number;
  ndirs: number;
};

const pow2 = (v: number) => v > 0 && (v & (v - 1)) === 0;
const align = (v: number, a: number) => Math.ceil(v / a) * a;

/** Parses the headers far enough to rewrite them; throws with what is wrong. */
export function readHeaders(img: Uint8Array): Hdr {
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  if (img.length < 0x40 || dv.getUint16(0, true) !== 0x5a4d) throw new Error("no MZ signature");
  const nt = dv.getUint32(0x3c, true);
  if (nt < 0x40 || nt + 24 > img.length || nt > 0x1000) throw new Error(`e_lfanew 0x${nt.toString(16)} is out of range`);
  if (dv.getUint32(nt, true) !== 0x4550) throw new Error("no PE signature");
  const fh = nt + 4;
  const machine = dv.getUint16(fh, true);
  const nsec = dv.getUint16(fh + 2, true);
  const optSize = dv.getUint16(fh + 16, true);
  const oh = fh + 20;
  if (oh + 2 > img.length) throw new Error("the optional header is cut short");
  const magic = dv.getUint16(oh, true);
  if (magic !== 0x20b && magic !== 0x10b) throw new Error(`bad optional header magic 0x${magic.toString(16)}`);
  const is64 = magic === 0x20b;
  const dirOff = oh + (is64 ? 112 : 96);
  if (dirOff > img.length || optSize < (is64 ? 112 : 96)) throw new Error("the optional header is cut short");
  const st = oh + optSize;
  if (nsec === 0 || nsec > 96) throw new Error(`implausible section count ${nsec}`);
  if (st + nsec * 40 > img.length) throw new Error("the section table runs past the image");
  const sa = dv.getUint32(oh + 32, true);
  const fa = dv.getUint32(oh + 36, true);
  const sectAlign = pow2(sa) && sa <= 0x10000 ? sa : 0x1000;
  const fileAlign = pow2(fa) && fa >= 0x200 && fa <= sectAlign ? fa : Math.min(0x200, sectAlign);
  const ndirs = Math.min(16, dv.getUint32(oh + (is64 ? 108 : 92), true), Math.floor((st - dirOff) / 8));
  return {
    is64, machine, nt, fh, oh, nsec, st, sectAlign, fileAlign,
    sizeOfHeaders: dv.getUint32(oh + 60, true),
    sizeOfImage: dv.getUint32(oh + 56, true),
    entryRva: dv.getUint32(oh + 16, true),
    imageBase: is64 ? dv.getBigUint64(oh + 24, true) : BigInt(dv.getUint32(oh + 28, true)),
    timestamp: dv.getUint32(fh + 4, true),
    checksumOff: oh + 64,
    dirOff,
    ndirs: Math.max(0, ndirs),
  };
}

export function headerProblem(img: Uint8Array): string | null {
  try {
    readHeaders(img);
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

/** Headers wiped or mangled in memory (anti-dump): copy them from the file on disk. */
export function recoverHeaders(img: Uint8Array, disk: Uint8Array | null, prefer: "memory" | "disk" = "memory"): { img: Uint8Array; source: "memory" | "disk"; note?: string } {
  const bad = headerProblem(img);
  if (!bad && prefer === "memory") return { img, source: "memory" };
  if (!disk) return bad ? { img, source: "memory", note: `headers in memory are broken (${bad}) and no file on disk was given` } : { img, source: "memory" };
  let dh: Hdr;
  try {
    dh = readHeaders(disk);
  } catch (e) {
    return { img, source: "memory", note: `the file on disk has no usable headers either (${e instanceof Error ? e.message : e})` };
  }
  const n = Math.min(Math.max(dh.sizeOfHeaders, dh.st + dh.nsec * 40), disk.length, img.length, 0x1000 * 16);
  const out = img.slice();
  out.set(disk.subarray(0, n));
  return { img: out, source: "disk", note: bad ? `headers in memory are broken (${bad}); took them from the file on disk` : "headers taken from the file on disk" };
}

/** The PE checksum (imagehlp's CheckSumMappedFile) with the checksum field taken as zero. */
export function peChecksum(b: Uint8Array, csumOff: number): number {
  let sum = 0;
  const n = b.length & ~1;
  for (let i = 0; i < n; i += 2) {
    if (i === csumOff || i === csumOff + 2) continue;
    sum += b[i] | (b[i + 1] << 8);
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  if (b.length & 1) {
    sum += b[b.length - 1];
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  sum = (sum & 0xffff) + (sum >>> 16);
  return (sum + b.length) >>> 0;
}

export type DumpSection = { name: string; rva: number; vsize: number; rawPtr: number; rawSize: number; badPages: number };
export type DumpReport = {
  layout: DumpLayout;
  size: number;
  imageBase: string;
  entryRva: number;
  checksum: number;
  sections: DumpSection[];
  badPages: number;
  warnings: string[];
};
export type FixOptions = {
  layout: DumpLayout;
  /** the address the image was read at; becomes ImageBase (default: keep the header's) */
  base?: bigint;
  /** new entry point (OEP) */
  oepRva?: number;
  /** RVAs of 4 KiB pages that could not be read (zero-filled in the dump) */
  badPages?: readonly number[];
};

type Sec = { o: number; name: string; rva: number; vsize: number; span: number };

function sectionTable(img: Uint8Array, h: Hdr): Sec[] {
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const secs: Sec[] = [];
  for (let i = 0; i < h.nsec; i++) {
    const o = h.st + i * 40;
    const name = new TextDecoder().decode(img.subarray(o, o + 8)).replace(/\0.*$/s, "");
    secs.push({ o, name, rva: dv.getUint32(o + 12, true), vsize: dv.getUint32(o + 8, true), span: 0 });
  }
  const order = [...secs].sort((a, b) => a.rva - b.rva);
  order.forEach((s, i) => {
    const next = i + 1 < order.length ? order[i + 1].rva : img.length;
    // a section reaches its aligned virtual size, the next section or the end of the image
    const end = Math.min(s.rva + align(Math.max(s.vsize, 1), h.sectAlign), next > s.rva ? next : img.length, img.length);
    s.span = Math.max(0, end - s.rva);
  });
  return secs;
}

function lastNonZero(b: Uint8Array): number {
  for (let i = b.length - 1; i >= 0; i--) if (b[i] !== 0) return i + 1;
  return 0;
}

/** Turns an image read from memory into a loadable PE; see the file comment. */
export function fixDump(input: Uint8Array, opts: FixOptions): { bytes: Uint8Array; report: DumpReport } {
  const h = readHeaders(input);
  const warnings: string[] = [];
  const secs = sectionTable(input, h);
  const bad = new Set((opts.badPages ?? []).map((r) => r & ~0xfff));
  if (bad.has(0)) warnings.push("the header page could not be read");
  const headersMin = h.st + h.nsec * 40;
  const firstRva = Math.min(...secs.map((s) => s.rva).filter((r) => r > 0), input.length);
  const out = (() => {
    if (opts.layout === "virtual") {
      const size = align(input.length, h.sectAlign);
      const b = new Uint8Array(size);
      b.set(input);
      return b;
    }
    return null;
  })();
  const sections: DumpSection[] = [];
  let bytes: Uint8Array;
  // where each RVA lands in the output (for file-offset directories)
  const rvaToOff: { rva: number; size: number; off: number }[] = [];
  if (opts.layout === "virtual") {
    bytes = out!;
    const dv = new DataView(bytes.buffer);
    for (const s of secs) {
      const raw = s.rva < bytes.length ? Math.min(align(Math.max(s.span, s.vsize, 1), h.sectAlign), bytes.length - s.rva) : 0;
      dv.setUint32(s.o + 16, raw, true);
      dv.setUint32(s.o + 20, raw ? s.rva : 0, true);
      if (!s.vsize) dv.setUint32(s.o + 8, s.span, true);
      rvaToOff.push({ rva: s.rva, size: raw, off: s.rva });
    }
    dv.setUint32(h.oh + 36, h.sectAlign, true); // FileAlignment = SectionAlignment
    dv.setUint32(h.oh + 60, Math.min(align(Math.max(headersMin, 1), h.sectAlign), firstRva || h.sectAlign), true);
  } else {
    const fa = h.fileAlign;
    const hdrSize = align(Math.max(headersMin, Math.min(h.sizeOfHeaders || 0, firstRva || Infinity)), fa);
    const chunks: { off: number; data: Uint8Array }[] = [{ off: 0, data: input.subarray(0, Math.min(hdrSize, input.length)) }];
    let ptr = hdrSize;
    const placed = new Map<Sec, { ptr: number; raw: number }>();
    for (const s of [...secs].sort((a, b) => a.rva - b.rva)) {
      const data = s.span ? input.subarray(s.rva, s.rva + s.span) : new Uint8Array(0);
      const used = lastNonZero(data);
      const raw = used ? align(used, fa) : 0;
      placed.set(s, { ptr: raw ? ptr : 0, raw });
      if (raw) {
        chunks.push({ off: ptr, data: data.subarray(0, Math.min(raw, data.length)) });
        rvaToOff.push({ rva: s.rva, size: raw, off: ptr });
        ptr += raw;
      }
    }
    bytes = new Uint8Array(ptr);
    for (const c of chunks) bytes.set(c.data, c.off);
    const dv = new DataView(bytes.buffer);
    for (const s of secs) {
      const p = placed.get(s)!;
      dv.setUint32(s.o + 16, p.raw, true);
      dv.setUint32(s.o + 20, p.ptr, true);
      if (!s.vsize) dv.setUint32(s.o + 8, s.span, true);
    }
    dv.setUint32(h.oh + 36, fa, true);
    dv.setUint32(h.oh + 60, hdrSize, true);
  }
  const dv = new DataView(bytes.buffer);
  const rvaToFile = (rva: number) => {
    const hit = rvaToOff.find((r) => rva >= r.rva && rva < r.rva + r.size);
    return hit ? hit.off + (rva - hit.rva) : null;
  };
  // ImageBase: the dump's absolute addresses are relocated for where it was read
  if (opts.base !== undefined) {
    if (h.is64) dv.setBigUint64(h.oh + 24, opts.base, true);
    else if (opts.base > 0xffffffffn) warnings.push("a PE32 image above 4 GiB: ImageBase left as it was");
    else dv.setUint32(h.oh + 28, Number(opts.base), true);
  }
  if (opts.oepRva !== undefined) dv.setUint32(h.oh + 16, opts.oepRva, true);
  // the certificate table is addressed by file offset and is not mapped: drop it
  if (h.ndirs > 4 && dv.getUint32(h.dirOff + 4 * 8, true)) {
    dv.setUint32(h.dirOff + 4 * 8, 0, true);
    dv.setUint32(h.dirOff + 4 * 8 + 4, 0, true);
    warnings.push("the Authenticode signature is not in memory and was dropped");
  }
  // debug directory entries carry a file offset next to their RVA
  if (h.ndirs > 6) {
    const drva = dv.getUint32(h.dirOff + 6 * 8, true);
    const dsize = dv.getUint32(h.dirOff + 6 * 8 + 4, true);
    const at = drva ? rvaToFile(drva) : null;
    if (at !== null) {
      for (let k = 0; k < Math.min(64, Math.floor(dsize / 28)); k++) {
        const e = at + k * 28;
        if (e + 28 > bytes.length) break;
        const ar = dv.getUint32(e + 20, true);
        dv.setUint32(e + 24, ar ? (rvaToFile(ar) ?? 0) : 0, true);
      }
    }
  }
  for (const s of secs) {
    let n = 0;
    for (let p = s.rva & ~0xfff; p < s.rva + Math.max(s.span, s.vsize); p += 0x1000) if (bad.has(p)) n++;
    sections.push({ name: s.name, rva: s.rva, vsize: dv.getUint32(s.o + 8, true), rawPtr: dv.getUint32(s.o + 20, true), rawSize: dv.getUint32(s.o + 16, true), badPages: n });
  }
  if (bad.size) warnings.push(`${bad.size} page(s) could not be read and are zero-filled`);
  if (opts.layout === "file" && h.entryRva && rvaToFile(opts.oepRva ?? h.entryRva) === null) warnings.push("the entry point lies in data trimmed from the file layout");
  dv.setUint32(h.checksumOff, 0, true);
  const checksum = peChecksum(bytes, h.checksumOff);
  dv.setUint32(h.checksumOff, checksum, true);
  return {
    bytes,
    report: {
      layout: opts.layout, size: bytes.length, imageBase: `0x${(opts.base ?? h.imageBase).toString(16)}`, entryRva: dv.getUint32(h.oh + 16, true),
      checksum, sections, badPages: bad.size, warnings,
    },
  };
}

/** Recomputes the checksum of a PE in place (after another pass rewrote it). */
export function updateChecksum(bytes: Uint8Array): number {
  const h = readHeaders(bytes);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  dv.setUint32(h.checksumOff, 0, true);
  const c = peChecksum(bytes, h.checksumOff);
  dv.setUint32(h.checksumOff, c, true);
  return c;
}

// ---- images the loader does not list ------------------------------------------------------------

export type RegionHead = { base: bigint; size: number; executable: boolean; head: Uint8Array | null };
export type FoundImage = { base: bigint; size: number; kind: "pe" | "headerless-code"; listed: boolean; machine?: number; is64?: boolean; timestamp?: number; reason?: string };

/**
 * Every region that starts with PE headers (with its SizeOfImage), flagged when no loaded module
 * covers it, plus executable regions outside every module that have no headers (code a manual
 * mapper copied without them, or wiped).
 */
export function findImages(regions: readonly RegionHead[], modules: readonly { base: bigint; size: number }[]): FoundImage[] {
  const inModule = (a: bigint) => modules.some((m) => a >= m.base && a < m.base + BigInt(m.size));
  const out: FoundImage[] = [];
  let skipUntil = 0n;
  for (const r of [...regions].sort((a, b) => (a.base < b.base ? -1 : 1))) {
    if (r.base < skipUntil) continue;
    const listed = inModule(r.base);
    if (r.head) {
      try {
        const h = readHeaders(r.head);
        const size = h.sizeOfImage || r.size;
        out.push({ base: r.base, size, kind: "pe", listed, machine: h.machine, is64: h.is64, timestamp: h.timestamp });
        skipUntil = r.base + BigInt(size);
        continue;
      } catch { /* not headers */ }
    }
    if (r.executable && !listed) out.push({ base: r.base, size: r.size, kind: "headerless-code", listed: false, reason: r.head ? "executable memory outside every module, no PE headers" : "executable memory outside every module (unreadable)" });
  }
  return out;
}

// ---- full-memory dumps --------------------------------------------------------------------------

export type DumpRegion = { base: bigint; size: number; writable?: boolean; executable?: boolean };
export type MdModule = { name: string; base: bigint; size: number; checksum?: number; timestamp?: number; cv?: Uint8Array };

class Buf {
  b: number[] = [];
  get len() { return this.b.length; }
  u8(v: number) { this.b.push(v & 0xff); }
  u16(v: number) { this.u8(v); this.u8(v >>> 8); }
  u32(v: number) { for (let i = 0; i < 4; i++) this.u8(v >>> (8 * i)); }
  u64(v: bigint) { for (let i = 0n; i < 8n; i++) this.u8(Number((v >> (8n * i)) & 0xffn)); }
  bytes(a: ArrayLike<number>) { for (let i = 0; i < a.length; i++) this.b.push(a[i]); }
  zero(n: number) { for (let i = 0; i < n; i++) this.b.push(0); }
  pad(a: number) { while (this.b.length % a) this.b.push(0); }
  set32(at: number, v: number) { for (let i = 0; i < 4; i++) this.b[at + i] = (v >>> (8 * i)) & 0xff; }
  set64(at: number, v: bigint) { for (let i = 0n; i < 8n; i++) this.b[at + Number(i)] = Number((v >> (8n * i)) & 0xffn); }
  out() { return Uint8Array.from(this.b); }
}

/** Total size of a full dump: the prefix plus every region. */
export function dumpSize(prefix: Uint8Array, regions: readonly DumpRegion[]): number {
  return prefix.length + regions.reduce((a, r) => a + r.size, 0);
}

/**
 * The headers of a full-memory MINIDUMP (SystemInfo, MiscInfo with the pid, an empty thread list,
 * the module list with CodeView records, Memory64List). Region data follows it directly, region
 * after region in the order given, each exactly `size` bytes.
 */
export function minidumpPrefix(o: { arch: "x64" | "arm64"; pid?: number; modules: readonly MdModule[]; regions: readonly DumpRegion[]; time?: number; os?: { major: number; minor: number; build: number } }): Uint8Array {
  const b = new Buf();
  const streams: { type: number; at: number; size: number }[] = [];
  const kStreams = 5;
  // header
  b.u32(0x504d444d); // "MDMP"
  b.u32(0xa793); // version (low word), implementation-specific high word
  b.u32(kStreams);
  b.u32(32); // stream directory
  b.u32(0); // checksum
  b.u32(o.time ?? Math.floor(Date.now() / 1000));
  b.u64(0x2n); // MiniDumpWithFullMemory
  const dir = b.len;
  b.zero(kStreams * 12);
  const begin = (type: number) => { b.pad(4); const at = b.len; streams.push({ type, at, size: 0 }); return at; };
  const end = () => { const s = streams[streams.length - 1]; s.size = b.len - s.at; };
  // SystemInfoStream (7)
  begin(7);
  b.u16(o.arch === "arm64" ? 12 : 9);
  b.u16(o.arch === "arm64" ? 8 : 6); // level
  b.u16(0);
  b.u8(1); // processors
  b.u8(1); // VER_NT_WORKSTATION
  b.u32(o.os?.major ?? 10);
  b.u32(o.os?.minor ?? 0);
  b.u32(o.os?.build ?? 0);
  b.u32(2); // VER_PLATFORM_WIN32_NT
  const csd = b.len;
  b.u32(0); // CSDVersionRva, patched below
  b.u16(0);
  b.u16(0);
  b.zero(24); // CPU_INFORMATION
  end();
  // MiscInfoStream (15): the process id
  begin(15);
  b.u32(24);
  b.u32(o.pid !== undefined ? 1 : 0);
  b.u32(o.pid ?? 0);
  b.zero(12);
  end();
  // ThreadListStream (3): no thread contexts are read from memory
  begin(3);
  b.u32(0);
  end();
  // ModuleListStream (4)
  begin(4);
  b.u32(o.modules.length);
  const modAt: number[] = [];
  for (const m of o.modules) {
    modAt.push(b.len);
    b.u64(m.base);
    b.u32(m.size);
    b.u32(m.checksum ?? 0);
    b.u32(m.timestamp ?? 0);
    b.u32(0); // name rva
    b.zero(52); // VS_FIXEDFILEINFO
    b.u32(0); // CvRecord size
    b.u32(0); // CvRecord rva
    b.zero(8); // MiscRecord
    b.zero(16); // reserved
  }
  end();
  // strings and CodeView records after the stream
  b.pad(4);
  const empty = b.len;
  b.u32(0);
  b.u16(0);
  b.set32(csd, empty);
  o.modules.forEach((m, i) => {
    b.pad(4);
    b.set32(modAt[i] + 20, b.len);
    const name = m.name;
    b.u32(name.length * 2);
    for (let k = 0; k < name.length; k++) b.u16(name.charCodeAt(k));
    b.u16(0);
    if (m.cv?.length) {
      b.pad(4);
      b.set32(modAt[i] + 76, m.cv.length);
      b.set32(modAt[i] + 80, b.len);
      b.bytes(m.cv);
    }
  });
  // Memory64ListStream (9) last: its data starts right after the prefix
  begin(9);
  b.u64(BigInt(o.regions.length));
  const baseRvaAt = b.len;
  b.u64(0n);
  for (const r of o.regions) {
    b.u64(r.base);
    b.u64(BigInt(r.size));
  }
  end();
  b.pad(16);
  b.set64(baseRvaAt, BigInt(b.len));
  streams.forEach((s, i) => {
    b.set32(dir + i * 12, s.type);
    b.set32(dir + i * 12 + 4, s.size);
    b.set32(dir + i * 12 + 8, s.at);
  });
  return b.out();
}

/**
 * The headers of an ELF core file: one PT_LOAD per region (flags from its protection), a PT_NOTE
 * with NT_PRPSINFO (pid and program name). Region data follows, page-aligned, in order.
 */
/** user_regs_struct order (x86-64) for NT_PRSTATUS. */
const kX64Regs = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"];

export function elfCorePrefix(o: { arch: "x64" | "arm64"; regions: readonly DumpRegion[]; pid?: number; name?: string; regs?: Record<string, bigint> }): Uint8Array {
  if (o.regions.length + 1 >= 0xffff) throw new Error(`${o.regions.length} regions: an ELF core holds at most 65533 segments; narrow the dump`);
  const b = new Buf();
  const phnum = o.regions.length + 1;
  b.bytes([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
  b.zero(8);
  b.u16(4); // ET_CORE
  b.u16(o.arch === "arm64" ? 183 : 62);
  b.u32(1);
  b.u64(0n); // entry
  b.u64(64n); // phoff
  b.u64(0n); // shoff
  b.u32(0);
  b.u16(64);
  b.u16(56);
  b.u16(phnum);
  b.u16(64);
  b.u16(0);
  b.u16(0);
  const ph = b.len;
  b.zero(phnum * 56);
  const note = b.len;
  // NT_PRSTATUS: one thread (gdb needs one to open a core); its registers when they are known
  const nreg = o.arch === "arm64" ? 34 : 27;
  const prSize = 112 + nreg * 8 + 8;
  b.u32(5);
  b.u32(prSize);
  b.u32(1);
  b.bytes(new TextEncoder().encode("CORE\0\0\0\0"));
  const pr = b.len;
  b.zero(prSize);
  const pid0 = o.pid ?? 0;
  for (let i = 0; i < 4; i++) b.b[pr + 32 + i] = (pid0 >>> (8 * i)) & 0xff;
  if (o.arch === "x64" && o.regs) kX64Regs.forEach((r, i) => { if (o.regs![r] !== undefined) b.set64(pr + 112 + i * 8, o.regs![r]); });
  // NT_PRPSINFO
  b.u32(5);
  b.u32(136);
  b.u32(3);
  b.bytes(new TextEncoder().encode("CORE\0\0\0\0"));
  const desc = b.len;
  b.zero(136);
  b.b[desc + 1] = "R".charCodeAt(0);
  const pid = o.pid ?? 0;
  for (let i = 0; i < 4; i++) b.b[desc + 24 + i] = (pid >>> (8 * i)) & 0xff;
  const fname = new TextEncoder().encode((o.name ?? "").slice(0, 15));
  fname.forEach((c, i) => { b.b[desc + 40 + i] = c; });
  const fargs = new TextEncoder().encode((o.name ?? "").slice(0, 79));
  fargs.forEach((c, i) => { b.b[desc + 56 + i] = c; });
  const noteSize = b.len - note;
  b.pad(0x1000);
  let off = BigInt(b.len);
  const phAt = (i: number) => ph + i * 56;
  const setPh = (i: number, type: number, flags: number, offset: bigint, vaddr: bigint, filesz: bigint, memsz: bigint, alignv: bigint) => {
    const p = phAt(i);
    b.set32(p, type);
    b.set32(p + 4, flags);
    b.set64(p + 8, offset);
    b.set64(p + 16, vaddr);
    b.set64(p + 24, 0n);
    b.set64(p + 32, filesz);
    b.set64(p + 40, memsz);
    b.set64(p + 48, alignv);
  };
  setPh(0, 4, 0, BigInt(note), 0n, BigInt(noteSize), 0n, 4n);
  o.regions.forEach((r, i) => {
    const flags = 4 | (r.writable ? 2 : 0) | (r.executable ? 1 : 0);
    setPh(i + 1, 1, flags, off, r.base, BigInt(r.size), BigInt(r.size), 0x1000n);
    off += BigInt(r.size);
  });
  return b.out();
}

/** A CodeView (RSDS) record from an image's debug directory, for the minidump's module list. */
export function codeViewRecord(img: Uint8Array): Uint8Array | null {
  let h: Hdr;
  try {
    h = readHeaders(img);
  } catch {
    return null;
  }
  if (h.ndirs <= 6) return null;
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const drva = dv.getUint32(h.dirOff + 48, true);
  const dsize = dv.getUint32(h.dirOff + 52, true);
  for (let k = 0; k < Math.min(32, Math.floor(dsize / 28)); k++) {
    const e = drva + k * 28;
    if (e + 28 > img.length) break;
    if (dv.getUint32(e + 12, true) !== 2) continue; // IMAGE_DEBUG_TYPE_CODEVIEW
    const size = dv.getUint32(e + 16, true);
    const at = dv.getUint32(e + 20, true);
    if (!at || size < 24 || size > 0x1000 || at + size > img.length) continue;
    if (dv.getUint32(at, true) !== 0x53445352) continue; // "RSDS"
    return img.slice(at, at + size);
  }
  return null;
}
