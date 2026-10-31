// IDA FLIRT signature files (.sig): the compiler function-signature databases
// that ship with IDA and the public sigdb.
//
// A .sig file is a prefix tree of byte patterns. Each leaf carries the
// functions that share a pattern, with the CRC of the bytes that follow the
// pattern, so a match can be confirmed against the real function body.
//
// The format is documented by the radare2 implementation (flirt.c) and by
// angr's Python parser; both are followed here.
import { decompress as zstdDecompress } from "fzstd";

export type FlirtFunction = {
  /** the function name as the signature file spells it */
  name: string;
  /** offset of the function inside the pattern */
  offset: number;
  /** the function only exists in this module (not exported) */
  local: boolean;
  /** the name could not be resolved to a single function */
  collision: boolean;
};

export type FlirtModule = {
  /** total length of the function in bytes */
  length: number;
  /** how many bytes of the pattern are covered by the CRC */
  crcLength: number;
  /** the CRC of the bytes after the pattern */
  crc: number;
  functions: FlirtFunction[];
  /** byte values that must appear at the given offsets */
  tailBytes: { offset: number; value: number }[];
  /** functions this one calls */
  referenced: { name: string; offset: number }[];
};

export type FlirtNode = {
  /** the bytes of this level; -1 is a wildcard */
  pattern: number[];
  /** the number of bytes this level covers */
  length: number;
  children: FlirtNode[];
  /** set on the leaves */
  module?: FlirtModule;
};

export type FlirtSignature = {
  version: number;
  arch: number;
  fileTypes: number;
  osTypes: number;
  appTypes: number;
  features: number;
  crc16: number;
  ctype: string;
  libraryName: string;
  /** number of functions the header claims */
  functionCount: number | null;
  root: FlirtNode | null;
};

export class FlirtError extends Error {}

const kFeatureCompressed = 0x10;
const kParseMorePublicNames = 0x1;
const kParseReadTailBytes = 0x2;
const kParseReadReferencedFunctions = 0x4;
const kParseMoreModulesWithSameCrc = 0x8;
const kParseMoreModules = 0x10;

/** A cursor over the signature file. */
class Reader {
  private p = 0;
  constructor(readonly buf: Uint8Array) {}

  get offset(): number {
    return this.p;
  }

  get remaining(): number {
    return this.buf.length - this.p;
  }

  u8(): number {
    if (this.p >= this.buf.length) throw new FlirtError("unexpected end of file");
    return this.buf[this.p++];
  }

  u16le(): number {
    if (this.p + 2 > this.buf.length) throw new FlirtError("unexpected end of file");
    const v = this.buf[this.p] | (this.buf[this.p + 1] << 8);
    this.p += 2;
    return v;
  }

  u16be(): number {
    if (this.p + 2 > this.buf.length) throw new FlirtError("unexpected end of file");
    const v = (this.buf[this.p] << 8) | this.buf[this.p + 1];
    this.p += 2;
    return v;
  }

  u32le(): number {
    if (this.p + 4 > this.buf.length) throw new FlirtError("unexpected end of file");
    const v = this.buf[this.p] | (this.buf[this.p + 1] << 8) | (this.buf[this.p + 2] << 16) | (this.buf[this.p + 3] << 24);
    this.p += 4;
    return v >>> 0;
  }

  bytes(n: number): Uint8Array {
    if (this.p + n > this.buf.length) throw new FlirtError("unexpected end of file");
    const b = this.buf.subarray(this.p, this.p + n);
    this.p += n;
    return b;
  }

  /** 1 byte, or 2 bytes when the high bit is set. */
  max2(): number {
    const b = this.u8();
    if ((b & 0x80) !== 0x80) return b;
    return ((b & 0x7f) << 8) + this.u8();
  }

  /** 1, 2, 4 or 5 bytes depending on the leading bits. */
  multiple(): number {
    const b = this.u8();
    if ((b & 0x80) !== 0x80) return b;
    if ((b & 0xc0) !== 0xc0) return ((b & 0x7f) << 8) + this.u8();
    if ((b & 0xe0) !== 0xe0) {
      let v = (b & 0x3f) << 24;
      v += this.u8() << 16;
      v += this.u16be();
      return v >>> 0;
    }
    return this.u32le();
  }
}

/** Parses the header of a FLIRT signature file. */
export function parseFlirtHeader(buf: Uint8Array): FlirtSignature {
  const r = new Reader(buf);
  const magic = String.fromCharCode(...r.bytes(6));
  if (magic !== "IDASGN") throw new FlirtError("not a FLIRT signature file");
  const version = r.u8();
  if (version < 5) throw new FlirtError(`unsupported FLIRT version ${version}`);
  const arch = r.u8();
  const fileTypes = r.u32le();
  const osTypes = r.u16le();
  const appTypes = r.u16le();
  const features = r.u16le();
  r.u16le(); // old function count, superseded by the v6 field
  const crc16 = r.u16le();
  const ctype = String.fromCharCode(...r.bytes(12)).replace(/\0+$/, "");
  const libraryNameLength = r.u8();
  r.u16le(); // ctypes crc
  let functionCount: number | null = null;
  if (version >= 6) functionCount = r.u32le();
  if (version >= 8) r.u16le(); // pattern size
  if (version >= 10) r.u16le(); // unknown
  const libraryName = String.fromCharCode(...r.bytes(libraryNameLength)).replace(/\0+$/, "");
  return { version, arch, fileTypes, osTypes, appTypes, features, crc16, ctype, libraryName, functionCount, root: null };
}

function parseVariantMask(r: Reader, length: number): bigint {
  if (length < 0x10) return BigInt(r.max2());
  if (length <= 0x20) return BigInt(r.multiple());
  if (length <= 0x40) return (BigInt(r.multiple()) << 32n) | BigInt(r.multiple());
  throw new FlirtError(
    `this signature file holds a ${length} byte pattern, a layout this parser does not support yet`,
  );
}

function parseNode(r: Reader, length: number, variantMask: bigint): number[] {
  const pattern: number[] = [];
  for (let i = 0; i < length; i++) {
    // The mask is big-endian over the pattern bytes.
    const bit = 1n << BigInt(length - i - 1);
    const wildcard = (variantMask & bit) === 0n;
    pattern.push(wildcard ? r.u8() : -1);
  }
  return pattern;
}

function parsePublicFunction(r: Reader, offset: number, version: number): { fn: FlirtFunction; offset: number; flags: number } {
  const relative = vword(r, version);
  let flags = r.u8();
  let local = false;
  let collision = false;
  let negative = false;
  let next: number;
  if (flags < 0x20) {
    // The flags byte is present only when the name does not start here.
    local = (flags & 0x2) !== 0;
    collision = (flags & 0x8) !== 0;
    negative = (flags & 0x10) !== 0;
    next = r.u8();
  } else {
    next = flags;
  }
  const off = negative ? offset - relative : offset + relative;
  let name = "";
  let ended = false;
  for (let i = 0; i < 4096; i++) {
    if (next < 0x20) {
      ended = true;
      break;
    }
    name += String.fromCharCode(next);
    next = r.u8();
  }
  if (!ended) name += "...";
  return { fn: { name, offset: off, local, collision }, offset: off, flags: next };
}

/** A 16 bit field before version 9, a 32 bit one from version 9 on. */
function vword(r: Reader, version: number): number {
  return version >= 9 ? r.multiple() : r.max2();
}

function parseTailBytes(r: Reader, version: number): { offset: number; value: number }[] {
  const count = version >= 8 ? vword(r, version) : 1;
  const out: { offset: number; value: number }[] = [];
  for (let i = 0; i < count; i++) {
    const off = vword(r, version);
    out.push({ offset: off, value: r.u8() });
  }
  return out;
}

function parseReferencedFunctions(r: Reader, version: number): { name: string; offset: number }[] {
  const count = version >= 8 ? vword(r, version) : 1;
  const out: { name: string; offset: number }[] = [];
  for (let i = 0; i < count; i++) {
    const off = vword(r, version);
    let nameLen = r.u8();
    if (nameLen === 0) nameLen = r.max2();
    if (nameLen > 4096) throw new FlirtError("function name too long");
    const name = String.fromCharCode(...r.bytes(nameLen)).replace(/\0+$/, "");
    out.push({ name, offset: off });
  }
  return out;
}

function parseModule(r: Reader, version: number): { module: FlirtModule; flags: number } {
  const length = vword(r, version);
  const functions: FlirtFunction[] = [];
  let off = 0;
  let flags = 0;
  for (;;) {
    const p = parsePublicFunction(r, off, version);
    functions.push(p.fn);
    off = p.offset;
    flags = p.flags;
    if ((flags & kParseMorePublicNames) === 0) break;
  }
  const tailBytes = (flags & kParseReadTailBytes) !== 0 ? parseTailBytes(r, version) : [];
  const referenced = (flags & kParseReadReferencedFunctions) !== 0 ? parseReferencedFunctions(r, version) : [];
  return { module: { length, crcLength: 0, crc: 0, functions, tailBytes, referenced }, flags };
}

function parseModules(r: Reader, version: number): FlirtModule[] {
  const modules: FlirtModule[] = [];
  for (;;) {
    const crcLength = r.u8();
    const crc = r.u16be();
    let flags = 0;
    for (;;) {
      const p = parseModule(r, version);
      p.module.crcLength = crcLength;
      p.module.crc = crc;
      modules.push(p.module);
      flags = p.flags;
      if ((flags & kParseMoreModulesWithSameCrc) === 0) break;
    }
    if ((flags & kParseMoreModules) === 0) break;
  }
  return modules;
}

function parseTree(r: Reader, version: number, root = false): FlirtNode {
  let length = 0;
  let pattern: number[] = [];
  if (!root) {
    // Since version 10 the length is a variable-length integer.
    length = version >= 10 ? r.max2() : r.u8();
    const mask = parseVariantMask(r, length);
    pattern = parseNode(r, length, mask);
  }
  const nodeCount = r.multiple();
  if (nodeCount > 0) {
    const children: FlirtNode[] = [];
    for (let i = 0; i < nodeCount; i++) children.push(parseTree(r, version));
    return { pattern, length, children };
  }
  const modules = parseModules(r, version);
  return { pattern, length, children: [], module: modules[0] };
}

/** Parses a whole FLIRT signature file that is not compressed. */
export function parseFlirt(buf: Uint8Array): FlirtSignature {
  const header = parseFlirtHeader(buf);
  const body = buf.subarray(bodyOffset(buf, header));
  const r = new Reader(body);
  header.root = parseTree(r, header.version, true);
  return header;
}

/** Decompresses a payload with the given stream format. */
async function inflate(payload: Uint8Array, format: "deflate" | "deflate-raw"): Promise<Uint8Array> {
  const stream = new Blob([payload as BlobPart]).stream().pipeThrough(new DecompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const kZstdMagic = [0x28, 0xb5, 0x2f, 0xfd];

/**
 * Parses a FLIRT signature file, decompressing it when needed.
 *
 * IDA has used three schemes: no compression at all, zlib (the header of
 * which is not always a valid zlib header, so the raw stream is tried too) and
 * zstd since version 11.
 */
export async function parseFlirtFile(buf: Uint8Array): Promise<FlirtSignature> {
  const header = parseFlirtHeader(buf);
  if (header.version > 10) {
    throw new FlirtError(
      `this signature file uses the version ${header.version} format (IDA 9.5 and newer), which is not supported yet; use a version 10 file or older`,
    );
  }
  const payload = buf.subarray(bodyOffset(buf, header));
  let body: Uint8Array;
  if (payload.length >= 4 && kZstdMagic.every((b, i) => payload[i] === b)) {
    body = zstdDecompress(payload);
  } else if ((header.features & kFeatureCompressed) !== 0) {
    body = await decompressPayload(payload);
  } else {
    body = payload;
  }
  const r = new Reader(body);
  header.root = parseTree(r, header.version, true);
  return header;
}

/**
 * Decompresses a signature payload.
 *
 * IDA has used three shapes: a zlib stream, a zlib stream whose header does
 * not validate, and a raw deflate stream with no header at all.
 */
async function decompressPayload(payload: Uint8Array): Promise<Uint8Array> {
  const attempts: { data: Uint8Array; format: "deflate" | "deflate-raw" }[] = [
    { data: payload, format: "deflate" },
    { data: payload, format: "deflate-raw" },
    { data: payload.subarray(2), format: "deflate-raw" },
  ];
  let last = "";
  for (const a of attempts) {
    try {
      return await inflate(a.data, a.format);
    } catch (e) {
      last = (e as Error).message ?? "";
    }
  }
  throw new FlirtError(`could not decompress the signature payload${last ? `: ${last}` : ""}`);
}

/** The offset of the tree inside the file: the end of the header. */
function bodyOffset(buf: Uint8Array, header: FlirtSignature): number {
  // The fixed header is 37 bytes, then the version-specific fields, then the
  // library name whose length sits at offset 34.
  const nameLength = buf[34];
  const expected = 37 + extraHeaderSize(header.version);
  if (isPrintableRun(buf, expected, nameLength)) return expected + nameLength;
  // The layout of the newest versions is not published; fall back to looking
  // for the library name.
  for (let i = 37; i < Math.min(buf.length, 128); i++) {
    if (isPrintableRun(buf, i, nameLength)) return i + nameLength;
  }
  return expected + nameLength;
}

/** The bytes that follow the fixed header, per signature file version. */
function extraHeaderSize(version: number): number {
  if (version <= 5) return 0;
  if (version <= 7) return 4; // function count
  if (version <= 9) return 6; // function count, pattern size
  if (version === 10) return 8; // function count, pattern size, unknown
  return 9; // version 11 adds one more field
}

function isPrintableRun(buf: Uint8Array, at: number, length: number): boolean {
  if (length <= 0 || at + length > buf.length) return false;
  for (let i = 0; i < length; i++) {
    const c = buf[at + i];
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

/** CRC-16/ARC over a byte range, the checksum FLIRT stores for the function tail. */
export function crc16(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = (crc & 1) !== 0 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
  }
  return crc & 0xffff;
}

export type FlirtMatch = {
  /** RVA of the match */
  rva: number;
  /** absolute address */
  address: string;
  /** the function the pattern belongs to */
  name: string;
  /** how many bytes of the pattern matched */
  patternLength: number;
  /** the length of the whole function, when the signature knows it */
  functionLength: number;
  /** true when the CRC of the function tail matched */
  crcVerified: boolean;
};

type Candidate = { module: FlirtModule; patternLength: number };

/** Walks the signature tree against one byte position and collects the leaves. */
function walk(root: FlirtNode, data: Uint8Array, at: number, out: Candidate[], depth = 0): void {
  if (depth > 32) return;
  for (const node of root.children) {
    if (node.length > 0) {
      if (at + node.length > data.length) continue;
      let ok = true;
      for (let i = 0; i < node.length; i++) {
        const p = node.pattern[i];
        if (p >= 0 && data[at + i] !== p) { ok = false; break; }
      }
      if (!ok) continue;
    }
    if (node.children.length > 0) {
      walk(node, data, at, out, depth + 1);
    } else if (node.module) {
      out.push({ module: node.module, patternLength: node.length });
    }
  }
}

/**
 * Matches a FLIRT signature set against a module image.
 *
 * The image is indexed by RVA. The result carries one entry per matched
 * function; when the signature knows the function length the CRC of the tail
 * is checked, which removes the false positives the pattern alone gives.
 */
export function matchFlirt(sig: FlirtSignature, img: Uint8Array, base?: bigint, ranges?: readonly { rva: number; size: number }[]): FlirtMatch[] {
  if (!sig.root) return [];
  const scan = ranges ?? [{ rva: 0, size: img.length }];
  const out: FlirtMatch[] = [];
  const seen = new Set<string>();
  for (const range of scan) {
    const end = Math.min(img.length, range.rva + range.size);
    for (let at = range.rva; at < end; at++) {
      const candidates: Candidate[] = [];
      walk(sig.root, img, at, candidates);
      for (const c of candidates) {
        for (const fn of c.module.functions) {
          const key = `${at}|${fn.name}`;
          if (seen.has(key)) continue;
          seen.add(key);
          // The pattern covers the bytes from the start; the CRC covers the
          // bytes that follow it, as many as the signature recorded.
          const tailStart = at + c.patternLength;
          const crcBytes = Math.min(c.module.crcLength, c.module.length - c.patternLength);
          let crcVerified = false;
          if (crcBytes > 0 && tailStart + crcBytes <= img.length) {
            crcVerified = crc16(img.subarray(tailStart, tailStart + crcBytes)) === c.module.crc;
          }
          out.push({
            rva: at,
            address: "0x" + ((base ?? 0n) + BigInt(at)).toString(16),
            name: fn.name,
            patternLength: c.patternLength,
            functionLength: c.module.length,
            crcVerified,
          });
        }
      }
    }
  }
  return out;
}

/** A human name for the architecture code. */
export function flirtArchName(arch: number): string {
  const names: Record<number, string> = {
    0: "x86", 8: "Java", 12: "MIPS", 13: "ARM", 15: "PowerPC", 18: "SuperH",
    19: "MS .NET", 23: "SPARC", 24: "Alpha", 31: "Itanium", 34: "TMS320C54x",
    60: "Dalvik",
  };
  return names[arch] ?? `arch ${arch}`;
}
