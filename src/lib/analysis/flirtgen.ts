// FLIRT generation: IDA .pat lines (the input of FLAIR's sigmake) and an uncompressed version 10
// .sig file that IDA, radare2/rizin and this app can load.
//
// A function contributes its first 32 bytes as the pattern (relocated operands wildcarded), the
// CRC of the bytes after them up to the first wildcard (at most 255), and its length.
import { crc16 } from "./flirt";

export type GenFunction = {
  name: string;
  /** the function's bytes */
  bytes: Uint8Array;
  /** per byte: true when it varies between builds (relocations, rel32/disp32) */
  variable: boolean[];
  local?: boolean;
};

export type PatEntry = {
  pattern: number[]; // 32 entries, -1 = wildcard
  crcLength: number;
  crc: number;
  length: number;
  name: string;
  local: boolean;
};

export const kPatternSize = 32;

export function toPatEntry(f: GenFunction): PatEntry | null {
  if (f.bytes.length < 6 || !f.name) return null;
  const pattern: number[] = [];
  for (let i = 0; i < kPatternSize; i++) pattern.push(i < f.bytes.length && !f.variable[i] ? f.bytes[i] : -1);
  let crcLength = 0;
  while (kPatternSize + crcLength < f.bytes.length && crcLength < 255 && !f.variable[kPatternSize + crcLength]) crcLength++;
  const crc = crc16(f.bytes.subarray(kPatternSize, kPatternSize + crcLength));
  return { pattern, crcLength, crc, length: f.bytes.length, name: f.name, local: Boolean(f.local) };
}

const h2 = (v: number) => v.toString(16).toUpperCase().padStart(2, "0");
const h4 = (v: number) => v.toString(16).toUpperCase().padStart(4, "0");

/** One .pat line: `<64 hex/..> <crclen> <crc> <len> :0000 <name>`; `:0000@` marks a local name. */
export function toPatLine(e: PatEntry): string {
  const pat = e.pattern.map((b) => (b < 0 ? ".." : h2(b))).join("");
  return `${pat} ${h2(e.crcLength)} ${h4(e.crc)} ${h4(e.length)} :0000${e.local ? "@" : ""} ${e.name.replace(/\s/g, "_")}`;
}

export function toPatFile(entries: readonly PatEntry[]): string {
  return entries.map(toPatLine).join("\n") + "\n---\n";
}

/** Parses .pat text back into entries (the first public name of each line). */
export function parsePat(text: string): PatEntry[] {
  const out: PatEntry[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("---")) continue;
    const m = /^([0-9A-F.]{2,64}) ([0-9A-F]{2}) ([0-9A-F]{4}) ([0-9A-F]{4,8}) :([0-9A-F]{4})(@?) (\S+)/i.exec(line.trim());
    if (!m) continue;
    const pattern: number[] = [];
    for (let i = 0; i < m[1].length; i += 2) pattern.push(m[1].slice(i, i + 2) === ".." ? -1 : parseInt(m[1].slice(i, i + 2), 16));
    while (pattern.length < kPatternSize) pattern.push(-1);
    out.push({ pattern, crcLength: parseInt(m[2], 16), crc: parseInt(m[3], 16), length: parseInt(m[4], 16), local: m[6] === "@", name: m[7] });
  }
  return out;
}

// ------------------------------------------------------------------------------------------------
// .sig writer
// ------------------------------------------------------------------------------------------------

class Writer {
  readonly out: number[] = [];
  u8(v: number) { this.out.push(v & 0xff); }
  u16le(v: number) { this.u8(v); this.u8(v >> 8); }
  u16be(v: number) { this.u8(v >> 8); this.u8(v); }
  u32le(v: number) { this.u16le(v & 0xffff); this.u16le(v >>> 16); }
  bytes(b: ArrayLike<number>) { for (let i = 0; i < b.length; i++) this.u8(b[i]); }
  /** inverse of Reader.max2: 1 byte below 0x80, else 2 bytes (15-bit values) */
  max2(v: number) {
    if (v < 0x80) return this.u8(v);
    if (v >= 0x8000) throw new Error(`value ${v} does not fit a max2 field`);
    this.u8(0x80 | (v >> 8));
    this.u8(v);
  }
  /** inverse of Reader.multiple: 1, 2, 4 or 5 bytes */
  multiple(v: number) {
    if (v < 0x80) return this.u8(v);
    if (v < 0x4000) {
      this.u8(0x80 | (v >> 8));
      return this.u8(v);
    }
    if (v < 0x20000000) {
      this.u8(0xc0 | (v >>> 24));
      this.u8(v >>> 16);
      return this.u16be(v & 0xffff);
    }
    this.u8(0xe0);
    this.u32le(v >>> 0);
  }
}

type Trie = { key: number[]; children: Trie[]; entries: PatEntry[] };

/** Prefix tree over the 32-entry patterns (wildcards are a symbol of their own), chains merged. */
function buildTrie(entries: readonly PatEntry[]): Trie {
  type Raw = { kids: Map<number, Raw>; entries: PatEntry[] };
  const root: Raw = { kids: new Map(), entries: [] };
  for (const e of entries) {
    let n = root;
    for (const b of e.pattern) {
      let k = n.kids.get(b);
      if (!k) n.kids.set(b, (k = { kids: new Map(), entries: [] }));
      n = k;
    }
    n.entries.push(e);
  }
  const compress = (sym: number, r: Raw): Trie => {
    const key = [sym];
    let cur = r;
    while (cur.kids.size === 1 && cur.entries.length === 0) {
      const [s, next] = [...cur.kids][0];
      key.push(s);
      cur = next;
    }
    return { key, entries: cur.entries, children: [...cur.kids].sort((a, b) => a[0] - b[0]).map(([s, k]) => compress(s, k)) };
  };
  return { key: [], entries: [], children: [...root.kids].sort((a, b) => a[0] - b[0]).map(([s, k]) => compress(s, k)) };
}

function writeNode(w: Writer, n: Trie): void {
  w.max2(n.key.length); // version >= 10
  let mask = 0n;
  n.key.forEach((b, i) => {
    if (b < 0) mask |= 1n << BigInt(n.key.length - i - 1);
  });
  if (n.key.length < 0x10) w.max2(Number(mask));
  else if (n.key.length <= 0x20) w.multiple(Number(mask));
  else {
    w.multiple(Number(mask >> 32n));
    w.multiple(Number(mask & 0xffffffffn));
  }
  for (const b of n.key) if (b >= 0) w.u8(b);
  writeChildren(w, n);
}

function writeChildren(w: Writer, n: Trie): void {
  w.multiple(n.children.length);
  if (n.children.length) {
    for (const c of n.children) writeNode(w, c);
    return;
  }
  // leaf: modules grouped by CRC
  const groups = new Map<string, PatEntry[]>();
  for (const e of n.entries) {
    const k = `${e.crcLength}:${e.crc}`;
    groups.set(k, [...(groups.get(k) ?? []), e]);
  }
  const list = [...groups.values()];
  list.forEach((mods, gi) => {
    w.u8(mods[0].crcLength);
    w.u16be(mods[0].crc);
    mods.forEach((e, mi) => {
      w.multiple(e.length); // module length (version >= 9)
      w.multiple(0); // offset of the public name
      if (e.local) w.u8(0x02);
      for (const ch of e.name) {
        const c = ch.charCodeAt(0);
        w.u8(c >= 0x20 && c < 0x7f ? c : 0x5f);
      }
      let flags = 0;
      if (mi < mods.length - 1) flags |= 0x08; // more modules with the same CRC
      else if (gi < list.length - 1) flags |= 0x10; // more modules
      w.u8(flags);
    });
  });
}

export type SigOptions = { libraryName: string; arch?: number; fileTypes?: number; osTypes?: number; appTypes?: number };

/** An uncompressed version 10 .sig holding `entries`. Duplicate names at one pattern are kept. */
export function writeSig(entries: readonly PatEntry[], opts: SigOptions): Uint8Array {
  if (!entries.length) throw new Error("no functions to write");
  const w = new Writer();
  w.bytes(Array.from(new TextEncoder().encode("IDASGN")));
  w.u8(10); // version
  w.u8(opts.arch ?? 0); // x86 family
  w.u32le(opts.fileTypes ?? 0x00000800 | 0x00004000); // PE + ELF
  w.u16le(opts.osTypes ?? 0x0003); // MS-DOS/Windows family + unix
  w.u16le(opts.appTypes ?? 0x0108 | 0x0400); // 64-bit console/gui, library
  w.u16le(0); // features: uncompressed
  w.u16le(Math.min(entries.length, 0xffff)); // old function count
  w.u16le(0); // crc16 of the file (unused by loaders)
  w.bytes(new Uint8Array(12)); // ctype
  const name = Array.from(new TextEncoder().encode(opts.libraryName.slice(0, 255)));
  w.u8(name.length);
  w.u16le(0); // ctypes crc
  w.u32le(entries.length); // function count (v6+)
  w.u16le(kPatternSize); // pattern size (v8+)
  w.u16le(0); // v10 field
  w.bytes(name);
  writeChildren(w, buildTrie(entries));
  return new Uint8Array(w.out);
}
