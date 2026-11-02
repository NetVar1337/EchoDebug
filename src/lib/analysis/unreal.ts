// Unreal Engine name and object tables (x64 shipping builds), decoded from raw reads.
//
// FNamePool (UE4.23+ and UE5): NamePoolData holds an FNameEntryAllocator whose Blocks[] array of
// pointers follows a lock and two cursors. An FName comparison index is a handle: the high bits
// pick the block, the low 16 bits are an offset in 2-byte units inside it. Each entry starts with
// a 2-byte header { bIsWide:1, LowercaseProbeHash:5, Len:10 } followed by Len chars.
// Legacy GNames (UE4.22 and older): a chunked TNameEntryArray of FNameEntry pointers, 16384 per
// chunk; the entry holds its index (bit 0 = wide) and then the NUL-terminated name.
// GUObjectArray (FUObjectArray, UE4.20+): ObjObjects is a chunked array of FUObjectItem, 65536 per
// chunk. Every offset below is the common default and can be overridden: games patch these.

export type Reader = (reads: { address: bigint; size: number }[]) => Promise<(Uint8Array | null)[]>;

export type NamePoolLayout = {
  /** offset of Blocks[] inside NamePoolData (after FRWLock + CurrentBlock + CurrentByteCursor) */
  blocksOffset: number;
  /** FNameBlockOffsetBits */
  blockBits: number;
  /** alignof(FNameEntry): handle offsets are in these units */
  stride: number;
  /** Len = header >> lenShift; bIsWide = header & 1 */
  lenShift: number;
};
export const kNamePool: NamePoolLayout = { blocksOffset: 0x10, blockBits: 16, stride: 2, lenShift: 6 };

export type LegacyNamesLayout = { perChunk: number; nameOffset: number };
export const kLegacyNames: LegacyNamesLayout = { perChunk: 16384, nameOffset: 0x10 };

export type NameSource =
  | { kind: "pool"; address: bigint; layout: NamePoolLayout }
  | { kind: "legacy"; address: bigint; layout: LegacyNamesLayout };

export type ObjectArrayLayout = {
  /** offset of ObjObjects.Objects inside FUObjectArray */
  objectsOffset: number;
  /** offset of ObjObjects.NumElements */
  numOffset: number;
  /** false for the flat FFixedUObjectArray of UE4.19 and older */
  chunked: boolean;
  perChunk: number;
  /** sizeof(FUObjectItem): 0x18 typical, 0x10 when the serial number is compiled out */
  itemSize: number;
};
export const kObjectArray: ObjectArrayLayout = { objectsOffset: 0x10, numOffset: 0x24, chunked: true, perChunk: 65536, itemSize: 0x18 };

export type UObjectLayout = { flags: number; index: number; cls: number; name: number; outer: number };
export const kUObject: UObjectLayout = { flags: 0x08, index: 0x0c, cls: 0x10, name: 0x18, outer: 0x20 };

/** Documented AOB patterns; each resolves a RIP-relative operand at `disp` of a `len`-byte instruction. */
export const kUnrealSigs = [
  { id: "pool", label: "FNamePool (UE4.23+): lea rcx, NamePoolData; call FNamePool ctor; mov byte [inited], 1", pattern: "48 8D 0D ? ? ? ? E8 ? ? ? ? C6 05 ? ? ? ? 01", disp: 3, len: 7, adjust: 0, deref: false },
  { id: "legacy", label: "GNames (≤UE4.22): mov rax, [GNames]; test rax, rax; jnz", pattern: "48 8B 05 ? ? ? ? 48 85 C0 75 ? B9 ? ? 00 00", disp: 3, len: 7, adjust: 0, deref: true },
  { id: "objects", label: "GUObjectArray: mov rax, [ObjObjects.Objects]; mov rcx, [rax+rcx*8]; lea rax, [rcx+rdx*8]", pattern: "48 8B 05 ? ? ? ? 48 8B 0C C8 48 8D 04 D1", disp: 3, len: 7, adjust: 0x10, deref: false },
] as const;

/** Target of a RIP-relative instruction at `hit`, given the 4 displacement bytes. */
export function ripTarget(hit: bigint, disp: Uint8Array, len: number): bigint {
  return hit + BigInt(len) + BigInt(new DataView(disp.buffer, disp.byteOffset, 4).getInt32(0, true));
}

const dv = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength);

export function decodeNameHeader(h: number, l: NamePoolLayout = kNamePool): { wide: boolean; len: number } {
  return { wide: (h & 1) === 1, len: h >> l.lenShift };
}

/** The string of an FNamePool entry; null when the buffer is too short or the entry looks broken. */
export function decodePoolEntry(b: Uint8Array, l: NamePoolLayout = kNamePool): string | null {
  if (b.length < 2) return null;
  const { wide, len } = decodeNameHeader(dv(b).getUint16(0, true), l);
  if (len === 0 || 2 + len * (wide ? 2 : 1) > b.length) return null;
  return wide
    ? String.fromCharCode(...Array.from({ length: len }, (_, i) => dv(b).getUint16(2 + i * 2, true)))
    : String.fromCharCode(...b.subarray(2, 2 + len));
}

export function poolLocation(index: number, l: NamePoolLayout = kNamePool): { block: number; offset: number } {
  return { block: index >>> l.blockBits, offset: (index & ((1 << l.blockBits) - 1)) * l.stride };
}

/** A legacy FNameEntry: wide flag in bit 0 of its index, then the NUL-terminated name. */
export function decodeLegacyEntry(b: Uint8Array, l: LegacyNamesLayout = kLegacyNames): string | null {
  if (b.length < l.nameOffset + 1) return null;
  const wide = (dv(b).getInt32(0, true) & 1) === 1;
  let s = "";
  for (let i = l.nameOffset; i + (wide ? 1 : 0) < b.length; i += wide ? 2 : 1) {
    const c = wide ? dv(b).getUint16(i, true) : b[i];
    if (c === 0) return s;
    s += String.fromCharCode(c);
  }
  return s || null;
}

/** FName display form: Number is stored +1, so 0 means no suffix. */
export const fnameString = (base: string, number: number) => (number > 0 ? `${base}_${number - 1}` : base);

const u64 = (b: Uint8Array | null | undefined, o = 0) => (b && b.length >= o + 8 ? dv(b).getBigUint64(o, true) : 0n);

/** Resolves comparison indices to strings; `cache` is filled and reused across calls. */
export async function readNames(read: Reader, src: NameSource, indices: readonly number[], cache = new Map<number, string>()): Promise<Map<number, string>> {
  const todo = [...new Set(indices)].filter((i) => !cache.has(i) && i >= 0);
  if (!todo.length) return cache;
  const entries = new Map<number, bigint>();
  if (src.kind === "pool") {
    const l = src.layout;
    const blocks = [...new Set(todo.map((i) => poolLocation(i, l).block))];
    const ptrs = await read(blocks.map((b) => ({ address: src.address + BigInt(l.blocksOffset + b * 8), size: 8 })));
    const blockBase = new Map(blocks.map((b, k) => [b, u64(ptrs[k])]));
    for (const i of todo) {
      const { block, offset } = poolLocation(i, l);
      const b = blockBase.get(block) ?? 0n;
      if (b) entries.set(i, b + BigInt(offset));
    }
    const ids = [...entries.keys()];
    // short read first, the rare long name gets a second, exact one
    let bufs = await read(ids.map((i) => ({ address: entries.get(i)!, size: 0x42 })));
    const long = ids.map((i, k) => ({ i, k, b: bufs[k] })).filter(({ b }) => b && b.length >= 2 && decodePoolEntry(b, l) === null && decodeNameHeader(dv(b).getUint16(0, true), l).len > 0);
    if (long.length) {
      const more = await read(long.map(({ i, b }) => {
        const h = decodeNameHeader(dv(b!).getUint16(0, true), l);
        return { address: entries.get(i)!, size: 2 + h.len * (h.wide ? 2 : 1) };
      }));
      bufs = [...bufs];
      long.forEach(({ k }, j) => (bufs[k] = more[j]));
    }
    ids.forEach((i, k) => cache.set(i, (bufs[k] && decodePoolEntry(bufs[k]!, l)) ?? `<bad name ${i}>`));
  } else {
    const l = src.layout;
    const chunks = [...new Set(todo.map((i) => Math.floor(i / l.perChunk)))];
    const cp = await read(chunks.map((c) => ({ address: src.address + BigInt(c * 8), size: 8 })));
    const chunkBase = new Map(chunks.map((c, k) => [c, u64(cp[k])]));
    const slots = todo.filter((i) => chunkBase.get(Math.floor(i / l.perChunk)));
    const ep = await read(slots.map((i) => ({ address: chunkBase.get(Math.floor(i / l.perChunk))! + BigInt((i % l.perChunk) * 8), size: 8 })));
    slots.forEach((i, k) => u64(ep[k]) && entries.set(i, u64(ep[k])));
    const ids = [...entries.keys()];
    const bufs = await read(ids.map((i) => ({ address: entries.get(i)!, size: l.nameOffset + 0x100 })));
    ids.forEach((i, k) => cache.set(i, (bufs[k] && decodeLegacyEntry(bufs[k]!, l)) ?? `<bad name ${i}>`));
  }
  for (const i of todo) if (!cache.has(i)) cache.set(i, `<no name ${i}>`);
  return cache;
}

export type UObjectHeader = { vtable: bigint; flags: number; index: number; cls: bigint; nameIndex: number; nameNumber: number; outer: bigint };

export function parseUObject(b: Uint8Array, l: UObjectLayout = kUObject): UObjectHeader | null {
  if (b.length < Math.max(l.outer, l.cls) + 8 || b.length < l.name + 8) return null;
  const d = dv(b);
  return {
    vtable: d.getBigUint64(0, true), flags: d.getInt32(l.flags, true), index: d.getInt32(l.index, true), cls: d.getBigUint64(l.cls, true),
    nameIndex: d.getInt32(l.name, true), nameNumber: d.getInt32(l.name + 4, true), outer: d.getBigUint64(l.outer, true),
  };
}

export function parseObjectArray(b: Uint8Array, l: ObjectArrayLayout = kObjectArray): { objects: bigint; num: number } | null {
  if (b.length < Math.max(l.objectsOffset + 8, l.numOffset + 4)) return null;
  return { objects: dv(b).getBigUint64(l.objectsOffset, true), num: dv(b).getInt32(l.numOffset, true) };
}

export type ObjRow = { index: number; address: bigint; name: string; className: string; outer: bigint };

/**
 * Lists GUObjectArray items [start, start+count): the object, its name and its class name.
 * Null slots (freed objects) are skipped, so a page can hold fewer rows than `count`.
 */
export async function readObjects(
  read: Reader, gobjects: bigint, names: NameSource, start: number, count: number,
  o: { array?: ObjectArrayLayout; object?: UObjectLayout; cache?: Map<number, string> } = {},
): Promise<{ total: number; rows: ObjRow[] }> {
  const al = o.array ?? kObjectArray, ol = o.object ?? kUObject;
  const [hdr] = await read([{ address: gobjects, size: Math.max(al.objectsOffset + 8, al.numOffset + 4) }]);
  const arr = hdr && parseObjectArray(hdr, al);
  if (!arr || !arr.objects || arr.num <= 0) return { total: 0, rows: [] };
  const idx = Array.from({ length: Math.max(0, Math.min(count, arr.num - start)) }, (_, k) => start + k);
  let itemAddr: (i: number) => bigint;
  if (al.chunked) {
    const chunks = [...new Set(idx.map((i) => Math.floor(i / al.perChunk)))];
    const cp = await read(chunks.map((c) => ({ address: arr.objects + BigInt(c * 8), size: 8 })));
    const base = new Map(chunks.map((c, k) => [c, u64(cp[k])]));
    itemAddr = (i) => { const b = base.get(Math.floor(i / al.perChunk)) ?? 0n; return b ? b + BigInt((i % al.perChunk) * al.itemSize) : 0n; };
  } else itemAddr = (i) => arr.objects + BigInt(i * al.itemSize);
  const live = idx.filter((i) => itemAddr(i));
  const items = await read(live.map((i) => ({ address: itemAddr(i), size: 8 })));
  const objs = live.map((i, k) => ({ i, a: u64(items[k]) })).filter((x) => x.a);
  const hsize = Math.max(ol.outer, ol.cls, ol.name) + 8;
  const heads = await read(objs.map((x) => ({ address: x.a, size: hsize })));
  const parsed = objs.map((x, k) => ({ ...x, h: heads[k] ? parseUObject(heads[k]!, ol) : null })).filter((x) => x.h);
  const classes = [...new Set(parsed.map((x) => x.h!.cls).filter((c) => c))];
  const ch = await read(classes.map((c) => ({ address: c, size: hsize })));
  const clsHead = new Map(classes.map((c, k) => [c, ch[k] ? parseUObject(ch[k]!, ol) : null]));
  const cache = await readNames(read, names, [...parsed.map((x) => x.h!.nameIndex), ...[...clsHead.values()].flatMap((h) => (h ? [h.nameIndex] : []))], o.cache);
  return {
    total: arr.num,
    rows: parsed.map(({ i, a, h }) => {
      const c = clsHead.get(h!.cls);
      return { index: i, address: a, name: fnameString(cache.get(h!.nameIndex) ?? "?", h!.nameNumber), className: c ? fnameString(cache.get(c.nameIndex) ?? "?", c.nameNumber) : "?", outer: h!.outer };
    }),
  };
}
