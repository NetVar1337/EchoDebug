// Unreal Engine (4.23+ / 5.x) object and SDK dumper.
//
// GNames is the static FNamePool in the game module's .data: { FRWLock Lock; uint32 CurrentBlock;
// uint32 CurrentByteCursor; uint8* Blocks[8192] }, and block 0 starts with the "None" entry.
// GObjects is the static FUObjectArray: { int32 ObjFirstGCIndex, ObjLastNonGCIndex,
// MaxObjectsNotConsideredByGC; bool OpenForDisregardForGC; FChunkedFixedUObjectArray ObjObjects
// { FUObjectItem** Objects; FUObjectItem* PreAllocated; int32 Max, Num, MaxChunks, NumChunks } }.
// Both are found by shape in the module image, then confirmed through live memory, or by the
// documented AOB patterns below (kUnrealSigs), or typed in.
// Legacy GNames (UE4.22 and older) is a chunked TNameEntryArray of FNameEntry pointers, 16384 per
// chunk; each entry holds its index (bit 0 = wide) and then the NUL-terminated name (LegacyNames).
//
// Field offsets (UObject, UStruct, FField, FProperty) follow the stock UE 4.25–5.x layout and can
// be overridden per game (Offsets).

export type Mem = {
  read(addr: bigint, n: number): Promise<Uint8Array | null>;
  /** optional batched reads (one round trip) */
  readMany?(reads: { address: bigint; size: number }[]): Promise<(Uint8Array | null)[]>;
};

export type Offsets = {
  itemSize: number; // FUObjectItem
  objClass: number; objName: number; objOuter: number;
  structSuper: number; structChildProps: number; structSize: number;
  fieldClass: number; fieldNext: number; fieldName: number;
  propArrayDim: number; propElementSize: number; propOffset: number;
  propInner: number; // Struct / PropertyClass / Inner / Enum pointer right after FProperty
  boolFieldMask: number;
};

export const kDefaultOffsets: Offsets = {
  itemSize: 0x18,
  objClass: 0x10, objName: 0x18, objOuter: 0x20,
  structSuper: 0x40, structChildProps: 0x50, structSize: 0x58,
  fieldClass: 0x08, fieldNext: 0x20, fieldName: 0x28,
  propArrayDim: 0x38, propElementSize: 0x3c, propOffset: 0x4c,
  propInner: 0x78,
  boolFieldMask: 0x7b,
};

const kChunkItems = 0x10000;
const le = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength);

// ---- locating GNames / GObjects in the module image ------------------------------------------

export type Candidate = { address: bigint };

/** FNamePool candidates: CurrentBlock blocks allocated, the next one null, cursor within a block. */
export function findNamePools(img: Uint8Array, base: bigint, ranges: { rva: number; size: number }[]): Candidate[] {
  const dv = le(img);
  const out: Candidate[] = [];
  for (const r of ranges) {
    const end = Math.min(img.length, r.rva + r.size) - 0x40;
    for (let o = r.rva; o < end; o += 8) {
      const cur = dv.getUint32(o + 8, true);
      const cursor = dv.getUint32(o + 12, true);
      if (cur > 8191 || cursor === 0 || cursor > 0x20000 || (cursor & 1)) continue;
      if (o + 16 + (cur + 2) * 8 > img.length) continue;
      let ok = true;
      for (let b = 0; b <= cur && ok; b++) {
        const p = dv.getBigUint64(o + 16 + b * 8, true);
        ok = p > 0x10000n && p < 0x7fffffffffffn && (p & 1n) === 0n;
      }
      if (ok && dv.getBigUint64(o + 16 + (cur + 1) * 8, true) === 0n) out.push({ address: base + BigInt(o) });
    }
  }
  return out;
}

/** FUObjectArray candidates by the chunk arithmetic of ObjObjects. */
export function findObjectArrays(img: Uint8Array, base: bigint, ranges: { rva: number; size: number }[]): Candidate[] {
  const dv = le(img);
  const out: Candidate[] = [];
  for (const r of ranges) {
    const end = Math.min(img.length, r.rva + r.size) - 0x30;
    for (let o = r.rva; o < end; o += 4) {
      const objs = dv.getBigUint64(o + 0x10, true);
      if (objs < 0x10000n || objs > 0x7fffffffffffn || (objs & 7n)) continue;
      const max = dv.getInt32(o + 0x20, true);
      const num = dv.getInt32(o + 0x24, true);
      const maxChunks = dv.getInt32(o + 0x28, true);
      const numChunks = dv.getInt32(o + 0x2c, true);
      if (num < 64 || num > max || max > 0x4000000) continue;
      if (maxChunks !== Math.ceil(max / kChunkItems) || numChunks !== Math.ceil(num / kChunkItems)) continue;
      out.push({ address: base + BigInt(o) });
    }
  }
  return out;
}

/** Documented AOB patterns; each resolves a RIP-relative operand at `disp` of a `len`-byte instruction. */
export const kUnrealSigs = [
  { id: "pool", label: "FNamePool (UE4.23+): lea rcx, NamePoolData; call FNamePool ctor; mov byte [inited], 1", pattern: "48 8D 0D ? ? ? ? E8 ? ? ? ? C6 05 ? ? ? ? 01", disp: 3, len: 7, adjust: 0, deref: false },
  { id: "legacy", label: "GNames (≤UE4.22): mov rax, [GNames]; test rax, rax; jnz", pattern: "48 8B 05 ? ? ? ? 48 85 C0 75 ? B9 ? ? 00 00", disp: 3, len: 7, adjust: 0, deref: true },
  { id: "objects", label: "GUObjectArray: mov rax, [ObjObjects.Objects]; mov rcx, [rax+rcx*8]; lea rax, [rcx+rdx*8]", pattern: "48 8B 05 ? ? ? ? 48 8B 0C C8 48 8D 04 D1", disp: 3, len: 7, adjust: 0x10, deref: false },
] as const;
export type UnrealSig = (typeof kUnrealSigs)[number];

/** Target of a RIP-relative instruction at `hit`, given the 4 displacement bytes. */
export function ripTarget(hit: bigint, disp: Uint8Array, len: number): bigint {
  return hit + BigInt(len) + BigInt(new DataView(disp.buffer, disp.byteOffset, 4).getInt32(0, true));
}

// ---- names -----------------------------------------------------------------------------------

/** Anything that turns an FName into text: the FNamePool (4.23+) or legacy GNames (≤4.22). */
export type Names = {
  readonly mem: Mem;
  readonly address: bigint;
  init(): Promise<boolean>;
  name(comparisonIndex: number, number?: number): Promise<string>;
};

/** FNameEntry header { bIsWide:1, LowercaseProbeHash:5, Len:10 }. */
export function decodeNameHeader(h: number): { wide: boolean; len: number } {
  return { wide: (h & 1) === 1, len: h >> 6 };
}

/** The string of an FNamePool entry (header + chars); null when the buffer is short or the entry broken. */
export function decodePoolEntry(b: Uint8Array): string | null {
  if (b.length < 2) return null;
  const { wide, len } = decodeNameHeader(le(b).getUint16(0, true));
  if (len === 0 || 2 + len * (wide ? 2 : 1) > b.length) return null;
  return wide ? new TextDecoder("utf-16le").decode(b.subarray(2, 2 + len * 2)) : String.fromCharCode(...b.subarray(2, 2 + len));
}

/** A legacy FNameEntry: wide flag in bit 0 of its index, then the NUL-terminated name at `nameOffset`. */
export function decodeLegacyEntry(b: Uint8Array, nameOffset = 0x10): string | null {
  if (b.length < nameOffset + 1) return null;
  const wide = (le(b).getInt32(0, true) & 1) === 1;
  let s = "";
  for (let i = nameOffset; i + (wide ? 1 : 0) < b.length; i += wide ? 2 : 1) {
    const c = wide ? le(b).getUint16(i, true) : b[i];
    if (c === 0) return s;
    s += String.fromCharCode(c);
  }
  return s || null;
}

/** FName display form: Number is stored +1, so 0 means no suffix. */
export const fnameString = (base: string, number: number) => (number > 0 ? `${base}_${number - 1}` : base);

export class NamePool implements Names {
  private blocks: bigint[] = [];
  private cache = new Map<number, string>();
  constructor(readonly mem: Mem, readonly address: bigint) {}

  /** Reads the block table; true when block 0 starts with "None". */
  async init(): Promise<boolean> {
    const hdr = await this.mem.read(this.address + 8n, 8);
    if (!hdr) return false;
    const cur = le(hdr).getUint32(0, true);
    if (cur > 8191) return false;
    const tbl = await this.mem.read(this.address + 16n, (cur + 1) * 8);
    if (!tbl) return false;
    this.blocks = Array.from({ length: cur + 1 }, (_, i) => le(tbl).getBigUint64(i * 8, true));
    return (await this.entry(0)) === "None";
  }

  private async entry(idx: number): Promise<string | null> {
    const hit = this.cache.get(idx);
    if (hit !== undefined) return hit;
    const block = this.blocks[idx >>> 16];
    if (!block) return null;
    const at = block + BigInt((idx & 0xffff) * 2);
    const h = await this.mem.read(at, 2);
    if (!h) return null;
    const { wide, len } = decodeNameHeader(le(h).getUint16(0, true));
    if (len === 0 || len > 1024) return null;
    const raw = await this.mem.read(at + 2n, wide ? len * 2 : len);
    if (!raw) return null;
    const s = wide ? new TextDecoder("utf-16le").decode(raw) : String.fromCharCode(...raw);
    this.cache.set(idx, s);
    return s;
  }

  /** FName → text ("Name" or "Name_<Number-1>"). */
  async name(comparisonIndex: number, number = 0): Promise<string> {
    return fnameString((await this.entry(comparisonIndex)) ?? `name#${comparisonIndex}`, number);
  }
}

/** Legacy GNames (UE4.22 and older): TNameEntryArray, `perChunk` FNameEntry pointers per chunk. */
export class LegacyNames implements Names {
  private cache = new Map<number, string>();
  constructor(readonly mem: Mem, readonly address: bigint, readonly perChunk = 16384, readonly nameOffset = 0x10) {}

  /** True when entry 0 is "None". */
  async init(): Promise<boolean> {
    return (await this.entry(0).catch(() => null)) === "None";
  }

  private async entry(idx: number): Promise<string | null> {
    const hit = this.cache.get(idx);
    if (hit !== undefined) return hit;
    if (idx < 0) return null;
    const c = await this.mem.read(this.address + BigInt(Math.floor(idx / this.perChunk) * 8), 8);
    const chunk = c ? le(c).getBigUint64(0, true) : 0n;
    if (!chunk) return null;
    const e = await this.mem.read(chunk + BigInt((idx % this.perChunk) * 8), 8);
    const entry = e ? le(e).getBigUint64(0, true) : 0n;
    if (!entry) return null;
    // names are short; a page-crossing long read can fail where a shorter one succeeds
    const b = (await this.mem.read(entry, this.nameOffset + 0x100)) ?? (await this.mem.read(entry, this.nameOffset + 0x40));
    const s = b ? decodeLegacyEntry(b, this.nameOffset) : null;
    if (s !== null) this.cache.set(idx, s);
    return s;
  }

  async name(comparisonIndex: number, number = 0): Promise<string> {
    return fnameString((await this.entry(comparisonIndex)) ?? `name#${comparisonIndex}`, number);
  }
}

// ---- objects -----------------------------------------------------------------------------------

export type UObjectInfo = { index: number; address: bigint; name: string; className: string; outer: bigint; classAddr: bigint };

export class ObjectArray {
  num = 0;
  private chunks: bigint[] = [];
  constructor(readonly mem: Mem, readonly address: bigint, readonly off: Offsets = kDefaultOffsets) {}

  async init(): Promise<boolean> {
    const h = await this.mem.read(this.address + 0x10n, 0x20);
    if (!h) return false;
    const dv = le(h);
    const objects = dv.getBigUint64(0, true);
    this.num = dv.getInt32(0x14, true);
    const numChunks = dv.getInt32(0x1c, true);
    if (this.num <= 0 || numChunks <= 0 || numChunks > 1024) return false;
    const tbl = await this.mem.read(objects, numChunks * 8);
    if (!tbl) return false;
    this.chunks = Array.from({ length: numChunks }, (_, i) => le(tbl).getBigUint64(i * 8, true));
    return this.chunks[0] !== 0n;
  }

  /** Object pointers (0n for free slots), chunk by chunk. */
  async pointers(limit = this.num): Promise<bigint[]> {
    const n = Math.min(limit, this.num);
    const out: bigint[] = [];
    for (let c = 0; c * kChunkItems < n; c++) {
      const count = Math.min(kChunkItems, n - c * kChunkItems);
      const b = await this.mem.read(this.chunks[c], count * this.off.itemSize);
      for (let i = 0; i < count; i++) out.push(b ? le(b).getBigUint64(i * this.off.itemSize, true) : 0n);
    }
    return out;
  }

  /** Non-null object pointers of items [start, start+count), with their index. */
  async range(start: number, count: number): Promise<{ index: number; address: bigint }[]> {
    const end = Math.min(this.num, start + count);
    const out: { index: number; address: bigint }[] = [];
    for (let i = Math.max(0, start); i < end;) {
      const c = Math.floor(i / kChunkItems);
      const n = Math.min(end, (c + 1) * kChunkItems) - i;
      const b = this.chunks[c] ? await this.mem.read(this.chunks[c] + BigInt((i % kChunkItems) * this.off.itemSize), n * this.off.itemSize) : null;
      for (let k = 0; b && k < n; k++) {
        const p = le(b).getBigUint64(k * this.off.itemSize, true);
        if (p) out.push({ index: i + k, address: p });
      }
      i += n;
    }
    return out;
  }
}

/**
 * One page of GUObjectArray, [start, start+count): each live object with its name and class name,
 * without dumping the whole array first. Free slots are skipped, so a page can hold fewer rows.
 */
export async function listObjects(names: Names, objs: ObjectArray, start: number, count: number): Promise<UObjectInfo[]> {
  const off = objs.off;
  const ptrs = await objs.range(start, count);
  const heads = await readAll(objs.mem, ptrs.map((x) => ({ address: x.address, size: off.objOuter + 8 })));
  const out: UObjectInfo[] = [];
  for (const [k, x] of ptrs.entries()) {
    const h = heads[k];
    if (!h) continue;
    const dv = le(h);
    out.push({ index: x.index, address: x.address, classAddr: dv.getBigUint64(off.objClass, true), outer: dv.getBigUint64(off.objOuter, true), name: await names.name(dv.getInt32(off.objName, true), dv.getInt32(off.objName + 4, true)), className: "" });
  }
  const classes = [...new Set(out.map((o) => o.classAddr).filter((c) => c))];
  const ch = await readAll(objs.mem, classes.map((c) => ({ address: c + BigInt(off.objName), size: 8 })));
  const clsName = new Map<bigint, string>();
  for (const [k, c] of classes.entries()) {
    const b = ch[k];
    if (b) clsName.set(c, await names.name(le(b).getInt32(0, true), le(b).getInt32(4, true)));
  }
  for (const o of out) o.className = clsName.get(o.classAddr) ?? "?";
  return out;
}

async function readAll(mem: Mem, reads: { address: bigint; size: number }[]): Promise<(Uint8Array | null)[]> {
  if (mem.readMany) return mem.readMany(reads);
  return Promise.all(reads.map((r) => mem.read(r.address, r.size)));
}

export type ObjectDump = { objects: UObjectInfo[]; byAddress: Map<bigint, UObjectInfo> };

/** Every live object with its name and class name. */
export async function dumpObjects(names: Names, objs: ObjectArray, onProgress?: (done: number, total: number) => void, limit?: number): Promise<ObjectDump> {
  const off = objs.off;
  const ptrs = await objs.pointers(limit);
  const live = ptrs.map((p, i) => ({ p, i })).filter((x) => x.p !== 0n);
  const heads: (Uint8Array | null)[] = [];
  for (let i = 0; i < live.length; i += 4096) {
    heads.push(...(await readAll(names.mem, live.slice(i, i + 4096).map((x) => ({ address: x.p, size: off.objOuter + 8 })))));
    onProgress?.(Math.min(live.length, i + 4096), live.length);
  }
  const objects: UObjectInfo[] = [];
  for (const [k, x] of live.entries()) {
    const h = heads[k];
    if (!h) continue;
    const dv = le(h);
    objects.push({ index: x.i, address: x.p, classAddr: dv.getBigUint64(off.objClass, true), outer: dv.getBigUint64(off.objOuter, true), name: await names.name(dv.getInt32(off.objName, true), dv.getInt32(off.objName + 4, true)), className: "" });
  }
  const byAddress = new Map(objects.map((o) => [o.address, o]));
  for (const o of objects) o.className = byAddress.get(o.classAddr)?.name ?? "?";
  return { objects, byAddress };
}

/** "Package.Outer.Name" for an object. */
export function fullName(o: UObjectInfo, d: ObjectDump): string {
  const parts = [o.name];
  let cur = d.byAddress.get(o.outer);
  for (let i = 0; cur && i < 32; i++) {
    parts.unshift(cur.name);
    cur = d.byAddress.get(cur.outer);
  }
  return parts.join(".");
}

// ---- SDK ---------------------------------------------------------------------------------------

export type SdkField = { name: string; type: string; offset: number; size: number; arrayDim: number; propClass: string; bitMask?: number };
export type SdkStruct = { name: string; cppName: string; kind: "class" | "struct"; superName: string; size: number; fields: SdkField[]; fullName: string };

const kScalar: Record<string, string> = {
  BoolProperty: "bool", ByteProperty: "uint8", Int8Property: "int8", Int16Property: "int16", IntProperty: "int32", Int64Property: "int64",
  UInt16Property: "uint16", UInt32Property: "uint32", UInt64Property: "uint64", FloatProperty: "float", DoubleProperty: "double",
  NameProperty: "FName", StrProperty: "FString", TextProperty: "FText", EnumProperty: "uint8", ClassProperty: "UClass*",
  InterfaceProperty: "FScriptInterface", DelegateProperty: "FScriptDelegate", MulticastInlineDelegateProperty: "FMulticastScriptDelegate",
  MulticastSparseDelegateProperty: "FSparseDelegate", SoftClassProperty: "TSoftClassPtr<UObject>",
};

function cppName(name: string, kind: "class" | "struct", isActor: boolean): string {
  return kind === "struct" ? `F${name}` : `${isActor ? "A" : "U"}${name}`;
}

/** Walks a UClass / UScriptStruct and its FProperty chain. */
export async function readStruct(mem: Mem, names: Names, d: ObjectDump, o: UObjectInfo, off: Offsets = kDefaultOffsets): Promise<SdkStruct | null> {
  const s = await mem.read(o.address, off.structSize + 4);
  if (!s) return null;
  const dv = le(s);
  const superAddr = dv.getBigUint64(off.structSuper, true);
  const size = dv.getInt32(off.structSize, true);
  const kind: "class" | "struct" = o.className === "ScriptStruct" ? "struct" : "class";
  const isActor = async (start: bigint): Promise<boolean> => {
    let a = start;
    for (let i = 0; a && i < 64; i++) {
      const x = d.byAddress.get(a);
      if (!x) return false;
      if (x.name === "Actor") return true;
      const b = await mem.read(a + BigInt(off.structSuper), 8);
      a = b ? le(b).getBigUint64(0, true) : 0n;
    }
    return false;
  };
  const sup = d.byAddress.get(superAddr);
  const fields: SdkField[] = [];
  let f = dv.getBigUint64(off.structChildProps, true);
  for (let i = 0; f && i < 4096; i++) {
    const b = await mem.read(f, off.propInner + 8);
    if (!b) break;
    const fv = le(b);
    const clsName = await fieldClassName(mem, names, fv.getBigUint64(off.fieldClass, true));
    const name = await names.name(fv.getInt32(off.fieldName, true), fv.getInt32(off.fieldName + 4, true));
    const inner = fv.getBigUint64(off.propInner, true);
    const field: SdkField = { name, propClass: clsName, offset: fv.getInt32(off.propOffset, true), size: fv.getInt32(off.propElementSize, true), arrayDim: fv.getInt32(off.propArrayDim, true), type: "" };
    field.type = await typeOf(mem, names, d, clsName, inner, field.size, off);
    if (clsName === "BoolProperty") field.bitMask = b[off.boolFieldMask];
    fields.push(field);
    f = fv.getBigUint64(off.fieldNext, true);
  }
  fields.sort((a, b) => a.offset - b.offset);
  return {
    name: o.name, kind, size, fields, fullName: fullName(o, d),
    cppName: cppName(o.name, kind, kind === "class" && (await isActor(o.address))),
    superName: sup ? cppName(sup.name, kind, kind === "class" && (await isActor(sup.address))) : "",
  };
}

async function fieldClassName(mem: Mem, names: Names, cls: bigint): Promise<string> {
  const b = cls ? await mem.read(cls, 8) : null; // FFieldClass starts with its FName
  return b ? names.name(le(b).getInt32(0, true), le(b).getInt32(4, true)) : "?";
}

async function typeOf(mem: Mem, names: Names, d: ObjectDump, cls: string, inner: bigint, size: number, off: Offsets, depth = 0): Promise<string> {
  if (kScalar[cls]) return kScalar[cls];
  const obj = d.byAddress.get(inner);
  switch (cls) {
    case "StructProperty": return obj ? `F${obj.name}` : `uint8[0x${size.toString(16)}]`;
    case "ObjectProperty": case "ObjectPtrProperty": return obj ? `U${obj.name}*` : "UObject*";
    case "WeakObjectProperty": return `TWeakObjectPtr<${obj ? `U${obj.name}` : "UObject"}>`;
    case "LazyObjectProperty": return `TLazyObjectPtr<${obj ? `U${obj.name}` : "UObject"}>`;
    case "SoftObjectProperty": return `TSoftObjectPtr<${obj ? `U${obj.name}` : "UObject"}>`;
    case "ArrayProperty": case "SetProperty": {
      if (!inner || depth > 4) return cls === "ArrayProperty" ? "TArray<uint8>" : "TSet<uint8>";
      const b = await mem.read(inner, off.propInner + 8);
      if (!b) return "TArray<uint8>";
      const fv = le(b);
      const ic = await fieldClassName(mem, names, fv.getBigUint64(off.fieldClass, true));
      const t = await typeOf(mem, names, d, ic, fv.getBigUint64(off.propInner, true), fv.getInt32(off.propElementSize, true), off, depth + 1);
      return cls === "ArrayProperty" ? `TArray<${t}>` : `TSet<${t}>`;
    }
    case "MapProperty": return "TMap<uint8, uint8>";
    default: return `uint8[0x${size.toString(16)}] /* ${cls} */`;
  }
}

const hex = (n: number, w = 4) => `0x${n.toString(16).toUpperCase().padStart(w, "0")}`;

/** C++ header text with explicit padding and offset comments. */
export function sdkText(structs: SdkStruct[], baseSizes: Map<string, number> = new Map()): string {
  const out: string[] = ["// Generated by EchoDebug (Unreal SDK dump). Offsets are for this build only.", "#pragma once", ""];
  for (const s of structs) {
    out.push(`// ${s.kind === "struct" ? "ScriptStruct" : "Class"} ${s.fullName}`, `// Size: ${hex(s.size)}`);
    out.push(`${s.kind} ${s.cppName}${s.superName ? ` : public ${s.superName}` : ""} {`);
    let at = s.superName ? (baseSizes.get(s.superName) ?? s.fields[0]?.offset ?? 0) : 0;
    let pad = 0;
    for (const f of s.fields) {
      if (f.offset > at) out.push(`\tuint8 pad_${pad++}[${hex(f.offset - at)}]; // ${hex(at)}(${hex(f.offset - at)})`);
      const dim = f.arrayDim > 1 ? `[${f.arrayDim}]` : "";
      const bits = f.bitMask !== undefined && f.bitMask !== 0xff ? ` : 1; // mask ${hex(f.bitMask, 2)}` : ";";
      out.push(`\t${f.type} ${f.name}${dim}${bits}${bits === ";" ? " //" : ""} ${hex(f.offset)}(${hex(f.size * Math.max(1, f.arrayDim))})`);
      at = Math.max(at, f.offset + f.size * Math.max(1, f.arrayDim));
    }
    if (s.size > at) out.push(`\tuint8 pad_${pad++}[${hex(s.size - at)}]; // ${hex(at)}(${hex(s.size - at)})`);
    out.push("};", "");
  }
  return out.join("\n");
}
