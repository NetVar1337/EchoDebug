// ECMA-335 / CLR metadata parser.
//
// Works on an in-memory *mapped* PE image: the byte at index R is the byte at
// RVA R (headers live at index 0).  Every offset handled here is therefore an
// RVA / absolute index into the image, never a file offset.
//
// Layout walked:  PE data directory 14 (CLR) -> IMAGE_COR20_HEADER ->
// metadata root ("BSJB") -> stream headers -> "#~" table stream -> rows.

import { parsePe } from "./pe";

export type DotnetMethod = { name: string; rva: number; flags: number; attributes: string[] };
export type DotnetField = { name: string; flags: number; attributes: string[] };
export type DotnetType = {
  fullName: string;
  namespace: string;
  name: string;
  flags: number;
  methods: DotnetMethod[];
  fields: DotnetField[];
  baseType: string;
};
export type DotnetInfo = {
  runtimeVersion: string;   // e.g. "v4.0.30319"
  metadataVersion: string;  // e.g. "v4.0.30319"
  entryPointToken: number;  // 0 when absent
  types: DotnetType[];      // sorted by fullName
};

/* ------------------------------------------------------------------ */
/* metadata table ids                                                 */
/* ------------------------------------------------------------------ */

const T = {
  Module: 0, TypeRef: 1, TypeDef: 2, FieldPtr: 3, Field: 4, MethodPtr: 5, MethodDef: 6,
  ParamPtr: 7, Param: 8, InterfaceImpl: 9, MemberRef: 10, Constant: 11, CustomAttribute: 12,
  FieldMarshal: 13, DeclSecurity: 14, ClassLayout: 15, FieldLayout: 16, StandAloneSig: 17,
  EventMap: 18, EventPtr: 19, Event: 20, PropertyMap: 21, PropertyPtr: 22, Property: 23,
  MethodSemantics: 24, MethodImpl: 25, ModuleRef: 26, TypeSpec: 27, ImplMap: 28, FieldRVA: 29,
  EncLog: 30, EncMap: 31, Assembly: 32, AssemblyProcessor: 33, AssemblyOS: 34, AssemblyRef: 35,
  AssemblyRefProcessor: 36, AssemblyRefOS: 37, File: 38, ExportedType: 39, ManifestResource: 40,
  NestedClass: 41, GenericParam: 42, MethodSpec: 43, GenericParamConstraint: 44,
} as const;

const kTableCount = 45;

/* ------------------------------------------------------------------ */
/* column kinds & table schemas (ECMA-335 II.22)                      */
/* ------------------------------------------------------------------ */

// "u8" | "u16" | "u32"            fixed size primitive
// "str" | "guid" | "blob"          heap index (width from heapSizes)
// { tbl }                          simple index into another table
// { coded }                        coded index (see kCoded)
type ColKind = "u8" | "u16" | "u32" | "str" | "guid" | "blob" | { tbl: number } | { coded: string };
type Schema = { id: number; name: string; cols: [string, ColKind][] };

const kSchemaList: Schema[] = [
  { id: T.Module, name: "Module", cols: [
    ["Generation", "u16"], ["Name", "str"], ["Mvid", "guid"], ["EncId", "guid"], ["EncBaseId", "guid"]] },
  { id: T.TypeRef, name: "TypeRef", cols: [
    ["ResolutionScope", { coded: "ResolutionScope" }], ["TypeName", "str"], ["TypeNamespace", "str"]] },
  { id: T.TypeDef, name: "TypeDef", cols: [
    ["Flags", "u32"], ["TypeName", "str"], ["TypeNamespace", "str"],
    ["Extends", { coded: "TypeDefOrRef" }],
    ["FieldList", { tbl: T.Field }], ["MethodList", { tbl: T.MethodDef }]] },
  { id: T.FieldPtr, name: "FieldPtr", cols: [["Field", { tbl: T.Field }]] },
  { id: T.Field, name: "Field", cols: [["Flags", "u16"], ["Name", "str"], ["Signature", "blob"]] },
  { id: T.MethodPtr, name: "MethodPtr", cols: [["Method", { tbl: T.MethodDef }]] },
  { id: T.MethodDef, name: "MethodDef", cols: [
    ["RVA", "u32"], ["ImplFlags", "u16"], ["Flags", "u16"],
    ["Name", "str"], ["Signature", "blob"], ["ParamList", { tbl: T.Param }]] },
  { id: T.ParamPtr, name: "ParamPtr", cols: [["Param", { tbl: T.Param }]] },
  { id: T.Param, name: "Param", cols: [["Flags", "u16"], ["Sequence", "u16"], ["Name", "str"]] },
  { id: T.InterfaceImpl, name: "InterfaceImpl", cols: [
    ["Class", { tbl: T.TypeDef }], ["Interface", { coded: "TypeDefOrRef" }]] },
  { id: T.MemberRef, name: "MemberRef", cols: [
    ["Class", { coded: "MemberRefParent" }], ["Name", "str"], ["Signature", "blob"]] },
  { id: T.Constant, name: "Constant", cols: [
    ["Type", "u8"], ["Padding", "u8"], ["Parent", { coded: "HasConstant" }], ["Value", "blob"]] },
  { id: T.CustomAttribute, name: "CustomAttribute", cols: [
    ["Parent", { coded: "HasCustomAttribute" }], ["Type", { coded: "CustomAttributeType" }],
    ["Value", "blob"]] },
  { id: T.FieldMarshal, name: "FieldMarshal", cols: [
    ["Parent", { coded: "HasFieldMarshal" }], ["NativeType", "blob"]] },
  { id: T.DeclSecurity, name: "DeclSecurity", cols: [
    ["Action", "u16"], ["Parent", { coded: "HasDeclSecurity" }], ["PermissionSet", "blob"]] },
  { id: T.ClassLayout, name: "ClassLayout", cols: [
    ["PackingSize", "u16"], ["ClassSize", "u32"], ["Parent", { tbl: T.TypeDef }]] },
  { id: T.FieldLayout, name: "FieldLayout", cols: [["Offset", "u32"], ["Field", { tbl: T.Field }]] },
  { id: T.StandAloneSig, name: "StandAloneSig", cols: [["Signature", "blob"]] },
  { id: T.EventMap, name: "EventMap", cols: [
    ["Parent", { tbl: T.TypeDef }], ["EventList", { tbl: T.Event }]] },
  { id: T.EventPtr, name: "EventPtr", cols: [["Event", { tbl: T.Event }]] },
  { id: T.Event, name: "Event", cols: [
    ["EventFlags", "u16"], ["Name", "str"], ["EventType", { coded: "TypeDefOrRef" }]] },
  { id: T.PropertyMap, name: "PropertyMap", cols: [
    ["Parent", { tbl: T.TypeDef }], ["PropertyList", { tbl: T.Property }]] },
  { id: T.PropertyPtr, name: "PropertyPtr", cols: [["Property", { tbl: T.Property }]] },
  { id: T.Property, name: "Property", cols: [["Flags", "u16"], ["Name", "str"], ["Type", "blob"]] },
  { id: T.MethodSemantics, name: "MethodSemantics", cols: [
    ["Semantics", "u16"], ["Method", { tbl: T.MethodDef }], ["Association", { coded: "HasSemantics" }]] },
  { id: T.MethodImpl, name: "MethodImpl", cols: [
    ["Class", { tbl: T.TypeDef }],
    ["MethodBody", { coded: "MethodDefOrRef" }], ["MethodDeclaration", { coded: "MethodDefOrRef" }]] },
  { id: T.ModuleRef, name: "ModuleRef", cols: [["Name", "str"]] },
  { id: T.TypeSpec, name: "TypeSpec", cols: [["Signature", "blob"]] },
  { id: T.ImplMap, name: "ImplMap", cols: [
    ["MappingFlags", "u16"], ["MemberForwarded", { coded: "MemberForwarded" }],
    ["ImportName", "str"], ["ImportScope", { tbl: T.ModuleRef }]] },
  { id: T.FieldRVA, name: "FieldRVA", cols: [["RVA", "u32"], ["Field", { tbl: T.Field }]] },
  { id: T.EncLog, name: "EncLog", cols: [["Token", "u32"], ["FuncCode", "u32"]] },
  { id: T.EncMap, name: "EncMap", cols: [["Token", "u32"]] },
  { id: T.Assembly, name: "Assembly", cols: [
    ["HashAlgId", "u32"], ["MajorVersion", "u16"], ["MinorVersion", "u16"],
    ["BuildNumber", "u16"], ["RevisionNumber", "u16"], ["Flags", "u32"],
    ["PublicKey", "blob"], ["Name", "str"], ["Culture", "str"]] },
  { id: T.AssemblyProcessor, name: "AssemblyProcessor", cols: [["Processor", "u32"]] },
  { id: T.AssemblyOS, name: "AssemblyOS", cols: [
    ["OSPlatformID", "u32"], ["OSMajorVersion", "u32"], ["OSMinorVersion", "u32"]] },
  { id: T.AssemblyRef, name: "AssemblyRef", cols: [
    ["MajorVersion", "u16"], ["MinorVersion", "u16"], ["BuildNumber", "u16"], ["RevisionNumber", "u16"],
    ["Flags", "u32"], ["PublicKeyOrToken", "blob"], ["Name", "str"], ["Culture", "str"],
    ["HashValue", "blob"]] },
  { id: T.AssemblyRefProcessor, name: "AssemblyRefProcessor", cols: [
    ["Processor", "u32"], ["AssemblyRef", { tbl: T.AssemblyRef }]] },
  { id: T.AssemblyRefOS, name: "AssemblyRefOS", cols: [
    ["OSPlatformId", "u32"], ["OSMajorVersion", "u32"], ["OSMinorVersion", "u32"],
    ["AssemblyRef", { tbl: T.AssemblyRef }]] },
  { id: T.File, name: "File", cols: [["Flags", "u32"], ["Name", "str"], ["HashValue", "blob"]] },
  { id: T.ExportedType, name: "ExportedType", cols: [
    ["Flags", "u32"], ["TypeDefId", "u32"], ["TypeName", "str"], ["TypeNamespace", "str"],
    ["Implementation", { coded: "Implementation" }]] },
  { id: T.ManifestResource, name: "ManifestResource", cols: [
    ["Offset", "u32"], ["Flags", "u32"], ["Name", "str"], ["Implementation", { coded: "Implementation" }]] },
  { id: T.NestedClass, name: "NestedClass", cols: [
    ["NestedClass", { tbl: T.TypeDef }], ["EnclosingClass", { tbl: T.TypeDef }]] },
  { id: T.GenericParam, name: "GenericParam", cols: [
    ["Number", "u16"], ["Flags", "u16"], ["Owner", { coded: "TypeOrMethodDef" }], ["Name", "str"]] },
  { id: T.MethodSpec, name: "MethodSpec", cols: [
    ["Method", { coded: "MethodDefOrRef" }], ["Instantiation", "blob"]] },
  { id: T.GenericParamConstraint, name: "GenericParamConstraint", cols: [
    ["Owner", { tbl: T.GenericParam }], ["Constraint", { coded: "TypeDefOrRef" }]] },
];

if (kSchemaList.length !== kTableCount) throw new Error("incomplete metadata table schema");

/* ------------------------------------------------------------------ */
/* coded index definitions (ECMA-335 II.24.2.6)                       */
/* ------------------------------------------------------------------ */

type CodedDef = { tables: number[]; bits: number };

const kCoded: Record<string, CodedDef> = {
  TypeDefOrRef: { tables: [T.TypeDef, T.TypeRef, T.TypeSpec], bits: 2 },
  HasConstant: { tables: [T.Field, T.Param, T.Property], bits: 2 },
  HasCustomAttribute: {
    tables: [
      T.MethodDef, T.Field, T.TypeRef, T.TypeDef, T.Param, T.InterfaceImpl, T.MemberRef, T.Module,
      T.DeclSecurity, T.Property, T.Event, T.StandAloneSig, T.ModuleRef, T.TypeSpec, T.Assembly,
      T.AssemblyRef, T.File, T.ExportedType, T.ManifestResource, T.GenericParam,
      T.GenericParamConstraint, T.MethodSpec,
    ],
    bits: 5,
  },
  HasFieldMarshal: { tables: [T.Field, T.Param], bits: 1 },
  HasDeclSecurity: { tables: [T.TypeDef, T.MethodDef, T.Assembly], bits: 2 },
  MemberRefParent: { tables: [T.TypeDef, T.TypeRef, T.ModuleRef, T.MethodDef, T.TypeSpec], bits: 3 },
  HasSemantics: { tables: [T.Event, T.Property], bits: 1 },
  MethodDefOrRef: { tables: [T.MethodDef, T.MemberRef], bits: 1 },
  MemberForwarded: { tables: [T.Field, T.MethodDef], bits: 1 },
  Implementation: { tables: [T.File, T.AssemblyRef, T.ExportedType], bits: 2 },
  // tags 0/1/4 are "not used"; 2 = MethodDef, 3 = MemberRef
  CustomAttributeType: { tables: [-1, -1, T.MethodDef, T.MemberRef, -1], bits: 3 },
  ResolutionScope: { tables: [T.Module, T.ModuleRef, T.AssemblyRef, T.TypeRef], bits: 2 },
  TypeOrMethodDef: { tables: [T.TypeDef, T.MethodDef], bits: 1 },
};

/* ------------------------------------------------------------------ */
/* low level helpers                                                   */
/* ------------------------------------------------------------------ */

const utf8 = new TextDecoder("utf-8");

function decodeUtf8(b: Uint8Array): string {
  try {
    return utf8.decode(b);
  } catch {
    return "";
  }
}

function sliceAt(dv: DataView, off: number, size: number): Uint8Array | null {
  if (off < 0 || size < 0 || off + size > dv.byteLength) return null;
  return new Uint8Array(dv.buffer, dv.byteOffset + off, size);
}

function readHeapString(heap: Uint8Array, idx: number): string {
  if (idx <= 0 || idx >= heap.length) return "";
  let end = idx;
  while (end < heap.length && heap[end] !== 0) end++;
  return decodeUtf8(heap.subarray(idx, end));
}

type Row = Record<string, number>;

type CliHeader = {
  cb: number;
  majorRuntimeVersion: number;
  minorRuntimeVersion: number;
  metaRva: number;
  metaSize: number;
  flags: number;
  entryPointToken: number;
};

type MetaRoot = {
  major: number;
  minor: number;
  version: string;
  streams: Record<string, { off: number; size: number } | undefined>;
};

type Meta = {
  strings: Uint8Array;
  blob: Uint8Array;
  guid: Uint8Array;
  rows: Map<number, Row[]>;
};

function readCliHeader(dv: DataView, rva: number): CliHeader | null {
  if (rva < 0 || rva + 24 > dv.byteLength) return null;
  return {
    cb: dv.getUint32(rva, true),
    majorRuntimeVersion: dv.getUint16(rva + 4, true),
    minorRuntimeVersion: dv.getUint16(rva + 6, true),
    metaRva: dv.getUint32(rva + 8, true),
    metaSize: dv.getUint32(rva + 12, true),
    flags: dv.getUint32(rva + 16, true),
    entryPointToken: dv.getUint32(rva + 20, true),
  };
}

function parseMetadataRoot(dv: DataView, base: number): MetaRoot | null {
  if (base < 0 || base + 20 > dv.byteLength) return null;
  if (dv.getUint32(base, true) !== 0x424a5342) return null; // "BSJB"
  const major = dv.getUint16(base + 4, true);
  const minor = dv.getUint16(base + 6, true);
  const verLen = dv.getUint32(base + 12, true);
  if (verLen > 0x10000 || base + 16 + verLen > dv.byteLength) return null;
  const raw = sliceAt(dv, base + 16, verLen);
  const version = raw ? decodeUtf8(raw).replace(/\0+$/, "") : "";
  let o = base + 16 + verLen;
  o = (o + 3) & ~3; // version string is padded to a 4 byte boundary
  if (o + 4 > dv.byteLength) return null;
  const numStreams = dv.getUint16(o + 2, true);
  o += 4;
  const streams: Record<string, { off: number; size: number } | undefined> = {};
  for (let i = 0; i < numStreams; i++) {
    if (o + 8 > dv.byteLength) return null;
    const off = dv.getUint32(o, true);
    const size = dv.getUint32(o + 4, true);
    o += 8;
    const nameStart = o;
    while (o < dv.byteLength && dv.getUint8(o) !== 0) o++;
    if (o >= dv.byteLength) return null;
    let name = "";
    for (let j = nameStart; j < o; j++) name += String.fromCharCode(dv.getUint8(j));
    o = nameStart + ((o - nameStart + 1 + 3) & ~3); // name + NUL, padded to 4 bytes
    streams[name] = { off, size };
  }
  return { major, minor, version, streams };
}

/* ------------------------------------------------------------------ */
/* table stream decoding                                               */
/* ------------------------------------------------------------------ */

function codedWidth(coded: string, counts: number[]): number {
  const def = kCoded[coded];
  let max = 0;
  for (const t of def.tables) if (t >= 0) max = Math.max(max, counts[t] ?? 0);
  return max <= (1 << def.bits) - 1 ? 2 : 4;
}

function colWidth(kind: ColKind, counts: number[], heapSizes: number): number {
  if (kind === "u8") return 1;
  if (kind === "u16") return 2;
  if (kind === "u32") return 4;
  if (kind === "str") return heapSizes & 0x01 ? 4 : 2;
  if (kind === "guid") return heapSizes & 0x02 ? 4 : 2;
  if (kind === "blob") return heapSizes & 0x04 ? 4 : 2;
  if ("tbl" in kind) return (counts[kind.tbl] ?? 0) <= 0xffff ? 2 : 4;
  return codedWidth(kind.coded, counts);
}

// Row sizes only depend on the row counts of the referenced tables and on the
// heap index widths, so the widths reach a fixed point immediately.
function computeWidths(counts: number[], heapSizes: number): Record<number, number[]> {
  const widths: Record<number, number[]> = {};
for (const sch of kSchemaList) widths[sch.id] = sch.cols.map(([, k]) => colWidth(k, counts, heapSizes));
  return widths;
}

function parseTableStream(buf: Uint8Array): { rows: Map<number, Row[]>; heapSizes: number } | null {
  if (buf.length < 24) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const heapSizes = dv.getUint8(6);
  const valid = dv.getBigUint64(8, true);
  const counts: number[] = new Array(kTableCount).fill(0);
  let o = 24;
  for (let t = 0; t < kTableCount; t++) {
    if ((valid >> BigInt(t)) & 1n) {
      if (o + 4 > buf.length) return null;
      counts[t] = dv.getUint32(o, true);
      o += 4;
    }
  }
  const widths = computeWidths(counts, heapSizes);
  const rows = new Map<number, Row[]>();
  for (const sch of kSchemaList) {
    const t = sch.id;
    if (counts[t] === 0) continue;
    const w = widths[t] ?? [];
    const rowSize = w.reduce((a, b) => a + b, 0);
    const list: Row[] = [];
    for (let r = 0; r < counts[t]; r++) {
      if (o + rowSize > buf.length) break;
      const row: Row = {};
      let ro = o;
      for (let i = 0; i < sch.cols.length; i++) {
        const width = w[i];
        const v = width === 1 ? dv.getUint8(ro) : width === 2 ? dv.getUint16(ro, true) : dv.getUint32(ro, true);
        row[sch.cols[i][0]] = v;
        ro += width;
      }
      o = ro;
      list.push(row);
    }
    rows.set(t, list);
  }
  return { rows, heapSizes };
}

function splitCoded(coded: string, value: number): { table: number; row: number } | null {
  const def = kCoded[coded];
  if (!def) return null;
  const tag = value & ((1 << def.bits) - 1);
  const row = value >>> def.bits;
  if (row === 0 || tag >= def.tables.length) return null;
  const t = def.tables[tag];
  if (t < 0) return null;
  return { table: t, row };
}

/* ------------------------------------------------------------------ */
/* model building                                                      */
/* ------------------------------------------------------------------ */

function buildInfo(meta: Meta, cli: CliHeader, root: MetaRoot): DotnetInfo {
  const typeDefs = meta.rows.get(T.TypeDef) ?? [];
  const typeRefs = meta.rows.get(T.TypeRef) ?? [];
  const methodRows = meta.rows.get(T.MethodDef) ?? [];
  const fieldRows = meta.rows.get(T.Field) ?? [];
  const memberRefs = meta.rows.get(T.MemberRef) ?? [];

  const readStr = (idx: number) => readHeapString(meta.strings, idx);

  // nested types: TypeDef row -> enclosing TypeDef row
  const enclosing = new Map<number, number>();
  for (const r of meta.rows.get(T.NestedClass) ?? []) {
    if (r.NestedClass && r.EnclosingClass) enclosing.set(r.NestedClass, r.EnclosingClass);
  }

  // per TypeDef row: namespace + name part ("Outer+Inner" for nested types)
  const parts = new Map<number, { ns: string; name: string }>();
  const visiting = new Set<number>();
  function typeParts(row1: number): { ns: string; name: string } {
    const cached = parts.get(row1);
    if (cached) return cached;
    const td = typeDefs[row1 - 1];
    if (!td) return { ns: "", name: "" };
    if (visiting.has(row1)) return { ns: "", name: "" };
    visiting.add(row1);
    const own = readStr(td.TypeName);
    const ns = readStr(td.TypeNamespace);
    const enc = enclosing.get(row1);
    const name = enc ? `${typeParts(enc).name}+${own}` : own;
    visiting.delete(row1);
    const res = { ns, name };
    parts.set(row1, res);
    return res;
  }
  function typeFullName(row1: number): string {
    const p = typeParts(row1);
    return p.ns ? `${p.ns}.${p.name}` : p.name;
  }
  function typeRefName(row1: number): string {
    const tr = typeRefs[row1 - 1];
    if (!tr) return "";
    const n = readStr(tr.TypeName);
    const ns = readStr(tr.TypeNamespace);
    return ns ? `${ns}.${n}` : n;
  }

  // custom attributes (the exported DotnetType shape carries no attribute list,
  // so attributes are surfaced on methods and fields only)
  const methodAttrs = new Map<number, string[]>();
  const fieldAttrs = new Map<number, string[]>();
  const push = (m: Map<number, string[]>, row: number, name: string) => {
    const list = m.get(row);
    if (list) list.push(name);
    else m.set(row, [name]);
  };

  function attributeName(value: number): string {
    const s = splitCoded("CustomAttributeType", value);
    if (!s) return "";
    let full = "";
    if (s.table === T.MemberRef) {
      const mr = memberRefs[s.row - 1];
      if (!mr) return "";
      const parent = splitCoded("MemberRefParent", mr.Class);
      if (parent && (parent.table === T.TypeDef || parent.table === T.TypeRef)) {
        full = parent.table === T.TypeDef ? typeFullName(parent.row) : typeRefName(parent.row);
      }
      if (!full) full = readStr(mr.Name);
    } else if (s.table === T.MethodDef) {
      const md = methodRows[s.row - 1];
      if (!md) return "";
      full = readStr(md.Name);
    }
    const dot = full.lastIndexOf(".");
    return dot >= 0 ? full.slice(dot + 1) : full;
  }

  for (const ca of meta.rows.get(T.CustomAttribute) ?? []) {
    const parent = splitCoded("HasCustomAttribute", ca.Parent);
    if (!parent) continue;
    const name = attributeName(ca.Type);
    if (!name) continue;
    if (parent.table === T.MethodDef) push(methodAttrs, parent.row, name);
    else if (parent.table === T.Field) push(fieldAttrs, parent.row, name);
  }

  function baseTypeOf(td: Row): string {
    const s = splitCoded("TypeDefOrRef", td.Extends ?? 0);
    if (!s) return "";
    if (s.table === T.TypeDef) return typeFullName(s.row);
    if (s.table === T.TypeRef) return typeRefName(s.row);
    if (s.table === T.TypeSpec) return "System.Type";
    return "";
  }

  const types: DotnetType[] = [];
  for (let i = 0; i < typeDefs.length; i++) {
    const td = typeDefs[i];
    const p = typeParts(i + 1);

    const mStart = td.MethodList ?? 0;
    const mEnd = i + 1 < typeDefs.length ? (typeDefs[i + 1].MethodList ?? 0) : methodRows.length + 1;
    const methods: DotnetMethod[] = [];
    if (mStart > 0) {
      for (let r = mStart; r < mEnd && r <= methodRows.length; r++) {
        const md = methodRows[r - 1];
        if (!md) continue;
        methods.push({
          name: readStr(md.Name),
          rva: md.RVA ?? 0,
          flags: md.Flags ?? 0,
          attributes: methodAttrs.get(r) ?? [],
        });
      }
    }

    const fStart = td.FieldList ?? 0;
    const fEnd = i + 1 < typeDefs.length ? (typeDefs[i + 1].FieldList ?? 0) : fieldRows.length + 1;
    const fields: DotnetField[] = [];
    if (fStart > 0) {
      for (let r = fStart; r < fEnd && r <= fieldRows.length; r++) {
        const fd = fieldRows[r - 1];
        if (!fd) continue;
        fields.push({ name: readStr(fd.Name), flags: fd.Flags ?? 0, attributes: fieldAttrs.get(r) ?? [] });
      }
    }

    types.push({
      fullName: p.ns ? `${p.ns}.${p.name}` : p.name,
      namespace: p.ns,
      name: p.name,
      flags: td.Flags ?? 0,
      methods,
      fields,
      baseType: baseTypeOf(td),
    });
  }

  types.sort((a, b) => (a.fullName < b.fullName ? -1 : a.fullName > b.fullName ? 1 : 0));

  const metadataVersion = root.version || `v${root.major}.${root.minor}.0`;
  const runtimeVersion = root.version || `v${cli.majorRuntimeVersion}.${cli.minorRuntimeVersion}.0`;
  return { runtimeVersion, metadataVersion, entryPointToken: cli.entryPointToken ?? 0, types };
}

/* ------------------------------------------------------------------ */
/* entry point                                                         */
/* ------------------------------------------------------------------ */

/**
 * Parse the CLR metadata of a mapped PE image.
 * Returns null when the image carries no CLR header or no valid metadata.
 */
export function parseDotnet(img: Uint8Array): DotnetInfo | null {
  try {
    return parseDotnetSafe(img);
  } catch {
    return null;
  }
}

function parseDotnetSafe(img: Uint8Array): DotnetInfo | null {
  const pe = parsePe(img); // throws for non PE images
  const clr = pe.dirs.find((d) => d.name === "CLR");
  if (!clr || !clr.rva || !clr.size) return null;
  if (clr.rva + 24 > img.length) return null;

  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const cli = readCliHeader(dv, clr.rva);
  if (!cli) return null;
  if (!cli.metaRva || cli.metaRva + 20 > img.length) return null;

  const root = parseMetadataRoot(dv, cli.metaRva);
  if (!root) return null;

  const tblStream = root.streams["#~"] ?? root.streams["#-"];
  if (!tblStream) return null;
  const stringsStream = root.streams["#Strings"];
  if (!stringsStream) return null;
  const blobStream = root.streams["#Blob"];
  const guidStream = root.streams["#GUID"];

  const tblBuf = sliceAt(dv, cli.metaRva + tblStream.off, tblStream.size);
  if (!tblBuf) return null;
  const decoded = parseTableStream(tblBuf);
  if (!decoded) return null;

  const empty = new Uint8Array(0);
  const meta: Meta = {
    strings: (stringsStream && sliceAt(dv, cli.metaRva + stringsStream.off, stringsStream.size)) || empty,
    blob: (blobStream && sliceAt(dv, cli.metaRva + blobStream.off, blobStream.size)) || empty,
    guid: (guidStream && sliceAt(dv, cli.metaRva + guidStream.off, guidStream.size)) || empty,
    rows: decoded.rows,
  };
  return buildInfo(meta, cli, root);
}
