// Test helper: a mapped PE32+ image carrying real CLR metadata (Module/TypeRef/TypeDef/Field/
// MethodDef/MemberRef/CustomAttribute/NestedClass rows, #Strings/#Blob/#US heaps, method bodies).
// Used by the .NET parser tests and the fuzz seeds.

/* ------------------------------------------------------------------ */
/* little endian byte helpers                                         */
/* ------------------------------------------------------------------ */

const le8 = (v: number) => [v & 0xff];
const le16 = (v: number) => [v & 0xff, (v >> 8) & 0xff];
const le32 = (v: number) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff];
const le64 = (v: bigint) => {
  const b: number[] = [];
  for (let i = 0; i < 8; i++) b.push(Number((v >> BigInt(8 * i)) & 0xffn));
  return b;
};

// coded index: row number in the high bits, tag in the low bits
const ci = (row: number, tag: number, bits: number) => (row << bits) | tag;

/* ------------------------------------------------------------------ */
/* heaps                                                               */
/* ------------------------------------------------------------------ */

export function buildStrings(names: string[]): { data: number[]; at: Record<string, number | undefined> } {
  const data: number[] = [0]; // offset 0 is the empty string
  const at: Record<string, number | undefined> = { "": 0 };
  for (const n of [...names].sort()) {
    if (at[n] !== undefined) continue;
    at[n] = data.length;
    for (const ch of n) data.push(ch.charCodeAt(0) & 0xff);
    data.push(0);
  }
  return { data, at };
}

function buildBlobs(entries: number[][]): { data: number[]; at: number[] } {
  const data: number[] = [0]; // offset 0 is the empty blob
  const at: number[] = [];
  for (const e of entries) {
    at.push(data.length);
    const len = e.length;
    if (len < 0x80) data.push(len);
    else if (len < 0x4000) data.push(0x80 | (len >> 8), len & 0xff);
    else data.push(0xc0 | (len >> 24), (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff);
    data.push(...e);
  }
  return { data, at };
}

/* ------------------------------------------------------------------ */
/* metadata streams                                                    */
/* ------------------------------------------------------------------ */

export type TableDef = { id: number; widths: number[]; rows: number[][] };

export function buildTables(tables: TableDef[], heapSizes: number): number[] {
  const out: number[] = [];
  const push = (b: number[]) => {
    for (const x of b) out.push(x);
  };
  push(le32(0)); // reserved
  push(le8(2)); // major version
  push(le8(0)); // minor version
  push(le8(heapSizes)); // heap index widths
  push(le8(1)); // reserved
  let valid = 0n;
  for (const t of tables) valid |= 1n << BigInt(t.id);
  push(le64(valid)); // valid mask
  push(le64(0n)); // sorted mask
  for (const t of tables) push(le32(t.rows.length)); // row counts, ascending table id
  for (const t of tables) {
    for (const row of t.rows) {
      row.forEach((v, i) => {
        const w = t.widths[i];
        if (w === 1) push(le8(v));
        else if (w === 2) push(le16(v));
        else push(le32(v));
      });
    }
  }
  return out;
}

export function buildMetadata(streams: { name: string; data: number[] }[]): Uint8Array {
  const version = "v4.0.30319";
  const vbytes = [...version].map((c) => c.charCodeAt(0));
  const namePad = streams.map((s) => (s.name.length + 1 + 3) & ~3);
  const afterVersion = (16 + vbytes.length + 3) & ~3;
  const streamHdrStart = afterVersion + 4; // flags + stream count
  let dataCursor = streamHdrStart + streams.length * 8 + namePad.reduce((a, b) => a + b, 0);
  dataCursor = (dataCursor + 3) & ~3;
  const offsets: number[] = [];
  for (const s of streams) {
    offsets.push(dataCursor);
    dataCursor = (dataCursor + s.data.length + 3) & ~3;
  }
  const out = new Uint8Array(dataCursor);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, 0x424a5342, true); // "BSJB"
  dv.setUint16(4, 1, true);
  dv.setUint16(6, 1, true);
  dv.setUint32(8, 0, true);
  dv.setUint32(12, vbytes.length, true);
  out.set(vbytes, 16);
  dv.setUint16(afterVersion, 0, true); // flags
  dv.setUint16(afterVersion + 2, streams.length, true);
  let ho = streamHdrStart;
  streams.forEach((s, i) => {
    dv.setUint32(ho, offsets[i], true); // offset, relative to the metadata root
    dv.setUint32(ho + 4, s.data.length, true);
    ho += 8;
    for (let j = 0; j < s.name.length; j++) out[ho + j] = s.name.charCodeAt(j);
    ho += namePad[i];
    out.set(s.data, offsets[i]);
  });
  return out;
}

/* ------------------------------------------------------------------ */
/* mapped PE image                                                     */
/* ------------------------------------------------------------------ */

export const kImageSize = 0x4000;
export const kCliRva = 0x2000;
export const kMetaRva = 0x3000; // clear of the method bodies at 0x2250 and 0x2300

function buildPe(meta: Uint8Array, opts: { numDirs?: number; clrRva?: number } = {}): Uint8Array {
  const img = new Uint8Array(kImageSize);
  const dv = new DataView(img.buffer);
  const str = (o: number, s: string) => {
    for (let i = 0; i < s.length; i++) img[o + i] = s.charCodeAt(i);
  };
  dv.setUint16(0, 0x5a4d, true);
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x4550, true);
  const fh = 0x84;
  dv.setUint16(fh, 0x8664, true); // machine
  dv.setUint16(fh + 2, 1, true); // sections
  dv.setUint16(fh + 16, 240, true); // optional header size
  const oh = fh + 20;
  dv.setUint16(oh, 0x20b, true); // PE32+
  dv.setUint32(oh + 16, 0x1000, true); // entry point rva
  dv.setBigUint64(oh + 24, 0x140000000n, true); // image base
  dv.setUint32(oh + 56, kImageSize, true); // size of image
  dv.setUint16(oh + 68, 3, true); // subsystem
  dv.setUint32(oh + 108, opts.numDirs ?? 16, true); // number of data directories
  const dd = oh + 112;
  dv.setUint32(dd + 14 * 8, opts.clrRva ?? kCliRva, true);
  dv.setUint32(dd + 14 * 8 + 4, 0x48, true);
  const st = oh + 240;
  str(st, ".text");
  dv.setUint32(st + 8, kImageSize - 0x1000, true); // virtual size
  dv.setUint32(st + 12, 0x1000, true); // rva
  dv.setUint32(st + 16, kImageSize - 0x1000, true); // raw size
  dv.setUint32(st + 36, 0x60000020, true); // characteristics
  // IMAGE_COR20_HEADER
  dv.setUint32(kCliRva, 0x48, true); // cb
  dv.setUint16(kCliRva + 4, 2, true); // major runtime version
  dv.setUint16(kCliRva + 6, 5, true); // minor runtime version
  dv.setUint32(kCliRva + 8, kMetaRva, true); // metadata rva
  dv.setUint32(kCliRva + 12, meta.length, true); // metadata size
  dv.setUint32(kCliRva + 16, 1, true); // flags (ILONLY)
  dv.setUint32(kCliRva + 20, 0x06000001, true); // entry point token
  img.set(meta, kMetaRva);
  return img;
}

/* ------------------------------------------------------------------ */
/* the fixture: a real metadata blob with Module/TypeRef/TypeDef/      */
/* Field/MethodDef/MemberRef/CustomAttribute/NestedClass rows         */
/* ------------------------------------------------------------------ */

// `wide` selects 4 byte heap indexes (heapSizes 0x05) instead of the 2 byte
// default, the way real assemblies with big heaps encode their rows.
export function buildManagedImage(wide = false, extra: { us?: number[]; bodies?: { rva: number; bytes: number[] }[] } = {}): Uint8Array {
  const strs = buildStrings([
    ".ctor", "Compute", "Helper", "m_count", "m_value", "Nested", "ObsoleteAttribute",
    "Object", "Sample", "System", "Test.dll", "ToString", "Widget",
  ]);
  const blobs = buildBlobs([
    [0x20, 0x00, 0x01, 0x01, 0x08, 0x00], // 0: instance void .ctor(int32)
    [0x20, 0x00, 0x01, 0x08, 0x08, 0x00], // 1: instance int32 Compute(int32)
    [0x06, 0x08, 0x00], // 2: field int32
    [0x00, 0x01, 0x01, 0x08, 0x00], // 3: memberref signature
    [0x01, 0x00, 0x00, 0x00], // 4: custom attribute blob
  ]);
  const s = (n: string): number => {
    const idx = strs.at[n];
    if (idx === undefined) throw new Error(`unknown string ${n}`);
    return idx;
  };
  const strW = wide ? 4 : 2;
  const blobW = wide ? 4 : 2;
  const guidW = 2;

  // Module: Generation, Name, Mvid, EncId, EncBaseId
  const moduleRow = [0, s("Test.dll"), 1, 0, 0];
  // TypeRef: ResolutionScope, TypeName, TypeNamespace
  const typeRefRows = [
    [ci(1, 0, 2), s("Object"), s("System")], // scope = Module #1
    [ci(1, 3, 2), s("ObsoleteAttribute"), s("System")], // scope = TypeRef #1
  ];
  // TypeDef: Flags, TypeName, TypeNamespace, Extends, FieldList, MethodList
  const typeDefRows = [
    [0x00000001, s("Widget"), s("Sample"), ci(1, 1, 2), 1, 1], // extends System.Object
    [0x00000002, s("Nested"), s(""), ci(1, 0, 2), 3, 3], // nested, extends Widget
  ];
  // Field: Flags, Name, Signature
  const fieldRows = [
    [0x0011, s("m_value"), blobs.at[2]],
    [0x0002, s("m_count"), blobs.at[2]],
  ];
  // MethodDef: RVA, ImplFlags, Flags, Name, Signature, ParamList
  const methodDefRows = [
    [0x2200, 0x0003, 0x1886, s(".ctor"), blobs.at[0], 0],
    [0x2250, 0x0003, 0x0006, s("Compute"), blobs.at[1], 0],
    [0x2300, 0x0003, 0x0006, s("Helper"), blobs.at[1], 0],
  ];
  // MemberRef: Class, Name, Signature
  const memberRefRows = [
    [ci(1, 1, 3), s("ToString"), blobs.at[3]], // class = TypeRef #1
    [ci(2, 1, 3), s(".ctor"), blobs.at[0]], // class = TypeRef #2 (attribute ctor)
  ];
  // CustomAttribute: Parent, Type, Value
  const customAttributeRows = [
    [ci(2, 0, 5), ci(2, 3, 3), blobs.at[4]], // on MethodDef #2
    [ci(1, 3, 5), ci(2, 3, 3), blobs.at[4]], // on TypeDef #1
    [ci(1, 1, 5), ci(2, 3, 3), blobs.at[4]], // on Field #1
  ];
  // NestedClass: NestedClass, EnclosingClass
  const nestedClassRows = [[2, 1]];

  const tables: TableDef[] = [
    { id: 0, widths: [2, strW, guidW, guidW, guidW], rows: [moduleRow] },
    { id: 1, widths: [2, strW, strW], rows: typeRefRows },
    { id: 2, widths: [4, strW, strW, 2, 2, 2], rows: typeDefRows },
    { id: 4, widths: [2, strW, blobW], rows: fieldRows },
    { id: 6, widths: [4, 2, 2, strW, blobW, 2], rows: methodDefRows },
    { id: 10, widths: [2, strW, blobW], rows: memberRefRows },
    { id: 12, widths: [2, 2, blobW], rows: customAttributeRows },
    { id: 41, widths: [2, 2], rows: nestedClassRows },
  ];

  const meta = buildMetadata([
    { name: "#~", data: buildTables(tables, wide ? 0x05 : 0x00) },
    { name: "#Strings", data: strs.data },
    { name: "#Blob", data: blobs.data },
    ...(extra.us ? [{ name: "#US", data: extra.us }] : []),
  ]);
  const img = buildPe(meta);
  for (const body of extra.bodies ?? []) img.set(body.bytes, body.rva);
  return img;
}
