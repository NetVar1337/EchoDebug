import { describe, expect, it } from "vitest";
import { openMetadata, parseDotnet } from "./dotnet";
import { disassembleIl, formatIl, userStringRefs } from "./cil";

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

function buildStrings(names: string[]): { data: number[]; at: Record<string, number | undefined> } {
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

type TableDef = { id: number; widths: number[]; rows: number[][] };

function buildTables(tables: TableDef[], heapSizes: number): number[] {
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

function buildMetadata(streams: { name: string; data: number[] }[]): Uint8Array {
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

const kImageSize = 0x4000;
const kCliRva = 0x2000;
const kMetaRva = 0x3000; // clear of the method bodies at 0x2250 and 0x2300

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
function buildManagedImage(wide = false, extra: { us?: number[]; bodies?: { rva: number; bytes: number[] }[] } = {}): Uint8Array {
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

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

describe("dotnet", () => {
  it("parses types, methods, fields and attributes", () => {
    const info = parseDotnet(buildManagedImage());
    expect(info).not.toBeNull();
    if (!info) return;

    expect(info.runtimeVersion).toBe("v4.0.30319");
    expect(info.metadataVersion).toBe("v4.0.30319");
    expect(info.entryPointToken).toBe(0x06000001);

    expect(info.types.map((t) => t.fullName)).toEqual(["Sample.Widget", "Sample.Widget+Nested"]);

    const widget = info.types[0];
    expect(widget.namespace).toBe("Sample");
    expect(widget.name).toBe("Widget");
    expect(widget.flags).toBe(1);
    expect(widget.baseType).toBe("System.Object");

    expect(widget.methods.map((m) => m.name)).toEqual([".ctor", "Compute"]);
    expect(widget.methods[0]).toMatchObject({ name: ".ctor", rva: 0x2200, flags: 0x1886 });
    expect(widget.methods[1]).toMatchObject({ name: "Compute", rva: 0x2250, flags: 0x0006 });
    expect(widget.methods[1].attributes).toEqual(["ObsoleteAttribute"]);
    expect(widget.methods[0].attributes).toEqual([]);

    expect(widget.fields.map((f) => f.name)).toEqual(["m_value", "m_count"]);
    expect(widget.fields[0]).toMatchObject({ name: "m_value", flags: 0x0011 });
    expect(widget.fields[0].attributes).toEqual(["ObsoleteAttribute"]);
    expect(widget.fields[1]).toMatchObject({ name: "m_count", flags: 0x0002 });
    expect(widget.fields[1].attributes).toEqual([]);

    const nested = info.types[1];
    expect(nested.namespace).toBe("Sample");
    expect(nested.name).toBe("Widget+Nested");
    expect(nested.flags).toBe(2);
    expect(nested.baseType).toBe("Sample.Widget");
    expect(nested.methods.map((m) => m.name)).toEqual(["Helper"]);
    expect(nested.methods[0]).toMatchObject({ rva: 0x2300, flags: 0x0006 });
    expect(nested.fields).toEqual([]);
  });

  it("decodes the same metadata with 4 byte heap indexes", () => {
    const narrow = parseDotnet(buildManagedImage(false));
    const wide = parseDotnet(buildManagedImage(true));
    expect(wide).toEqual(narrow);
    expect(wide?.types.map((t) => t.fullName)).toEqual(["Sample.Widget", "Sample.Widget+Nested"]);
  });

  it("returns null without a CLR data directory", () => {
    const img = buildManagedImage();
    const dv = new DataView(img.buffer);
    const oh = 0x84 + 20;
    dv.setUint32(oh + 108, 14, true); // only 14 directories -> no "CLR" entry
    expect(parseDotnet(img)).toBeNull();

    const img2 = buildManagedImage();
    const dv2 = new DataView(img2.buffer);
    dv2.setUint32(oh + 112 + 14 * 8, 0, true); // directory present but empty
    expect(parseDotnet(img2)).toBeNull();
  });

  it("returns null for garbage and for a broken metadata root", () => {
    expect(parseDotnet(new Uint8Array(0x100))).toBeNull();
    expect(parseDotnet(new Uint8Array(0))).toBeNull();

    const rnd = new Uint8Array(0x400);
    for (let i = 0; i < rnd.length; i++) rnd[i] = (i * 37 + 11) & 0xff;
    expect(parseDotnet(rnd)).toBeNull();

    const broken = buildManagedImage();
    new DataView(broken.buffer).setUint32(kMetaRva, 0x12345678, true); // not "BSJB"
    expect(parseDotnet(broken)).toBeNull();

    const broken2 = buildManagedImage();
    new DataView(broken2.buffer).setUint32(kMetaRva + 12, 0xfffffff0, true); // bogus version length
    expect(parseDotnet(broken2)).toBeNull();

    const broken3 = buildManagedImage();
    new DataView(broken3.buffer).setUint32(kCliRva + 8, 0xffffff00, true); // metadata rva out of range
    expect(parseDotnet(broken3)).toBeNull();
  });
});

describe("IL and user strings", () => {
  // #US heap: index 1 = "hello" (len 11 = 5 chars * 2 + flag byte), index 13 = "x"
  const us = [0, 11, ...Array.from("hello").flatMap((c) => [c.charCodeAt(0), 0]), 0, 3, 0x78, 0, 0];
  // Compute (MethodDef #2, rva 0x2250), tiny header: ldstr "hello"; callvirt ToString; pop;
  // ldarg.1; ldc.i4.s 5; add; brtrue.s +1; nop; ret
  const tinyCode = [0x72, 0x01, 0, 0, 0x70, 0x6f, 0x01, 0, 0, 0x0a, 0x26, 0x03, 0x1f, 0x05, 0x58, 0x2d, 0x01, 0x00, 0x2a];
  const tiny = [(tinyCode.length << 2) | 2, ...tinyCode];
  // Helper (#3, rva 0x2300), fat header with a try/finally: switch(2 targets); leave.s; endfinally; ret
  const fatCode = [0x45, 0x02, 0, 0, 0, 0x00, 0, 0, 0, 0x01, 0, 0, 0, 0xde, 0x00, 0xdc, 0x2a];
  const fatHeader = [0x1b, 0x30, 0x02, 0x00, ...[fatCode.length, 0, 0, 0], 0, 0, 0, 0];
  const pad = Array((4 - ((12 + fatCode.length) % 4)) % 4).fill(0);
  // small EH section: kind=1 (EHTable), size 16, one clause: finally, try 0..15, handler 15..16
  const eh = [0x01, 16, 0, 0, 0x02, 0x00, 0x00, 0x00, 15, 0x0f, 0x00, 1, 0, 0, 0, 0];
  const img = buildManagedImage(false, { us, bodies: [{ rva: 0x2250, bytes: tiny }, { rva: 0x2300, bytes: [...fatHeader, ...fatCode, ...pad, ...eh] }] });

  it("resolves tokens and reads the #US heap", () => {
    const md = openMetadata(img)!;
    expect(md).not.toBeNull();
    expect(md.userStrings.map((u) => u.text)).toEqual(["hello", "x"]);
    expect(md.userString(0x70000001)).toBe("hello");
    expect(md.tokenName(0x06000002)).toBe("Sample.Widget::Compute");
    expect(md.tokenName(0x06000003)).toBe("Sample.Widget/Nested::Helper");
    expect(md.tokenName(0x0a000001)).toBe("System.Object::ToString");
    expect(md.tokenName(0x01000002)).toBe("System.ObsoleteAttribute");
    expect(md.tokenName(0x04000002)).toBe("Sample.Widget::m_count");
    expect(md.methods.map((m) => m.name)).toEqual([".ctor", "Compute", "Helper"]);
  });

  it("disassembles tiny and fat bodies", () => {
    const md = openMetadata(img)!;
    const t = disassembleIl(img, 0x2250, md.tokenName);
    expect(t.headerSize).toBe(1);
    expect(formatIl(t)).toEqual([
      'IL_0000: ldstr "hello"',
      "IL_0005: callvirt System.Object::ToString",
      "IL_000a: pop",
      "IL_000b: ldarg.1",
      "IL_000c: ldc.i4.s 5",
      "IL_000e: add",
      "IL_000f: brtrue.s IL_0012",
      "IL_0011: nop",
      "IL_0012: ret",
    ]);
    const f = disassembleIl(img, 0x2300, md.tokenName);
    expect(f.headerSize).toBe(12);
    expect(f.maxStack).toBe(2);
    expect(f.code[0].opcode).toBe("switch");
    expect(f.code[0].targets).toEqual([13, 14]);
    expect(f.clauses).toEqual([{ kind: "finally", tryStart: 0, tryEnd: 15, handlerStart: 15, handlerEnd: 16 }]);
    expect(() => disassembleIl(img, 0, md.tokenName)).toThrow(/no body/);
  });

  it("finds where each user string is loaded", () => {
    const md = openMetadata(img)!;
    const refs = userStringRefs(img, md.methods);
    expect(refs.get(0x70000001)).toEqual([{ token: 0x70000001, method: "Sample.Widget::Compute", methodToken: 0x06000002, offset: 0 }]);
    expect(refs.has(0x7000000d)).toBe(false);
  });
});
