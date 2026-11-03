// Struct exports for other tools: plain C (IDA, Ghidra and Binary Ninja all parse it), an
// IDAPython script, a Ghidra (Jython) script, a Binary Ninja script, and a ReClass.NET project.
import { kFieldSizes, layout, type Field, type FieldType } from "./struct";

const kC: Record<FieldType, [string, number]> = {
  hex64: ["unsigned long long", 1], hex32: ["unsigned int", 1], hex16: ["unsigned short", 1], hex8: ["unsigned char", 1],
  u8: ["unsigned char", 1], u16: ["unsigned short", 1], u32: ["unsigned int", 1], u64: ["unsigned long long", 1],
  i8: ["signed char", 1], i16: ["short", 1], i32: ["int", 1], i64: ["long long", 1], f32: ["float", 1], f64: ["double", 1],
  ptr: ["void *", 1], vec2: ["float", 2], vec3: ["float", 3], vec4: ["float", 4], ascii: ["char", 32], utf16: ["wchar_t", 32],
};

const ident = (s: string, fallback: string) => (s.replace(/[^A-Za-z0-9_]/g, "_").replace(/^(\d)/, "_$1") || fallback);

/** A plain C declaration (no stdint, no static_assert) every importer accepts. */
export function toC(name: string, fields: readonly Field[]): string {
  const lay = layout(fields);
  const lines = [`struct ${ident(name, "Class")} {`];
  fields.forEach((f, i) => {
    const [t, n] = kC[f.type];
    const nm = ident(f.name, `field_${lay[i].offset.toString(16)}`);
    lines.push(`    ${t} ${nm}${n > 1 ? `[${n}]` : ""}; /* 0x${lay[i].offset.toString(16)} */`);
  });
  lines.push("};");
  return lines.join("\n");
}

const py = (s: string) => s.replace(/\\/g, "\\\\").replace(/"""/g, '\\"\\"\\"');

export function toIdaPython(name: string, fields: readonly Field[]): string {
  return `# EchoDebug: import the struct into the IDB (IDA 7.x - 9.x)\nimport idc\ndecl = """${py(toC(name, fields))}"""\nerrors = idc.parse_decls(decl, 0)\nprint("EchoDebug: ${ident(name, "Class")} imported" if errors == 0 else "EchoDebug: %d parse errors" % errors)\n`;
}

const kGhidra: Record<FieldType, string> = {
  hex64: "QWordDataType.dataType", hex32: "DWordDataType.dataType", hex16: "WordDataType.dataType", hex8: "ByteDataType.dataType",
  u8: "ByteDataType.dataType", u16: "WordDataType.dataType", u32: "UnsignedIntegerDataType.dataType", u64: "UnsignedLongLongDataType.dataType",
  i8: "SignedByteDataType.dataType", i16: "ShortDataType.dataType", i32: "IntegerDataType.dataType", i64: "LongLongDataType.dataType",
  f32: "FloatDataType.dataType", f64: "DoubleDataType.dataType", ptr: "PointerDataType.dataType",
  vec2: "ArrayDataType(FloatDataType.dataType, 2, 4)", vec3: "ArrayDataType(FloatDataType.dataType, 3, 4)", vec4: "ArrayDataType(FloatDataType.dataType, 4, 4)",
  ascii: "ArrayDataType(CharDataType.dataType, 32, 1)", utf16: "ArrayDataType(WideCharDataType.dataType, 32, 2)",
};

export function toGhidra(name: string, fields: readonly Field[]): string {
  const lay = layout(fields);
  const n = ident(name, "Class");
  const body = fields.map((f, i) => `s.add(${kGhidra[f.type]}, ${kFieldSizes[f.type]}, "${ident(f.name, `field_${lay[i].offset.toString(16)}`)}", None)`).join("\n");
  return `# EchoDebug: run from Ghidra's Script Manager (Python)\n# @category EchoDebug\nfrom ghidra.program.model.data import *\ns = StructureDataType(CategoryPath("/EchoDebug"), "${n}", 0)\n${body}\ncurrentProgram.getDataTypeManager().addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)\nprint("EchoDebug: ${n} added")\n`;
}

export function toBinja(name: string, fields: readonly Field[]): string {
  return `# EchoDebug: run in Binary Ninja's Python console\ndecl = """${py(toC(name, fields))}"""\nt, n = bv.parse_type_string(decl)\nbv.define_user_type(n, t)\nprint("EchoDebug: %s defined" % n)\n`;
}

// ---- ReClass.NET project (.rcnet = zip with Data.xml) -----------------------------------------

const kRcNode: Record<FieldType, string> = {
  hex64: "Hex64Node", hex32: "Hex32Node", hex16: "Hex16Node", hex8: "Hex8Node", u8: "UInt8Node", u16: "UInt16Node", u32: "UInt32Node", u64: "UInt64Node",
  i8: "Int8Node", i16: "Int16Node", i32: "Int32Node", i64: "Int64Node", f32: "FloatNode", f64: "DoubleNode", ptr: "Hex64Node",
  vec2: "Vector2Node", vec3: "Vector3Node", vec4: "Vector4Node", ascii: "Utf8TextNode", utf16: "Utf16TextNode",
};

const xml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function toReclassXml(classes: readonly { name: string; fields: readonly Field[]; address?: string }[]): string {
  const uuid = (i: number) => `${(0x1000 + i).toString(16).padStart(8, "0")}-ec0d-4ebc-8d00-${(i + 1).toString(16).padStart(12, "0")}`;
  const cls = classes.map((c, i) => {
    const nodes = c.fields.map((f) => {
      const len = f.type === "ascii" || f.type === "utf16" ? ' length="32"' : "";
      const comment = f.type === "ptr" ? "pointer" : "";
      return `      <node type="${kRcNode[f.type]}" name="${xml(f.name)}" comment="${comment}" hidden="false"${len} />`;
    }).join("\n");
    return `    <class uuid="${uuid(i)}" name="${xml(c.name)}" comment="EchoDebug" address="${xml(c.address ?? "0")}">\n${nodes}\n    </class>`;
  }).join("\n");
  return `<?xml version="1.0" encoding="utf-8"?>\n<reclass version="65537" type="ReClass.NET">\n  <custom_data />\n  <type_mapping />\n  <enums />\n  <classes>\n${cls}\n  </classes>\n</reclass>\n`;
}

const kCrc = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

export function crc32(b: Uint8Array): number {
  let c = 0xffffffff;
  for (const x of b) c = kCrc[(c ^ x) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** A zip archive with stored (uncompressed) entries. */
export function zipStore(files: readonly { name: string; data: Uint8Array }[]): Uint8Array {
  const parts: number[] = [];
  const central: number[] = [];
  const u16 = (a: number[], v: number) => a.push(v & 0xff, (v >> 8) & 0xff);
  const u32 = (a: number[], v: number) => a.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff);
  for (const f of files) {
    const name = new TextEncoder().encode(f.name);
    const crc = crc32(f.data);
    const off = parts.length;
    u32(parts, 0x04034b50); u16(parts, 20); u16(parts, 0); u16(parts, 0); u16(parts, 0); u16(parts, 0x21);
    u32(parts, crc); u32(parts, f.data.length); u32(parts, f.data.length); u16(parts, name.length); u16(parts, 0);
    parts.push(...name, ...f.data);
    u32(central, 0x02014b50); u16(central, 20); u16(central, 20); u16(central, 0); u16(central, 0); u16(central, 0); u16(central, 0x21);
    u32(central, crc); u32(central, f.data.length); u32(central, f.data.length); u16(central, name.length);
    u16(central, 0); u16(central, 0); u16(central, 0); u16(central, 0); u32(central, 0); u32(central, off);
    central.push(...name);
  }
  const cdOff = parts.length;
  const out = [...parts, ...central];
  u32(out, 0x06054b50); u16(out, 0); u16(out, 0); u16(out, files.length); u16(out, files.length);
  u32(out, central.length); u32(out, cdOff); u16(out, 0);
  return new Uint8Array(out);
}

export function toReclassProject(classes: readonly { name: string; fields: readonly Field[]; address?: string }[]): Uint8Array {
  return zipStore([{ name: "Data.xml", data: new TextEncoder().encode(toReclassXml(classes)) }]);
}
