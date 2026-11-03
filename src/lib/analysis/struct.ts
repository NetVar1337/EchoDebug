// ReClass-style field layout: offsets are cumulative, so retyping shifts what follows
import { decode, type ValueType } from "./values";

export type FieldType = "hex64" | "hex32" | "hex16" | "hex8" | Exclude<ValueType, "ascii" | "utf16"> | "vec2" | "vec3" | "vec4" | "ascii" | "utf16";
export type Field = { type: FieldType; name: string };

export const kFieldSizes: Record<FieldType, number> = {
  hex64: 8, hex32: 4, hex16: 2, hex8: 1, u8: 1, u16: 2, u32: 4, u64: 8, i8: 1, i16: 2, i32: 4, i64: 8,
  f32: 4, f64: 8, ptr: 8, vec2: 8, vec3: 12, vec4: 16, ascii: 32, utf16: 64,
};

export function layout(fields: readonly Field[]): { offset: number; size: number }[] {
  let off = 0;
  return fields.map((f) => {
    const r = { offset: off, size: kFieldSizes[f.type] };
    off += r.size;
    return r;
  });
}

export function fieldValue(buf: Uint8Array, off: number, t: FieldType): string {
  if (t.startsWith("hex")) {
    const n = kFieldSizes[t];
    if (off < 0 || off + n > buf.length) return "??";
    let s = "";
    for (let i = n - 1; i >= 0; i--) s += buf[off + i].toString(16).padStart(2, "0").toUpperCase();
    return s;
  }
  if (t === "vec2" || t === "vec3" || t === "vec4") {
    const n = Number(t[3]);
    return Array.from({ length: n }, (_, i) => decode(buf, off + i * 4, "f32")).join(", ");
  }
  return decode(buf, off, t as ValueType);
}

const kCpp: Record<FieldType, string> = {
  hex64: "uint64_t", hex32: "uint32_t", hex16: "uint16_t", hex8: "uint8_t", u8: "uint8_t", u16: "uint16_t", u32: "uint32_t", u64: "uint64_t",
  i8: "int8_t", i16: "int16_t", i32: "int32_t", i64: "int64_t", f32: "float", f64: "double", ptr: "void*", vec2: "float", vec3: "float", vec4: "float",
  ascii: "char", utf16: "wchar_t",
};

/** C++ struct; unnamed hex fields collapse into padding arrays. */
export function toCpp(name: string, fields: readonly Field[]): string {
  const lay = layout(fields);
  const total = lay.length ? lay[lay.length - 1].offset + lay[lay.length - 1].size : 0;
  const lines: string[] = [`struct ${name || "Class"} {`];
  let padStart = -1;
  const flush = (end: number) => {
    if (padStart >= 0) lines.push(`    uint8_t pad_0x${padStart.toString(16)}[0x${(end - padStart).toString(16)}];`);
    padStart = -1;
  };
  fields.forEach((f, i) => {
    const { offset } = lay[i];
    if (f.type.startsWith("hex") && !f.name) {
      if (padStart < 0) padStart = offset;
      return;
    }
    flush(offset);
    const nm = f.name || `field_0x${offset.toString(16)}`;
    const arr = f.type === "vec2" ? "[2]" : f.type === "vec3" ? "[3]" : f.type === "vec4" ? "[4]" : f.type === "ascii" ? "[32]" : f.type === "utf16" ? "[32]" : "";
    lines.push(`    ${kCpp[f.type]} ${nm}${arr}; // 0x${offset.toString(16)}`);
  });
  flush(total);
  lines.push("};", `static_assert(sizeof(${name || "Class"}) == 0x${total.toString(16)});`);
  return lines.join("\n");
}
