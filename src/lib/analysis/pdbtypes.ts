// PDB type layouts (the relay's `pdb_type` reply) → the Structs view's ReClass-style field list.
// The field model is flat and cumulative, so embedded structs are flattened with dotted names
// (`pos.x`), three/four float structs become vec3/vec4, bitfields share one storage field, unions
// keep their largest member, and gaps become unnamed hex padding so every offset stays exact.
import { kFieldSizes, type Field, type FieldType } from "./struct";

/** One field description as the relay sends it (`TypeDb::desc` + name/offset). */
export type PdbDesc = {
  type: string;
  type_index?: number;
  size: number;
  category: "primitive" | "pointer" | "array" | "udt" | "enum" | "bitfield" | "function" | "other";
  scalar?: string;
  udt?: number;
  points_to?: number;
  count?: number;
  elem?: PdbDesc;
  function?: boolean;
};
export type PdbField = PdbDesc & { name: string; offset: number; kind: "member" | "base" | "vtable"; bit_pos?: number; bit_len?: number };
export type PdbLayout = {
  index: number;
  name: string;
  kind: "struct" | "class" | "union" | "interface" | "enum";
  size: number;
  forward?: boolean;
  fields?: PdbField[];
  values?: { name: string; value: number }[];
  underlying?: string;
  nested?: PdbLayout[];
};

const kScalar: Record<string, FieldType> = { i8: "i8", u8: "u8", i16: "i16", u16: "u16", i32: "i32", u32: "u32", i64: "i64", u64: "u64", f32: "f32", f64: "f64", ptr: "ptr", wchar: "u16" };
const kHex: Record<number, FieldType> = { 8: "hex64", 4: "hex32", 2: "hex16", 1: "hex8" };
const kUnsigned: Record<number, FieldType> = { 8: "u64", 4: "u32", 2: "u16", 1: "u8" };

function scalarField(d: PdbDesc): FieldType | null {
  if (d.scalar === "bool") return kUnsigned[d.size] ?? null;
  const t = d.scalar ? kScalar[d.scalar] : undefined;
  if (!t) return null;
  // a size the PDB disagrees on stays raw bytes
  return kFieldSizes[t] === d.size ? t : kHex[d.size] ?? null;
}

const isCharType = (t: string) => /^(const |volatile )*(signed |unsigned )?char$/.test(t);
const isWideType = (t: string) => /^(const |volatile )*(wchar_t|char16_t)$/.test(t);

type Ctx = { nested: Map<number, PdbLayout>; out: Field[]; depth: number };

/** Unnamed (or, for the first chunk, named) hex rows covering `n` bytes from absolute offset `at`. */
function pad(ctx: Ctx, at: number, n: number, name = "") {
  let first = true;
  while (n > 0) {
    let k = 8;
    while (k > 1 && (k > n || at % k !== 0)) k >>= 1;
    ctx.out.push({ type: kHex[k], name: first ? name : "" });
    first = false;
    at += k;
    n -= k;
  }
}

/** A float-only struct of 2..4 members becomes one vecN field. */
function vecOf(l: PdbLayout): FieldType | null {
  const f = l.fields ?? [];
  if (l.kind === "union" || f.length < 2 || f.length > 4 || l.size !== f.length * 4) return null;
  if (!f.every((x, i) => x.scalar === "f32" && x.offset === i * 4 && x.category === "primitive")) return null;
  return (`vec${f.length}` as FieldType);
}

/** Emits one value of description `d` at absolute offset `at`; returns the bytes covered. */
function place(ctx: Ctx, d: PdbDesc, name: string, at: number): number {
  const size = d.size;
  switch (d.category) {
    case "primitive":
    case "pointer":
    case "enum": {
      const t = scalarField(d.category === "enum" ? { ...d, scalar: d.scalar ?? "i32" } : d);
      if (t) ctx.out.push({ type: t, name });
      else pad(ctx, at, size, name);
      return size;
    }
    case "udt": {
      const l = d.udt !== undefined ? ctx.nested.get(d.udt) : undefined;
      if (!l || ctx.depth > 8) {
        pad(ctx, at, size, name);
        return size;
      }
      const v = vecOf(l);
      if (v) {
        ctx.out.push({ type: v, name });
        return size;
      }
      ctx.depth++;
      emit(ctx, l, `${name}.`, at);
      ctx.depth--;
      return l.size;
    }
    case "array": {
      const n = d.count ?? 0;
      const e = d.elem;
      if (!e || !n || !e.size) {
        pad(ctx, at, size, name);
        return size;
      }
      if (isCharType(e.type) && n >= 32) {
        ctx.out.push({ type: "ascii", name });
        pad(ctx, at + 32, size - 32);
        return size;
      }
      if (isWideType(e.type) && n >= 32) {
        ctx.out.push({ type: "utf16", name });
        pad(ctx, at + 64, size - 64);
        return size;
      }
      // short arrays of numbers, pointers and structs are spelled out; text and long arrays stay bytes
      if (isCharType(e.type) || n > 64 || size > 0x400) {
        pad(ctx, at, size, name);
        return size;
      }
      for (let i = 0; i < n; i++) place(ctx, e, `${name}[${i}]`, at + i * e.size);
      return size;
    }
    default:
      pad(ctx, at, size, name);
      return size;
  }
}

/** Lays out `l` (fields relative to `base`) into ctx.out, names prefixed. */
function emit(ctx: Ctx, l: PdbLayout, prefix: string, base: number) {
  const fields = [...(l.fields ?? [])].sort((a, b) => a.offset - b.offset);
  let cur = 0;
  for (let i = 0; i < fields.length; ) {
    // everything at one offset: a union's members, or the bitfields sharing a storage unit
    const off = fields[i].offset;
    let j = i;
    while (j < fields.length && fields[j].offset === off) j++;
    const group = fields.slice(i, j);
    i = j;
    if (off < cur) continue; // overlaps what is already laid out
    if (off > cur) pad(ctx, base + cur, off - cur);
    const bits = group.filter((f) => f.bit_len !== undefined);
    let covered: number;
    if (bits.length && bits.length === group.length) {
      const unit = Math.max(...bits.map((b) => b.size));
      const t = kUnsigned[unit];
      const name = prefix + bits.map((b) => `${b.name}:${b.bit_len}`).join(",");
      if (t) ctx.out.push({ type: t, name });
      else pad(ctx, base + off, unit, name);
      covered = unit;
    } else {
      const pick = group.reduce((a, b) => (b.size > a.size ? b : a));
      const others = group.filter((g) => g !== pick && g.bit_len === undefined).map((g) => g.name);
      const name = prefix + (pick.kind === "vtable" ? "vftable" : pick.name) + (others.length && pick.category !== "udt" ? `|${others.join("|")}` : "");
      covered = place(ctx, pick, name, base + off);
    }
    cur = off + covered;
  }
  if (l.size > cur) pad(ctx, base + cur, l.size - cur);
}

/** Field list for a struct/class/union layout (nested types come from `layout.nested`). */
export function pdbFields(layout: PdbLayout, extra: readonly PdbLayout[] = []): Field[] {
  const nested = new Map<number, PdbLayout>();
  for (const n of [...(layout.nested ?? []), ...extra]) nested.set(n.index, n);
  const ctx: Ctx = { nested, out: [], depth: 0 };
  if (layout.kind === "enum") {
    pad(ctx, 0, layout.size);
    return ctx.out;
  }
  emit(ctx, layout, "", 0);
  return ctx.out;
}

/** The type and every struct/union it embeds, each as its own catalog entry (enums are skipped). */
export function pdbCatalog(layout: PdbLayout): { name: string; fields: Field[] }[] {
  const all = [layout, ...(layout.nested ?? [])].filter((l) => l.kind !== "enum");
  return all.map((l) => ({ name: l.name, fields: pdbFields(l, layout.nested ?? []) }));
}

/** C declaration of a layout (for the type browser preview). */
export function pdbDecl(l: PdbLayout): string {
  if (l.kind === "enum") {
    return [`enum ${l.name} : ${l.underlying ?? "int"} {`, ...(l.values ?? []).map((v) => `    ${v.name} = ${v.value},`), "};"].join("\n");
  }
  const lines = [`${l.kind === "union" ? "union" : l.kind === "class" ? "class" : "struct"} ${l.name} { // 0x${l.size.toString(16)} bytes`];
  for (const f of l.fields ?? []) {
    const bits = f.bit_len !== undefined ? ` : ${f.bit_len}` : "";
    const ty = f.bit_len !== undefined ? f.type.replace(/\s*:\s*\d+$/, "") : f.type;
    const decl = /\(\*\)/.test(ty) ? ty.replace("(*)", `(*${f.name})`) : /\[\d+\]$/.test(ty) ? ty.replace(/(\[\d+\])+$/, (m) => ` ${f.name}${m}`) : `${ty} ${f.name}`;
    lines.push(`    /* 0x${f.offset.toString(16).padStart(3, "0")} */ ${f.kind === "base" ? `// base ${ty}` : f.kind === "vtable" ? "void** vftable" : decl}${bits};`);
  }
  lines.push("};");
  return lines.join("\n");
}
