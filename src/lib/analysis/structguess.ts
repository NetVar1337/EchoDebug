// Guesses a struct layout from the live bytes of an object, the way you would by eye in ReClass:
// pointers into code are function pointers (a vtable when at offset 0 and into read-only data),
// pointers into data/heap are pointers, printable runs are strings, runs of sane floats are
// vectors or floats, small integers are ints, zeros stay padding.
import { labelAddr, type Module } from "../hex";
import { kFieldSizes, layout, type Field, type FieldType } from "./struct";

export type PtrKind = "code" | "rdata" | "data" | "heap";
export type GuessContext = { kindOf: (v: bigint) => PtrKind | null };

export function plausibleFloat(f: number): boolean {
  const a = Math.abs(f);
  return Number.isFinite(f) && f !== 0 && a >= 1e-4 && a <= 1e7;
}

function asciiRun(b: Uint8Array, o: number): number {
  let n = 0;
  while (o + n < b.length && b[o + n] >= 0x20 && b[o + n] < 0x7f) n++;
  return o + n < b.length && b[o + n] === 0 ? n : 0;
}

export function guessFields(b: Uint8Array, ctx: GuessContext): Field[] {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out: Field[] = [];
  let o = 0;
  while (o < b.length) {
    if (o % 8 === 0 && o + 8 <= b.length) {
      const v = dv.getBigUint64(o, true);
      const k = v ? ctx.kindOf(v) : null;
      if (k) {
        const name = o === 0 && k === "rdata" ? "vftable" : k === "code" ? `fn_${o.toString(16)}` : `p_${o.toString(16)}`;
        out.push({ type: "ptr", name });
        o += 8;
        continue;
      }
      const s = asciiRun(b, o);
      if (s >= 6 && o + 32 <= b.length) {
        out.push({ type: "ascii", name: `str_${o.toString(16)}` });
        o += 32;
        continue;
      }
      if (v === 0n) {
        out.push({ type: "hex64", name: "" });
        o += 8;
        continue;
      }
    }
    if (o + 4 <= b.length) {
      let run = 0;
      while (run < 4 && o + (run + 1) * 4 <= b.length && plausibleFloat(dv.getFloat32(o + run * 4, true))) run++;
      if (run >= 2) {
        const n = run === 4 ? 4 : run === 3 ? 3 : 2;
        out.push({ type: n === 4 ? "vec4" : n === 3 ? "vec3" : "vec2", name: `v_${o.toString(16)}` });
        o += n * 4;
        continue;
      }
      const f = dv.getFloat32(o, true);
      const i = dv.getInt32(o, true);
      if (plausibleFloat(f)) out.push({ type: "f32", name: `f_${o.toString(16)}` });
      else if (i !== 0 && Math.abs(i) < 1_000_000) out.push({ type: "i32", name: `i_${o.toString(16)}` });
      else out.push({ type: "hex32", name: "" });
      o += 4;
      continue;
    }
    out.push({ type: "hex8", name: "" });
    o += 1;
  }
  return out;
}

/** Per-field change counters for a struct being watched over time. */
export function changedFields(prev: Uint8Array, cur: Uint8Array, offsets: readonly { offset: number; size: number }[]): boolean[] {
  return offsets.map(({ offset, size }) => {
    for (let i = offset; i < offset + size && i < prev.length && i < cur.length; i++) if (prev[i] !== cur[i]) return true;
    return false;
  });
}

// ---- per-slot proposals (Structs → Auto-detect) ------------------------------------------------
// Unlike guessFields, which retypes the whole layout at once, proposeFields returns one proposal
// per 8-byte slot (split into 4-byte halves where that reads better) with the evidence behind it,
// so the user can accept them one by one. Pointers are classified with the same kindOf as
// guessFields (lib/ptrkind); the bytes behind each pointer (`deref`) tell vtables and string
// pointers apart. Pure: the caller does the reads.

export type GuessKind =
  | "zero" | "vtable" | "code-ptr" | "module-ptr" | "heap-ptr" | "string-ptr" | "wstring-ptr"
  | "f64" | "f32" | "bool" | "small-int" | "int" | "ascii" | "utf16" | "unknown";

export type Guess = { offset: number; type: FieldType; kind: GuessKind; name: string; label: string };

export type ProposeContext = GuessContext & {
  /** for "module+rva" labels */
  modules: readonly Module[];
  /** first bytes (32 is plenty) at each pointer target, keyed by lowercase 0x address */
  deref?: ReadonlyMap<string, Uint8Array>;
  /** RTTI class name per slot offset, for slots that look like vtable pointers */
  rtti?: ReadonlyMap<number, string>;
};

const key = (v: bigint) => "0x" + v.toString(16);
const u64 = (b: Uint8Array, o: number) => new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true);

/** Every distinct pointer-looking value in the dump, for the caller to read `deref` bytes at. */
export function pointerTargets(buf: Uint8Array, ctx: GuessContext): string[] {
  const out = new Set<string>();
  for (let o = 0; o + 8 <= buf.length; o += 8) {
    const v = u64(buf, o);
    if (v && ctx.kindOf(v)) out.add(key(v));
  }
  return [...out];
}

const printable = (c: number) => c >= 0x20 && c < 0x7f;

/** Printable ASCII run at o (stops at NUL, a non-printable byte or the end). */
function asciiSpan(b: Uint8Array, o: number): { n: number; nul: boolean } {
  let n = 0;
  while (o + n < b.length && printable(b[o + n])) n++;
  return { n, nul: o + n < b.length && b[o + n] === 0 };
}

function utf16Span(b: Uint8Array, o: number): { n: number; nul: boolean } {
  let n = 0;
  while (o + n * 2 + 1 < b.length && printable(b[o + n * 2]) && b[o + n * 2 + 1] === 0) n++;
  const i = o + n * 2;
  return { n, nul: i + 1 < b.length && b[i] === 0 && b[i + 1] === 0 };
}

const preview = (b: Uint8Array, o: number, n: number, step: number) => {
  let s = "";
  for (let i = 0; i < Math.min(n, 24); i++) s += String.fromCharCode(b[o + i * step]);
  return JSON.stringify(n > 24 ? s + "…" : s);
};

function plausibleDouble(d: number): boolean {
  const a = Math.abs(d);
  return Number.isFinite(d) && a >= 1e-6 && a <= 1e9;
}

function dword(lo: number, o: number): Guess {
  const i = lo | 0;
  const f = new DataView(new Uint32Array([lo]).buffer).getFloat32(0, true);
  if (lo === 0) return { offset: o, type: "hex32", kind: "zero", name: "", label: "zero / padding" };
  if (lo === 1) return { offset: o, type: "u32", kind: "bool", name: "", label: "bool / flag?" };
  if (lo <= 0xff) return { offset: o, type: "u32", kind: "small-int", name: "", label: `small int / enum (${lo})` };
  if (i < 0 && i >= -0x10000) return { offset: o, type: "i32", kind: "int", name: "", label: `int (${i})` };
  // floats before ints: 0x3f800000 is far more likely 1.0f than 1065353216
  if (plausibleFloat(f)) return { offset: o, type: "f32", kind: "f32", name: "", label: `float ${+f.toPrecision(6)}` };
  if (lo <= 0xffffff) return { offset: o, type: "i32", kind: "int", name: "", label: `int (${lo})` };
  return { offset: o, type: "hex32", kind: "unknown", name: "", label: "" };
}

function strPtr(t: Uint8Array | undefined): { kind: GuessKind; label: string } | null {
  if (!t) return null;
  const a = asciiSpan(t, 0);
  if ((a.n >= 4 && a.nul) || a.n >= 16) return { kind: "string-ptr", label: `char* ${preview(t, 0, a.n, 1)}` };
  const w = utf16Span(t, 0);
  if ((w.n >= 3 && w.nul) || w.n >= 8) return { kind: "wstring-ptr", label: `wchar_t* ${preview(t, 0, w.n, 2)}` };
  return null;
}

/** Classifies one 8-byte slot (or an inline string starting there, which may cover several slots). */
function slot(buf: Uint8Array, o: number, ctx: ProposeContext): Guess[] {
  const v = u64(buf, o);
  if (v === 0n) return [{ offset: o, type: "hex64", kind: "zero", name: "", label: "zero / padding" }];

  const k = ctx.kindOf(v);
  if (k) {
    const where = labelAddr(v, ctx.modules);
    const t = ctx.deref?.get(key(v));
    const isCode = (p: bigint) => p !== 0n && ctx.kindOf(p) === "code";
    // vtable: lives in read-only image data and its first slots point at code
    if (k === "rdata" && t && t.length >= 16 && isCode(u64(t, 0)) && isCode(u64(t, 8))) {
      const cls = ctx.rtti?.get(o);
      return [{ offset: o, type: "ptr", kind: "vtable", name: o === 0 ? "vtable" : `vtable_${o.toString(16)}`, label: `vtable → ${where}${cls ? ` (${cls})` : ""}` }];
    }
    if (k === "code") return [{ offset: o, type: "ptr", kind: "code-ptr", name: "", label: `code → ${where}` }];
    const sp = strPtr(t);
    if (sp) return [{ offset: o, type: "ptr", kind: sp.kind, name: "", label: sp.label }];
    if (k === "rdata" || k === "data") return [{ offset: o, type: "ptr", kind: "module-ptr", name: "", label: `→ ${where}` }];
    return [{ offset: o, type: "ptr", kind: "heap-ptr", name: "", label: `heap → ${where}` }];
  }

  const a = asciiSpan(buf, o);
  if (a.n >= 8 && o + kFieldSizes.ascii <= buf.length) return [{ offset: o, type: "ascii", kind: "ascii", name: "", label: `inline ${preview(buf, o, a.n, 1)}` }];
  const w = utf16Span(buf, o);
  if (w.n >= 4 && o + kFieldSizes.utf16 <= buf.length) return [{ offset: o, type: "utf16", kind: "utf16", name: "", label: `inline L${preview(buf, o, w.n, 2)}` }];

  const lo = Number(v & 0xffffffffn), hi = Number(v >> 32n);
  const halves = [dword(lo, o), dword(hi, o + 4)];
  // two plausible floats (a vec2, say) also decode as a plausible double, so they win
  if (halves.every((h) => h.kind === "f32")) return halves;
  const d = new DataView(buf.buffer, buf.byteOffset + o, 8).getFloat64(0, true);
  if (plausibleDouble(d)) return [{ offset: o, type: "f64", kind: "f64", name: "", label: `double ${+d.toPrecision(8)}` }];
  if (halves.every((h) => h.kind === "unknown")) return [{ offset: o, type: "hex64", kind: "unknown", name: "", label: "" }];
  return halves;
}

/** One proposal per slot of the dump, in offset order; inline strings swallow the slots they cover. */
export function proposeFields(buf: Uint8Array, ctx: ProposeContext): Guess[] {
  const out: Guess[] = [];
  let o = 0;
  while (o + 8 <= buf.length) {
    const g = slot(buf, o, ctx);
    out.push(...g);
    const last = g[g.length - 1];
    o = Math.max(o + 8, last.offset + kFieldSizes[last.type]);
  }
  return out;
}

/** Greedy hex padding for [from, to). */
function pad(from: number, to: number): Field[] {
  const out: Field[] = [];
  for (let o = from; o < to;) {
    const n = to - o >= 8 && o % 8 === 0 ? 8 : to - o >= 4 && o % 4 === 0 ? 4 : to - o >= 2 && o % 2 === 0 ? 2 : 1;
    out.push({ type: `hex${n * 8}` as FieldType, name: "" });
    o += n;
  }
  return out;
}

/**
 * Puts `field` at byte `offset` of a cumulative layout without moving anything else: the fields it
 * overlaps are replaced, their uncovered parts become hex padding, and the layout grows if needed.
 * A replaced field with the same range keeps its name when the new one has none.
 */
export function placeField(fields: readonly Field[], offset: number, field: Field): Field[] {
  const end = offset + kFieldSizes[field.type];
  const lay = layout(fields);
  const out: Field[] = [];
  let placed = false;
  const put = (f: Field) => { out.push(f); placed = true; };
  fields.forEach((f, i) => {
    const a = lay[i].offset, b = a + lay[i].size;
    if (b <= offset || a >= end) {
      if (!placed && a >= end) put(field);
      out.push(f);
      return;
    }
    if (a < offset) out.push(...pad(a, offset));
    if (!placed) put(a === offset && b === end && !field.name ? { ...field, name: f.name } : field);
    if (b > end) out.push(...pad(end, b));
  });
  if (!placed) {
    const size = lay.length ? lay[lay.length - 1].offset + lay[lay.length - 1].size : 0;
    out.push(...pad(size, offset), field);
  }
  return out;
}

/** Builds a layout from sparse `[offset, type, name]` entries, padding the gaps up to `size`. */
export function fromOffsets(size: number, entries: readonly [number, FieldType, string][]): Field[] {
  let f = pad(0, size);
  for (const [o, t, n] of entries) f = placeField(f, o, { type: t, name: n });
  return f;
}
