// Struct auto-detect: proposes a field type per 8-byte slot (split into 4-byte halves where that
// reads better) from a raw dump of an object plus the process memory map. Pure: the caller does
// the reads (the dump, the regions, and a few bytes at every pointer target) and passes them in.
import { labelAddr, moduleOf, toBig, type Module } from "../hex";
import { kFieldSizes, layout, type Field, type FieldType } from "./struct";

export type MapRegion = { base: string | bigint; size: number; writable: boolean; executable: boolean; present?: boolean };

export type GuessKind =
  | "zero" | "vtable" | "code-ptr" | "module-ptr" | "heap-ptr" | "string-ptr" | "wstring-ptr"
  | "f64" | "f32" | "bool" | "small-int" | "int" | "ascii" | "utf16" | "unknown";

export type Guess = { offset: number; type: FieldType; kind: GuessKind; name: string; label: string };

export type GuessContext = {
  modules: readonly Module[];
  /** from the `regions` verb; empty when it failed, then only module pointers are recognised */
  regions: readonly MapRegion[];
  /** first bytes (32 is plenty) at each pointer target, keyed by lowercase 0x address */
  deref?: ReadonlyMap<string, Uint8Array>;
  /** RTTI class name per slot offset, for slots that look like vtable pointers */
  rtti?: ReadonlyMap<number, string>;
};

type Span = { base: bigint; end: bigint; w: boolean; x: boolean };
const kUserMin = 0x10000n;
const kUserMax = 0x7fffffffffffn;

function spans(regions: readonly MapRegion[]): Span[] {
  return regions
    .filter((r) => r.present !== false)
    .map((r) => ({ base: toBig(r.base), end: toBig(r.base) + BigInt(r.size), w: r.writable, x: r.executable }))
    .sort((a, b) => (a.base < b.base ? -1 : 1));
}

function regionOf(v: bigint, s: readonly Span[]): Span | undefined {
  let lo = 0, hi = s.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (v < s[mid].base) hi = mid - 1;
    else if (v >= s[mid].end) lo = mid + 1;
    else return s[mid];
  }
  return undefined;
}

const key = (v: bigint) => "0x" + v.toString(16);
const u64 = (b: Uint8Array, o: number) => new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true);

/** True when v is a canonical user address inside a module or a mapped region. */
function mapped(v: bigint, ctx: GuessContext, s: readonly Span[]): boolean {
  return v >= kUserMin && v <= kUserMax && (!!regionOf(v, s) || !!moduleOf(v, ctx.modules));
}

/** Every distinct pointer-looking value in the dump, for the caller to read `deref` bytes at. */
export function pointerTargets(buf: Uint8Array, ctx: GuessContext): string[] {
  const s = spans(ctx.regions);
  const out = new Set<string>();
  for (let o = 0; o + 8 <= buf.length; o += 8) {
    const v = u64(buf, o);
    if (mapped(v, ctx, s)) out.add(key(v));
  }
  return [...out];
}

const printable = (c: number) => c >= 0x20 && c < 0x7f;

/** Length of the printable ASCII run at o (stops at NUL, a non-printable byte or the end). */
function asciiRun(b: Uint8Array, o: number): { n: number; nul: boolean } {
  let n = 0;
  while (o + n < b.length && printable(b[o + n])) n++;
  return { n, nul: o + n < b.length && b[o + n] === 0 };
}

function utf16Run(b: Uint8Array, o: number): { n: number; nul: boolean } {
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

function plausibleFloat(f: number, min: number, max: number): boolean {
  const a = Math.abs(f);
  return Number.isFinite(f) && a >= min && a <= max;
}

function dword(lo: number, o: number): Guess {
  const i = lo | 0;
  const f = new DataView(new Uint32Array([lo]).buffer).getFloat32(0, true);
  if (lo === 0) return { offset: o, type: "hex32", kind: "zero", name: "", label: "zero / padding" };
  if (lo === 1) return { offset: o, type: "u32", kind: "bool", name: "", label: "bool / flag?" };
  if (lo <= 0xff) return { offset: o, type: "u32", kind: "small-int", name: "", label: `small int / enum (${lo})` };
  if (i < 0 && i >= -0x10000) return { offset: o, type: "i32", kind: "int", name: "", label: `int (${i})` };
  // floats before ints: 0x3f800000 is far more likely 1.0f than 1065353216
  if (plausibleFloat(f, 1e-4, 1e7)) return { offset: o, type: "f32", kind: "f32", name: "", label: `float ${+f.toPrecision(6)}` };
  if (lo <= 0xffffff) return { offset: o, type: "i32", kind: "int", name: "", label: `int (${lo})` };
  return { offset: o, type: "hex32", kind: "unknown", name: "", label: "" };
}

function strPtr(t: Uint8Array | undefined): { kind: GuessKind; label: string } | null {
  if (!t) return null;
  const a = asciiRun(t, 0);
  if ((a.n >= 4 && a.nul) || a.n >= 16) return { kind: "string-ptr", label: `char* ${preview(t, 0, a.n, 1)}` };
  const w = utf16Run(t, 0);
  if ((w.n >= 3 && w.nul) || w.n >= 8) return { kind: "wstring-ptr", label: `wchar_t* ${preview(t, 0, w.n, 2)}` };
  return null;
}

/** Classifies one 8-byte slot (or an inline string starting there, which may cover several slots). */
function slot(buf: Uint8Array, o: number, ctx: GuessContext, s: readonly Span[]): Guess[] {
  const v = u64(buf, o);
  if (v === 0n) return [{ offset: o, type: "hex64", kind: "zero", name: "", label: "zero / padding" }];

  if (mapped(v, ctx, s)) {
    const r = regionOf(v, s);
    // the Linux backend lists [heap]/[stack] as modules; those are not images
    const mod = moduleOf(v, ctx.modules.filter((m) => !m.name.startsWith("[")));
    const where = labelAddr(v, ctx.modules);
    const t = ctx.deref?.get(key(v));
    const isCode = (p: bigint) => !!regionOf(p, s)?.x;
    // vtable: lives in a non-writable image section and its first slots point at code
    if (r && !r.w && t && t.length >= 16 && isCode(u64(t, 0)) && isCode(u64(t, 8))) {
      const cls = ctx.rtti?.get(o);
      return [{ offset: o, type: "ptr", kind: "vtable", name: o === 0 ? "vtable" : `vtable_${o.toString(16)}`, label: `vtable → ${where}${cls ? ` (${cls})` : ""}` }];
    }
    if (r?.x) return [{ offset: o, type: "ptr", kind: "code-ptr", name: "", label: `code → ${where}` }];
    const sp = strPtr(t);
    if (sp) return [{ offset: o, type: "ptr", kind: sp.kind, name: "", label: sp.label }];
    if (mod) return [{ offset: o, type: "ptr", kind: "module-ptr", name: "", label: `→ ${where}` }];
    return [{ offset: o, type: "ptr", kind: "heap-ptr", name: "", label: `heap → ${where}${r?.w ? "" : " (read-only)"}` }];
  }

  const a = asciiRun(buf, o);
  if (a.n >= 8 && o + kFieldSizes.ascii <= buf.length) return [{ offset: o, type: "ascii", kind: "ascii", name: "", label: `inline ${preview(buf, o, a.n, 1)}` }];
  const w = utf16Run(buf, o);
  if (w.n >= 4 && o + kFieldSizes.utf16 <= buf.length) return [{ offset: o, type: "utf16", kind: "utf16", name: "", label: `inline L${preview(buf, o, w.n, 2)}` }];

  const lo = Number(v & 0xffffffffn), hi = Number(v >> 32n);
  const halves = [dword(lo, o), dword(hi, o + 4)];
  // two plausible floats (a vec2, say) also decode as a plausible double, so they win
  if (halves.every((h) => h.kind === "f32")) return halves;
  const d = new DataView(buf.buffer, buf.byteOffset + o, 8).getFloat64(0, true);
  if (plausibleFloat(d, 1e-6, 1e9)) return [{ offset: o, type: "f64", kind: "f64", name: "", label: `double ${+d.toPrecision(8)}` }];
  if (halves.every((h) => h.kind === "unknown")) return [{ offset: o, type: "hex64", kind: "unknown", name: "", label: "" }];
  return halves;
}

/** One proposal per slot of the dump, in offset order; inline strings swallow the slots they cover. */
export function guessFields(buf: Uint8Array, ctx: GuessContext): Guess[] {
  const s = spans(ctx.regions);
  const out: Guess[] = [];
  let o = 0;
  while (o + 8 <= buf.length) {
    const g = slot(buf, o, ctx, s);
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
