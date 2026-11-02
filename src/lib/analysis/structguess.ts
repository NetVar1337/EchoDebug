// Guesses a struct layout from the live bytes of an object, the way you would by eye in ReClass:
// pointers into code are function pointers (a vtable when at offset 0 and into read-only data),
// pointers into data/heap are pointers, printable runs are strings, runs of sane floats are
// vectors or floats, small integers are ints, zeros stay padding.
import type { Field } from "./struct";

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
