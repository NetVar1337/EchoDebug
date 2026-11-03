// Client-side value scanning helpers: float rounding modes, comparisons for narrowing a candidate
// list the app holds itself (undo, save/load), and group scans (several values at fixed offsets).

export type NumType = "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "f32" | "f64";
export type Compare = "exact" | "changed" | "unchanged" | "increased" | "decreased" | "greater" | "less" | "between" | "unknown";
export type FloatMode = "rounded" | "truncated" | "epsilon";

export const kNumSize: Record<NumType, number> = { u8: 1, u16: 2, u32: 4, u64: 8, i8: 1, i16: 2, i32: 4, i64: 8, f32: 4, f64: 8 };

/** Number of decimals the user typed: "1.25" → 2, "3" → 0. */
export function decimals(text: string): number {
  const m = /\.(\d+)/.exec(text.trim());
  return m ? m[1].length : 0;
}

/**
 * Cheat-Engine style float matching for an "exact" scan of `text`:
 *  - rounded:   |x - v| <= 0.5 * 10^-d       (1.5 matches 1.45 … 1.55)
 *  - truncated: v <= x < v + 10^-d            (1.5 matches 1.50 … 1.5999)
 *  - epsilon:   |x - v| <= eps
 * Returns the request fields for scan_new / scan_next (compare, value, value2, float_epsilon).
 */
export function floatScanFields(text: string, mode: FloatMode, eps = 0.0001): Record<string, unknown> {
  const v = Number(text);
  const step = 10 ** -decimals(text);
  if (mode === "epsilon") return { compare: "exact", value: text, float_epsilon: eps };
  if (mode === "rounded") return { compare: "exact", value: text, float_epsilon: step / 2 };
  const hi = v >= 0 ? v + step : v - step;
  const [a, b] = v >= 0 ? [v, hi - step * 1e-6] : [hi + step * 1e-6, v];
  return { compare: "between", value: String(a), value2: String(b) };
}

export function readNum(b: Uint8Array, off: number, t: NumType): number | bigint | null {
  if (off < 0 || off + kNumSize[t] > b.length) return null;
  const dv = new DataView(b.buffer, b.byteOffset + off, kNumSize[t]);
  switch (t) {
    case "u8": return dv.getUint8(0);
    case "i8": return dv.getInt8(0);
    case "u16": return dv.getUint16(0, true);
    case "i16": return dv.getInt16(0, true);
    case "u32": return dv.getUint32(0, true);
    case "i32": return dv.getInt32(0, true);
    case "u64": return dv.getBigUint64(0, true);
    case "i64": return dv.getBigInt64(0, true);
    case "f32": return dv.getFloat32(0, true);
    case "f64": return dv.getFloat64(0, true);
  }
}

function parseTarget(text: string, t: NumType): number | bigint {
  const s = text.trim();
  if (t === "f32" || t === "f64") return Number(s);
  if (t === "u64" || t === "i64") return s.startsWith("-") ? -BigInt(s.slice(1)) : BigInt(s);
  return Number(s.startsWith("0x") || s.startsWith("-0x") ? Number.parseInt(s, 16) : Number(s));
}

/**
 * Whether a candidate survives a next scan. `cur`/`prev` are its bytes now and at the last scan.
 * Float exact uses `eps`.
 */
export function keep(t: NumType, cmp: Compare, cur: Uint8Array, prev: Uint8Array, value = "", value2 = "", eps = 0.0001): boolean {
  const c = readNum(cur, 0, t);
  const p = readNum(prev, 0, t);
  if (c === null) return false;
  const lt = (a: number | bigint, b: number | bigint) => (typeof a === "bigint" || typeof b === "bigint" ? BigInt(a) < BigInt(b) : a < b);
  const eq = (a: number | bigint, b: number | bigint) => (typeof a === "bigint" || typeof b === "bigint" ? BigInt(a) === BigInt(b) : a === b);
  switch (cmp) {
    case "unknown": return true;
    case "changed": return p === null || !eq(c, p);
    case "unchanged": return p !== null && eq(c, p);
    case "increased": return p !== null && lt(p, c);
    case "decreased": return p !== null && lt(c, p);
  }
  const v = parseTarget(value, t);
  const isF = t === "f32" || t === "f64";
  switch (cmp) {
    case "exact": return isF ? Math.abs(Number(c) - Number(v)) <= eps : eq(c, v);
    case "greater": return lt(v, c);
    case "less": return lt(c, v);
    case "between": {
      const v2 = parseTarget(value2, t);
      const [lo, hi] = lt(v2, v) ? [v2, v] : [v, v2];
      return !lt(c, lo) && !lt(hi, c);
    }
  }
  return false;
}

export type GroupMember = { offset: number; type: NumType; value: string | null };

/**
 * Group scan spec: members separated by ';' or ',', each `[+off] type:value` (`*` = any value).
 * The first member is scanned for; the rest are checked at their offsets from it.
 *   "i32:100; +4 f32:1.5; +8 i32:*"
 */
export function parseGroup(spec: string): GroupMember[] {
  const out: GroupMember[] = [];
  let next = 0;
  for (const raw of spec.split(/[;,\n]/).map((x) => x.trim()).filter(Boolean)) {
    const m = /^(?:\+?(0x[0-9a-f]+|\d+)\s+)?(u8|u16|u32|u64|i8|i16|i32|i64|f32|f64)\s*:\s*(\*|\S+)$/i.exec(raw);
    if (!m) throw new Error(`bad group member: ${raw} (expected '[+offset] type:value')`);
    const type = m[2].toLowerCase() as NumType;
    const offset = m[1] !== undefined ? Number(m[1]) : next;
    out.push({ offset, type, value: m[3] === "*" ? null : m[3] });
    next = offset + kNumSize[type];
  }
  if (!out.length) throw new Error("empty group");
  if (out[0].offset !== 0) throw new Error("the first member is the anchor and sits at offset 0");
  if (out[0].value === null) throw new Error("the first member needs a value to scan for");
  return out;
}

/** Bytes covering every member, starting at the anchor. */
export function groupSpan(g: readonly GroupMember[]): number {
  return Math.max(...g.map((m) => m.offset + kNumSize[m.type]));
}

/** Checks a group against the bytes read at a candidate anchor. */
export function groupMatches(g: readonly GroupMember[], bytes: Uint8Array, eps = 0.0001): boolean {
  return g.every((m) => {
    if (m.value === null) return m.offset + kNumSize[m.type] <= bytes.length;
    const slice = bytes.subarray(m.offset, m.offset + kNumSize[m.type]);
    return slice.length === kNumSize[m.type] && keep(m.type, "exact", slice, slice, m.value, "", eps);
  });
}
