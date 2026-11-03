// Value graphs: per-series history ring buffers, numeric decoding of watched bytes, and the
// min/max downsampling and stats the Graphs view draws from. Pure, so it is unit-tested.
import type { ValueType } from "./analysis/values";

export type GraphType = "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "f32" | "f64";
export const kGraphTypes: GraphType[] = ["i32", "u32", "f32", "f64", "i8", "u8", "i16", "u16", "i64", "u64"];
export const kGraphSizes: Record<GraphType, number> = { u8: 1, u16: 2, u32: 4, u64: 8, i8: 1, i16: 2, i32: 4, i64: 8, f32: 4, f64: 8 };

/** The graph type for a watch's type; strings cannot be graphed, pointers graph as u64. */
export function graphTypeOf(t: ValueType): GraphType | null {
  if (t === "ascii" || t === "utf16") return null;
  if (t === "ptr") return "u64";
  return t;
}

/** Little-endian number at `off`; null when the bytes are missing or the float is not finite. */
export function decodeNumber(buf: Uint8Array | null | undefined, t: GraphType, off = 0): number | null {
  if (!buf || off < 0 || off + kGraphSizes[t] > buf.length) return null;
  const dv = new DataView(buf.buffer, buf.byteOffset + off, kGraphSizes[t]);
  let v: number;
  switch (t) {
    case "u8": v = dv.getUint8(0); break;
    case "i8": v = dv.getInt8(0); break;
    case "u16": v = dv.getUint16(0, true); break;
    case "i16": v = dv.getInt16(0, true); break;
    case "u32": v = dv.getUint32(0, true); break;
    case "i32": v = dv.getInt32(0, true); break;
    // 64-bit values lose precision above 2^53; graphs are about shape, the watchlist shows exact values
    case "u64": v = Number(dv.getBigUint64(0, true)); break;
    case "i64": v = Number(dv.getBigInt64(0, true)); break;
    case "f32": v = dv.getFloat32(0, true); break;
    case "f64": v = dv.getFloat64(0, true); break;
  }
  return Number.isFinite(v) ? v : null;
}

/** Fixed-capacity history of (time, value) samples; the oldest drop out first. */
export class RingBuffer {
  private t: Float64Array;
  private v: Float64Array;
  private start = 0;
  private n = 0;

  constructor(readonly capacity: number) {
    const c = Math.max(2, Math.floor(capacity));
    this.capacity = c;
    this.t = new Float64Array(c);
    this.v = new Float64Array(c);
  }

  get length(): number {
    return this.n;
  }

  push(time: number, value: number): void {
    const c = this.capacity;
    const at = (this.start + this.n) % c;
    this.t[at] = time;
    this.v[at] = value;
    if (this.n < c) this.n++;
    else this.start = (this.start + 1) % c;
  }

  /** i-th oldest sample */
  at(i: number): { t: number; v: number } {
    const k = (this.start + i) % this.capacity;
    return { t: this.t[k], v: this.v[k] };
  }

  last(): { t: number; v: number } | null {
    return this.n ? this.at(this.n - 1) : null;
  }

  /** samples in time order */
  toArrays(): { t: number[]; v: number[] } {
    const t: number[] = new Array(this.n);
    const v: number[] = new Array(this.n);
    for (let i = 0; i < this.n; i++) {
      const k = (this.start + i) % this.capacity;
      t[i] = this.t[k];
      v[i] = this.v[k];
    }
    return { t, v };
  }

  /** a buffer with another capacity holding the newest samples of this one */
  resized(capacity: number): RingBuffer {
    const r = new RingBuffer(capacity);
    const skip = Math.max(0, this.n - r.capacity);
    for (let i = skip; i < this.n; i++) {
      const s = this.at(i);
      r.push(s.t, s.v);
    }
    return r;
  }

  clear(): void {
    this.start = 0;
    this.n = 0;
  }

  /** index of the first sample with time >= t (binary search; samples are in time order) */
  lowerBound(time: number): number {
    return this.search((t) => t < time);
  }

  /** index of the first sample with time > t */
  upperBound(time: number): number {
    return this.search((t) => t <= time);
  }

  private search(before: (t: number) => boolean): number {
    let lo = 0;
    let hi = this.n;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (before(this.t[(this.start + mid) % this.capacity])) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  }
}

export type Point = { t: number; v: number };

/**
 * Samples of `buf` inside [t0, t1], reduced to at most ~4 points per bucket (first, min, max, last)
 * so a line drawn through them keeps every spike. Includes one sample on each side of the window
 * so the line reaches the edges.
 */
export function downsample(buf: RingBuffer, t0: number, t1: number, buckets: number): Point[] {
  if (!buf.length || t1 <= t0) return [];
  const from = Math.max(0, buf.lowerBound(t0) - 1);
  const to = Math.min(buf.length, buf.upperBound(t1) + 1);
  const count = to - from;
  const out: Point[] = [];
  if (count <= buckets * 4) {
    for (let i = from; i < to; i++) out.push(buf.at(i));
    return out;
  }
  const width = (t1 - t0) / Math.max(1, buckets);
  let i = from;
  while (i < to) {
    const first = buf.at(i);
    const bucket = Math.floor((first.t - t0) / width);
    let min = first;
    let max = first;
    let last = first;
    i++;
    while (i < to) {
      const s = buf.at(i);
      if (Math.floor((s.t - t0) / width) !== bucket) break;
      if (s.v < min.v) min = s;
      if (s.v > max.v) max = s;
      last = s;
      i++;
    }
    const pts = [first, min, max, last].filter((p, k, a) => a.indexOf(p) === k).sort((a, b) => a.t - b.t);
    out.push(...pts);
  }
  return out;
}

export type Stats = { count: number; min: number; max: number; avg: number; last: number };

/** min / max / average of the samples inside [t0, t1] (all samples when omitted) */
export function stats(buf: RingBuffer, t0 = -Infinity, t1 = Infinity): Stats | null {
  const from = Number.isFinite(t0) ? buf.lowerBound(t0) : 0;
  let count = 0;
  let min = Infinity;
  let max = -Infinity;
  let sum = 0;
  let last = 0;
  for (let i = from; i < buf.length; i++) {
    const s = buf.at(i);
    if (s.t > t1) break;
    count++;
    if (s.v < min) min = s.v;
    if (s.v > max) max = s.v;
    sum += s.v;
    last = s.v;
  }
  return count ? { count, min, max, avg: sum / count, last } : null;
}

/** sample of `buf` nearest to time `t` */
export function nearest(buf: RingBuffer, t: number): Point | null {
  if (!buf.length) return null;
  const i = buf.lowerBound(t);
  const cands = [i - 1, i].filter((k) => k >= 0 && k < buf.length).map((k) => buf.at(k));
  return cands.reduce((a, b) => (Math.abs(b.t - t) < Math.abs(a.t - t) ? b : a));
}

/** y range of the points with a little headroom; a flat line gets a ±1 band */
export function yRange(points: Point[][]): [number, number] {
  let lo = Infinity;
  let hi = -Infinity;
  for (const ps of points) for (const p of ps) {
    if (p.v < lo) lo = p.v;
    if (p.v > hi) hi = p.v;
  }
  if (!Number.isFinite(lo)) return [0, 1];
  if (lo === hi) return [lo - 1, hi + 1];
  const pad = (hi - lo) * 0.06;
  return [lo - pad, hi + pad];
}

/** ~`count` round tick values covering [lo, hi] */
export function niceTicks(lo: number, hi: number, count = 5): number[] {
  if (!(hi > lo)) return [lo];
  const raw = (hi - lo) / Math.max(1, count);
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? raw;
  const out: number[] = [];
  for (let v = Math.ceil(lo / step) * step; v <= hi + step * 1e-9; v += step) out.push(Math.abs(v) < step * 1e-9 ? 0 : v);
  return out;
}

export type CsvSeries = { label: string; buf: RingBuffer };

/**
 * CSV with one row per timestamp and one column per series (empty where a series has no sample
 * at that time). Times are ISO strings plus milliseconds since the first sample.
 */
export function toCsv(series: CsvSeries[]): string {
  const rows = new Map<number, (number | undefined)[]>();
  series.forEach((s, k) => {
    for (let i = 0; i < s.buf.length; i++) {
      const p = s.buf.at(i);
      let row = rows.get(p.t);
      if (!row) rows.set(p.t, (row = new Array(series.length).fill(undefined)));
      row[k] = p.v;
    }
  });
  const times = [...rows.keys()].sort((a, b) => a - b);
  const esc = (x: string) => (/[",\n]/.test(x) ? `"${x.replace(/"/g, '""')}"` : x);
  const head = ["time", "ms", ...series.map((s) => esc(s.label))].join(",");
  const t0 = times[0] ?? 0;
  const lines = times.map((t) => [new Date(t).toISOString(), String(t - t0), ...rows.get(t)!.map((v) => (v === undefined ? "" : String(v)))].join(","));
  return [head, ...lines].join("\n") + "\n";
}

/** "12.5 s" / "3 min" style span label */
export function fmtSpan(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
  if (ms < 3_600_000) return `${(ms / 60_000).toFixed(1)} min`;
  return `${(ms / 3_600_000).toFixed(1)} h`;
}

/** compact number for axes and the cursor readout */
export function fmtValue(v: number): string {
  if (!Number.isFinite(v)) return String(v);
  const a = Math.abs(v);
  if (a !== 0 && (a < 1e-3 || a >= 1e9)) return v.toExponential(3);
  if (Number.isInteger(v)) return String(v);
  return String(Math.round(v * 1e4) / 1e4);
}
