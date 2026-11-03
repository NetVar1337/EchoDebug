import { describe, expect, it } from "vitest";
import { RingBuffer, decodeNumber, downsample, graphTypeOf, nearest, niceTicks, stats, toCsv, yRange } from "./graphs";

describe("ring buffer", () => {
  it("keeps the newest samples in order", () => {
    const b = new RingBuffer(3);
    for (let i = 1; i <= 5; i++) b.push(i * 10, i);
    expect(b.length).toBe(3);
    expect(b.toArrays()).toEqual({ t: [30, 40, 50], v: [3, 4, 5] });
    expect(b.last()).toEqual({ t: 50, v: 5 });
    expect(b.at(0)).toEqual({ t: 30, v: 3 });
  });

  it("resizes keeping the newest", () => {
    const b = new RingBuffer(5);
    for (let i = 0; i < 5; i++) b.push(i, i);
    expect(b.resized(2).toArrays().v).toEqual([3, 4]);
    expect(b.resized(10).toArrays().v).toEqual([0, 1, 2, 3, 4]);
  });

  it("finds times with lowerBound after wrapping", () => {
    const b = new RingBuffer(4);
    for (let i = 0; i < 7; i++) b.push(i * 100, i);
    // holds t = 300..600
    expect(b.lowerBound(0)).toBe(0);
    expect(b.lowerBound(350)).toBe(1);
    expect(b.lowerBound(600)).toBe(3);
    expect(b.lowerBound(601)).toBe(4);
    expect(nearest(b, 440)).toEqual({ t: 400, v: 4 });
  });
});

describe("decodeNumber", () => {
  const bytes = (...b: number[]) => new Uint8Array(b);
  it("decodes little-endian ints", () => {
    expect(decodeNumber(bytes(0xff), "u8")).toBe(255);
    expect(decodeNumber(bytes(0xff), "i8")).toBe(-1);
    expect(decodeNumber(bytes(0x34, 0x12), "u16")).toBe(0x1234);
    expect(decodeNumber(bytes(0xfe, 0xff, 0xff, 0xff), "i32")).toBe(-2);
    expect(decodeNumber(bytes(0xfe, 0xff, 0xff, 0xff), "u32")).toBe(0xfffffffe);
    expect(decodeNumber(bytes(1, 0, 0, 0, 0, 0, 0, 0), "u64")).toBe(1);
    expect(decodeNumber(bytes(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), "i64")).toBe(-1);
  });
  it("decodes floats and rejects NaN / short buffers", () => {
    const f = new Uint8Array(new Float32Array([1.5]).buffer);
    expect(decodeNumber(f, "f32")).toBe(1.5);
    const d = new Uint8Array(new Float64Array([-2.25]).buffer);
    expect(decodeNumber(d, "f64")).toBe(-2.25);
    expect(decodeNumber(new Uint8Array(new Float32Array([NaN]).buffer), "f32")).toBeNull();
    expect(decodeNumber(bytes(1, 2), "i32")).toBeNull();
    expect(decodeNumber(null, "i32")).toBeNull();
  });
  it("maps watch types", () => {
    expect(graphTypeOf("ptr")).toBe("u64");
    expect(graphTypeOf("ascii")).toBeNull();
    expect(graphTypeOf("f32")).toBe("f32");
  });
});

describe("downsampling and stats", () => {
  it("keeps every spike when reducing", () => {
    const b = new RingBuffer(10_000);
    for (let i = 0; i < 10_000; i++) b.push(i, i === 5_000 ? 999 : i === 7_777 ? -999 : 0);
    const pts = downsample(b, 0, 10_000, 100);
    expect(pts.length).toBeLessThanOrEqual(100 * 4 + 8);
    expect(pts.some((p) => p.v === 999)).toBe(true);
    expect(pts.some((p) => p.v === -999)).toBe(true);
    for (let i = 1; i < pts.length; i++) expect(pts[i].t).toBeGreaterThanOrEqual(pts[i - 1].t);
  });

  it("returns raw samples in a small window, plus neighbours", () => {
    const b = new RingBuffer(100);
    for (let i = 0; i < 100; i++) b.push(i * 10, i);
    const pts = downsample(b, 200, 300, 50);
    expect(pts[0].t).toBe(190);
    expect(pts[pts.length - 1].t).toBe(310);
  });

  it("computes stats over a window", () => {
    const b = new RingBuffer(10);
    [3, 1, 4, 1, 5].forEach((v, i) => b.push(i, v));
    expect(stats(b)).toEqual({ count: 5, min: 1, max: 5, avg: 14 / 5, last: 5 });
    expect(stats(b, 2, 3)).toEqual({ count: 2, min: 1, max: 4, avg: 2.5, last: 1 });
    expect(stats(new RingBuffer(4))).toBeNull();
  });

  it("pads the y range and ticks round values", () => {
    expect(yRange([[{ t: 0, v: 5 }]])).toEqual([4, 6]);
    const [lo, hi] = yRange([[{ t: 0, v: 0 }, { t: 1, v: 100 }]]);
    expect(lo).toBeLessThan(0);
    expect(hi).toBeGreaterThan(100);
    expect(niceTicks(0, 100, 5)).toEqual([0, 20, 40, 60, 80, 100]);
    expect(niceTicks(-1, 1, 4)).toEqual([-1, -0.5, 0, 0.5, 1]);
  });
});

describe("csv", () => {
  it("joins series on time", () => {
    const a = new RingBuffer(4);
    const b = new RingBuffer(4);
    a.push(1000, 1);
    a.push(2000, 2);
    b.push(2000, 20);
    const csv = toCsv([{ label: "hp", buf: a }, { label: 'x,"y"', buf: b }]);
    const lines = csv.trim().split("\n");
    expect(lines[0]).toBe('time,ms,hp,"x,""y"""');
    expect(lines[1].endsWith(",0,1,")).toBe(true);
    expect(lines[2].endsWith(",1000,2,20")).toBe(true);
  });
});
