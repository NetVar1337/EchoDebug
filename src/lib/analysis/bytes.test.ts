import { describe, expect, it } from "vitest";
import { buildNeedle, findIn, formatAs, inspect } from "./bytes";
import { decimals, floatScanFields, groupMatches, groupSpan, keep, parseGroup } from "./scancmp";

const B = (...x: number[]) => new Uint8Array(x);

describe("memory search", () => {
  it("builds needles in every mode", () => {
    expect(Array.from(buildNeedle("48 8b ?? 05", "hex").bytes)).toEqual([0x48, 0x8b, 0, 5]);
    expect(buildNeedle("488b??05", "hex").mask).toEqual([true, true, false, true]);
    expect(Array.from(buildNeedle("AB", "utf16").bytes)).toEqual([0x41, 0, 0x42, 0]);
    expect(Array.from(buildNeedle("-1", "i16").bytes)).toEqual([0xff, 0xff]);
    expect(Array.from(buildNeedle("0x1234", "u32", false).bytes)).toEqual([0, 0, 0x12, 0x34]);
    expect(Array.from(buildNeedle("1", "f32").bytes)).toEqual([0, 0, 0x80, 0x3f]);
    expect(() => buildNeedle("zz", "hex")).toThrow();
  });
  it("finds forward and backward with wildcards", () => {
    const buf = B(1, 2, 3, 1, 9, 3, 1, 2, 3);
    const n = buildNeedle("01 ?? 03", "hex");
    expect(findIn(buf, n, 0, 1)).toBe(0);
    expect(findIn(buf, n, 1, 1)).toBe(3);
    expect(findIn(buf, n, 8, -1)).toBe(6);
    expect(findIn(buf, n, 5, -1)).toBe(3);
    expect(findIn(buf, buildNeedle("ff", "hex"), 0, 1)).toBe(-1);
  });
});

describe("copy as", () => {
  const b = B(0x48, 0x8b, 0x05);
  it("formats bytes", () => {
    expect(formatAs(b, "spaced")).toBe("48 8b 05");
    expect(formatAs(b, "ida")).toBe("48 8B 05");
    expect(formatAs(b, "python")).toBe('b"\\x48\\x8b\\x05"');
    expect(formatAs(b, "base64")).toBe("SIsF");
    expect(formatAs(b, "c", "code")).toBe("unsigned char code[3] = {\n    0x48, 0x8b, 0x05,\n};");
    expect(formatAs(b, "rust", "code")).toContain("const CODE: [u8; 3]");
  });
});

describe("data inspector", () => {
  it("decodes little and big endian", () => {
    const b = B(0x00, 0x00, 0x80, 0x3f, 0, 0, 0, 0);
    const le = Object.fromEntries(inspect(b).map((r) => [r.type, r.value]));
    expect(le.f32).toBe("1");
    expect(le.u32).toBe(String(0x3f800000));
    const be = Object.fromEntries(inspect(b, false).map((r) => [r.type, r.value]));
    expect(be.u32).toBe(String(0x8000 * 1 + 0x3f));
    expect(Object.fromEntries(inspect(B(1)).map((r) => [r.type, r.value])).u32).toBe("??");
  });
});

describe("scan comparisons", () => {
  const f = (v: number) => new Uint8Array(new Float32Array([v]).buffer);
  const i = (v: number) => new Uint8Array(new Int32Array([v]).buffer);
  it("float rounding modes", () => {
    expect(decimals("1.25")).toBe(2);
    expect(floatScanFields("1.5", "rounded")).toEqual({ compare: "exact", value: "1.5", float_epsilon: 0.05 });
    const t = floatScanFields("1.5", "truncated");
    expect(t.compare).toBe("between");
    expect(Number(t.value)).toBe(1.5);
    expect(Number(t.value2)).toBeLessThan(1.6);
    expect(Number(t.value2)).toBeGreaterThan(1.599);
  });
  it("keeps candidates like a next scan", () => {
    expect(keep("i32", "increased", i(5), i(4))).toBe(true);
    expect(keep("i32", "decreased", i(5), i(4))).toBe(false);
    expect(keep("i32", "changed", i(5), i(5))).toBe(false);
    expect(keep("i32", "between", i(5), i(0), "10", "1")).toBe(true);
    expect(keep("f32", "exact", f(1.50004), f(0), "1.5")).toBe(true);
    expect(keep("i32", "exact", i(-3), i(0), "-3")).toBe(true);
    expect(keep("u64", "greater", new Uint8Array(new BigUint64Array([10n]).buffer), new Uint8Array(8), "9")).toBe(true);
  });
  it("parses and matches group scans", () => {
    const g = parseGroup("i32:100; +4 f32:1.5; i32:*");
    expect(g).toEqual([{ offset: 0, type: "i32", value: "100" }, { offset: 4, type: "f32", value: "1.5" }, { offset: 8, type: "i32", value: null }]);
    expect(groupSpan(g)).toBe(12);
    const bytes = new Uint8Array(12);
    const dv = new DataView(bytes.buffer);
    dv.setInt32(0, 100, true);
    dv.setFloat32(4, 1.5, true);
    expect(groupMatches(g, bytes)).toBe(true);
    dv.setFloat32(4, 2, true);
    expect(groupMatches(g, bytes)).toBe(false);
    expect(() => parseGroup("+4 i32:1")).toThrow(/anchor/);
    expect(() => parseGroup("i32:*")).toThrow(/needs a value/);
  });
});
