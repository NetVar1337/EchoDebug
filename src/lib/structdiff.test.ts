import { describe, expect, it } from "vitest";
import { diffStruct } from "./structdiff";
import type { Field } from "./analysis/struct";

const fields: Field[] = [
  { type: "u32", name: "health" },
  { type: "f32", name: "speed" },
  { type: "u64", name: "flags" },
];

const mk = (health: number, speed: number, flags: bigint) => {
  const b = new Uint8Array(16);
  new DataView(b.buffer).setUint32(0, health, true);
  new DataView(b.buffer).setFloat32(4, speed, true);
  new DataView(b.buffer).setBigUint64(8, flags, true);
  return b;
};

describe("struct-aware diff", () => {
  it("reports changed fields with decoded before/after and counts unchanged", () => {
    const a = mk(100, 1.5, 7n);
    const b = mk(80, 1.5, 7n);
    const d = diffStruct(fields, a, b);
    expect(d.changed).toEqual([{ name: "health", offset: 0, type: "u32", before: "100", after: "80" }]);
    expect(d.unchanged).toBe(2);
    expect(d.unmapped).toEqual([]);
  });

  it("reports unmapped changed bytes and short buffers", () => {
    const a = mk(100, 1.5, 7n);
    const b = mk(100, 1.5, 7n);
    b[15] = 0xff; // inside flags? flags is bytes 8..15, so mapped; use a tail byte instead
    const c = mk(100, 1.5, 7n);
    c[15] = 0xff;
    const d = diffStruct(fields, b, c);
    expect(d.changed).toEqual([]); // byte 15 is the last byte of flags (u64) — still mapped
    const e = new Uint8Array(18);
    e.set(a);
    e[16] = 1;
    e[17] = 2;
    const d2 = diffStruct(fields, a, e);
    expect(d2.unmapped).toEqual([{ offset: 16, length: 2 }]);
    const short = a.slice(0, 10);
    const d3 = diffStruct(fields, a, short);
    expect(d3.changed.map((x) => x.name)).toContain("flags");
    expect(d3.changed.find((x) => x.name === "flags")?.after).toBe("<short>");
  });
});
