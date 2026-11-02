import { describe, expect, it } from "vitest";
import { layout } from "./struct";
import { fromOffsets, guessFields, placeField, pointerTargets, type GuessContext } from "./structguess";

const modules = [{ name: "game.exe", base: "0x140000000", size: 0x100000 }];
const regions = [
  { base: "0x140000000", size: 0x1000, writable: false, executable: false }, // headers
  { base: "0x140001000", size: 0x7f000, writable: false, executable: true }, // .text
  { base: "0x140080000", size: 0x40000, writable: false, executable: false }, // .rdata
  { base: "0x1400c0000", size: 0x40000, writable: true, executable: false }, // .data
  { base: "0x20000000", size: 0x100000, writable: true, executable: false }, // heap
];

function obj(slots: (bigint | number[])[]): Uint8Array {
  const b = new Uint8Array(slots.length * 8);
  const dv = new DataView(b.buffer);
  slots.forEach((s, i) => (typeof s === "bigint" ? dv.setBigUint64(i * 8, s, true) : b.set(s, i * 8)));
  return b;
}
const qw = (...v: bigint[]) => { const b = new Uint8Array(v.length * 8); v.forEach((x, i) => new DataView(b.buffer).setBigUint64(i * 8, x, true)); return b; };
const f32pair = (a: number, b: number) => { const x = new Uint8Array(8); const dv = new DataView(x.buffer); dv.setFloat32(0, a, true); dv.setFloat32(4, b, true); return [...x]; };
const f64 = (d: number) => { const x = new Uint8Array(8); new DataView(x.buffer).setFloat64(0, d, true); return [...x]; };
const ascii = (s: string) => [...new TextEncoder().encode(s)];

describe("structguess", () => {
  const buf = obj([
    0x140080100n, // vtable in .rdata
    0x20000010n, // heap object
    0x20000100n, // heap char*
    0x1400c0010n, // module global
    0x140001234n, // function pointer
    0n,
    f32pair(1.5, -2.25),
    f64(1234.5),
    [1, 0, 0, 0, 7, 0, 0, 0],
    [0xff, 0xff, 0xff, 0xff, 0x10, 0x27, 0, 0], // -1, 10000
    ascii("PlayerNa"), ascii("me_Long"), [0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0],
    0xff800001ff800001n, // NaN halves
  ]);
  const deref = new Map<string, Uint8Array>([
    ["0x140080100", qw(0x140001000n, 0x140001010n, 0x140001020n)],
    ["0x20000010", qw(0x140080100n, 5n)],
    ["0x20000100", new Uint8Array([...ascii("hello world"), 0])],
  ]);
  const ctx: GuessContext = { modules, regions, deref, rtti: new Map([[0, "class Player"]]) };

  it("lists pointer targets for the deref pass", () => {
    expect(pointerTargets(buf, ctx).sort()).toEqual(["0x140001234", "0x140080100", "0x1400c0010", "0x20000010", "0x20000100"].sort());
  });

  it("classifies every slot", () => {
    const g = guessFields(buf, ctx);
    const by = (o: number) => g.find((x) => x.offset === o)!;
    expect(by(0)).toMatchObject({ kind: "vtable", type: "ptr", name: "vtable" });
    expect(by(0).label).toContain("game.exe+0x80100");
    expect(by(0).label).toContain("class Player");
    expect(by(8)).toMatchObject({ kind: "heap-ptr", type: "ptr" });
    expect(by(0x10)).toMatchObject({ kind: "string-ptr" });
    expect(by(0x10).label).toContain("hello world");
    expect(by(0x18)).toMatchObject({ kind: "module-ptr", label: "→ game.exe+0xc0010" });
    expect(by(0x20)).toMatchObject({ kind: "code-ptr" });
    expect(by(0x28)).toMatchObject({ kind: "zero", type: "hex64" });
    expect(by(0x30)).toMatchObject({ kind: "f32", type: "f32" });
    expect(by(0x34)).toMatchObject({ kind: "f32", label: "float -2.25" });
    expect(by(0x38)).toMatchObject({ kind: "f64", label: "double 1234.5" });
    expect(by(0x40)).toMatchObject({ kind: "bool" });
    expect(by(0x44)).toMatchObject({ kind: "small-int" });
    expect(by(0x48)).toMatchObject({ kind: "int", type: "i32", label: "int (-1)" });
    expect(by(0x4c)).toMatchObject({ kind: "int", label: "int (10000)" });
    expect(by(0x50)).toMatchObject({ kind: "ascii", type: "ascii" });
    // the inline string swallowed 0x58..0x6f
    expect(g.some((x) => x.offset > 0x50 && x.offset < 0x70)).toBe(false);
    expect(by(0x70)).toMatchObject({ kind: "unknown", type: "hex64" });
  });

  it("does not call an rdata pointer a vtable when its slots are not code", () => {
    const g = guessFields(obj([0x140080200n]), { modules, regions, deref: new Map([["0x140080200", qw(5n, 6n)]]) });
    expect(g[0].kind).toBe("module-ptr");
  });

  it("falls back to module pointers without a region map", () => {
    const g = guessFields(obj([0x140080100n, 0x20000010n]), { modules, regions: [] });
    expect(g[0].kind).toBe("module-ptr");
    expect(g[1].kind).not.toContain("ptr");
  });

  it("detects UTF-16 inline strings and wchar_t* targets", () => {
    const w = [...new Uint8Array([...ascii("Hello!")].flatMap((c) => [c, 0]))];
    const g = guessFields(new Uint8Array([...w, ...new Array(64 - w.length).fill(0)]), { modules, regions });
    expect(g[0]).toMatchObject({ kind: "utf16", type: "utf16" });
    const p = guessFields(obj([0x20000200n]), { modules, regions, deref: new Map([["0x20000200", new Uint8Array([...w, 0, 0])]]) });
    expect(p[0]).toMatchObject({ kind: "wstring-ptr" });
  });

  it("places fields without shifting the rest", () => {
    const base = fromOffsets(0x20, []);
    expect(base).toHaveLength(4);
    const f = placeField(base, 0x0c, { type: "f32", name: "hp" });
    const lay = layout(f);
    expect(lay[f.findIndex((x) => x.name === "hp")].offset).toBe(0x0c);
    expect(lay.at(-1)!.offset + lay.at(-1)!.size).toBe(0x20);
    // wider than what it replaces, and past the end
    const g = placeField(f, 0x08, { type: "hex64", name: "" });
    expect(layout(g).at(-1)!.offset + layout(g).at(-1)!.size).toBe(0x20);
    const h = placeField(g, 0x30, { type: "ptr", name: "far" });
    expect(layout(h)[h.length - 1]).toEqual({ offset: 0x30, size: 8 });
    // same range keeps the user's name
    const k = placeField([{ type: "hex64", name: "mine" }], 0, { type: "ptr", name: "" });
    expect(k).toEqual([{ type: "ptr", name: "mine" }]);
  });

  it("builds sparse layouts", () => {
    const f = fromOffsets(0x28, [[0, "ptr", "vtable"], [0x0c, "i32", "InternalIndex"], [0x20, "ptr", "Outer"]]);
    const lay = layout(f);
    const at = (n: string) => lay[f.findIndex((x) => x.name === n)].offset;
    expect([at("vtable"), at("InternalIndex"), at("Outer")]).toEqual([0, 0x0c, 0x20]);
    expect(lay.at(-1)!.offset + lay.at(-1)!.size).toBe(0x28);
  });
});
