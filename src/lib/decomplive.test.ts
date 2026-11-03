import { describe, expect, it, vi } from "vitest";

vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => undefined, removeItem: () => undefined });
vi.mock("./client", () => ({ client: { send: () => undefined }, request: async () => ({ results: [] }) }));

const { directCallees, fieldsFrom, imageString, liveNameOf, structureOf } = await import("./decomplive");
const { buildIr } = await import("./analysis/decompile");
const { buildStructure } = await import("./analysis/structure");

describe("decompiler against the live target", () => {
  it("reads C strings from the module image", () => {
    const img = new Uint8Array(0x40);
    img.set(new TextEncoder().encode("hello %s\n\0"), 0x10);
    img.set([0x41, 0x01, 0x00], 0x30);
    const at = imageString(img, 0x400000n);
    expect(at(0x400010n)).toBe("hello %s\n");
    expect(at(0x400030n)).toBeNull(); // not printable
    expect(at(0x500000n)).toBeNull(); // outside the image
    expect(imageString(null, 0n)(0x10n)).toBeNull();
  });

  it("struct layouts come from the Structs catalog", () => {
    const fields = fieldsFrom([{ id: "1", name: "Player", fields: [{ type: "ptr", name: "vtable" }, { type: "i32", name: "health" }, { type: "hex32", name: "" }, { type: "f32", name: "speed" }] }]);
    expect(fields("player")).toEqual([
      { offset: 0, size: 8, name: "vtable", type: "ptr" },
      { offset: 8, size: 4, name: "health", type: "i32" },
      { offset: 12, size: 4, name: "field_c", type: "hex32" },
      { offset: 16, size: 4, name: "speed", type: "f32" },
    ]);
    expect(fields("Enemy")).toBeNull();
  });

  it("names: the user's first, then the imports", () => {
    const nameOf = liveNameOf((a) => (a === "0x401000" ? "main" : ""), null, 0n);
    expect(nameOf("0x401000")).toBe("main");
    expect(nameOf("0x402000")).toBe("");
  });

  it("switch tables of the graph become case edges, direct callees are listed", () => {
    const line = (a: number, text: string, length = 2) => ({ address: "0x" + a.toString(16), length, bytes: "", text });
    const cfg = {
      entry: 0x10n,
      truncated: false,
      blocks: [
        { start: 0x10n, end: 0x14n, terminator: "indirect" as const, lines: [line(0x10, "call 0x900"), line(0x12, "jmp qword ptr [rcx*8+0x1000]")] },
        { start: 0x20n, end: 0x22n, terminator: "ret" as const, lines: [line(0x20, "ret")] },
        { start: 0x30n, end: 0x32n, terminator: "ret" as const, lines: [line(0x30, "ret")] },
      ],
      edges: [],
      switches: new Map([[0x12n, [0x20n, 0x30n, 0x20n]]]),
    };
    const st = structureOf(cfg);
    expect(st.edges.filter((e) => e.kind === "case").map((e) => [e.to, e.values])).toEqual([[1, [0, 2]], [2, [1]]]);
    const { ir } = buildIr(buildStructure(st.blocks.flatMap((b) => b.insns)));
    expect(directCallees(ir)).toEqual(["0x900"]);
  });
});
