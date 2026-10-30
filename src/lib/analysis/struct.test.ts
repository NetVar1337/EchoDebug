import { describe, expect, it } from "vitest";
import { fieldValue, layout, toCpp } from "./struct";

describe("struct", () => {
  it("lays out cumulatively", () => {
    expect(layout([{ type: "hex64", name: "" }, { type: "f32", name: "hp" }, { type: "vec3", name: "" }])).toEqual([
      { offset: 0, size: 8 }, { offset: 8, size: 4 }, { offset: 12, size: 12 },
    ]);
  });
  it("formats hex fields big-endian for reading", () => {
    expect(fieldValue(new Uint8Array([0x78, 0x56, 0x34, 0x12]), 0, "hex32")).toBe("12345678");
  });
  it("exports C++ with padding", () => {
    const s = toCpp("Player", [{ type: "hex64", name: "" }, { type: "hex64", name: "" }, { type: "f32", name: "health" }, { type: "hex32", name: "" }]);
    expect(s).toContain("uint8_t pad_0x0[0x10];");
    expect(s).toContain("float health; // 0x10");
    expect(s).toContain("uint8_t pad_0x14[0x4];");
    expect(s).toContain("sizeof(Player) == 0x18");
  });
});
