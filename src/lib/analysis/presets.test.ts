import { describe, expect, it } from "vitest";
import { kPresets } from "./presets";
import { layout } from "./struct";

const at = (id: string, name: string) => {
  const p = kPresets.find((x) => x.id === id)!;
  return layout(p.fields)[p.fields.findIndex((f) => f.name === name)]?.offset;
};

describe("presets", () => {
  it("keep every named field at its documented offset", () => {
    expect([at("ue-uobject", "ClassPrivate"), at("ue-uobject", "NameIndex"), at("ue-uobject", "OuterPrivate")]).toEqual([0x10, 0x18, 0x20]);
    expect(at("ue-fuobjectarray", "NumElements")).toBe(0x24);
    expect(at("ue-ulevel", "Actors.Data")).toBe(0x98);
    expect(at("il2cpp-string", "chars")).toBe(0x14);
    expect(at("il2cpp-class", "static_fields")).toBe(0xb8);
    expect(at("s2-entityidentity", "m_pNextByClass")).toBe(0x70);
  });
  it("have unique ids and a description", () => {
    expect(new Set(kPresets.map((p) => p.id)).size).toBe(kPresets.length);
    for (const p of kPresets) expect(p.description.length).toBeGreaterThan(20);
  });
});
