import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { layout } from "./struct";
import { pdbCatalog, pdbDecl, pdbFields, type PdbLayout } from "./pdbtypes";

// The relay's pdb_type reply for `struct Entity` of src-tauri/relay/tests/fixtures/pdbtypes/types.c
// (the relay's own test checks it still produces exactly this).
const entity = JSON.parse(readFileSync(new URL("../../../src-tauri/relay/tests/fixtures/pdbtypes/entity.json", import.meta.url), "utf8")) as PdbLayout;

const offsets = (l: PdbLayout) => {
  const f = pdbFields(l);
  const lay = layout(f);
  return { fields: f, at: (name: string) => lay[f.findIndex((x) => x.name === name)]?.offset, size: lay.length ? lay[lay.length - 1].offset + lay[lay.length - 1].size : 0 };
};

describe("PDB type → struct fields", () => {
  it("keeps every offset of a real lld/clang layout", () => {
    const r = offsets(entity);
    expect(r.size).toBe(entity.size);
    for (const f of entity.fields!) {
      if (f.category === "udt" || f.category === "array") continue;
      expect([f.name, r.at(f.name)]).toEqual([f.name, f.offset]);
    }
    expect(r.fields.find((f) => f.name === "next")?.type).toBe("ptr");
    expect(r.fields.find((f) => f.name === "id")?.type).toBe("u64");
    expect(r.fields.find((f) => f.name === "pad")?.type).toBe("u8");
    expect(r.fields.find((f) => f.name === "color")?.type).toBe("i32");
  });

  it("turns float triples into vec3, spells out short struct arrays, merges bitfields and unions", () => {
    const r = offsets(entity);
    expect(r.fields.find((f) => f.name === "pos")?.type).toBe("vec3");
    expect(r.at("pos")).toBe(8);
    expect(r.fields.filter((f) => /^path\[\d\]$/.test(f.name)).map((f) => f.type)).toEqual(["vec3", "vec3", "vec3", "vec3"]);
    expect(r.at("path[3]")).toBe(20 + 3 * 12);
    const flags = r.fields.find((f) => f.name.startsWith("flags."))!;
    expect(flags).toEqual({ type: "u32", name: "flags.visible:1,kind:3,team:4,rest:24" });
    expect(r.at(flags.name)).toBe(68);
    const value = r.fields.find((f) => f.name.startsWith("value."))!;
    expect(value.name).toBe("value.i|f|bytes");
    expect(r.at(value.name)).toBe(72);
    // char[16] stays bytes, named on its first row
    expect(r.at("name")).toBe(96);
    expect(r.fields.find((f) => f.name === "name")?.type).toBe("hex64");
  });

  it("flattens nested structs with dotted names and pads gaps", () => {
    const inner: PdbLayout = { index: 2, name: "Inner", kind: "struct", size: 8, fields: [
      { name: "a", offset: 0, size: 2, type: "short", category: "primitive", scalar: "i16", kind: "member" },
      { name: "b", offset: 4, size: 4, type: "double", category: "primitive", scalar: "f64", kind: "member" },
    ] };
    const outer: PdbLayout = { index: 1, name: "Outer", kind: "class", size: 0x20, nested: [inner], fields: [
      { name: "vftable", offset: 0, size: 8, type: "void**", category: "pointer", scalar: "ptr", kind: "vtable" },
      { name: "in", offset: 0x10, size: 8, type: "Inner", category: "udt", udt: 2, kind: "member" },
      { name: "big", offset: 0x18, size: 8, type: "Missing", category: "udt", udt: 99, kind: "member" },
    ] };
    const f = pdbFields(outer);
    expect(f.map((x) => x.name)).toEqual(["vftable", "", "in.a", "", "in.b", "big"]);
    expect(f.map((x) => x.type)).toEqual(["ptr", "hex64", "i16", "hex16", "hex32", "hex64"]);
    expect(layout(f).at(-1)).toEqual({ offset: 0x18, size: 8 });
  });

  it("imports the type with its nested structs as catalog entries and prints a declaration", () => {
    const c = pdbCatalog(entity);
    expect(c.map((x) => x.name)).toEqual(["Entity", "Vec3", "Flags", "Value"]);
    expect(c[1].fields).toEqual([{ type: "f32", name: "x" }, { type: "f32", name: "y" }, { type: "f32", name: "z" }]);
    const d = pdbDecl(entity);
    expect(d).toContain("struct Entity { // 0x80 bytes");
    expect(d).toContain("/* 0x070 */ int (*on_hit)(int, void*);");
    expect(d).toContain("/* 0x060 */ char name[16];");
    const flags = entity.nested!.find((n) => n.name === "Flags")!;
    expect(pdbDecl(flags)).toContain("unsigned int kind : 3;");
    expect(pdbDecl(entity.nested!.find((n) => n.name === "Color")!)).toContain("COLOR_BLUE = 4,");
  });
});
