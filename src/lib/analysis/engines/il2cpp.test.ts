import { describe, expect, it } from "vitest";
import { applyMethodPointers, dumpCs, parseMetadata, scriptJson } from "./il2cpp";
import { il2cppMetadata as metadata } from "./testengines";

describe("il2cpp metadata", () => {
  it("parses images, types, fields and methods with derived record sizes", () => {
    for (const slot of [0xa8, 0xb0]) {
      const md = parseMetadata(metadata(slot));
      expect(md.version).toBe(29);
      expect(md.sizes).toEqual({ image: 40, type: 88, method: 32, field: 12 });
      const [im] = md.images;
      expect(im.name).toBe("Assembly-CSharp.dll");
      expect(im.methodCount).toBe(3);
      expect(im.types.map((t) => `${t.namespace}.${t.name}`)).toEqual(["Game.Player", "Game.Enemy"]);
      expect(im.types[0].fields.map((f) => f.name)).toEqual(["health", "speed"]);
      expect(im.types[0].methods.map((m) => [m.name, m.params])).toEqual([["Update", 0], ["TakeDamage", 1]]);
      expect(im.types[1].methods[0].name).toBe(".ctor");
    }
    expect(() => parseMetadata(new Uint8Array(0x200))).toThrow(/sanity/);
  });

  it("recovers method RVAs from the code-gen module table", () => {
    const md = parseMetadata(metadata());
    const base = 0x180000000n;
    const ga = new Uint8Array(0x3000);
    const dv = new DataView(ga.buffer);
    ga.set(new TextEncoder().encode("Assembly-CSharp.dll\0"), 0x100);
    // Il2CppCodeGenModule at .data+0x2000: name ptr, count, methodPointers -> table at 0x1800
    dv.setBigUint64(0x2000, base + 0x100n, true);
    dv.setUint32(0x2008, 3, true);
    dv.setBigUint64(0x2010, base + 0x1800n, true);
    [0x1000, 0x1040, 0x1080].forEach((rva, i) => dv.setBigUint64(0x1800 + i * 8, base + BigInt(rva), true));
    expect(applyMethodPointers(md, ga, base, [{ rva: 0x2000, size: 0x1000 }])).toEqual(["Assembly-CSharp.dll"]);
    expect(md.images[0].types[0].methods.map((m) => m.rva)).toEqual([0x1000, 0x1040]);
    expect(md.images[0].types[1].methods[0].rva).toBe(0x1080);
    expect(dumpCs(md)).toContain("// RVA: 0x1040 Token: 0x6000002");
    expect(scriptJson(md).ScriptMethod).toContainEqual({ Address: 0x1080, Name: "Game_Enemy$$.ctor", Signature: "", TypeSignature: "" });
  });
});
