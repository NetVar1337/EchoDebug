import { describe, expect, it } from "vitest";
import { applyMethodPointers, dumpCs, parseMetadata, scriptJson } from "./il2cpp";

/** A v29-shaped global-metadata.dat: one image, two types, three methods, two fields. */
function metadata(imageSlot = 0xa8) {
  const b = new Uint8Array(0x1000);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, 0xfab11baf, true);
  dv.setInt32(4, 29, true);
  // strings at 0x200
  let sp = 0;
  const strs = new Uint8Array(0x200);
  const s = (t: string) => { const i = sp; strs.set(new TextEncoder().encode(t + "\0"), i); sp += t.length + 1; return i; };
  const img = s("Assembly-CSharp.dll"), ns = s("Game"), player = s("Player"), enemy = s("Enemy");
  const update = s("Update"), takeDamage = s("TakeDamage"), ctor = s(".ctor"), hp = s("health"), spd = s("speed");
  b.set(strs, 0x200);
  const pair = (o: number, off: number, size: number) => { dv.setUint32(o, off, true); dv.setUint32(o + 4, size, true); };
  pair(0x18, 0x200, 0x200);
  // types (88 bytes): name 0, namespace 4, fieldStart size-56, methodStart size-52, method_count size-24, field_count size-20, token size-4
  const TS = 88;
  const type = (i: number, name: number, fieldStart: number, fc: number, methodStart: number, mc: number) => {
    const o = 0x400 + i * TS;
    dv.setInt32(o, name, true); dv.setInt32(o + 4, ns, true);
    dv.setInt32(o + TS - 56, fieldStart, true); dv.setInt32(o + TS - 52, methodStart, true);
    dv.setUint16(o + TS - 24, mc, true); dv.setUint16(o + TS - 20, fc, true);
    dv.setUint32(o + TS - 4, 0x02000002 + i, true);
  };
  type(0, player, 0, 2, 0, 2);
  type(1, enemy, -1, 0, 2, 1);
  pair(0xa0, 0x400, 2 * TS);
  // methods (32 bytes): name 0, token size-12, params size-2
  const MS = 32;
  [[update, 0], [takeDamage, 1], [ctor, 0]].forEach(([n, params], i) => {
    const o = 0x600 + i * MS;
    dv.setInt32(o, n, true); dv.setUint32(o + MS - 12, 0x06000001 + i, true); dv.setUint16(o + MS - 2, params, true);
  });
  pair(0x30, 0x600, 3 * MS);
  // fields (12 bytes): name 0, token 8
  [hp, spd].forEach((n, i) => { dv.setInt32(0x700 + i * 12, n, true); dv.setUint32(0x700 + i * 12 + 8, 0x04000001 + i, true); });
  pair(0x60, 0x700, 24);
  // image (40 bytes): name 0, typeStart 8, typeCount 12
  dv.setInt32(0x800, img, true); dv.setInt32(0x808, 0, true); dv.setUint32(0x80c, 2, true);
  pair(imageSlot, 0x800, 40);
  return b;
}

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
