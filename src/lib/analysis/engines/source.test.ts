import { describe, expect, it } from "vitest";
import { dumpNetvars, flatten, netvarText } from "./source";

/** A tiny x64 client image: two ClientClasses, a derived table with a baseclass and a nested table. */
function image() {
  const base = 0x180000000n;
  const img = new Uint8Array(0x4000);
  const dv = new DataView(img.buffer);
  let str = 0x100;
  const s = (t: string) => { const a = str; img.set(new TextEncoder().encode(t + "\0"), a); str += t.length + 1; return base + BigInt(a); };
  const p64 = (o: number, v: bigint) => dv.setBigUint64(o, v, true);
  // RecvProp x64 (0x60 bytes): name 0, type 8, datatable 0x40, offset 0x48, elements 0x50
  const prop = (o: number, name: string, type: number, offset: number, table = 0n) => { p64(o, s(name)); dv.setInt32(o + 8, type, true); p64(o + 0x40, table); dv.setInt32(o + 0x48, offset, true); dv.setInt32(o + 0x50, 1, true); };
  // RecvTable x64: props 0, count 8, name 0x18
  const table = (o: number, name: string, props: number, n: number) => { p64(o, base + BigInt(props)); dv.setInt32(o + 8, n, true); p64(o + 0x18, s(name)); return base + BigInt(o); };
  const dtLocal = table(0x2000, "DT_LocalData", 0x2100, 1);
  prop(0x2100, "m_vecVelocity", 2, 0x10);
  const dtBase = table(0x2200, "DT_BaseEntity", 0x2300, 2);
  prop(0x2300, "m_iTeamNum", 0, 0xf4);
  prop(0x2360, "m_vecOrigin", 2, 0x138);
  const dtPlayer = table(0x2400, "DT_BasePlayer", 0x2500, 3);
  prop(0x2500, "baseclass", 6, 0, dtBase);
  prop(0x2560, "m_iHealth", 0, 0x100);
  prop(0x25c0, "localdata", 6, 0x200, dtLocal);
  // ClientClass x64: name 0x10, table 0x18, next 0x20, id 0x28
  const cc = (o: number, name: string, t: bigint, next: bigint, id: number) => { p64(o + 0x10, s(name)); p64(o + 0x18, t); p64(o + 0x20, next); dv.setInt32(o + 0x28, id, true); return base + BigInt(o); };
  const c2 = cc(0x3040, "C_BaseEntity", dtBase, 0n, 1);
  cc(0x3000, "C_BasePlayer", dtPlayer, c2, 2);
  return { img, base };
}

describe("source netvars", () => {
  it("finds the ClientClass chain and walks the tables", () => {
    const { img, base } = image();
    const d = dumpNetvars(img, base, true)!;
    expect(d.head).toBe(base + 0x3000n);
    expect(d.classes.map((c) => [c.name, c.table, c.id])).toEqual([["C_BasePlayer", "DT_BasePlayer", 2], ["C_BaseEntity", "DT_BaseEntity", 1]]);
    expect(Object.keys(d.tables).sort()).toEqual(["DT_BaseEntity", "DT_BasePlayer", "DT_LocalData"]);
    const flat = flatten(d, "DT_BasePlayer");
    expect(flat).toContainEqual({ name: "m_iTeamNum", offset: 0xf4, type: "int" });
    expect(flat).toContainEqual({ name: "m_iHealth", offset: 0x100, type: "int" });
    expect(flat).toContainEqual({ name: "localdata.m_vecVelocity", offset: 0x210, type: "vector" });
    expect(netvarText(d)).toContain("0x0100  m_iHealth  [int]");
  });
  it("returns null when there is no chain", () => {
    expect(dumpNetvars(new Uint8Array(0x1000), 0x10000000n, true)).toBeNull();
  });
});
