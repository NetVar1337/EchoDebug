import { describe, expect, it } from "vitest";
import { dumpNetvars, flatten, netvarText } from "./source";
import { sourceImage as image } from "./testengines";

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
