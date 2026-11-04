// Tests for the vtable report: RTTI class resolution, slot counting,
// INHERIT/OVERRIDE diff against a base vtable, prefixes, duplicates.
import { describe, expect, it } from "vitest";
import { classOnly, vtableReport, type VtReader } from "./vtablereport";

const VT = 0x8000;
const BASE_VT = 0x8100;
const F1 = 0x6000n;
const F2 = 0x6100n;
const F3 = 0x6200n;
const F4 = 0x6300n;

function mem(): { buf: Uint8Array; read: VtReader } {
  const buf = new Uint8Array(0x10000);
  const dv = new DataView(buf.buffer);
  const p64 = (o: number, v: bigint) => dv.setBigUint64(o, v, true);
  const str = (o: number, t: string) => buf.set(new TextEncoder().encode(t + "\0"), o);
  // vtable slots: F1, F2, F1(dup), F3 ; then a zero qword (end)
  p64(VT, F1);
  p64(VT + 8, F2);
  p64(VT + 16, F1);
  p64(VT + 24, F3);
  // base vtable: F1, F4, F1, F4
  p64(BASE_VT, F1);
  p64(BASE_VT + 8, F4);
  p64(BASE_VT + 16, F1);
  p64(BASE_VT + 24, F4);
  // RTTI: vtable-8 -> COL(0x9000): sig 1, td 0xA000; td+8 -> mangled; td-0x10 -> bcd 0xA100 -> base td
  p64(VT - 8, 0x9000n);
  dv.setUint32(0x9000, 1, true);
  p64(0x9000 + 16, 0xa000n);
  str(0xb000, ".?AVC_WeaponX@@");
  p64(0xa000 + 8, 0xb000n);
  p64(0xa000 - 0x10, 0xa100n);
  str(0xb100, ".?AVC_BaseCombatWeapon@@");
  p64(0xa100 + 8, 0xb100n);
  // object whose head is the vtable
  p64(0x7000, BigInt(VT));
  // function bytes for prefixes
  buf.set([0x48, 0x89, 0x5c, 0x24], Number(F1));
  buf.set([0x40, 0x53, 0x48, 0x83], Number(F2));
  const read: VtReader = async (addr, size) => {
    const o = Number(addr);
    return o >= 0 && o + size <= buf.length ? buf.subarray(o, o + size) : null;
  };
  return { buf, read };
}

const code = (a: bigint) => a >= 0x6000n && a < 0x7000n;

describe("vtable report", () => {
  it("resolves the class from RTTI and counts slots until the first non-pointer", async () => {
    const { read } = mem();
    const r = await vtableReport(read, BigInt(VT), { code });
    expect(r.class).toBe("C_WeaponX");
    expect(r.base_class).toBe("C_BaseCombatWeapon");
    expect(r.slots).toBe(4);
    expect(r.complete).toBe(true);
    expect(r.rows.map((x) => x.function)).toEqual([F1, F2, F1, F3]);
  });

  it("diffs a base vtable into INHERIT/OVERRIDE and flags duplicates", async () => {
    const { read } = mem();
    const r = await vtableReport(read, BigInt(VT), { base: BigInt(BASE_VT), code });
    expect(r.rows.map((x) => x.status)).toEqual(["INHERIT", "OVERRIDE", "INHERIT", "OVERRIDE"]);
    expect(r.rows.map((x) => x.base)).toEqual([F1, F4, F1, F4]);
    expect(r.overrides).toBe(2);
    expect(r.rows[2].duplicate).toBe(true);
    expect(r.rows[0].duplicate).toBe(false);
  });

  it("reads an object head with fromObject and captures byte prefixes", async () => {
    const { read } = mem();
    const r = await vtableReport(read, 0x7000n, { fromObject: true, prefixBytes: 4, code });
    expect(r.vtable).toBe(BigInt(VT));
    expect(r.rows[0].prefix).toBe("48895c24");
    expect(r.rows[1].prefix).toBe("40534883");
  });

  it("honours an exact slot count and stops on non-code without one", async () => {
    const { read } = mem();
    const exact = await vtableReport(read, BigInt(VT), { slots: 6, code });
    expect(exact.slots).toBe(6);
    expect(exact.complete).toBe(true); // an explicit count is exact by definition
    expect(exact.rows[4].function).toBe(0n); // zero qword after the slots
    const noCode = await vtableReport(read, BigInt(VT), { code: () => false });
    expect(noCode.slots).toBe(0);
  });

  it("demangles MSVC RTTI names", () => {
    expect(classOnly(".?AVC_WeaponX@@")).toBe("C_WeaponX");
    expect(classOnly(".?AVC_BaseCombatWeapon@@")).toBe("C_BaseCombatWeapon");
    expect(classOnly("class Foo")).toBe("Foo");
    expect(classOnly("")).toBe("");
  });
});
