// Tests for the Respawn-Source automation: offset harvest (both descriptor layouts),
// ClientClass lookup, Squirrel binding dump, rip-relative lea map, ctor vtable stores.
import { describe, expect, it } from "vitest";
import { dumpScriptBindings, findClientClass, findCtorVtables, findRipLeas, harvestOffsets } from "./respawn";

const base = 0x140000000n;
const STR = 0x1000;
const DATA = 0x2000;
const CC = 0x3000;
const RT = 0x3100;
const BIND = 0x4000;
const CODE = 0x5000;
const RDATA = 0x6000;

type B = { img: Uint8Array; dv: DataView };
function image(): B {
  const img = new Uint8Array(0x8000);
  const dv = new DataView(img.buffer);
  return { img, dv };
}
let strOff = STR;
function str(b: B, t: string): number {
  const o = strOff;
  b.img.set(new TextEncoder().encode(t + "\0"), o);
  strOff += t.length + 1;
  return o;
}
const p64 = (b: B, o: number, v: bigint | number) => b.dv.setBigUint64(o, BigInt(v), true);
const i32 = (b: B, o: number, v: number) => b.dv.setInt32(o, v, true);

const dataRanges = [{ rva: DATA, size: 0x2000 }];
const execRanges = [{ rva: CODE, size: 0x1000 }];
const rdataRanges = [{ rva: RDATA, size: 0x1000 }];

describe("respawn offset harvest", () => {
  it("cross-confirms offsets across both descriptor layouts", () => {
    const b = image();
    const health = str(b, "m_iHealth");
    const origin = str(b, "m_vecAbsOrigin");
    // TABLE-2 (DataDesc) for m_iHealth @ DATA: type 0, offset 0x330, string at +0x28
    i32(b, DATA, 0);
    i32(b, DATA + 4, 0x330);
    p64(b, DATA + 0x28, health);
    // TABLE-1 (compact RecvProp) @ DATA+0x100: string, offset at +8
    p64(b, DATA + 0x100, health);
    i32(b, DATA + 0x108, 0x330);
    // TABLE-2 composite (type 1) for m_vecAbsOrigin @ DATA+0x200
    i32(b, DATA + 0x200, 1);
    i32(b, DATA + 0x204, 0x54);
    p64(b, DATA + 0x228, origin);
    const h = harvestOffsets(b.img, base, ["m_iHealth", "m_vecAbsOrigin"], dataRanges);
    const healthF = h.fields.find((f) => f.name === "m_iHealth")!;
    expect(healthF.confirmed).toBe(0x330);
    expect(healthF.hits.map((x) => x.layout).sort()).toEqual(["table1", "table2"]);
    const originF = h.fields.find((f) => f.name === "m_vecAbsOrigin")!;
    expect(originF.confirmed).toBe(0); // single layout only
    expect(originF.composite).toBe(true);
    expect(h.cpp).toContain("#define OFF_M_IHEALTH  0x0330");
  });

  it("reports zero hits for unknown names", () => {
    const b = image();
    const h = harvestOffsets(b.img, base, ["m_nope"], dataRanges);
    expect(h.fields[0].hits).toEqual([]);
    expect(h.fields[0].strings).toBe(0);
  });
});

describe("respawn ClientClass", () => {
  it("finds the struct by network name with table, class name, next and id", () => {
    const b = image();
    const net = str(b, "CWeaponX");
    const cls = str(b, "C_WeaponX");
    const dt = str(b, "DT_WeaponX");
    // RecvTable name pointer at table+0x18
    p64(b, RT + 0x18, dt);
    // classic x64 ClientClass: name @+0x10, table @+0x18, next @+0x20, id @+0x28
    p64(b, CC + 0x10, net);
    p64(b, CC + 0x18, RT);
    p64(b, CC + 0x20, 0);
    i32(b, CC + 0x28, 7);
    p64(b, CC + 0x30, cls);
    const hit = findClientClass(b.img, base, "CWeaponX", dataRanges)!;
    expect(hit.address).toBe(base + BigInt(CC));
    expect(hit.class_name).toBe("C_WeaponX");
    expect(hit.table_name).toBe("DT_WeaponX");
    expect(hit.id).toBe(7);
    expect(hit.kind).toBe("classic");
    expect(findClientClass(b.img, base, "CMissing", dataRanges)).toBeNull();
  });
});

describe("respawn script bindings", () => {
  it("dumps {name, handler} pairs at stride 16 and stops at the terminator", () => {
    const b = image();
    const names = ["IsPredicted", "GetWeaponPrintName", "SetWeaponSkin", "GetAttackSpreadAngle"].map((t) => str(b, t));
    names.forEach((n, i) => {
      p64(b, BIND + i * 16, n);
      p64(b, BIND + i * 16 + 8, base + BigInt(CODE + 0x20 + i * 0x20));
    });
    p64(b, BIND + 4 * 16, 0n); // terminator
    const d = dumpScriptBindings(b.img, base, base + BigInt(BIND), execRanges)!;
    expect(d.stride).toBe(16);
    expect(d.count).toBe(4);
    expect(d.complete).toBe(true);
    expect(d.entries.map((e) => e.name)).toEqual(["IsPredicted", "GetWeaponPrintName", "SetWeaponSkin", "GetAttackSpreadAngle"]);
    expect(d.entries[0].handler).toBe(base + BigInt(CODE + 0x20));
  });

  it("returns null when nothing validates", () => {
    const b = image();
    expect(dumpScriptBindings(b.img, base, base + BigInt(BIND), execRanges)).toBeNull();
  });
});

describe("rip-relative lea map and ctor vtable stores", () => {
  it("indexes lea targets and finds constructor vtable installs", () => {
    const b = image();
    const name = str(b, "IsPredicted");
    // lea rax,[rip+disp] at CODE whose target is the string
    b.img[CODE] = 0x48;
    b.img[CODE + 1] = 0x8d;
    b.img[CODE + 2] = 0x05;
    i32(b, CODE + 3, name - (CODE + 7));
    // ctor at CODE+0x40: lea rax,[rip] (vtable in rdata) ; mov [rcx+0x1650], rax
    const lea = CODE + 0x40;
    b.img[lea] = 0x48;
    b.img[lea + 1] = 0x8d;
    b.img[lea + 2] = 0x05;
    i32(b, lea + 3, RDATA - (lea + 7));
    b.img[lea + 7] = 0x48;
    b.img[lea + 8] = 0x89;
    b.img[lea + 9] = 0x81; // mov [rcx+disp32], rax
    i32(b, lea + 10, 0x1650);
    const leas = findRipLeas(b.img, execRanges);
    expect(leas.get(name)).toContain(CODE);
    const stores = findCtorVtables(b.img, base, execRanges, rdataRanges);
    expect(stores).toContainEqual({ site: base + BigInt(lea), vtable: base + BigInt(RDATA), object_offset: 0x1650 });
  });
});
