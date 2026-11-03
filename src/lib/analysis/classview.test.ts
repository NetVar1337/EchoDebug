import { describe, expect, it } from "vitest";
import { classView, diffLiveAgainstRtti, listClasses } from "./classview";
import type { RttiInventory } from "./rtti";
import type { VObject } from "./vtable";

const inv: RttiInventory = {
  unnamed: 0,
  classes: [
    { mangled: ".?AVPlayer@@", name: "Player", base: "Actor", address: "0x140003000", rva: 0x3000, vftables: [{ address: "0x140004000", rva: 0x4000, slots: 8 }] },
    { mangled: ".?AVEnemy@@", name: "Enemy", base: "Pawn", address: "0x140003100", rva: 0x3100, vftables: [] },
  ],
};

const live: VObject = {
  object: "0x22334455",
  vtable: "0x140004000",
  className: "Player",
  baseName: "Actor",
  failed: null,
  slots: [
    { index: 0, slotAddress: "0x140004000", target: "0x140001000", module: "game.exe", offset: "0x1000", valid: true },
    { index: 1, slotAddress: "0x140004008", target: "0x50000000", module: "heap", offset: "0x0", valid: true }, // patched slot
    { index: 2, slotAddress: "0x140004010", target: "0x0", module: "", offset: "0x0", valid: false },
  ],
};

describe("classView (#22)", () => {
  it("lists all classes", () => {
    expect(listClasses(inv).map((c) => c.name)).toEqual(["Player", "Enemy"]);
  });

  it("joins RTTI with the live object, case-insensitive", () => {
    const v = classView(inv, "player", live);
    expect(v).toMatchObject({ name: "Player", base: "Actor", typeDescriptor: "0x140003000" });
    expect(v!.live?.slots).toHaveLength(3);
    expect(v!.vftables[0].address).toBe("0x140004000");
  });

  it("returns null for unknown classes and handles no-live", () => {
    expect(classView(inv, "Nope")).toBeNull();
    expect(classView(inv, "Enemy")?.live).toBeNull();
  });

  it("flags live slots that point outside the on-disk vftable as hooked", () => {
    const v = diffLiveAgainstRtti(classView(inv, "Player", live)!);
    expect(v.live!.slots.map((s) => !!s.hooked)).toEqual([false, true, false]);
  });
});
