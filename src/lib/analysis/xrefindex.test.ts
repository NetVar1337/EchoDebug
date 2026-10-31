import { describe, expect, it } from "vitest";
import { buildXrefIndex, executableRanges } from "./xrefindex";

describe("xref index", () => {
  it("finds a direct call", () => {
    const img = new Uint8Array(0x1000);
    const dv = new DataView(img.buffer);
    // call rel32 at 0x100, target 0x200 -> rel = 0x200 - 0x105
    dv.setUint8(0x100, 0xe8);
    dv.setInt32(0x101, 0x200 - 0x105, true);
    const idx = buildXrefIndex(img, [{ rva: 0x100, size: 0x20 }]);
    expect(idx.all).toHaveLength(1);
    expect(idx.all[0].kind).toBe("call");
    expect(idx.all[0].fromRva).toBe(0x100);
    expect(idx.all[0].toRva).toBe(0x200);
    expect(idx.to.get(0x200)).toHaveLength(1);
    expect(idx.from.get(0x100)).toHaveLength(1);
  });

  it("finds a direct jump and a conditional jump", () => {
    const img = new Uint8Array(0x1000);
    const dv = new DataView(img.buffer);
    dv.setUint8(0x100, 0xe9);
    dv.setInt32(0x101, 0x300 - 0x105, true);
    dv.setUint8(0x200, 0x0f);
    dv.setUint8(0x201, 0x84);
    dv.setInt32(0x202, 0x400 - 0x206, true);
    const idx = buildXrefIndex(img, [{ rva: 0x100, size: 0x200 }]);
    const kinds = idx.all.map((x) => x.kind).sort();
    expect(kinds).toEqual(["jcc", "jmp"]);
    expect(idx.to.get(0x400)).toHaveLength(1);
  });

  it("finds a rip-relative data reference", () => {
    const img = new Uint8Array(0x1000);
    const dv = new DataView(img.buffer);
    // mov rax, [rip+0xF0] at 0x100: 48 8B 05 F0 00 00 00 -> target 0x1F7
    dv.setUint8(0x100, 0x48);
    dv.setUint8(0x101, 0x8b);
    dv.setUint8(0x102, 0x05);
    dv.setInt32(0x103, 0xf0, true);
    const idx = buildXrefIndex(img, [{ rva: 0x100, size: 0x20 }]);
    const rip = idx.all.find((x) => x.kind === "rip");
    expect(rip).toBeDefined();
    // The instruction is 7 bytes (REX, opcode, ModRM, disp32) so it ends at
    // 0x107 and the displacement is relative to that.
    expect(rip!.fromRva).toBe(0x100);
    expect(rip!.toRva).toBe(0x107 + 0xf0);
  });

  it("returns nothing for an empty range", () => {
    expect(buildXrefIndex(new Uint8Array(0x100), []).all).toHaveLength(0);
  });

  it("reports no executable ranges for a non-PE image", () => {
    expect(executableRanges(new Uint8Array(0x100))).toHaveLength(0);
  });
});
