import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { bytePatches, parse1337, patchFile, rvaToOffset, to1337 } from "./patchfile";

const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));

describe("x64dbg .1337 patch files", () => {
  it("writes x64dbg's format: >module, then RVA:OLD->NEW per byte", () => {
    const b = bytePatches([
      { module: "game.exe", rva: 0x1234, before: "7405", written: "eb05" },
      { module: "game.exe", rva: 0x2000, before: "90", written: "90" },
      { module: "ntdll.dll", rva: 0x10, before: "c3", written: "cc" },
    ]);
    expect(to1337(b)).toBe(">game.exe\n0000000000001234:74->EB\n>ntdll.dll\n0000000000000010:C3->CC");
    expect(to1337(b, 8)).toContain("00001234:74->EB");
  });

  it("keeps a byte's first original and last value when patched twice", () => {
    const b = bytePatches([
      { module: "m", rva: 0x10, before: "74", written: "eb" },
      { module: "m", rva: 0x10, before: "eb", written: "90" },
    ]);
    expect(b).toEqual([{ module: "m", rva: 0x10, old: 0x74, new: 0x90 }]);
  });

  it("reads them back, reporting what it cannot read", () => {
    const { patches, errors } = parse1337(">game.exe\r\n0000000000001234:74->EB\r\n\r\n1235:5->90\nnonsense\n>other.dll\n10:c3->cc\n");
    expect(patches).toEqual([
      { module: "game.exe", rva: 0x1234, old: 0x74, new: 0xeb },
      { module: "game.exe", rva: 0x1235, old: 0x05, new: 0x90 },
      { module: "other.dll", rva: 0x10, old: 0xc3, new: 0xcc },
    ]);
    expect(errors).toEqual(['line 5: cannot read "nonsense"']);
    expect(parse1337("10:00->01").errors[0]).toMatch(/before any/);
  });
});

describe("patch file", () => {
  const file = fixture("fix-res.exe"); // .text rva 0x1000 raw 0x400; .data rva 0x3000 has no raw data

  it("maps RVAs to file offsets through the section table", () => {
    expect(rvaToOffset(file, 0x1000)).toBe(0x400);
    expect(rvaToOffset(file, 0x1010)).toBe(0x410);
    expect(rvaToOffset(file, 0x6008)).toBe(0xc08);
    expect(rvaToOffset(file, 0x40)).toBe(0x40);
    expect(rvaToOffset(file, 0x3000)).toBeNull();
    expect(rvaToOffset(file, 0x9000)).toBeNull();
  });

  it("writes the patches into a copy and reports bytes the file had differently", () => {
    const orig = file[0x410];
    const { bytes, report } = patchFile(file, [
      { module: "fix-res.exe", rva: 0x1010, old: orig, new: orig ^ 0xff },
      { module: "fix-res.exe", rva: 0x1011, old: (file[0x411] + 1) & 0xff, new: 0x90 },
      { module: "fix-res.exe", rva: 0x3004, old: 0, new: 1 },
    ]);
    expect(bytes[0x410]).toBe(orig ^ 0xff);
    expect(bytes[0x411]).toBe(0x90);
    expect(file[0x410]).toBe(orig);
    expect(report.applied).toBe(2);
    expect(report.differed).toEqual([{ rva: 0x1011, offset: 0x411, file: file[0x411], memory: (file[0x411] + 1) & 0xff }]);
    expect(report.outside).toEqual([0x3004]);
  });
});
