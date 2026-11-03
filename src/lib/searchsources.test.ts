import { describe, expect, it } from "vitest";
import { buildTestPe } from "./analysis/testpe";
import { exportDirOf, parseExportChunk } from "./searchsources";

/** An export directory at 0x2000 with two named exports and one forwarder. */
function exportImage(): { img: Uint8Array; dir: { rva: number; size: number } } {
  const sec = new Uint8Array(0x400);
  const dv = new DataView(sec.buffer);
  const rva = 0x2000;
  const at = (r: number) => r - rva;
  // directory
  dv.setUint32(0x14, 3, true); // functions
  dv.setUint32(0x18, 3, true); // names
  dv.setUint32(0x1c, rva + 0x40, true);
  dv.setUint32(0x20, rva + 0x60, true);
  dv.setUint32(0x24, rva + 0x80, true);
  // functions: 0x1010, 0x1020, forwarder string inside the directory
  dv.setUint32(at(rva + 0x40), 0x1010, true);
  dv.setUint32(at(rva + 0x44), 0x1020, true);
  dv.setUint32(at(rva + 0x48), rva + 0x100, true);
  const names = ["Alpha", "Beta", "Fwd"];
  names.forEach((n, i) => {
    const s = rva + 0xa0 + i * 0x10;
    dv.setUint32(at(rva + 0x60 + i * 4), s, true);
    new TextEncoder().encodeInto(n, sec.subarray(at(s)));
    dv.setUint16(at(rva + 0x80 + i * 2), i, true);
  });
  new TextEncoder().encodeInto("other.Fn", sec.subarray(0x100));
  const dir = { rva, size: 0x200 };
  return { img: buildTestPe([{ name: ".text", rva: 0x1000, bytes: new Uint8Array(0x100) }, { name: ".edata", rva, bytes: sec }], { 0: dir }), dir };
}

describe("export directory", () => {
  it("finds the directory in the header page", () => {
    const { img, dir } = exportImage();
    expect(exportDirOf(img.subarray(0, 0x1000))).toEqual(dir);
    expect(exportDirOf(new Uint8Array(0x1000))).toBeNull();
  });

  it("lists named exports and skips forwarders", () => {
    const { img, dir } = exportImage();
    const chunk = img.subarray(dir.rva, dir.rva + 0x400);
    expect(parseExportChunk(chunk, dir.rva, dir)).toEqual([{ name: "Alpha", rva: 0x1010 }, { name: "Beta", rva: 0x1020 }]);
  });

  it("returns nothing when the tables are outside the chunk", () => {
    const { img, dir } = exportImage();
    expect(parseExportChunk(img.subarray(dir.rva, dir.rva + 0x30), dir.rva, dir)).toEqual([]);
  });
});
