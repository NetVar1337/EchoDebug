import { describe, expect, it } from "vitest";
import { buildExports, findExport } from "./exports";
import { parsePe } from "./pe";

/** Mapped PE with one export: name "MyFunc" at rva 0x1234. */
function buildExportPe(): Uint8Array {
  const image = new Uint8Array(0x3000);
  const dv = new DataView(image.buffer);
  image[0] = 0x4d; image[1] = 0x5a;
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x4550, true);
  const fh = 0x84;
  dv.setUint16(fh, 0x8664, true);
  dv.setUint16(fh + 2, 1, true);
  dv.setUint16(fh + 16, 0xf0, true);
  const oh = fh + 20;
  dv.setUint16(oh, 0x20b, true);
  dv.setUint32(oh + 16, 0x1000, true);
  dv.setBigUint64(oh + 24, 0x140000000n, true);
  dv.setUint32(oh + 56, image.length, true);
  dv.setUint16(oh + 68, 3, true);
  const dd = oh + 112;
  dv.setUint32(oh + 108, 16, true);
  dv.setUint32(dd, 0x2000, true); // export directory rva
  dv.setUint32(dd + 4, 0x100, true);
  const st = oh + 0xf0;
  image.set(new TextEncoder().encode(".text"), st);
  dv.setUint32(st + 8, 0x2000, true);
  dv.setUint32(st + 12, 0x1000, true);
  dv.setUint32(st + 16, 0x2000, true);
  dv.setUint32(st + 36, 0x60000020, true);

  // export directory at 0x2000
  const ed = 0x2000;
  dv.setUint32(ed + 16, 1, true); // ordinal base
  dv.setUint32(ed + 20, 1, true); // number of functions
  dv.setUint32(ed + 24, 1, true); // number of names
  dv.setUint32(ed + 28, 0x2100, true); // address table rva
  dv.setUint32(ed + 32, 0x2200, true); // name pointer table rva
  dv.setUint32(ed + 36, 0x2300, true); // ordinal table rva
  dv.setUint32(0x2100, 0x1234, true); // function rva
  dv.setUint32(0x2200, 0x2400, true); // name rva
  dv.setUint16(0x2300, 0, true); // ordinal index
  image.set(new TextEncoder().encode("MyFunc"), 0x2400);
  return image;
}

describe("export resolution", () => {
  it("maps an exported name to its address", () => {
    const img = buildExportPe();
    const pe = parsePe(img);
    const map = buildExports(img, 0x140000000n, pe);
    expect(map.entries).toHaveLength(1);
    const e = map.entries[0];
    expect(e.name).toBe("MyFunc");
    expect(e.rva).toBe(0x1234);
    expect(e.address).toBe("0x140001234");
    expect(map.byAddress.get("0x140001234")).toBe(e);
  });

  it("looks an export up by name, case-insensitively", () => {
    const img = buildExportPe();
    const map = buildExports(img, 0n);
    expect(findExport(map, "myfunc")?.name).toBe("MyFunc");
    expect(findExport(map, "OTHER.dll!MyFunc")?.name).toBe("MyFunc");
    expect(findExport(map, "nope")).toBeNull();
  });

  it("returns an empty map for a non-PE image", () => {
    expect(buildExports(new Uint8Array(0x100), 0n).entries).toHaveLength(0);
  });
});
