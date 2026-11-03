import { describe, expect, it } from "vitest";
import { findCodeCaves } from "./caves";

/** Minimal PE32+ image with one executable section (.text) at RVA 0x1000. */
function fakePe(): Uint8Array {
  const img = new Uint8Array(0x3000);
  const dv = new DataView(img.buffer);
  const str = (o: number, s: string) => {
    for (let i = 0; i < s.length; i++) img[o + i] = s.charCodeAt(i);
  };

  dv.setUint16(0, 0x5a4d, true);
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x4550, true);

  const fh = 0x84;
  dv.setUint16(fh, 0x8664, true);
  dv.setUint16(fh + 2, 1, true); // one section
  dv.setUint16(fh + 16, 240, true); // optional header size

  const oh = fh + 20;
  dv.setUint16(oh, 0x20b, true);
  dv.setUint32(oh + 16, 0x1000, true); // entry rva
  dv.setBigUint64(oh + 24, 0x140000000n, true);
  dv.setUint32(oh + 56, 0x3000, true); // size of image

  const st = oh + 240;
  str(st, ".text");
  dv.setUint32(st + 8, 0x1000, true); // virtual size
  dv.setUint32(st + 12, 0x1000, true); // rva
  dv.setUint32(st + 16, 0x1000, true); // raw size
  dv.setUint32(st + 36, 0x60000020, true); // code | execute | read

  // Fill the executable section with a byte that is not a cave fill, so that
  // only the runs a test carves out are reported.
  img.fill(0x41, 0x1000, 0x2000);

  return img;
}

describe("caves", () => {
  it("finds a 0xCC run inside an executable section", () => {
    const img = fakePe();
    img.fill(0xcc, 0x1200, 0x1280); // 128-byte cave

    const caves = findCodeCaves(img);
    const cave = caves.find((c) => c.fill === 0xcc);
    expect(cave).toBeDefined();
    expect(cave?.rva).toBe(0x1200);
    expect(cave?.size).toBe(0x80);
    expect(cave?.section).toBe(".text");
    expect(cave?.address).toBe("0x1200");
  });

  it("applies the module base to cave addresses", () => {
    const img = fakePe();
    img.fill(0xcc, 0x1200, 0x1280);
    const base = 0x7ff600000000n;
    const caves = findCodeCaves(img, base);
    const cave = caves.find((c) => c.fill === 0xcc);
    expect(cave?.address).toBe(`0x${(base + 0x1200n).toString(16)}`);
  });

  it("honors minSize", () => {
    const img = fakePe();
    img.fill(0x90, 0x1100, 0x1120); // 32 bytes
    expect(findCodeCaves(img, undefined, { minSize: 32 }).some((c) => c.fill === 0x90)).toBe(true);
    expect(findCodeCaves(img, undefined, { minSize: 33 }).some((c) => c.fill === 0x90)).toBe(false);
  });

  it("honors the fill filter", () => {
    const img = fakePe();
    img.fill(0xcc, 0x1200, 0x1280);
    expect(findCodeCaves(img, undefined, { fills: [0x90] }).some((c) => c.fill === 0xcc)).toBe(false);
    expect(findCodeCaves(img, undefined, { fills: [0xcc] }).some((c) => c.fill === 0xcc)).toBe(true);
  });

  it("reports zero-filled runs but ranks them behind equal-sized padding", () => {
    const img = fakePe();
    img.fill(0x00, 0x1400, 0x1440); // 64 bytes of zeros
    img.fill(0xcc, 0x1500, 0x1540); // 64 bytes of 0xCC

    const caves = findCodeCaves(img);
    const zero = caves.find((c) => c.fill === 0x00);
    const cc = caves.find((c) => c.fill === 0xcc);
    expect(zero).toBeDefined();
    expect(cc).toBeDefined();
    expect(caves.indexOf(cc!)).toBeLessThan(caves.indexOf(zero!));
  });

  it("sorts by size descending, then rva ascending", () => {
    const img = fakePe();
    img.fill(0xcc, 0x1100, 0x1140); // 64 bytes
    img.fill(0xcc, 0x1200, 0x12c0); // 192 bytes
    img.fill(0xcc, 0x1300, 0x1340); // 64 bytes

    const caves = findCodeCaves(img, undefined, { fills: [0xcc] });
    expect(caves.map((c) => [c.rva, c.size])).toEqual([
      [0x1200, 192],
      [0x1100, 64],
      [0x1300, 64],
    ]);
  });

  it("returns an empty list for a non-PE image", () => {
    expect(findCodeCaves(new Uint8Array(0x1000))).toEqual([]);
  });
});
