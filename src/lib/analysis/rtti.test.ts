import { describe, expect, it } from "vitest";
import { buildRtti, demangleTypeName, findVftables } from "./rtti";
import { parsePe } from "./pe";

/**
 * A synthetic mapped PE with a .data section holding:
 *   - a type descriptor for ".?AVPlayerController@@"
 *   - a base class descriptor pointing at a ".?AVObject@@" descriptor
 *   - a vftable whose first slot points at a complete object locator
 */
function buildRttiPe(): Uint8Array {
  const image = new Uint8Array(0x4000);
  const dv = new DataView(image.buffer);
  image[0] = 0x4d; image[1] = 0x5a;
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x4550, true);
  const fh = 0x84;
  dv.setUint16(fh, 0x8664, true);
  dv.setUint16(fh + 2, 2, true);
  dv.setUint16(fh + 16, 0xf0, true);
  const oh = fh + 20;
  dv.setUint16(oh, 0x20b, true);
  dv.setUint32(oh + 16, 0x1000, true);
  dv.setBigUint64(oh + 24, 0x140000000n, true);
  dv.setUint32(oh + 56, image.length, true);
  dv.setUint16(oh + 68, 3, true);
  dv.setUint32(oh + 108, 16, true);
  const st = oh + 0xf0;
  // .text (executable, read)
  image.set(new TextEncoder().encode(".text"), st);
  dv.setUint32(st + 8, 0x1000, true);
  dv.setUint32(st + 12, 0x1000, true);
  dv.setUint32(st + 16, 0x1000, true);
  dv.setUint32(st + 36, 0x60000020, true);
  // .data (read/write, not executable)
  const st2 = st + 40;
  image.set(new TextEncoder().encode(".data"), st2);
  dv.setUint32(st2 + 8, 0x2000, true);
  dv.setUint32(st2 + 12, 0x2000, true);
  dv.setUint32(st2 + 16, 0x2000, true);
  dv.setUint32(st2 + 36, 0x40000040, true);

  // The strings.
  const nameA = 0x2800;
  const nameB = 0x2840;
  const nameC = 0x2880;
  image.set(new TextEncoder().encode(".?AVPlayerController@@"), nameA);
  image.set(new TextEncoder().encode(".?AVObject@@"), nameB);
  image.set(new TextEncoder().encode(".?AVWidget@@"), nameC);

  // Type descriptors: { vftable ptr, spare, name ptr }.
  const tdA = 0x2000;
  const tdB = 0x2020;
  const tdC = 0x2040;
  dv.setBigUint64(tdA + 8, BigInt(nameA), true);
  dv.setBigUint64(tdB + 8, BigInt(nameB), true);
  dv.setBigUint64(tdC + 8, BigInt(nameC), true);
  // Base class descriptor for A points at B's descriptor.
  dv.setBigUint64(tdA - 0x10, BigInt(tdB), true);

  // Complete object locator: { sig=1, offset, cdOffset, typeDesc, classDesc, self }.
  const col = 0x2100;
  dv.setUint32(col, 1, true);
  dv.setBigUint64(col + 16, BigInt(tdA), true);
  dv.setBigUint64(col + 32, BigInt(col), true);

  // A vftable whose first slot points at the COL, then two code pointers.
  const vft = 0x2200;
  dv.setBigUint64(vft, BigInt(col), true);
  dv.setBigUint64(vft + 8, BigInt(0x140001000), true);
  dv.setBigUint64(vft + 16, BigInt(0x140001040), true);
  return image;
}

describe("rtti inventory", () => {
  it("demangles the common type-descriptor names", () => {
    expect(demangleTypeName(".?AVPlayerController@@")).toBe("PlayerController");
    expect(demangleTypeName(".?AVFoo@Bar@@")).toBe("Foo@Bar");
    expect(demangleTypeName(".?AU<Foo@Bar>@@")).toBe("Foo@Bar");
    expect(demangleTypeName("not a name")).toBe("not a name");
  });

  it("lists the classes of a module image", () => {
    const img = buildRttiPe();
    const inv = buildRtti(img, 0x140000000n, parsePe(img));
    const names = inv.classes.map((c) => c.name);
    expect(names).toContain("PlayerController");
    expect(names).toContain("Object");
    expect(names).toContain("Widget");
    const pc = inv.classes.find((c) => c.name === "PlayerController")!;
    expect(pc.address).toBe("0x140002000");
    expect(pc.base).toBe("Object");
  });

  it("finds the vftable of a class", () => {
    const img = buildRttiPe();
    const pe = parsePe(img);
    const inv = buildRtti(img, 0x140000000n, pe);
    const pc = inv.classes.find((c) => c.name === "PlayerController")!;
    const vfts = findVftables(img, 0x140000000n, pc, pe);
    expect(vfts.length).toBeGreaterThan(0);
    expect(vfts[0].address).toBe("0x140002200");
    expect(vfts[0].slots).toBe(3);
  });

  it("returns an empty inventory for a non-PE image", () => {
    const inv = buildRtti(new Uint8Array(0x100), 0n);
    expect(inv.classes).toHaveLength(0);
  });
});
