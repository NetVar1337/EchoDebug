import { describe, expect, it } from "vitest";
import { buildIat, ripDisplacement } from "./iat";
import { parsePe } from "./pe";

/**
 * Builds a mapped PE image with one import descriptor and one IAT slot.
 * Layout: headers 0..0x1000, .text at 0x1000, .idata at 0x2000.
 */
function buildImportPe(): Uint8Array {
  const image = new Uint8Array(0x3000);
  const dv = new DataView(image.buffer);
  image[0] = 0x4d; image[1] = 0x5a;
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x4550, true);
  const fh = 0x84;
  dv.setUint16(fh, 0x8664, true);
  dv.setUint16(fh + 2, 2, true); // two sections
  dv.setUint16(fh + 16, 0xf0, true);
  const oh = fh + 20;
  dv.setUint16(oh, 0x20b, true);
  dv.setUint32(oh + 16, 0x1000, true); // entry
  dv.setBigUint64(oh + 24, 0x140000000n, true);
  dv.setUint32(oh + 56, image.length, true);
  dv.setUint16(oh + 68, 3, true);
  const dd = oh + 112;
  dv.setUint32(oh + 108, 16, true); // NumberOfRvaAndSizes
  dv.setUint32(dd + 8, 0x2000, true); // import directory rva
  dv.setUint32(dd + 12, 0x100, true); // import directory size

  const st = oh + 0xf0;
  // .text
  image.set(new TextEncoder().encode(".text"), st);
  dv.setUint32(st + 8, 0x1000, true);
  dv.setUint32(st + 12, 0x1000, true);
  dv.setUint32(st + 16, 0x1000, true);
  dv.setUint32(st + 36, 0x60000020, true);
  // .idata
  const st2 = st + 40;
  image.set(new TextEncoder().encode(".idata"), st2);
  dv.setUint32(st2 + 8, 0x1000, true);
  dv.setUint32(st2 + 12, 0x2000, true);
  dv.setUint32(st2 + 16, 0x1000, true);
  dv.setUint32(st2 + 36, 0x40000040, true);

  const id = 0x2000;
  // import descriptor: OFT, timestamp, forwarder, name rva, IAT rva
  dv.setUint32(id + 0, 0x2100, true); // original first thunk
  dv.setUint32(id + 12, 0x2200, true); // name rva -> "KERNEL32.dll"
  dv.setUint32(id + 16, 0x2300, true); // first thunk (IAT)
  // OFT entry points at the hint/name record, which sits at 0x2120
  dv.setBigUint64(0x2100, 0x2120n, true);
  dv.setBigUint64(0x2108, 0n, true);
  // hint/name record: 2-byte hint then the name
  dv.setUint16(0x2120, 1, true);
  image.set(new TextEncoder().encode("CreateFileW"), 0x2122);
  // the IAT slot mirrors it
  dv.setBigUint64(0x2300, 0x2120n, true);
  dv.setBigUint64(0x2308, 0n, true);
  image.set(new TextEncoder().encode("KERNEL32.dll"), 0x2200);
  return image;
}

describe("iat resolution", () => {
  it("reads the displacement of a rip-relative operand", () => {
    expect(ripDisplacement("call qword ptr [rip+0x1234]")).toBe(0x1234n);
    expect(ripDisplacement("mov eax, dword ptr [rip-0x20]")).toBe(-0x20n);
    expect(ripDisplacement("mov eax, dword ptr [rbx+8]")).toBeNull();
    expect(ripDisplacement("nop")).toBeNull();
  });

  it("maps IAT slots to their imported name", () => {
    const img = buildImportPe();
    const pe = parsePe(img);
    const iat = buildIat(img, 0x140000000n, pe);
    expect(iat.entries.length).toBeGreaterThan(0);
    const entry = iat.entries[0];
    expect(entry.dll).toBe("KERNEL32.dll");
    expect(entry.name).toBe("CreateFileW");
    // slot at rva 0x2300 -> absolute 0x140002300
    expect(entry.address).toBe("0x140002300");
    expect(iat.byAddress.get("0x140002300")).toBe(entry);
  });

  it("returns an empty map for a non-PE image", () => {
    const iat = buildIat(new Uint8Array(0x100), 0n);
    expect(iat.entries).toHaveLength(0);
  });
});
