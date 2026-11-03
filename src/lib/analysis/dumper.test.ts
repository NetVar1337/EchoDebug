import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { codeViewRecord, dumpSize, elfCorePrefix, fillFromDisk, findImages, fixDump, headerProblem, minidumpPrefix, overlayOf, peChecksum, readHeaders, recoverHeaders, updateChecksum } from "./dumper";
import { mapPeFile, parsePe } from "./pe";
import { buildTestPe } from "./testpe";

const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));

describe("PE checksum", () => {
  it("matches imagehlp (values from pefile.generate_checksum)", () => {
    for (const [f, want] of [["fix-seh.exe", 0x13dd], ["fix-res.exe", 0xdb96]] as const) {
      const b = fixture(f);
      expect(peChecksum(b, readHeaders(b).checksumOff)).toBe(want);
    }
  });
});

describe("fixDump", () => {
  it("turns a mapped image back into the file it was loaded from (file layout)", () => {
    const file = fixture("fix-res.exe");
    const img = mapPeFile(file);
    const { bytes, report } = fixDump(img, { layout: "file", base: 0x7ff6_1234_0000n });
    const pe = parsePe(mapPeFile(bytes));
    const orig = parsePe(img);
    expect(pe.sections.map((s) => s.name)).toEqual(orig.sections.map((s) => s.name));
    expect(pe.imageBase).toBe(0x7ff6_1234_0000n);
    // every section's bytes survive the round trip
    const again = mapPeFile(bytes);
    for (const s of orig.sections) expect(again.subarray(s.rva, s.rva + s.vsize)).toEqual(img.subarray(s.rva, s.rva + s.vsize));
    // .data has no raw data in the original and none here (all zero in memory)
    expect(report.sections.find((s) => s.name === ".data")).toMatchObject({ rawSize: 0, rawPtr: 0 });
    expect(bytes.length).toBeLessThanOrEqual(file.length);
    // the checksum is valid
    expect(peChecksum(bytes, readHeaders(bytes).checksumOff)).toBe(report.checksum);
    expect(new DataView(bytes.buffer).getUint32(readHeaders(bytes).checksumOff, true)).toBe(report.checksum);
  });

  it("virtual layout maps 1:1 and runs at the dump base", () => {
    const img = mapPeFile(fixture("fix-seh.exe"));
    const { bytes, report } = fixDump(img, { layout: "virtual", base: 0x1_8000_0000n, oepRva: 0x1010 });
    expect(bytes.length % 0x1000).toBe(0);
    for (const s of report.sections) expect(s.rawPtr).toBe(s.rva);
    const h = readHeaders(bytes);
    expect(h.fileAlign).toBe(0x1000);
    expect(h.entryRva).toBe(0x1010);
    expect(h.imageBase).toBe(0x1_8000_0000n);
    expect(mapPeFile(bytes).subarray(0x1000, 0x10c6)).toEqual(img.subarray(0x1000, 0x10c6));
  });

  it("fixes debug-directory file offsets and drops the certificate table", () => {
    const dbg = new Uint8Array(0x100);
    const dv = new DataView(dbg.buffer);
    dv.setUint32(12, 2, true); // CODEVIEW
    dv.setUint32(16, 28, true);
    dv.setUint32(20, 0x2040, true); // AddressOfRawData
    dv.setUint32(24, 0x9999, true); // stale PointerToRawData
    dv.setUint32(0x40, 0x53445352, true);
    const img = buildTestPe([{ name: ".text", rva: 0x1000, bytes: new Uint8Array([0xc3]) }, { name: ".rdata", rva: 0x2000, bytes: dbg }], { 4: { rva: 0x5000, size: 0x100 }, 6: { rva: 0x2000, size: 28 } });
    const { bytes, report } = fixDump(img, { layout: "file" });
    const h = readHeaders(bytes);
    const v = new DataView(bytes.buffer);
    expect(v.getUint32(h.dirOff + 32, true)).toBe(0);
    const rdata = report.sections.find((s) => s.name === ".rdata")!;
    expect(v.getUint32(rdata.rawPtr + 24, true)).toBe(rdata.rawPtr + 0x40);
    expect(report.warnings.join(" ")).toContain("Authenticode");
    // the CodeView record (RSDS + GUID + age + name) for the minidump's module list
    const cv = codeViewRecord(img);
    expect(cv?.length).toBe(28);
    expect(new DataView(cv!.buffer).getUint32(0, true)).toBe(0x53445352);
  });

  it("counts unreadable pages per section", () => {
    const img = buildTestPe([{ name: ".text", rva: 0x1000, bytes: new Uint8Array(0x3000).fill(0x90) }]);
    const { report } = fixDump(img, { layout: "virtual", badPages: [0x2000, 0x2123] });
    expect(report.badPages).toBe(1);
    expect(report.sections[0].badPages).toBe(1);
    expect(report.warnings.join(" ")).toContain("zero-filled");
  });

  it("refuses broken headers", () => {
    expect(() => fixDump(new Uint8Array(0x1000), { layout: "file" })).toThrow(/MZ/);
    const img = mapPeFile(fixture("fix-seh.exe"));
    const wiped = img.slice();
    wiped.fill(0, 0, 0x400);
    expect(headerProblem(wiped)).toMatch(/MZ/);
  });

  it("updateChecksum rewrites the field", () => {
    const b = fixture("fix-seh.exe").slice();
    expect(updateChecksum(b)).toBe(0x13dd);
    expect(new DataView(b.buffer).getUint32(readHeaders(b).checksumOff, true)).toBe(0x13dd);
  });
});

describe("recoverHeaders", () => {
  it("takes wiped headers from the file on disk", () => {
    const file = fixture("fix-seh.exe");
    const img = mapPeFile(file);
    const wiped = img.slice();
    wiped.fill(0, 0, 0x400);
    const r = recoverHeaders(wiped, file);
    expect(r.source).toBe("disk");
    expect(headerProblem(r.img)).toBeNull();
    expect(r.img.subarray(0x1000)).toEqual(img.subarray(0x1000));
    expect(recoverHeaders(img, file).source).toBe("memory");
    expect(recoverHeaders(img, file, "disk").source).toBe("disk");
    expect(recoverHeaders(wiped, null).note).toMatch(/no file/);
  });
});

describe("findImages", () => {
  it("flags unlisted PE images and headerless executable memory", () => {
    const pe = mapPeFile(fixture("fix-seh.exe"));
    const regions = [
      { base: 0x140000000n, size: 0x1000, executable: false, head: pe.subarray(0, 0x1000) },
      { base: 0x140001000n, size: 0x1000, executable: true, head: pe.subarray(0x1000, 0x2000) },
      { base: 0x2000_0000n, size: 0x1000, executable: false, head: pe.subarray(0, 0x1000) },
      { base: 0x3000_0000n, size: 0x2000, executable: true, head: new Uint8Array(0x1000).fill(0x90) },
      { base: 0x3100_0000n, size: 0x2000, executable: false, head: new Uint8Array(0x1000) },
    ];
    const found = findImages(regions, [{ base: 0x140000000n, size: 0x4000 }]);
    expect(found.map((f) => [f.base, f.kind, f.listed])).toEqual([
      [0x2000_0000n, "pe", false],
      [0x3000_0000n, "headerless-code", false],
      [0x140000000n, "pe", true],
    ].sort((a, b) => ((a[0] as bigint) < (b[0] as bigint) ? -1 : 1)));
    expect(found.find((f) => f.base === 0x2000_0000n)?.size).toBe(0x4000);
  });
});

describe("full dumps", () => {
  const u32 = (b: Uint8Array, o: number) => new DataView(b.buffer, b.byteOffset).getUint32(o, true);
  const u64 = (b: Uint8Array, o: number) => new DataView(b.buffer, b.byteOffset).getBigUint64(o, true);

  it("writes a MINIDUMP whose streams parse back", () => {
    const cv = new Uint8Array(30);
    new DataView(cv.buffer).setUint32(0, 0x53445352, true);
    const regions = [{ base: 0x10000n, size: 0x1000 }, { base: 0x7ff6_0000_0000n, size: 0x3000 }];
    const p = minidumpPrefix({ arch: "x64", pid: 4242, modules: [{ name: "C:\\game\\game.exe", base: 0x7ff6_0000_0000n, size: 0x3000, timestamp: 0x5f000000, checksum: 7, cv }], regions, time: 1 });
    expect(u32(p, 0)).toBe(0x504d444d);
    const n = u32(p, 8);
    const dir = u32(p, 12);
    const streams = new Map<number, [number, number]>();
    for (let i = 0; i < n; i++) streams.set(u32(p, dir + i * 12), [u32(p, dir + i * 12 + 8), u32(p, dir + i * 12 + 4)]);
    expect([...streams.keys()].sort((a, b) => a - b)).toEqual([3, 4, 7, 9, 15]);
    const [si] = streams.get(7)!;
    expect(new DataView(p.buffer).getUint16(si, true)).toBe(9);
    expect(u32(p, si + 8)).toBe(10);
    const [misc] = streams.get(15)!;
    expect(u32(p, misc + 8)).toBe(4242);
    const [ml] = streams.get(4)!;
    expect(u32(p, ml)).toBe(1);
    const m = ml + 4;
    expect(u64(p, m)).toBe(0x7ff6_0000_0000n);
    expect([u32(p, m + 8), u32(p, m + 12), u32(p, m + 16)]).toEqual([0x3000, 7, 0x5f000000]);
    const nameRva = u32(p, m + 20);
    const len = u32(p, nameRva);
    expect(new TextDecoder("utf-16le").decode(p.subarray(nameRva + 4, nameRva + 4 + len))).toBe("C:\\game\\game.exe");
    expect(u32(p, m + 76)).toBe(30);
    expect(u32(p, u32(p, m + 80))).toBe(0x53445352);
    const [m64] = streams.get(9)!;
    expect(u64(p, m64)).toBe(2n);
    expect(Number(u64(p, m64 + 8))).toBe(p.length);
    expect(u64(p, m64 + 16 + 16)).toBe(0x7ff6_0000_0000n);
    expect(u64(p, m64 + 16 + 24)).toBe(0x3000n);
    expect(dumpSize(p, regions)).toBe(p.length + 0x4000);
  });

  it("writes an ELF core with one PT_LOAD per region", () => {
    const regions = [{ base: 0x400000n, size: 0x2000, executable: true }, { base: 0x7f00_0000_0000n, size: 0x1000, writable: true }];
    const p = elfCorePrefix({ arch: "x64", regions, pid: 99, name: "e2e-target", regs: { rip: 0x401000n } });
    expect([...p.subarray(0, 4)]).toEqual([0x7f, 0x45, 0x4c, 0x46]);
    const dv = new DataView(p.buffer);
    expect(dv.getUint16(16, true)).toBe(4);
    expect(dv.getUint16(18, true)).toBe(62);
    expect(dv.getUint16(56, true)).toBe(3);
    expect(p.length % 0x1000).toBe(0);
    const ph = (i: number) => 64 + i * 56;
    expect(dv.getUint32(ph(0), true)).toBe(4);
    const note = Number(dv.getBigUint64(ph(0) + 8, true));
    // NT_PRSTATUS first (the thread gdb needs), with the pid and the registers given
    expect(dv.getUint32(note + 4, true)).toBe(336);
    expect(dv.getUint32(note + 8, true)).toBe(1);
    expect(dv.getInt32(note + 20 + 32, true)).toBe(99);
    expect(dv.getBigUint64(note + 20 + 112 + 16 * 8, true)).toBe(0x401000n); // rip
    // then NT_PRPSINFO with the program name
    const ps = note + 20 + 336;
    expect(dv.getUint32(ps + 8, true)).toBe(3);
    expect(dv.getInt32(ps + 20 + 24, true)).toBe(99);
    expect(new TextDecoder().decode(p.subarray(ps + 20 + 40, ps + 20 + 50))).toBe("e2e-target");
    expect(Number(dv.getBigUint64(ph(0) + 32, true))).toBe(20 + 336 + 20 + 136);
    expect(dv.getUint32(ph(1), true)).toBe(1);
    expect(dv.getUint32(ph(1) + 4, true)).toBe(5);
    expect(dv.getBigUint64(ph(1) + 8, true)).toBe(BigInt(p.length));
    expect(dv.getBigUint64(ph(2) + 8, true)).toBe(BigInt(p.length + 0x2000));
    expect(dv.getUint32(ph(2) + 4, true)).toBe(6);
    expect(dv.getBigUint64(ph(2) + 16, true)).toBe(0x7f00_0000_0000n);
  });
});

describe("full images from disk", () => {
  it("fills pages that were not resident from the file", () => {
    const file = fixture("fix-res.exe");
    const img = mapPeFile(file);
    const holed = img.slice();
    holed.fill(0, 0x1000, 0x2000); // .text not resident
    holed.fill(0, 0x3000, 0x4000); // .data: no file data behind it
    const r = fillFromDisk(holed, [0x1000, 0x3000, 0x3123], file);
    expect(r.filled).toEqual([0x1000]);
    expect(r.empty).toEqual([0x3000]);
    expect(r.img.subarray(0x1000, 0x2000)).toEqual(img.subarray(0x1000, 0x2000));
    expect(holed[0x1000]).toBe(0); // the input is not changed
  });

  it("finds the overlay after the last section", () => {
    const file = fixture("fix-res.exe");
    expect(overlayOf(file).length).toBe(0);
    const withOverlay = new Uint8Array(file.length + 5);
    withOverlay.set(file);
    withOverlay.set([1, 2, 3, 4, 5], file.length);
    expect([...overlayOf(withOverlay)]).toEqual([1, 2, 3, 4, 5]);
  });
});
