import { describe, expect, it } from "vitest";
import { parsePe, parseRuntimeFunctions } from "./pe";
import { buildTestPe } from "./testpe";

describe(".pdata function bounds", () => {
  it("reads RUNTIME_FUNCTION entries and flags chained fragments", () => {
    const pdata = new Uint8Array(36);
    const dv = new DataView(pdata.buffer);
    const put = (i: number, b: number, e: number, u: number) => { dv.setUint32(i * 12, b, true); dv.setUint32(i * 12 + 4, e, true); dv.setUint32(i * 12 + 8, u, true); };
    put(0, 0x1000, 0x1040, 0x3000);
    put(1, 0x1040, 0x1080, 0x3010); // chained fragment
    put(2, 0x1100, 0x1180, 0x3020);
    const unwind = new Uint8Array(0x30);
    unwind[0x00] = 1; // version 1, no flags
    unwind[0x10] = 1 | (4 << 3); // UNW_FLAG_CHAININFO
    unwind[0x20] = 1;
    const img = buildTestPe(
      [{ name: ".text", rva: 0x1000, bytes: new Uint8Array(0x200) }, { name: ".pdata", rva: 0x2000, bytes: pdata, chars: 0x40000040 }, { name: ".rdata", rva: 0x3000, bytes: unwind, chars: 0x40000040 }],
      { 3: { rva: 0x2000, size: 36 } },
    );
    const fns = parseRuntimeFunctions(img, parsePe(img));
    expect(fns.map((f) => [f.begin, f.end, f.chained])).toEqual([[0x1000, 0x1040, false], [0x1040, 0x1080, true], [0x1100, 0x1180, false]]);
  });

  it("returns nothing without an exception directory", () => {
    expect(parseRuntimeFunctions(buildTestPe([{ name: ".text", rva: 0x1000, bytes: new Uint8Array(16) }]))).toEqual([]);
  });
});
