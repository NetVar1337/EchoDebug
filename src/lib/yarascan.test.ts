import { describe, expect, it } from "vitest";
import { maxStringLen, scanBuffer, yaraScanMemory, type Region } from "./yarascan";
import { parseYara } from "./analysis/yara";

const src = `rule mz { strings: $a = "MZ" condition: $a }`;
const rules = parseYara(src);

describe("maxStringLen", () => {
  it("takes the longest pattern", () => {
    expect(maxStringLen(rules)).toBe(2);
    expect(maxStringLen(parseYara(`rule x { strings: $a = "abcdef" $b = "xy" condition: any of them }`))).toBe(6);
  });
});

describe("scanBuffer", () => {
  it("finds matches with absolute addresses", () => {
    const buf = new Uint8Array(100);
    buf[10] = 0x4d;
    buf[11] = 0x5a;
    const hits = scanBuffer(rules, buf, 0x140000000n, 64, 2);
    expect(hits).toHaveLength(1);
    expect(hits[0].address).toBe("0x14000000a");
    expect(hits[0].rule).toBe("mz");
  });

  it("catches a match straddling a chunk boundary and does not double-count it", () => {
    const buf = new Uint8Array(64);
    buf[31] = 0x4d; // "MZ" would be at 31..32, chunk edge at 32 with overlap 2
    buf[32] = 0x5a;
    const hits = scanBuffer(rules, buf, 0x1000n, 32, 2);
    expect(hits).toHaveLength(1);
    expect(hits[0].address).toBe("0x101f");
  });
});

describe("yaraScanMemory (#18)", () => {
  it("scans regions through the chunked reader with progress and reports truncation", async () => {
    const regions: Region[] = [
      { base: "0x1000", size: 100 },
      { base: "0x2000", size: 100 },
    ];
    const mem = new Uint8Array(0x3000);
    mem[0x1005] = 0x4d;
    mem[0x1006] = 0x5a;
    mem[0x2050] = 0x4d;
    mem[0x2051] = 0x5a;
    const read = async (addr: bigint, size: number) => mem.slice(Number(addr), Number(addr) + size);
    const progress: string[] = [];
    const r = await yaraScanMemory(rules, { read, regions, chunkBytes: 64, onProgress: (d, t) => progress.push(`${d}/${t}`) });
    expect(r.regions).toBe(2);
    expect(r.truncated).toBe(false);
    expect(r.matches.map((m) => m.address).sort()).toEqual(["0x1005", "0x2050"]);
    expect(progress).toEqual(["1/2", "2/2"]);
  });

  it("stops early when aborted", async () => {
    const signal = { aborted: true };
    const r = await yaraScanMemory(rules, { read: async () => new Uint8Array(0), regions: [{ base: "0x0", size: 10 }], signal });
    expect(r.matches).toEqual([]);
    expect(r.regions).toBe(1);
  });
});
