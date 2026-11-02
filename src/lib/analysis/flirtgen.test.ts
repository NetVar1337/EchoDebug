import { describe, expect, it } from "vitest";
import { matchFlirt, parseFlirt, parseFlirtFile } from "./flirt";
import { parsePat, toPatEntry, toPatFile, toPatLine, writeSig, type GenFunction } from "./flirtgen";

function fn(name: string, seed: number, len: number, variableAt: number[] = [], prefix: number[] = []): GenFunction {
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = (seed * 31 + i * 17 + (i * i) % 7) & 0xff;
  bytes.set(prefix);
  const variable = Array(len).fill(false);
  for (const v of variableAt) variable[v] = true;
  return { name, bytes, variable };
}

describe("FLIRT generation", () => {
  const funcs = [
    fn("alpha", 1, 80, [5, 6, 7, 8]),
    fn("beta", 2, 64, [40]), // crc stops at the wildcard at 40 → 8 bytes
    fn("gamma_shares_prefix", 3, 70, [], [0x48, 0x89, 0x5c, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x56]),
    fn("delta_shares_prefix", 4, 70, [], [0x48, 0x89, 0x5c, 0x24, 0x08, 0x55, 0x56, 0x57, 0x41, 0x56]),
  ];
  const entries = funcs.map(toPatEntry).filter((e) => e !== null);

  it("writes .pat lines that parse back", () => {
    const line = toPatLine(entries[0]);
    expect(line).toMatch(/^[0-9A-F]{10}\.{8}[0-9A-F]{46} [0-9A-F]{2} [0-9A-F]{4} 0050 :0000 alpha$/);
    expect(entries[1].crcLength).toBe(8);
    const back = parsePat(toPatFile(entries));
    expect(back).toEqual(entries);
  });

  it("writes a .sig that the parser loads and that matches the functions with verified CRCs", async () => {
    const sig = writeSig(entries, { libraryName: "EchoDebug test" });
    const parsed = parseFlirt(sig);
    expect(parsed.version).toBe(10);
    expect(parsed.libraryName).toBe("EchoDebug test");
    expect(parsed.functionCount).toBe(4);
    // the two functions with a shared prefix sit under one inner node
    expect(parsed.root!.children.length).toBe(3);
    expect((await parseFlirtFile(sig)).root!.children.length).toBe(3);

    const img = new Uint8Array(0x1000);
    const at = [0x100, 0x300, 0x500, 0x700];
    funcs.forEach((f, i) => img.set(f.bytes, at[i]));
    // relocations differ in the image: wildcarded bytes must not matter
    img[0x100 + 6] ^= 0xff;
    const hits = matchFlirt(parsed, img, 0x400000n);
    for (const [i, f] of funcs.entries()) {
      const h = hits.find((x) => x.name === f.name);
      expect(h, f.name).toBeDefined();
      expect(h!.rva).toBe(at[i]);
      expect(h!.crcVerified, f.name).toBe(true);
    }
    // a corrupted tail fails the CRC
    img[0x300 + 33] ^= 0xff;
    expect(matchFlirt(parsed, img).find((x) => x.name === "beta")!.crcVerified).toBe(false);
  });

  it("skips functions too short to sign", () => {
    expect(toPatEntry(fn("tiny", 1, 4))).toBeNull();
  });
});
