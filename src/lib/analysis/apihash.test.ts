import { describe, expect, it } from "vitest";
import { detectHashAlgo, hexImmediates, nameHashScheme, type Line } from "./apihash";

const ror13: Line[] = [
  { address: "0x1000", text: "mov eax, 0x5a827999" },
  { address: "0x1005", text: "ror eax, 0xd" },
  { address: "0x1009", text: "add eax, ecx" },
  { address: "0x100c", text: "xor eax, edx" },
];

const crc32: Line[] = [
  { address: "0x2000", text: "mov edx, 0xedb88320" },
  { address: "0x2005", text: "xor eax, ecx" },
];

const djb2: Line[] = [
  { address: "0x3000", text: "mov eax, 5381" },
  { address: "0x3005", text: "imul eax, eax, 33" },
  { address: "0x300a", text: "add eax, ecx" },
];

describe("api hash detection", () => {
  it("extracts hex immediates", () => {
    expect(hexImmediates("mov eax, 0xEDB88320")).toEqual([0xedb88320]);
    expect(hexImmediates("cmp rax, 0x10")).toEqual([0x10]);
  });

  it("detects ror13-style schemes and names the mixing ops", () => {
    const det = detectHashAlgo(ror13);
    const scheme = nameHashScheme(ror13, det)!;
    expect(scheme.mixing).toEqual(["ror13", "add", "xor"]);
    expect(scheme.bits).toBe(32);
  });

  it("detects CRC32 by its constant", () => {
    const det = detectHashAlgo(crc32);
    expect(det[0].algo.id).toBe("crc32");
    expect(det[0].evidence).toContain("constant 0xedb88320");
  });

  it("detects djb2 via the *33 add form", () => {
    const det = detectHashAlgo(djb2);
    expect(det.some((d) => d.algo.id === "djb2")).toBe(true);
  });

  it("returns null scheme for unrelated code", () => {
    expect(nameHashScheme([{ text: "mov eax, 1" }], [])).toBeNull();
  });
});
