import { describe, expect, it } from "vitest";
import { bytesToHex, hexDump, hexToBytes, labelAddr, parseAddress } from "./hex";

const mods = [{ name: "game.exe", base: "0x140000000", size: 0x10000 }];

describe("hex", () => {
  it("round trips bytes", () => {
    expect(bytesToHex(hexToBytes("4883ec28"))).toBe("4883ec28");
    expect(() => hexToBytes("abc")).toThrow();
  });
  it("parses addresses", () => {
    expect(parseAddress("0x10")).toBe(16n);
    expect(parseAddress("7ff6")).toBe(0x7ff6n);
    expect(parseAddress("game.exe+0x20", mods)).toBe(0x140000020n);
    expect(parseAddress("GAME.EXE + 10 - 8", mods)).toBe(0x140000008n);
    expect(parseAddress("nope.dll+1", mods)).toBeNull();
  });
  it("labels", () => {
    expect(labelAddr("0x140000123", mods)).toBe("game.exe+0x123");
    expect(labelAddr(5n, mods)).toBe("0x5");
  });
});

describe("hexDump", () => {
  it("formats 16-byte rows with ascii", () => {
    const d = hexDump("0x1000", "41".repeat(17)).split("\n");
    expect(d).toHaveLength(2);
    expect(d[0]).toBe(`0x1000  ${Array(16).fill("41").join(" ")}  ${"A".repeat(16)}`);
    expect(d[1]).toBe(`0x1010  ${"41".padEnd(47)}  A`);
  });
});

describe("module names with dashes", () => {
  it("parses", () => {
    expect(parseAddress("api-ms-win-core.dll+0x10", [{ name: "api-ms-win-core.dll", base: "0x1000", size: 0x100 }])).toBe(0x1010n);
  });
});
