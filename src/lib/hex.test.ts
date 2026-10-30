import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes, labelAddr, parseAddress } from "./hex";

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

describe("module names with dashes", () => {
  it("parses", () => {
    expect(parseAddress("api-ms-win-core.dll+0x10", [{ name: "api-ms-win-core.dll", base: "0x1000", size: 0x100 }])).toBe(0x1010n);
  });
});
