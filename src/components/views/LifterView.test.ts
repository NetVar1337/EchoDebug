import { describe, expect, it } from "vitest";
import { parseRegs, scratchArgs } from "./LifterView";

describe("lifter inputs", () => {
  it("parses register assignments", () => {
    expect(parseRegs("rcx=0x10, rdx=0x20", (s) => BigInt(s))).toEqual({ rcx: "0x10", rdx: "0x20" });
    expect(parseRegs("", (s) => BigInt(s))).toEqual({});
    expect(typeof parseRegs("rcx", () => 1n)).toBe("string");
    expect(typeof parseRegs("rcx=zz", () => null)).toBe("string");
  });
  it("builds scratch argument buffers", () => {
    const s = scratchArgs(0x1000n);
    expect(s.regs.rcx).toBe("0x1000");
    expect(s.regs.rsi).toBe("0x51000");
    expect(s.write).toHaveLength(6);
    expect(s.write[0].data.length).toBe(0x2000);
  });
});
