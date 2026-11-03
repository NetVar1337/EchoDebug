import { describe, expect, it } from "vitest";
import { fuzzFunction, type EmulateFn } from "./fuzztarget";

/** Fake target: faults with "unmapped-memory" when rcx is odd, "divide-by-zero" when rdx==0, else returns cleanly. */
const emulate: EmulateFn = async ({ regs }) => {
  const rcx = BigInt(regs.rcx ?? "0");
  const rdx = BigInt(regs.rdx ?? "0");
  if (rdx === 0n) return { error_name: "divide-by-zero", reached_end: false, instructions: 12, regs };
  if (rcx % 2n === 1n) return { error_name: "unmapped-memory", reached_end: false, instructions: 30, regs, fault_address: "0xdeadbeef" } as never;
  return { error_name: "ok", reached_end: true, instructions: 100, regs };
};

describe("fuzzFunction (#15)", () => {
  it("collects distinct crash stops with the inputs that triggered them", async () => {
    const r = await fuzzFunction(0x1000n, 0x1100n, emulate, { runs: 200, budgetMs: 5000, seed: 42 });
    expect(r.runs).toBeGreaterThan(0);
    expect(r.distinctStops.sort()).toEqual(["divide-by-zero", "unmapped-memory"]);
    expect(r.findings.every((f) => !f.stop.includes("ok"))).toBe(true);
    const unmapped = r.findings.find((f) => f.stop === "unmapped-memory");
    expect(unmapped?.faultAddress).toBe("0xdeadbeef");
    expect(BigInt(unmapped!.regs.rcx!) % 2n).toBe(1n);
    expect(r.timedOut).toBe(false);
  });

  it("reports request failures as findings instead of throwing", async () => {
    const failing: EmulateFn = async () => {
      throw new Error("relay down");
    };
    const r = await fuzzFunction(0x1000n, 0x1100n, failing, { runs: 5, budgetMs: 1000, seed: 1 });
    expect(r.distinctStops[0]).toMatch(/request-failed/);
    expect(r.findings).toHaveLength(r.runs);
  });

  it("respects the time budget", async () => {
    const slow: EmulateFn = async ({ regs }) => {
      await new Promise((r) => setTimeout(r, 5));
      return { error_name: "ok", reached_end: true, instructions: 1, regs };
    };
    const r = await fuzzFunction(0x1000n, 0x1100n, slow, { runs: 1000, budgetMs: 50, seed: 7 });
    expect(r.timedOut).toBe(true);
    expect(r.runs).toBeLessThan(1000);
  });
});
