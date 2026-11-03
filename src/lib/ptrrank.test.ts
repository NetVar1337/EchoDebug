import { describe, expect, it } from "vitest";
import { rankPointerChains, type PtrChain } from "./ptrrank";

const chains: PtrChain[] = [
  { path: ["0xaaa", "0xbbb", "0x1000"] }, // depth 2
  { path: ["0xccc", "0x1000"] }, // depth 1
  { path: ["0xddd", "0xeee", "0xfff", "0x1000"] }, // depth 3, one unreadable
];

describe("pointer path ranking", () => {
  it("prefers short, fully valid, stable chains", () => {
    const ranked = rankPointerChains(chains, {
      valid: (a) => a !== "0xfff",
      stability: new Map([["0x1000", 4]]),
    });
    expect(ranked[0].path).toEqual(["0xccc", "0x1000"]); // depth 1 + all valid + stable
    expect(ranked[0].reasons.join(" ")).toMatch(/stable in 4 snapshots/);
    expect(ranked[1].path).toEqual(["0xaaa", "0xbbb", "0x1000"]);
    expect(ranked[2].path).toEqual(["0xddd", "0xeee", "0xfff", "0x1000"]);
    expect(ranked[2].reasons.join(" ")).toMatch(/unreadable/);
    expect(ranked[0].score).toBeGreaterThan(ranked[2].score);
  });

  it("works without validators", () => {
    const ranked = rankPointerChains(chains);
    expect(ranked[0].path.length).toBe(2);
  });
});
