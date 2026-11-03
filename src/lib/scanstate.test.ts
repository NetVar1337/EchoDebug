import { describe, expect, it } from "vitest";
import { advanceCheckpoint, deserializeCheckpoint, newCheckpoint, progress, remainingRegions, serializeCheckpoint } from "./scanstate";

const regions = [{ base: "0x1000", size: 0x1000 }, { base: "0x2000", size: 0x1000 }, { base: "0x3000", size: 0x1000 }];

describe("scan checkpoints", () => {
  it("round-trips through JSON", () => {
    const c = newCheckpoint("abc", "2a", "u8", "exact", regions);
    const back = deserializeCheckpoint(serializeCheckpoint(c));
    expect(back).toMatchObject({ format: "echodebug.scan", version: 1, id: "abc", cursor: 0, done: false });
  });

  it("rejects corrupt checkpoints", () => {
    expect(() => deserializeCheckpoint("{}")).toThrow(/not an echodebug\.scan/);
    expect(() => deserializeCheckpoint(JSON.stringify({ format: "echodebug.scan", version: 1, regions: "x" }))).toThrow(/corrupt/);
  });

  it("advances the cursor, appends results and finishes at the end", () => {
    let c = newCheckpoint("s", "2a", "u8", "changed", regions);
    c = advanceCheckpoint(c, 2, ["0x10", "0x20"]);
    expect(progress(c)).toEqual({ done: 2, total: 3, pct: 2 / 3 });
    expect(remainingRegions(c).map((r) => r.base)).toEqual(["0x3000"]);
    c = advanceCheckpoint(c, 1, ["0x20", "0x30"]);
    expect(c.done).toBe(true);
    expect(c.results).toEqual(["0x10", "0x20", "0x30"]); // dedup
    expect(progress(c).pct).toBe(1);
  });
});
