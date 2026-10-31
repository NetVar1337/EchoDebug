import { describe, expect, it } from "vitest";
import { diffRange, diffSnapshots, type Snapshot } from "./snapshot";

function snap(name: string, address: string, bytes: number[]): Snapshot {
  return {
    id: name,
    name,
    address,
    size: bytes.length,
    bytes: Uint8Array.from(bytes),
    created: 0,
  };
}

describe("snapshot", () => {
  it("reports only differing bytes with absolute addresses", () => {
    const a = snap("a", "0x140001000", [1, 2, 3, 4]);
    const b = snap("b", "0x140001000", [1, 9, 3, 0]);
    const diff = diffSnapshots(a, b);
    expect(diff).toHaveLength(2);
    expect(diff[0]).toEqual({ offset: 1, address: "0x140001001", before: 2, after: 9 });
    expect(diff[1]).toEqual({ offset: 3, address: "0x140001003", before: 4, after: 0 });
  });

  it("compares by offset even when the base addresses differ", () => {
    const a = snap("a", "0x140001000", [1, 2, 3]);
    const b = snap("b", "0x180000000", [1, 5, 3]);
    const diff = diffSnapshots(a, b);
    expect(diff).toHaveLength(1);
    expect(diff[0].offset).toBe(1);
    expect(diff[0].before).toBe(2);
    expect(diff[0].after).toBe(5);
  });

  it("only compares up to the shorter length", () => {
    const a = snap("a", "0x1000", [1, 2, 3, 4]);
    const b = snap("b", "0x1000", [1, 2]);
    expect(diffSnapshots(a, b)).toEqual([]);
  });

  it("diffs raw byte ranges against a base address", () => {
    const a = Uint8Array.from([0, 1, 2]);
    const b = Uint8Array.from([0, 1, 9]);
    const diff = diffRange(a, b, "0x7ff600001000");
    expect(diff).toHaveLength(1);
    expect(diff[0]).toEqual({
      offset: 2,
      address: `0x${(0x7ff600001000n + 2n).toString(16)}`,
      before: 2,
      after: 9,
    });
  });

  it("returns an empty diff for identical buffers", () => {
    expect(diffRange(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 3]), "0x1000")).toEqual([]);
  });
});
