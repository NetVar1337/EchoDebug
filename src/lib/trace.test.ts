import { describe, expect, it } from "vitest";
import { b64ToBytes, bytesToB64, hexRows, nearestStep, parseKnown, sparkline, taintTree, writtenBy, type TaintHop } from "./trace";

describe("trace view helpers", () => {
  it("parses reconstructed memory with unknown bytes", () => {
    expect(parseKnown("a1??ff")).toEqual([0xa1, null, 0xff]);
    const rows = hexRows(0x1000n, "00".repeat(20) + "????", 16);
    expect(rows.length).toBe(2);
    expect(rows[1].address).toBe(0x1010n);
    expect(rows[1].bytes).toEqual([0, 0, 0, 0, null, null]);
  });

  it("marks the bytes a step wrote inside the view", () => {
    const w = writtenBy({ accesses: [{ kind: "write", address: "0xffe", size: 4, old: "", new: "" }, { kind: "read", address: "0x1000", size: 8 }] }, 0x1000n, 16);
    expect([...w]).toEqual([0, 1]);
    expect(writtenBy(null, 0n, 4).size).toBe(0);
  });

  it("draws a step function scaled to the box", () => {
    const s = sparkline([[0, "0x0"], [5, "0xa"], [10, "0x5"]], 100, 10);
    expect(s.min).toBe(0n);
    expect(s.max).toBe(10n);
    expect(s.path).toBe("M0.0,10.0 H50.0 V0.0 H100.0 V5.0");
    // 64-bit values keep their order
    const big = sparkline([[0, "0xffffffffffffff00"], [1, "0xffffffffffffffff"]], 10, 10);
    expect(big.path.endsWith("V0.0")).toBe(true);
    expect(sparkline([[0, "0x7"], [3, "0x7"]], 10, 10).path).toBe("M0.0,5.0 H10.0 V5.0");
    expect(sparkline([], 1, 1).path).toBe("");
  });

  it("orders the dataflow walk as a tree", () => {
    const hop = (id: number, parent: number | null): TaintHop => ({ id, parent, step: id, loc: { kind: "reg", reg: "rax" }, value: "0x1", kind: "mov" });
    const t = taintTree([hop(0, null), hop(1, 0), hop(2, 0), hop(3, 1)]);
    expect(t.map((x) => [x.hop.id, x.depth])).toEqual([[0, 0], [1, 1], [3, 2], [2, 1]]);
  });

  it("picks the nearest breakpoint hit and round-trips base64", () => {
    expect(nearestStep([12, null, 4, undefined], true)).toBe(4);
    expect(nearestStep([12, null, 4], false)).toBe(12);
    expect(nearestStep([null], true)).toBe(null);
    const b = new Uint8Array(70000).map((_, i) => i * 7);
    expect(b64ToBytes(bytesToB64(b))).toEqual(b);
  });
});
