import { describe, expect, it } from "vitest";
import { bestString, buffersFromLog } from "./decrypt";

const w = (address: number, after: string) => ({ rip: "0x1", address: "0x" + address.toString(16), size: after.length / 2, access: "w", before: "00".repeat(after.length / 2), after });
const hex = (s: string) => Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");

describe("batch decrypt helpers", () => {
  it("rebuilds written buffers and picks the decrypted string", () => {
    const log = [
      w(0x5000, hex("sec")), w(0x5003, hex("ret")), w(0x5006, "00"), // "secret\0" in two writes
      w(0x7ff0, "efbeadde"), // stack noise
      { rip: "0x1", address: "0x6000", size: 4, access: "r", before: "41414141" }, // reads are ignored
      w(0x8000, "4100420043000000"), // L"ABC"
    ];
    const bufs = buffersFromLog(log, (a) => a >= 0x7f00n && a < 0x8000n);
    expect(bufs.map((b) => b.address)).toEqual([0x5000n, 0x8000n]);
    expect(bestString(bufs)).toEqual({ text: "secret", encoding: "ascii", address: 0x5000n, score: 6 });
    expect(bestString([bufs[1]])?.text).toBe("ABC");
    expect(bestString([{ address: 0n, bytes: new Uint8Array([1, 2, 3, 4]) }])).toBeNull();
  });
});
