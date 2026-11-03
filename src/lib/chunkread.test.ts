import { describe, expect, it } from "vitest";
import { kMaxReadBytes, readChunked } from "./chunkread";

const mem = new Uint8Array(1024 * 1024 * 10);
for (let i = 0; i < mem.length; i++) mem[i] = i % 251;
const read = async (addr: bigint, size: number) => mem.slice(Number(addr), Number(addr) + size);

describe("readChunked", () => {
  it("reads in frames with progress and no truncation under the cap", async () => {
    const progress: number[] = [];
    const r = await readChunked(read, 0x1000n, 3000, { chunk: 1000, onProgress: (d) => progress.push(d) });
    expect(r.frames).toBe(3);
    expect(r.returned).toBe(3000);
    expect(r.truncated).toBe(false);
    expect(r.bytes[2999]).toBe((0x1000 + 2999) % 251);
    expect(progress).toEqual([1000, 2000, 3000]);
    expect(r.gaps).toBe(0);
  });

  it("caps at kMaxReadBytes and flags truncation", async () => {
    const r = await readChunked(read, 0n, kMaxReadBytes * 2, { chunk: kMaxReadBytes / 2 });
    expect(r.truncated).toBe(true);
    expect(r.returned).toBe(kMaxReadBytes);
  });

  it("zero-fills failed frames and counts gaps, never rejects", async () => {
    const flaky = async (addr: bigint, size: number) => {
      if (addr === 2000n) throw new Error("region gone");
      return mem.slice(Number(addr), Number(addr) + size);
    };
    const r = await readChunked(flaky, 0n, 3000, { chunk: 1000 });
    expect(r.gaps).toBe(1000);
    expect(r.bytes[2000]).toBe(0);
    expect(r.bytes[1999]).toBe((1999) % 251);
  });

  it("stops when aborted", async () => {
    const signal = { aborted: false };
    const p = readChunked(read, 0n, 5000, { chunk: 1000, signal });
    signal.aborted = true;
    const r = await p;
    expect(r.returned).toBeLessThanOrEqual(1000);
  });
});
