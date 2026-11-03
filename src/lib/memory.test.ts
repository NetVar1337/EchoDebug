import { beforeEach, describe, expect, it, vi } from "vitest";

vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => undefined, removeItem: () => undefined });

// short payloads are fine: readRange clamps with subarray, so this stays light even for 20 MiB
const readBatch = vi.fn(async (_type: string, fields: { reads: { address: string; size: number }[] }) => ({
  results: fields.reads.map((r) => ({ success: true, address: r.address, data: "ab" })),
}));
const readSingle = vi.fn(async (_t: string, _f: unknown) => ({ success: true, data: "ab".repeat(8) }));
vi.mock("./client", () => ({ client: { send: () => undefined }, request: (t: string, f: unknown) => (t === "read_batch" ? readBatch(t, f as never) : readSingle(t, f)) }));

const { readRange, readBytes } = await import("./memory");

describe("readRange batching (#37)", () => {
  beforeEach(() => {
    readBatch.mockClear();
    readSingle.mockClear();
  });

  it("uses read_batch in rounds of 64 KiB entries, not one read per MiB", async () => {
    const progress: string[] = [];
    const out = await readRange(0x10000n, 3 * 1024 * 1024, (d, t) => progress.push(`${d}/${t}`)); // 3 MiB = 48 entries
    expect(out.length).toBe(3 * 1024 * 1024);
    expect(out[0]).toBe(0xab);
    expect(readBatch).toHaveBeenCalledTimes(1); // 48 entries < 256 per round
    expect(readSingle).not.toHaveBeenCalled();
    expect(progress[progress.length - 1]).toBe("48/48");
  });

  it("splits bigger ranges into multiple rounds", async () => {
    await readRange(0n, 20 * 1024 * 1024); // 320 entries -> rounds of 256 + 64
    expect(readBatch).toHaveBeenCalledTimes(2);
    const second = readBatch.mock.calls[1][1] as { reads: unknown[] };
    expect(second.reads).toHaveLength(64);
  });

  it("zero-fills failed entries and keeps going", async () => {
    readBatch.mockImplementationOnce(async (_t: string, fields: { reads: { address: string; size: number }[] }) => ({
      results: fields.reads.map((r, i) => (i === 1 ? { success: false, address: r.address, data: "" } : { success: true, address: r.address, data: "cd" })),
    }));
    const out = await readRange(0n, 0x20000); // two 64 KiB entries
    expect(out[0]).toBe(0xcd);
    expect(out[0x10000]).toBe(0);
  });
});

describe("readBytes", () => {
  it("decodes the single-read reply", async () => {
    const b = await readBytes(0x1000n, 8);
    expect(b && b.length).toBe(8);
    expect(b![0]).toBe(0xab);
  });
});
