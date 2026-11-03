import { describe, expect, it, vi } from "vitest";

const memory = new Uint8Array(0x100);
memory.set([0x74, 0x05, 0x90, 0xc3], 0x10);
const writes: { at: bigint; data: number[] }[] = [];
vi.mock("./memory", () => ({ readBytes: async (a: bigint, n: number) => memory.slice(Number(a - 0x1000n), Number(a - 0x1000n) + n) }));
vi.mock("./patch", () => ({
  writeJournaled: async (a: bigint, d: Uint8Array) => { writes.push({ at: a, data: [...d] }); memory.set(d, Number(a - 0x1000n)); return true; },
}));
vi.mock("./modfile", () => ({ readModuleFileBytes: async () => { throw new Error("unused"); } }));

const { apply1337, journalBytePatches } = await import("./patchfilelive");
const mods = [{ name: "game.exe", base: "0x1000", size: 0x100 }];

describe(".1337 import", () => {
  it("applies runs where the original bytes are there, reports conflicts and missing modules", async () => {
    const r = await apply1337([
      { module: "GAME.exe", rva: 0x10, old: 0x74, new: 0xeb },
      { module: "game.exe", rva: 0x11, old: 0x05, new: 0x05 + 1 },
      { module: "game.exe", rva: 0x12, old: 0x33, new: 0xcc }, // memory has 0x90: conflict
      { module: "game.exe", rva: 0x13, old: 0x00, new: 0xc3 }, // already the new value
      { module: "other.dll", rva: 0, old: 0, new: 1 },
    ], mods);
    expect(r).toMatchObject({ applied: 2, already: 1, missing: ["other.dll"] });
    expect(r.conflicts).toEqual([{ module: "game.exe", rva: 0x12, found: 0x90, expected: 0x33 }]);
    expect(writes).toEqual([{ at: 0x1010n, data: [0xeb, 0x06, 0x90, 0xc3] }]);
    expect(memory[0x12]).toBe(0x90);
    const forced = await apply1337([{ module: "game.exe", rva: 0x12, old: 0x33, new: 0xcc }], mods, true);
    expect(forced.applied).toBe(1);
    expect(memory[0x12]).toBe(0xcc);
  });

  it("turns journal entries into per-byte patches, leaving out heap patches", () => {
    const p = journalBytePatches([
      { id: "a", address: "0x1010", before: "7405", written: "eb05", note: "", created: 0, reverted: false },
      { id: "b", address: "0x9000", before: "00", written: "01", note: "", created: 0, reverted: false },
    ], mods);
    expect(p).toEqual({ patches: [{ module: "game.exe", rva: 0x10, old: 0x74, new: 0xeb }], outside: 1 });
  });
});
