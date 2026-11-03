import { describe, expect, it } from "vitest";
import { diffNames, fromModuleRva, structDecls, toModuleRva, trailing } from "./sync";

const mods = [
  { name: "game.exe", base: "0x7ff600000000", size: 0x100000 },
  { name: "KERNEL32.DLL", base: "0x7ffb00000000", size: 0x80000 },
];

describe("sync mapping", () => {
  it("maps live addresses to module + RVA and back, wherever the module is loaded", () => {
    expect(toModuleRva("0x7ff600001234", mods)).toEqual({ module: "game.exe", rva: 0x1234 });
    expect(toModuleRva(0x7ffb00000010n, mods)).toEqual({ module: "KERNEL32.DLL", rva: 0x10 });
    expect(toModuleRva("0x1000", mods)).toBeNull();
    expect(fromModuleRva("GAME.EXE", "0x1234", mods)).toBe(0x7ff600001234n);
    expect(fromModuleRva("kernel32.dll", 16, mods)).toBe(0x7ffb00000010n);
    expect(fromModuleRva("game.exe", "1234", mods)).toBe(0x7ff600001234n);
    // a rebased load: same RVA, new base
    const rebased = [{ ...mods[0], base: "0x140000000" }];
    expect(fromModuleRva("game.exe", "0x1234", rebased)).toBe(0x140001234n);
    expect(fromModuleRva("game.exe", "0x200000", mods)).toBeNull();
    expect(fromModuleRva("other.dll", "0x10", mods)).toBeNull();
    expect(fromModuleRva("game.exe", "zz", mods)).toBeNull();
  });

  it("diffs name lists into the changes to send", () => {
    const prev = [
      { address: "00007ff600001000", name: "main", comment: "" },
      { address: "00007ff600002000", name: "old", comment: "note" },
      { address: "00007ff600003000", name: "gone", comment: "bye" },
    ];
    const next = [
      { address: "00007ff600001000", name: "main", comment: "entry" },
      { address: "00007ff600002000", name: "new", comment: "note" },
      { address: "00007ff600004000", name: "added", comment: "" },
    ];
    expect(diffNames(prev, next)).toEqual([
      { address: "0x00007ff600001000", comment: "entry" },
      { address: "0x00007ff600002000", name: "new" },
      { address: "0x00007ff600004000", name: "added" },
      { address: "0x00007ff600003000", name: "", comment: "" },
    ]);
    expect(diffNames(next, next)).toEqual([]);
  });

  it("turns the struct catalog into C declarations", () => {
    const { decls, names } = structDecls([
      { id: "a", name: "Player", fields: [{ type: "i32", name: "hp" }, { type: "ptr", name: "next" }] },
      { id: "b", name: "bad name", fields: [{ type: "u8", name: "x" }] },
      { id: "c", name: "Empty", fields: [] },
    ]);
    expect(names).toEqual(["Player"]);
    expect(decls).toContain("struct Player;");
    expect(decls).toContain("struct Player {");
    expect(decls).toMatch(/int hp;/);
    expect(decls).not.toContain("#include");
  });

  it("throttles to the trailing call", async () => {
    const seen: number[] = [];
    const f = trailing(10, (n: number) => seen.push(n));
    f(1); f(2); f(3);
    await new Promise((r) => setTimeout(r, 30));
    f(4);
    await new Promise((r) => setTimeout(r, 30));
    expect(seen).toEqual([3, 4]);
  });
});
