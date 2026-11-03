import { describe, expect, it } from "vitest";
import { analyzeIatHooks, moduleAt, type Mod } from "./iathook";
import type { IatMap } from "./iat";

const iat: IatMap = {
  byRva: new Map(),
  byAddress: new Map(),
  entries: [
    { rva: 0x3000, address: "0x143000", dll: "kernel32.dll", name: "CreateFileW" },
    { rva: 0x3008, address: "0x143008", dll: "user32.dll", name: "MessageBoxA" },
    { rva: 0x3010, address: "0x143010", dll: "ntdll.dll", name: "NtReadFile" },
  ],
};

const modules: Mod[] = [
  { name: "game.exe", base: "0x140000000", size: 0x100000 },
  { name: "kernel32.dll", base: "0x7ff80000000", size: 0x100000 },
  { name: "user32.dll", base: "0x7ff90000000", size: 0x100000 },
  { name: "ntdll.dll", base: "0x7ffa0000000", size: 0x200000 },
];

describe("moduleAt", () => {
  it("finds the containing module or null", () => {
    expect(moduleAt(0x140001000n, modules)).toBe("game.exe");
    expect(moduleAt(0x7ff80001000n, modules)).toBe("kernel32.dll");
    expect(moduleAt(0x5000n, modules)).toBeNull();
  });
});

describe("analyzeIatHooks (#13)", () => {
  it("flags slots pointing into the wrong module or nowhere, keeps ok ones", () => {
    const live = new Map<string, bigint>([
      ["0x143000", 0x7ff80001234n], // kernel32 slot -> kernel32: ok
      ["0x143008", 0x140005000n], // user32 slot -> game.exe code: foreign-module hook
      ["0x143010", 0x60000000n], // ntdll slot -> unmapped cave
    ]);
    const out = analyzeIatHooks(iat, live, modules);
    expect(out).toHaveLength(3);
    const byAddr = new Map(out.map((f) => [f.entry.address, f]));
    expect(byAddr.get("0x143000")?.kind).toBe("ok");
    expect(byAddr.get("0x143008")).toMatchObject({ kind: "foreign-module", targetModule: "game.exe" });
    expect(byAddr.get("0x143008")!.detail).toMatch(/expected user32\.dll/);
    expect(byAddr.get("0x143010")?.kind).toBe("unmapped");
    // unmapped first, then foreign-module, ok last
    expect(out.map((f) => f.kind)).toEqual(["unmapped", "foreign-module", "ok"]);
  });

  it("ignores slots that were not read", () => {
    expect(analyzeIatHooks(iat, new Map(), modules)).toEqual([]);
  });
});
