import { describe, expect, it } from "vitest";
import { classifyImports, kRiskRules } from "./risk";
import type { IatMap } from "./iat";

function iatMap(names: string[]): IatMap {
  const entries = names.map((name, i) => ({
    rva: 0x1000 + i * 8,
    address: "0x" + (0x140000000n + BigInt(0x1000 + i * 8)).toString(16),
    dll: "KERNEL32.dll",
    name,
  }));
  return { byRva: new Map(), byAddress: new Map(), entries };
}

describe("risk classification", () => {
  it("flags memory tampering and injection as high risk", () => {
    const hits = classifyImports(iatMap(["VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory"]));
    expect(hits).toHaveLength(3);
    for (const h of hits) expect(h.level).toBe("high");
  });

  it("flags anti-analysis and permission changes as medium", () => {
    const hits = classifyImports(iatMap(["IsDebuggerPresent", "VirtualProtect"]));
    expect(hits.map((h) => h.level).sort()).toEqual(["medium", "medium"]);
  });

  it("ignores ordinary imports", () => {
    const hits = classifyImports(iatMap(["CreateFileW", "ReadFile", "CloseHandle"]));
    expect(hits).toHaveLength(0);
  });

  it("sorts the most severe findings first", () => {
    const hits = classifyImports(iatMap(["GetTickCount", "VirtualAlloc", "VirtualProtect"]));
    expect(hits.map((h) => h.level)).toEqual(["high", "medium", "low"]);
  });

  it("has no rule that matches everything", () => {
    expect(kRiskRules.length).toBeGreaterThan(10);
    for (const r of kRiskRules) expect(r.match.length).toBeGreaterThan(2);
  });
});
