import { describe, expect, it } from "vitest";
import { buildAntiReport, toFindings } from "./antidbgreport";
import type { AntiHit } from "./antidebug";

const hits: AntiHit[] = [
  { kind: "int2d", rva: 0x10, address: "0x1000", bytes: "cd2d", detail: "INT 2D", confidence: 0.9 },
  { kind: "debug-api", rva: 0x20, address: "0x2000", bytes: "", detail: "IsDebuggerPresent import", confidence: 0.95 },
  { kind: "rdtsc", rva: 0x30, address: "0x3000", bytes: "0f31", detail: "RDTSC", confidence: 0.4 },
];

describe("anti-debug report", () => {
  it("sorts by severity and attaches patch suggestions", () => {
    const rep = buildAntiReport(hits);
    expect(rep.summary).toEqual({ total: 3, high: 2, medium: 0, low: 1, byKind: { int2d: 1, "debug-api": 1, rdtsc: 1 } });
    expect(rep.findings.map((f) => f.severity)).toEqual(["high", "high", "low"]);
    const int2d = rep.findings[0].suggestion;
    expect(int2d).toMatchObject({ action: "nop", at: "0x1000", bytes: "9090" });
    const api = rep.findings.find((f) => f.hit.kind === "debug-api")!.suggestion;
    expect(api.action).toBe("review");
  });

  it("converts to SARIF-ready findings", () => {
    const f = toFindings(buildAntiReport(hits));
    expect(f[0]).toMatchObject({ ruleId: "antidebug/int2d", level: "error", address: "0x1000" });
    expect(f[2].level).toBe("note");
  });
});
