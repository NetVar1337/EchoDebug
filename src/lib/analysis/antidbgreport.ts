// Anti-debug report (#20): turns raw AntiHit[]s into a prioritized report where every finding
// carries a concrete, revertable patch suggestion (NOP the check, or note the import to stub),
// so the report can be consumed by a human or by CI (via lib/report.ts).
import type { AntiHit } from "./antidebug";
import type { Finding } from "../report";

export type PatchSuggestion =
  | { action: "nop"; at: string; bytes: string; note: string }
  | { action: "review"; at: string; note: string };

export type ReportFinding = {
  hit: AntiHit;
  severity: "high" | "medium" | "low";
  suggestion: PatchSuggestion;
};

export type AntiReport = {
  summary: { total: number; high: number; medium: number; low: number; byKind: Record<string, number> };
  findings: ReportFinding[];
};

const kSeverity: Record<string, "high" | "medium" | "low"> = {
  int2d: "high",
  icebp: "high",
  vmcall: "high",
  vmclear: "high",
  sidt: "medium",
  sgdt: "medium",
  sldt: "medium",
  xgetbv: "medium",
  cpuid: "low",
  rdtsc: "low",
  rdtscp: "low",
  peb: "medium",
  teb: "low",
  "debug-api": "high",
  "debugger-window": "medium",
};

/** Inline byte checks can be neutralized by overwriting them with NOPs (0x90). */
function nopSuggestion(hit: AntiHit): PatchSuggestion {
  const len = hit.bytes.length / 2;
  return { action: "nop", at: hit.address, bytes: "90".repeat(len), note: `overwrite ${len} byte(s) at ${hit.address} with NOPs` };
}

export function buildAntiReport(hits: readonly AntiHit[]): AntiReport {
  const findings: ReportFinding[] = hits.map((hit) => {
    const severity = hit.confidence >= 0.8 ? kSeverity[hit.kind] ?? "medium" : hit.confidence >= 0.5 ? "medium" : "low";
    const suggestion: PatchSuggestion =
      hit.kind === "debug-api" || hit.kind === "debugger-window"
        ? { action: "review", at: hit.address, note: "import-based check: resolve the IAT entry to a stub that returns 'not debugged'" }
        : nopSuggestion(hit);
    return { hit, severity, suggestion };
  });
  findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "high" ? -1 : b.severity === "high" ? 1 : a.severity === "medium" ? -1 : 1));
  const byKind: Record<string, number> = {};
  const summary = { total: hits.length, high: 0, medium: 0, low: 0, byKind };
  for (const f of findings) {
    summary[f.severity]++;
    byKind[f.hit.kind] = (byKind[f.hit.kind] ?? 0) + 1;
  }
  return { summary, findings };
}

/** Converts the report into generic findings for SARIF/JSON export. */
export function toFindings(rep: AntiReport): Finding[] {
  return rep.findings.map((f) => ({
    ruleId: `antidebug/${f.hit.kind}`,
    level: f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "note",
    message: f.hit.detail,
    address: f.hit.address,
    detail: f.suggestion.note,
  }));
}
