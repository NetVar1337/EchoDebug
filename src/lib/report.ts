// Headless report export (CI): turn analysis findings into SARIF 2.1.0 or a plain JSON report.
// Used by headless runs so YARA / hook / anti-debug / risk scans can gate a build.

export type Finding = {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: string;
  /** absolute address, hex with 0x, when the finding is tied to code/data */
  address?: string;
  module?: string;
  detail?: string;
};

export type ReportMeta = {
  tool: string;
  version: string;
  target?: string; // "pid 1234 (game.exe)"
  startedAt?: string;
  finishedAt?: string;
};

const kSarifLevels: Record<Finding["level"], string> = { error: "error", warning: "warning", note: "note" };

/** SARIF 2.1.0 document. */
export function toSarif(findings: readonly Finding[], meta: ReportMeta): string {
  const rules = new Map<string, { id: string; shortDescription: { text: string } }>();
  for (const f of findings) {
    if (!rules.has(f.ruleId)) rules.set(f.ruleId, { id: f.ruleId, shortDescription: { text: f.ruleId } });
  }
  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    level: kSarifLevels[f.level],
    message: { text: f.detail ? `${f.message} — ${f.detail}` : f.message },
    locations: f.address
      ? [{ physicalLocation: { address: { absoluteAddress: Number(BigInt(f.address)) }, artifactLocation: { uri: f.module ?? "target" } } }]
      : [],
  }));
  const doc = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: meta.tool, version: meta.version, rules: [...rules.values()] } },
        results,
        properties: { target: meta.target ?? null, startedAt: meta.startedAt ?? null, finishedAt: meta.finishedAt ?? null },
      },
    ],
  };
  return JSON.stringify(doc, null, 2);
}

export type JsonReport = {
  format: "echodebug.report";
  version: 1;
  meta: ReportMeta & { findingCount: number };
  findings: Finding[];
};

export function toJsonReport(findings: readonly Finding[], meta: ReportMeta): JsonReport {
  return {
    format: "echodebug.report",
    version: 1,
    meta: { ...meta, findingCount: findings.length },
    findings: findings.map((f) => ({ ...f })),
  };
}

export function summarize(findings: readonly Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.ruleId] = (out[f.ruleId] ?? 0) + 1;
  return out;
}

/** CI exit code convention: 1 when any error-level finding is present. */
export function ciExitCode(findings: readonly Finding[]): number {
  return findings.some((f) => f.level === "error") ? 1 : 0;
}
