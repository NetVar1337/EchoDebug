import { describe, expect, it } from "vitest";
import { ciExitCode, summarize, toJsonReport, toSarif, type Finding } from "./report";

const findings: Finding[] = [
  { ruleId: "yara/mimikatz", level: "error", message: "mimikatz strings", address: "0x7ff600001000", module: "game.exe" },
  { ruleId: "antidebug/int2d", level: "warning", message: "INT 2D check", address: "0x7ff600002000", detail: "overwrite with NOPs" },
  { ruleId: "hooks/iat", level: "note", message: "IAT hook in kernel32" },
];

describe("report export", () => {
  it("builds SARIF 2.1.0 with one rule per ruleId and absolute addresses", () => {
    const sarif = JSON.parse(toSarif(findings, { tool: "EchoDebug", version: "0.9.10", target: "pid 1 (game.exe)" }));
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("EchoDebug");
    expect(run.tool.driver.rules).toHaveLength(3);
    expect(run.results).toHaveLength(3);
    expect(run.results[0].level).toBe("error");
    expect(run.results[0].locations[0].physicalLocation.address.absoluteAddress).toBe(0x7ff600001000);
    expect(run.results[1].message.text).toMatch(/overwrite with NOPs/);
    expect(run.results[2].locations).toEqual([]);
    expect(run.properties.target).toBe("pid 1 (game.exe)");
  });

  it("builds a JSON report with a count", () => {
    const r = toJsonReport(findings, { tool: "EchoDebug", version: "0.9.10" });
    expect(r.format).toBe("echodebug.report");
    expect(r.meta.findingCount).toBe(3);
    expect(r.findings).toHaveLength(3);
  });

  it("summarizes per rule and computes the CI exit code", () => {
    expect(summarize([...findings, { ruleId: "yara/mimikatz", level: "error", message: "again" }])).toEqual({ "yara/mimikatz": 2, "antidebug/int2d": 1, "hooks/iat": 1 });
    expect(ciExitCode(findings)).toBe(1);
    expect(ciExitCode(findings.filter((f) => f.level !== "error"))).toBe(0);
  });
});
