import { describe, expect, it } from "vitest";
import { mergeScanResults, restorePlan, scanProgress, scannerResumable, type PersistedTargetState } from "./resume";

const state: PersistedTargetState = {
  pid: 1234,
  name: "game.exe",
  watches: [
    { address: "0x1000", type: "i32", label: "health" },
    { address: "0x2000", type: "f32", label: "speed", frozen: true },
  ],
  frozen: ["0x2000"],
  alerts: [{ kind: "value", address: "0x1000", value: "100", enabled: true }, { kind: "value", address: "0x3000", enabled: false }],
  scanner: { id: "s1", value: "2a", vtype: "u8", scanType: "exact", regionsDone: 2, totalRegions: 5, results: ["0x10"], done: false },
};

describe("restorePlan", () => {
  it("asks to attach when nothing is attached", () => {
    const plan = restorePlan(state, null);
    expect(plan[0]).toEqual({ kind: "attach", pid: 1234, name: "game.exe" });
  });

  it("replays watches, freezes, enabled alerts and a resumable scanner when attached", () => {
    const plan = restorePlan(state, { pid: 1234, name: "game.exe" });
    expect(plan.filter((a) => a.kind === "watch")).toHaveLength(2);
    expect(plan.filter((a) => a.kind === "freeze").map((a) => a.kind === "freeze" && a.address)).toEqual(["0x2000"]);
    expect(plan.filter((a) => a.kind === "alert")).toHaveLength(1); // disabled alert skipped
    expect(plan.filter((a) => a.kind === "scan")).toHaveLength(1);
  });

  it("notes a target name mismatch instead of failing", () => {
    const plan = restorePlan(state, { pid: 999, name: "other.exe" });
    expect(plan.find((a) => a.kind === "note")?.kind === "note" && (plan.find((a) => a.kind === "note") as { message: string }).message).toMatch(/other\.exe/);
  });

  it("skips a finished scanner", () => {
    const plan = restorePlan({ ...state, scanner: { ...state.scanner!, done: true, regionsDone: 5 } }, { pid: 1234, name: "game.exe" });
    expect(plan.find((a) => a.kind === "scan")).toBeUndefined();
  });
});

describe("scanner helpers", () => {
  it("resumable only when regions remain", () => {
    expect(scannerResumable(state.scanner!)).toBe(true);
    expect(scannerResumable({ ...state.scanner!, regionsDone: 5 })).toBe(false);
    expect(scannerResumable(null)).toBe(false);
  });

  it("progress and merge with dedup", () => {
    expect(scanProgress(state.scanner!)).toBeCloseTo(0.4);
    const merged = mergeScanResults(state.scanner!, ["0x10", "0x20", "0x30"]);
    expect(merged.results).toEqual(["0x10", "0x20", "0x30"]);
  });
});
