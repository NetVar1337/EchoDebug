import { describe, expect, it } from "vitest";
import { fireRules } from "./autowire";
import type { Exec, Rule } from "./automation";

const rules: Rule[] = [
  { id: "r1", when: { event: "alert_event", match: { label: "hp*" } }, action: { kind: "verb", verb: "scan_new", args: { value: "$event.value" } } },
  { id: "r2", when: { event: "module_loaded" }, action: { kind: "command", command: "acme.refresh" } },
  { id: "r3", when: { event: "page_changed" }, action: { kind: "log", message: "page $event.address" } },
];

const exec = (calls: string[]): Exec => ({
  verb: async (v, a) => {
    calls.push(`verb ${v} ${JSON.stringify(a)}`);
    return { ok: 1 };
  },
  command: async (c) => {
    calls.push(`cmd ${c}`);
    if (c === "missing") throw new Error("no such command");
    return null;
  },
  log: (m) => calls.push(`log ${m}`),
});

describe("fireRules", () => {
  it("runs only matching rules and substitutes event fields", async () => {
    const calls: string[] = [];
    const out = await fireRules({ type: "event", event: "alert_event", label: "hp", value: "50" }, rules, exec(calls));
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ rule: "r1", ok: true });
    expect(calls[0]).toContain('"value":"50"');
  });

  it("runs command and log actions on their events", async () => {
    const calls: string[] = [];
    await fireRules({ type: "event", event: "module_loaded", name: "x.dll" }, rules, exec(calls));
    await fireRules({ type: "event", event: "page_changed", address: "0x1000" }, rules, exec(calls));
    expect(calls).toContain("cmd acme.refresh");
    expect(calls).toContain("log page 0x1000");
  });

  it("reports a failing action without throwing, and skips when no rules", async () => {
    const calls: string[] = [];
    const out = await fireRules({ type: "event", event: "module_loaded" }, [...rules, { id: "r4", when: { event: "module_loaded" }, action: { kind: "command", command: "missing" } }], exec(calls));
    expect(out.find((r) => r.rule === "r4")?.ok).toBe(false);
    expect(await fireRules({ type: "event", event: "module_loaded" }, [], exec(calls))).toEqual([]);
  });

  it("ignores non-matching events", async () => {
    const calls: string[] = [];
    const out = await fireRules({ type: "event", event: "alert_event", label: "other" }, rules, exec(calls));
    expect(out).toEqual([]);
    expect(calls).toEqual([]);
  });
});
