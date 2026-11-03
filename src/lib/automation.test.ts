import { describe, expect, it } from "vitest";
import { matchRule, runRules, substitute, substituteArgs, validateRules, type Exec, type Rule } from "./automation";

const rules: Rule[] = [
  { id: "on-alert", when: { event: "alert", match: { kind: "value" } }, action: { kind: "verb", verb: "decrypt_strings", args: { address: "$event.address" } } },
  { id: "on-page", when: { event: "page_changed", match: { label: "code*" } }, action: { kind: "log", message: "code page $event.address changed" } },
  { id: "disabled", enabled: false, when: { event: "alert" }, action: { kind: "log", message: "never" } },
  { id: "failing", when: { event: "alert", match: { label: "boom" } }, action: { kind: "verb", verb: "write", args: {} } },
];

describe("validateRules", () => {
  it("accepts a good file and rejects bad ones with reasons", () => {
    expect(validateRules({ format: "echodebug.rules", version: 1, rules }).ok).toBe(true);
    expect(validateRules("{nope").ok).toBe(false);
    expect(validateRules({ format: "x", version: 1, rules: [] }).ok).toBe(false);
    const bad = validateRules({ format: "echodebug.rules", version: 1, rules: [{ id: "Bad Id", when: { event: "alert" }, action: { kind: "verb", verb: "read" } }, { id: "ok", when: {}, action: { kind: "nope" } }] });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.errors.join("\n")).toMatch(/id.*duplicated|action\.kind|when\.event/);
  });
});

describe("matchRule + substitution", () => {
  it("matches event and glob fields, skips disabled", () => {
    expect(matchRule(rules[0], { event: "alert", kind: "value" })).toBe(true);
    expect(matchRule(rules[0], { event: "alert", kind: "string" })).toBe(false);
    expect(matchRule(rules[1], { event: "page_changed", label: "code cave" })).toBe(true);
    expect(matchRule(rules[2], { event: "alert" })).toBe(false);
  });

  it("substitutes $event fields, including nested", () => {
    const ev = { event: "alert", address: "0x1234", nested: { deep: 42 } };
    expect(substitute("hit at $event.address", ev)).toBe("hit at 0x1234");
    expect(substitute("$event.nested.deep ms", ev)).toBe("42 ms");
    expect(substitute("$event.missing!", ev)).toBe("!");
    expect(substituteArgs({ a: "$event.address", b: 1, c: { d: "$event.event" } }, ev)).toEqual({ a: "0x1234", b: 1, c: { d: "alert" } });
  });
});

describe("runRules", () => {
  it("executes matching rules and reports failures without throwing", async () => {
    const calls: string[] = [];
    const logs: string[] = [];
    const exec: Exec = {
      verb: async (verb, args) => {
        calls.push(`${verb} ${JSON.stringify(args)}`);
        if (verb === "write") throw new Error("denied");
        return { ok: true };
      },
      command: async () => ({}),
      log: (m) => logs.push(m),
    };
    const out = await runRules(rules, { event: "alert", kind: "value", label: "boom", address: "0x99" }, exec);
    expect(out.find((r) => r.rule === "on-alert")?.ok).toBe(true);
    expect(calls[0]).toContain('"address":"0x99"');
    expect(out.find((r) => r.rule === "failing")?.ok).toBe(false);
    expect(out.find((r) => r.rule === "failing")?.error).toMatch(/denied/);
    expect(out.find((r) => r.rule === "disabled")).toBeUndefined();
    const page = await runRules(rules, { event: "page_changed", label: "code cave", address: "0xabc" }, exec);
    expect(page).toEqual([{ rule: "on-page", ok: true, detail: undefined }]);
    expect(logs.some((l) => l.includes("0xabc"))).toBe(true);
  });
});
