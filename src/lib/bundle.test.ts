import { describe, expect, it } from "vitest";
import { buildBundle, diffBundles, validateBundle } from "./bundle";

const app = { name: "EchoDebug", version: "0.9.10" };
const state = {
  ui: { theme: "dark", accent: "blue" },
  watches: [{ id: "w1", address: "0x1000" }],
  names: [{ address: "0x1000", name: "health" }],
  types: [{ id: "t1", name: "CEntity" }],
  signatures: [{ id: "s1", name: "spawn" }],
  patches: [{ address: "0x2000", original: "cc", current: "90", note: "nop int3" }],
  rules: [{ id: "r1", when: { event: "alert" as const }, action: { kind: "log" as const, message: "hi" } }],
};

describe("bundle", () => {
  it("round-trips through build + validate", () => {
    const b = buildBundle(app, state, { name: "game.exe", module: "game.exe" });
    const v = validateBundle(JSON.stringify(b));
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.bundle.state.watches).toHaveLength(1);
  });

  it("rejects wrong format and bad rules", () => {
    expect(validateBundle({ format: "nope", version: 1, app, state: {} }).ok).toBe(false);
    const bad = validateBundle({ format: "echodebug.bundle", version: 1, app, state: { rules: [{ id: "bad id!" }] } });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.errors.join("\n")).toMatch(/state\.rules/);
  });

  it("diffs sections by id/address", () => {
    const a = buildBundle(app, state);
    const b = buildBundle(app, {
      ...state,
      watches: [{ id: "w1", address: "0x1000" }, { id: "w2", address: "0x3000" }],
      names: [],
      patches: [{ address: "0x2000", original: "cc", current: "cc", note: "reverted" }, { address: "0x4000", original: "90", current: "cc" }],
    });
    const d = diffBundles(a, b);
    expect(d.watches.added).toEqual(["w2"]);
    expect(d.names.removed).toEqual(["0x1000"]);
    expect(d.patches.added).toEqual(["0x4000"]);
    expect(d.patches.changed).toEqual(["0x2000"]);
  });
});
