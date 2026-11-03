import { describe, expect, it } from "vitest";
import { checkVerb, PermissionError } from "./api";
import { validateManifest } from "./manifest";

const base = { id: "acme.scoped", name: "Scoped", version: "1.0.0", entry: "index.js", permissions: ["write"] };

describe("manifest verbs scope (#29)", () => {
  it("accepts verb globs and rejects junk", () => {
    const ok = validateManifest({ ...base, verbs: ["read_*", "disassemble", "sig_scan"] });
    expect(ok.ok && ok.manifest.verbs).toEqual(["read_*", "disassemble", "sig_scan"]);
    for (const bad of [["read memory"], [""], [123], "read_*"]) {
      expect(validateManifest({ ...base, verbs: bad }).ok).toBe(false);
    }
  });

  it("narrows the catalog: outside-scope verbs are refused even with permission", () => {
    expect(() => checkVerb("acme.scoped", ["write"], "read", ["read*", "disassemble"])).not.toThrow();
    expect(() => checkVerb("acme.scoped", ["write"], "disassemble", ["read*", "disassemble"])).not.toThrow();
    expect(() => checkVerb("acme.scoped", ["write"], "scan_new", ["read*", "disassemble"])).toThrow(PermissionError);
    expect(() => checkVerb("acme.scoped", ["write"], "scan_new", ["read*"])).toThrow(/verbs.*scope/);
  });

  it("raw writes stay refused even when scoped in", () => {
    expect(() => checkVerb("acme.scoped", ["write"], "write", ["*"])).toThrow(/not available to plugins/);
  });

  it("no verbs field means the whole permitted catalog", () => {
    expect(() => checkVerb("acme.scoped", ["write"], "scan_new")).not.toThrow();
  });
});
