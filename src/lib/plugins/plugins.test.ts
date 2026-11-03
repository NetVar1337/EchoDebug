import { readFileSync } from "node:fs";
import { beforeEach, describe, expect, it } from "vitest";
import tools from "@/lib/tools.json";
import { providedVerbs } from "@/lib/provider";
import { useNames } from "@/store/names";
import { checkVerb, kAnnotate, kRawWrites, kStateful, makePluginContext, PermissionError } from "./api";
import { activateModule, checkFolders, unloadPlugin } from "./loader";
import { describePermissions, safeEntry, validateManifest, type Manifest } from "./manifest";
import { checkResult, register, unregisterPlugin, usePluginRegistry } from "./registry";

const good = { id: "acme.tools", name: "Acme tools", version: "1.2.3", entry: "dist/index.js", permissions: ["write"] };
const manifest = (perms: Manifest["permissions"] = [], id = "test.plugin"): Manifest => ({ id, name: "Test", version: "1.0.0", entry: "index.js", permissions: perms });
const quiet = () => undefined;

describe("plugin manifests", () => {
  it("accepts a complete manifest", () => {
    const r = validateManifest(good);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.manifest).toMatchObject({ id: "acme.tools", permissions: ["write"] });
    const t = validateManifest(JSON.stringify({ ...good, permissions: undefined, extra: 1 }));
    expect(t.ok && t.manifest.permissions).toEqual([]);
    expect(t.ok && t.warnings).toEqual(['unknown field "extra" ignored']);
  });

  it("rejects bad fields with a reason for each", () => {
    const bad = (m: unknown) => {
      const r = validateManifest(m);
      expect(r.ok).toBe(false);
      return r.ok ? [] : r.errors;
    };
    expect(bad("{nope")[0]).toMatch(/not valid JSON/);
    expect(bad([])[0]).toMatch(/object/);
    expect(bad({})).toHaveLength(4);
    expect(bad({ ...good, id: "Has Spaces" })[0]).toMatch(/"id"/);
    expect(bad({ ...good, id: "x" })[0]).toMatch(/"id"/);
    expect(bad({ ...good, version: "1.0" })[0]).toMatch(/semver/);
    expect(bad({ ...good, permissions: ["write", "root"] })[0]).toMatch(/unknown permission "root"/);
    expect(bad({ ...good, permissions: "write" })[0]).toMatch(/array/);
    expect(bad({ ...good, description: 3 })[0]).toMatch(/description/);
    for (const entry of ["../index.js", "/abs/index.js", "C:/x.js", "a\\b.js", "index.ts", "./index.js", "a//b.js", ""]) {
      expect(safeEntry(entry), entry).toBe(false);
    }
    expect(safeEntry("index.mjs") && safeEntry("dist/main.js")).toBe(true);
  });

  it("flags duplicate ids and folders without a manifest", () => {
    const text = JSON.stringify(good);
    const r = checkFolders([{ dir: "a", manifest: text }, { dir: "b", manifest: text }, { dir: "c", error: "manifest.json: not found" }]);
    expect(r[0].errors).toEqual([]);
    expect(r[1].errors[0]).toMatch(/already used/);
    expect(r[2].errors[0]).toMatch(/not found/);
  });

  it("describes what the plugin may do", () => {
    expect(describePermissions([])).toHaveLength(1);
    expect(describePermissions(["write", "annotate"]).join(" ")).toMatch(/journal.*names/s);
  });
});

describe("plugin permissions", () => {
  beforeEach(() => useNames.setState({ names: [] }));

  it("a read-only plugin cannot write", async () => {
    const { ctx } = makePluginContext(manifest([]), quiet);
    await expect(ctx.ed.write("0x1000", "90")).rejects.toThrow(PermissionError);
    await expect(ctx.ed.write("0x1000", "90")).rejects.toThrow(/"write" permission/);
    expect(() => ctx.ed.request("write", { address: "0x1000", data: "90" })).toThrow(PermissionError);
    expect(() => ctx.ed.request("freeze", {})).toThrow(/not available to plugins/);
    expect(() => ctx.ed.request("scan_new", {})).toThrow(/"write" permission/);
    expect(() => ctx.ed.ui("ui_revert_patch", { patch_id: "x" })).toThrow(PermissionError);
    expect(() => ctx.ed.names.set("0x401000", "main")).toThrow(/"annotate"/);
    expect(() => ctx.ed.names.comment("0x401000", "x")).toThrow(/"annotate"/);
    expect(() => ctx.ed.ui("ui_set_name", { address: "0x1", name: "a" })).toThrow(/"annotate"/);
    expect(useNames.getState().names).toEqual([]);
    // reads stay allowed
    expect(() => checkVerb("p", [], "read")).not.toThrow();
    expect(() => checkVerb("p", [], "ui_strings")).not.toThrow();
    expect(() => checkVerb("p", [], "disassemble")).not.toThrow();
    // the access finder / API monitor change execution: `write` needed to start them, not to read results
    expect(() => checkVerb("p", [], "dbg_trace_start")).toThrow(/"write"/);
    expect(() => checkVerb("p", [], "dbg_api_start")).toThrow(/"write"/);
    expect(() => checkVerb("p", [], "dbg_api_log")).not.toThrow();
  });

  it("write and annotate unlock their calls, raw writes stay closed", async () => {
    const { ctx } = makePluginContext(manifest(["write", "annotate"]), quiet);
    // the permission check passes; the journaled write then fails for lack of a relay (false, no throw)
    await expect(ctx.ed.write("0x1000", "90")).resolves.toBe(false);
    expect(() => checkVerb("p", ["write"], "scan_new")).not.toThrow();
    expect(() => ctx.ed.request("write", {})).toThrow(/use ed.write/);
    expect(() => ctx.ed.request("sync_send", {})).toThrow(/not a verb plugins can call/);
    ctx.ed.names.set("0x401000", "main");
    expect(ctx.ed.names.get("0x401000")).toBe("main");
    // plugins get copies, not the app's store objects
    const all = ctx.ed.names.all();
    all[0].name = "tampered";
    expect(useNames.getState().nameOf("0x401000")).toBe("main");
    expect(Object.isFrozen(ctx.ed) && Object.isFrozen(ctx.manifest.permissions)).toBe(true);
  });

  it("the plugin verb lists cover the relay's MCP annotations", () => {
    const src = readFileSync("src-tauri/relay/src/mcp.rs", "utf8");
    const list = (name: string) => [...(new RegExp(`const ${name}: &\\[&str\\] = &\\[([^\\]]*)\\]`).exec(src)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    const destructive = list("DESTRUCTIVE");
    const stateful = list("STATEFUL");
    expect(destructive.length).toBeGreaterThan(2);
    expect(stateful.length).toBeGreaterThan(10);
    for (const v of destructive) expect(kRawWrites.has(v), v).toBe(true);
    for (const v of stateful) expect(kStateful.has(v) || kAnnotate.has(v), v).toBe(true);
  });
});

describe("plugin registration", () => {
  beforeEach(() => {
    for (const id of ["test.plugin", "example.module-overview", "other.plugin"]) unregisterPlugin(id);
  });

  it("registers views, commands, address actions and analyses, and removes them on unload", async () => {
    const calls: string[] = [];
    const mod = {
      activate(ctx: ReturnType<typeof makePluginContext>["ctx"]) {
        ctx.registerView({ id: "v", title: "View", render: (el) => { calls.push(`render ${el ? "el" : ""}`); } });
        ctx.registerCommand({ id: "c", label: "Command", run: () => calls.push("cmd") });
        ctx.registerAddressAction({ id: "a", label: "Action", run: (addr) => calls.push(`act ${addr}`) });
        ctx.registerAnalysis({ id: "t", title: "Table", run: () => ({ columns: ["a"], rows: [["0x1"]] }) });
      },
      deactivate: () => calls.push("deactivate"),
    };
    const active = await activateModule(manifest(), mod, quiet);
    const r = usePluginRegistry.getState();
    expect(r.views.map((x) => x.key)).toEqual(["test.plugin/v"]);
    expect(r.commands[0]).toMatchObject({ key: "test.plugin/c", plugin: "test.plugin", pluginName: "Test" });
    r.actions[0].run("0x401000");
    expect(checkResult(await r.analyses[0].run({}))).toEqual({ columns: ["a"], rows: [["0x1"]] });
    expect(calls).toEqual(["act 0x401000"]);
    // never over MCP: no provider verb, no tool
    expect(providedVerbs().some((v) => v.includes("test.plugin"))).toBe(false);
    expect((tools as { name: string }[]).some((t) => t.name.includes("plugin"))).toBe(false);
    await unloadPlugin(active);
    expect(calls).toContain("deactivate");
    const after = usePluginRegistry.getState();
    expect(after.views.length + after.commands.length + after.actions.length + after.analyses.length).toBe(0);
  });

  it("rejects bad registrations and cleans up a failed activation", async () => {
    const p = { id: "other.plugin", name: "Other" };
    expect(() => register("view", p, { id: "x", title: "X" } as never)).toThrow(/render/);
    expect(() => register("command", p, { id: "bad id", label: "X", run: () => 0 })).toThrow(/"id"/);
    expect(() => register("analysis", p, { id: "x", title: "", run: () => ({ columns: [], rows: [] }) })).toThrow(/title/);
    register("command", p, { id: "x", label: "X", run: () => 0 });
    expect(() => register("command", p, { id: "x", label: "Y", run: () => 0 })).toThrow(/already registered/);
    const failing = {
      activate(ctx: ReturnType<typeof makePluginContext>["ctx"]) {
        ctx.registerCommand({ id: "first", label: "First", run: () => 0 });
        ctx.registerCommand({ id: "first", label: "Again", run: () => 0 });
      },
    };
    await expect(activateModule(manifest([], "test.plugin"), failing, quiet)).rejects.toThrow(/already registered/);
    expect(usePluginRegistry.getState().commands.filter((c) => c.plugin === "test.plugin")).toEqual([]);
    await expect(activateModule(manifest(), {}, quiet)).rejects.toThrow(/activate/);
    expect(() => checkResult({ columns: "a", rows: [] })).toThrow(/columns/);
    expect(checkResult({ columns: ["a", "b"], rows: [[1, { x: 1 }, "extra"]] }).rows).toEqual([[1, '{"x":1}']]);
  });

  it("loads the shipped example plugin", async () => {
    const text = readFileSync("examples/plugins/module-overview/manifest.json", "utf8");
    const m = validateManifest(text);
    expect(m.ok).toBe(true);
    if (!m.ok) return;
    expect(m.manifest.permissions).toEqual([]);
    const path: string = "../../../examples/plugins/module-overview/index.js";
    const example = (await import(/* @vite-ignore */ path)) as Parameters<typeof activateModule>[1];
    const active = await activateModule(m.manifest, example, quiet);
    const r = usePluginRegistry.getState();
    expect(r.views.map((v) => v.title)).toEqual(["Modules"]);
    expect(r.analyses.map((a) => a.key)).toEqual(["example.module-overview/pointer-table"]);
    expect(r.commands).toHaveLength(1);
    expect(r.actions).toHaveLength(1);
    await expect(r.analyses[0].run({ address: "" })).rejects.toThrow(/enter an address/);
    await unloadPlugin(active);
  });
});
