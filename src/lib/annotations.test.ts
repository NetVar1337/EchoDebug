import { describe, expect, it, vi } from "vitest";
import tools from "./tools.json";

vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => undefined, removeItem: () => undefined });
const writes: unknown[] = [];
vi.mock("./client", () => ({
  client: { send: () => undefined },
  request: async (type: string, fields: unknown) => void writes.push({ type, fields }),
}));
vi.mock("@/store/output", () => ({ log: () => undefined }));

const { annotationHandlers } = await import("./annotations");
const { usePatches } = await import("@/store/patches");

const call = (verb: string, args: Record<string, unknown>) => {
  const h = annotationHandlers[verb];
  if (!h) throw new Error(`unknown verb ${verb}`);
  return h(args);
};

describe("annotation verbs", () => {
  it("are the ui_* verbs of MCP tools (so the relay's provider routing and policy apply)", () => {
    const verbs = (tools as { verb: string }[]).map((t) => t.verb);
    for (const v of Object.keys(annotationHandlers)) {
      expect(v.startsWith("ui_")).toBe(true);
      expect(verbs).toContain(v);
    }
  });

  it("sets and lists names and comments with 0x addresses", async () => {
    expect(await call("ui_set_name", { address: "0x140001000", name: "main" })).toEqual({ address: "0x140001000", name: "main" });
    await call("ui_set_comment", { address: "0x140001000", comment: "entry" });
    expect(await call("ui_list_names", {})).toEqual({ names: [{ address: "0x140001000", name: "main" }] });
    expect(await call("ui_list_comments", {})).toEqual({ comments: [{ address: "0x140001000", comment: "entry" }] });
  });

  it("rejects bad arguments", async () => {
    await expect(call("ui_set_name", { address: "main", name: "x" })).rejects.toThrow(/address/);
    await expect(call("ui_set_comment", { address: "0x10" })).rejects.toThrow(/comment/);
  });

  it("reverts a patch once by writing the original bytes", async () => {
    usePatches.getState().add({ id: "p1", address: "0x1000", written: "90", before: "cc", note: "", created: 0, reverted: false });
    expect(await call("ui_revert_patch", { patch_id: "p1" })).toEqual({ patch_id: "p1", address: "0x1000", restored: "cc" });
    expect(writes).toEqual([{ type: "write", fields: { address: "0x1000", data: "cc" } }]);
    expect(usePatches.getState().patches[0].reverted).toBe(true);
    await expect(call("ui_revert_patch", { patch_id: "p1" })).rejects.toThrow(/already reverted/);
    await expect(call("ui_revert_patch", { patch_id: "zz" })).rejects.toThrow(/no patch/);
  });
});
