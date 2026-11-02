import { describe, expect, it, vi } from "vitest";

vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => undefined, removeItem: () => undefined });
const writes: unknown[] = [];
vi.mock("./client", () => ({
  client: { send: () => undefined },
  request: async (type: string, fields: unknown) => void writes.push({ type, fields }),
}));
vi.mock("@/store/output", () => ({ log: () => undefined }));

const { uiCall } = await import("./uiBridge");
const { usePatches } = await import("@/store/patches");

describe("uiBridge", () => {
  it("sets and lists names and comments with 0x addresses", async () => {
    expect(await uiCall("set_name", { address: "0x140001000", name: "main" })).toEqual({ address: "0x140001000", name: "main" });
    await uiCall("set_comment", { address: "0x140001000", comment: "entry" });
    expect(await uiCall("list_names", {})).toEqual({ names: [{ address: "0x140001000", name: "main" }] });
    expect(await uiCall("list_comments", {})).toEqual({ comments: [{ address: "0x140001000", comment: "entry" }] });
  });

  it("rejects bad arguments and unknown verbs", async () => {
    await expect(uiCall("set_name", { address: "main", name: "x" })).rejects.toThrow(/address/);
    await expect(uiCall("set_comment", { address: "0x10" })).rejects.toThrow(/comment/);
    await expect(uiCall("nope", {})).rejects.toThrow(/unknown/);
  });

  it("reverts a patch once by writing the original bytes", async () => {
    usePatches.getState().add({ id: "p1", address: "0x1000", written: "90", before: "cc", note: "", created: 0, reverted: false });
    expect(await uiCall("revert_patch", { patch_id: "p1" })).toEqual({ patch_id: "p1", address: "0x1000", restored: "cc" });
    expect(writes).toEqual([{ type: "write", fields: { address: "0x1000", data: "cc" } }]);
    expect(usePatches.getState().patches[0].reverted).toBe(true);
    await expect(uiCall("revert_patch", { patch_id: "p1" })).rejects.toThrow(/already reverted/);
    await expect(uiCall("revert_patch", { patch_id: "zz" })).rejects.toThrow(/no patch/);
  });
});
