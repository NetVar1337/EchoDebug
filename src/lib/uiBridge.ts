// Serves the relay's UI verbs (MCP tools list_names, set_name, list_comments, set_comment,
// list_patches, revert_patch, list_signatures) from the frontend stores. The relay sends
// `{type:"ui_call", call_id, verb, args}`; we answer `{type:"ui_reply", call_id, result|error}`.
// Kept thin on purpose: only the stores' public actions are used.
import { client, request, type Frame } from "./client";
import { fmtAddr } from "./hex";
import { useNames } from "@/store/names";
import { usePatches } from "@/store/patches";
import { useSigs } from "@/store/sigs";
import { log } from "@/store/output";

/** Stores keep addresses in their own form; MCP clients always see 0x-prefixed hex. */
const show = (a: string) => {
  try {
    return fmtAddr(BigInt(/^0x/i.test(a) ? a : `0x${a}`));
  } catch {
    return a; // a non-numeric key (e.g. module+rva) passes through unchanged
  }
};

function address(args: Record<string, unknown>): string {
  const a = String(args.address ?? "").trim();
  if (!/^0x[0-9a-f]{1,16}$/i.test(a)) throw new Error("address must be a 0x-prefixed hex string");
  return a.toLowerCase();
}

function text(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  if (typeof v !== "string") throw new Error(`${key} must be a string`);
  return v;
}

export async function uiCall(verb: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const names = useNames.getState();
  switch (verb) {
    case "list_names":
      return { names: names.list().filter((n) => n.name).map((n) => ({ address: show(n.address), name: n.name })) };
    case "set_name": {
      const at = address(args);
      names.rename(at, text(args, "name"));
      log("info", "mcp", `named ${at} "${text(args, "name")}"`);
      return { address: at, name: useNames.getState().nameOf(at) };
    }
    case "list_comments":
      return { comments: names.list().filter((n) => n.comment).map((n) => ({ address: show(n.address), comment: n.comment })) };
    case "set_comment": {
      const at = address(args);
      names.comment(at, text(args, "comment"));
      return { address: at, comment: useNames.getState().commentOf(at) };
    }
    case "list_patches":
      return { patches: usePatches.getState().patches };
    case "revert_patch": {
      const id = text(args, "patch_id");
      const p = usePatches.getState().patches.find((x) => x.id === id);
      if (!p) throw new Error(`no patch with id ${id}`);
      if (p.reverted) throw new Error(`patch ${id} is already reverted`);
      await request("write", { address: p.address, data: p.before });
      usePatches.getState().revert(id);
      log("info", "mcp", `reverted the write at ${p.address}`);
      return { patch_id: id, address: p.address, restored: p.before };
    }
    case "list_signatures":
      return {
        signatures: useSigs.getState().sigs.map((s) => ({ id: s.id, name: s.name, module: s.module, ida: s.ida, address: s.address, hits: s.hits, note: s.note })),
      };
    default:
      throw new Error(`unknown UI verb ${verb}`);
  }
}

export async function handleUiCall(f: Frame): Promise<void> {
  const args = (f.args && typeof f.args === "object" ? f.args : {}) as Record<string, unknown>;
  try {
    client.send({ type: "ui_reply", call_id: f.call_id, result: await uiCall(String(f.verb), args) });
  } catch (e) {
    client.send({ type: "ui_reply", call_id: f.call_id, error: e instanceof Error ? e.message : String(e) });
  }
}
