// The app window's annotation verbs for MCP clients (tools list_names, set_name, list_comments,
// set_comment, list_patches, revert_patch, list_signatures). They are ordinary `ui_*` provider
// verbs: provider.ts registers them, the relay forwards them as provider_call frames, and its MCP
// policy gates them like any other tool (revert_patch writes the target, so ask/read-only apply).
// Kept thin on purpose: only the stores' public actions are used.
import { request } from "./client";
import { fmtAddr } from "./hex";
import { useNames } from "@/store/names";
import { usePatches } from "@/store/patches";
import { useSigs } from "@/store/sigs";
import { log } from "@/store/output";

type Args = Record<string, unknown>;

/** Stores keep addresses in their own form; MCP clients always see 0x-prefixed hex. */
const show = (a: string) => {
  try {
    return fmtAddr(BigInt(/^0x/i.test(a) ? a : `0x${a}`));
  } catch {
    return a; // a non-numeric key (e.g. module+rva) passes through unchanged
  }
};

function address(args: Args): string {
  const a = String(args.address ?? "").trim();
  if (!/^0x[0-9a-f]{1,16}$/i.test(a)) throw new Error("address must be a 0x-prefixed hex string");
  return a.toLowerCase();
}

function text(args: Args, key: string): string {
  const v = args[key];
  if (typeof v !== "string") throw new Error(`${key} must be a string`);
  return v;
}

/** `ui_*` verb -> handler; provider.ts registers each with `provide`. */
export const annotationHandlers: Record<string, (args: Args) => Promise<Record<string, unknown>>> = {
  ui_list_names: async () => ({
    names: useNames.getState().list().filter((n) => n.name).map((n) => ({ address: show(n.address), name: n.name })),
  }),
  ui_set_name: async (args) => {
    const at = address(args);
    const name = text(args, "name");
    useNames.getState().rename(at, name);
    log("info", "mcp", `named ${at} "${name}"`);
    return { address: at, name: useNames.getState().nameOf(at) };
  },
  ui_list_comments: async () => ({
    comments: useNames.getState().list().filter((n) => n.comment).map((n) => ({ address: show(n.address), comment: n.comment })),
  }),
  ui_set_comment: async (args) => {
    const at = address(args);
    useNames.getState().comment(at, text(args, "comment"));
    return { address: at, comment: useNames.getState().commentOf(at) };
  },
  ui_list_patches: async () => ({ patches: usePatches.getState().patches }),
  ui_revert_patch: async (args) => {
    const id = text(args, "patch_id");
    const p = usePatches.getState().patches.find((x) => x.id === id);
    if (!p) throw new Error(`no patch with id ${id}`);
    if (p.reverted) throw new Error(`patch ${id} is already reverted`);
    await request("write", { address: p.address, data: p.before });
    usePatches.getState().revert(id);
    log("info", "mcp", `reverted the write at ${p.address}`);
    return { patch_id: id, address: p.address, restored: p.before };
  },
  ui_list_signatures: async () => ({
    signatures: useSigs.getState().sigs.map((s) => ({ id: s.id, name: s.name, module: s.module, ida: s.ida, address: s.address, hits: s.hits, note: s.note })),
  }),
};
