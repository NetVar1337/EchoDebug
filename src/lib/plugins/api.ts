// The object a plugin's `activate(ctx)` receives: the Script tab's `ed` API with the plugin's
// permissions enforced, plus the registration calls. Plugins get nothing else from the app.
//
// Permission rules (see manifest.ts):
// - every plugin may read memory, list modules, disassemble and run read-only verbs / analyses;
// - `write`: journaled memory writes (`ed.write`, listed in Patches) and stateful verbs
//   (scanner, emulator, attach, …). Raw target writes (`write`, `freeze`, …) are refused for every
//   plugin, so nothing bypasses the journal;
// - `annotate`: names and comments.
// `ed.request` / `ed.ui` only reach verbs of the MCP tool catalog (src/lib/tools.json).
import tools from "@/lib/tools.json";
import { makeApi } from "@/lib/scripting";
import { fmtAddr } from "@/lib/hex";
import { useUi } from "@/store/ui";
import type { Manifest, Permission } from "./manifest";
import { register, type AddressActionSpec, type AnalysisSpec, type CommandSpec, type ViewSpec } from "./registry";

// Raw target writes (refused for every plugin), stateful verbs (need `write`) and annotation
// verbs (need `annotate`): the lists mirror the MCP annotations in src-tauri/relay/src/mcp.rs.
import { kAnnotate, kRawWrites, kStateful } from "@/lib/verbclass";
export { kAnnotate, kRawWrites, kStateful };
const kCatalog = new Set((tools as { verb: string }[]).map((t) => t.verb));

export class PermissionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PermissionError";
  }
}

/** Throws unless a plugin with `perms` may call `verb`. */
export function checkVerb(pluginId: string, perms: readonly Permission[], verb: string): void {
  if (kRawWrites.has(verb)) throw new PermissionError(`plugin ${pluginId}: '${verb}' is not available to plugins; use ed.write (journaled, needs the "write" permission)`);
  if (!kCatalog.has(verb)) throw new PermissionError(`plugin ${pluginId}: '${verb}' is not a verb plugins can call (see the MCP tool catalog)`);
  if (kStateful.has(verb) && !perms.includes("write")) throw new PermissionError(`plugin ${pluginId}: '${verb}' changes state and needs the "write" permission in manifest.json`);
  if (kAnnotate.has(verb) && !perms.includes("annotate")) throw new PermissionError(`plugin ${pluginId}: '${verb}' changes names or comments and needs the "annotate" permission`);
}

export type PluginContext = ReturnType<typeof makePluginContext>["ctx"];

/** The context handed to `activate(ctx)`, and the loader's handle to undo its registrations. */
export function makePluginContext(manifest: Manifest, print: (...a: unknown[]) => void, signal: { aborted: boolean } = { aborted: false }) {
  const base = makeApi(print, signal);
  const perms = manifest.permissions;
  const id = manifest.id;
  const need = (p: Permission, what: string) => {
    if (!perms.includes(p)) throw new PermissionError(`plugin ${id}: ${what} needs the "${p}" permission in manifest.json`);
  };
  const ed = Object.freeze({
    ...base,
    request: (verb: string, args: Record<string, unknown> = {}) => {
      checkVerb(id, perms, verb);
      return base.request(verb, args);
    },
    ui: (verb: string, args: Record<string, unknown> = {}) => {
      if (!verb.startsWith("ui_")) throw new PermissionError(`plugin ${id}: ed.ui takes ui_* analyses`);
      checkVerb(id, perms, verb);
      return base.ui(verb, args);
    },
    write: async (a: string | number | bigint, data: Uint8Array | string, note?: string) => {
      need("write", "ed.write");
      return base.write(a, data, `plugin ${id}${note ? `: ${note}` : ""}`);
    },
    // copies: plugins never hold the app's own store objects
    modules: () => base.modules().map((m) => ({ ...m })),
    module: (name?: string) => ({ ...base.module(name) }),
    names: Object.freeze({
      get: base.names.get,
      all: () => base.names.all().map((n) => ({ ...n })),
      set: (a: string | number | bigint, name: string) => {
        need("annotate", "ed.names.set");
        return base.names.set(a, name);
      },
      comment: (a: string | number | bigint, text: string) => {
        need("annotate", "ed.names.comment");
        return base.names.comment(a, text);
      },
    }),
  });
  const plugin = { id, name: manifest.name };
  const disposers: (() => void)[] = [];
  const ctx = Object.freeze({
    /** a copy of the plugin's own manifest */
    manifest: Object.freeze({ ...manifest, permissions: Object.freeze([...manifest.permissions]) }),
    ed,
    log: (...a: unknown[]) => print(...a),
    /** opens the disassembly at an address (the only navigation plugins get) */
    navigate: (a: string | number | bigint): void => useUi.getState().goDisasm(fmtAddr(base.addr(a))),
    registerView: (spec: ViewSpec): void => void disposers.push(register("view", plugin, spec)),
    registerCommand: (spec: CommandSpec): void => void disposers.push(register("command", plugin, spec)),
    registerAddressAction: (spec: AddressActionSpec): void => void disposers.push(register("action", plugin, spec)),
    registerAnalysis: (spec: AnalysisSpec): void => void disposers.push(register("analysis", plugin, spec)),
  });
  return { ctx, dispose: () => { for (const d of disposers.splice(0)) d(); } };
}
