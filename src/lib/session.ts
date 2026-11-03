// Session export / import: a single JSON file that restores the workspace
// (theme, watches, bookmarks, names, comments, struct layout).
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { isTauri } from "./tauri";
import { useUi } from "@/store/ui";
import { useWatch, type WatchEntry, type Bookmark } from "@/store/watch";
import { useNames, type NameEntry } from "@/store/names";
import { useTypes, type TypeDef } from "@/store/types";
import { useSigs, type Signature } from "@/store/sigs";
import { usePatches, type Patch } from "@/store/patches";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import type { Rule } from "./automation";
import type { PersistedTargetState } from "./resume";

export type SessionFile = {
  format: "echodebug.session";
  /** v2 adds target state (resume), signatures, patches and automation rules */
  version: 1 | 2;
  savedAt: string;
  ui: {
    theme: string;
    accent: string;
    tab: string;
    module: string | null;
  };
  watches: WatchEntry[];
  bookmarks: Bookmark[];
  names: NameEntry[];
  types: TypeDef[];
  /** v2: */
  target?: PersistedTargetState;
  signatures?: Signature[];
  patches?: Patch[];
  rules?: Rule[];
};

export function buildSession(): SessionFile {
  const ui = useUi.getState();
  const w = useWatch.getState();
  const target = useConn.getState().target;
  return {
    format: "echodebug.session",
    version: 2,
    savedAt: new Date().toISOString(),
    ui: {
      theme: ui.theme,
      accent: ui.accent,
      tab: ui.tab,
      module: ui.module,
    },
    watches: w.watches,
    bookmarks: w.bookmarks,
    names: useNames.getState().names,
    types: useTypes.getState().types,
    target: target
      ? {
          pid: target.pid,
          name: target.name,
          savedAt: Date.now(),
          watches: w.watches.map((x) => ({ address: x.address, type: x.type, label: x.label, frozen: x.frozen })),
          frozen: w.watches.filter((x) => x.frozen).map((x) => x.address),
        }
      : undefined,
    signatures: useSigs.getState().sigs,
    patches: usePatches.getState().patches.filter((p) => !p.reverted),
  };
}

export async function exportSession(): Promise<string | null> {
  const data = buildSession();
  const text = JSON.stringify(data, null, 2);
  if (!isTauri()) {
    // Browser fallback: download the file.
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "echodebug-session.json" });
    a.click();
    URL.revokeObjectURL(url);
    return "echodebug-session.json";
  }
  const path = await save({ defaultPath: "echodebug-session.json", filters: [{ name: "EchoDebug session", extensions: ["json"] }] });
  if (!path) return null;
  await invoke("write_text_file", { path, contents: text });
  log("info", "session", `exported to ${path}`);
  return path;
}

export async function importSession(): Promise<boolean> {
  if (!isTauri()) {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "application/json,.json";
    const { promise, resolve } = Promise.withResolvers<File | null>();
    input.onchange = () => resolve(input.files?.[0] ?? null);
    input.click();
    const file = await promise;
    if (!file) return false;
    return applySession(JSON.parse(await file.text()) as SessionFile);
  }
  const picked = await open({ multiple: false, filters: [{ name: "EchoDebug session", extensions: ["json"] }] });
  const path = Array.isArray(picked) ? picked[0] : picked;
  if (!path) return false;
  const text = await invoke<string>("read_text_file", { path });
  return applySession(JSON.parse(text) as SessionFile);
}

export function applySession(data: SessionFile): boolean {
  if (!data || data.format !== "echodebug.session") {
    log("error", "session", "not an EchoDebug session file");
    return false;
  }
  const ui = useUi.getState();
  ui.set({
    theme: (data.ui?.theme ?? ui.theme) as typeof ui.theme,
    accent: data.ui?.accent ?? ui.accent,
    tab: (data.ui?.tab ?? ui.tab) as typeof ui.tab,
    module: data.ui?.module ?? ui.module,
  });
  const w = useWatch.getState();
  w.setWatches(data.watches ?? [], data.bookmarks ?? []);
  useNames.getState().setNames(data.names ?? []);
  useTypes.getState().setTypes(data.types ?? []);
  if (data.version >= 2) {
    if (data.signatures) useSigs.getState().setSigs(data.signatures);
    if (data.patches) for (const p of data.patches) usePatches.getState().add(p);
  }
  log("info", "session", `imported (${(data.watches ?? []).length} watches, ${(data.names ?? []).length} names, ${(data.types ?? []).length} types${data.version >= 2 ? `, ${(data.signatures ?? []).length} signatures, ${(data.patches ?? []).length} patches` : ""})`);
  return true;
}
