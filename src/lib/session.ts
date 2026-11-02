// Session export / import: a single JSON file that restores the workspace
// (theme, watches, bookmarks, names, comments, struct layout).
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { isTauri } from "./tauri";
import { useUi } from "@/store/ui";
import { useWatch, type WatchEntry, type Bookmark } from "@/store/watch";
import { useNames, type NameEntry } from "@/store/names";
import { useTypes, type TypeDef } from "@/store/types";
import { log } from "@/store/output";

export type SessionFile = {
  format: "echodebug.session";
  version: 1;
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
};

export function buildSession(): SessionFile {
  const ui = useUi.getState();
  const w = useWatch.getState();
  return {
    format: "echodebug.session",
    version: 1,
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
  };
}

export async function exportSession(): Promise<string | null> {
  const path = await saveTextFile("echodebug-session.json", JSON.stringify(buildSession(), null, 2), "EchoDebug session");
  if (path) log("info", "session", `exported to ${path}`);
  return path;
}

export async function importSession(): Promise<boolean> {
  const text = await openTextFile("EchoDebug session");
  return text !== null && applySession(JSON.parse(text) as SessionFile);
}

/** Saves a JSON text file: Tauri save dialog, or a browser download. Returns the path, or null if cancelled. */
export async function saveTextFile(name: string, text: string, filterName: string): Promise<string | null> {
  if (!isTauri()) {
    // Browser fallback: download the file.
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: name });
    a.click();
    URL.revokeObjectURL(url);
    return name;
  }
  const path = await save({ defaultPath: name, filters: [{ name: filterName, extensions: ["json"] }] });
  if (!path) return null;
  await invoke("write_text_file", { path, contents: text });
  return path;
}

/** Picks a JSON text file: Tauri open dialog, or a browser file input. Returns its text, or null if cancelled. */
export async function openTextFile(filterName: string): Promise<string | null> {
  if (!isTauri()) {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = "application/json,.json";
    const { promise, resolve } = Promise.withResolvers<File | null>();
    input.onchange = () => resolve(input.files?.[0] ?? null);
    input.click();
    const file = await promise;
    return file ? file.text() : null;
  }
  const picked = await open({ multiple: false, filters: [{ name: filterName, extensions: ["json"] }] });
  const path = Array.isArray(picked) ? picked[0] : picked;
  return path ? invoke<string>("read_text_file", { path }) : null;
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
  log("info", "session", `imported (${(data.watches ?? []).length} watches, ${(data.names ?? []).length} names, ${(data.types ?? []).length} types)`);
  return true;
}
