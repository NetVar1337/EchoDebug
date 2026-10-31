// Session export / import: a single JSON file that restores the workspace
// (theme, watches, bookmarks, names, comments, struct layout and AI settings).
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { isTauri } from "./tauri";
import { useUi, type AiProvider } from "@/store/ui";
import { useWatch, type WatchEntry, type Bookmark } from "@/store/watch";
import { useNames, type NameEntry } from "@/store/names";
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
    ai: { provider: string; model: string; baseUrl: string };
  };
  watches: WatchEntry[];
  bookmarks: Bookmark[];
  names: NameEntry[];
  struct: unknown;
};

const kStructKey = "echodebug.struct";

export function buildSession(): SessionFile {
  const ui = useUi.getState();
  const w = useWatch.getState();
  let struct: unknown = null;
  try {
    struct = JSON.parse(localStorage.getItem(kStructKey) ?? "null");
  } catch {
    struct = null;
  }
  return {
    format: "echodebug.session",
    version: 1,
    savedAt: new Date().toISOString(),
    ui: {
      theme: ui.theme,
      accent: ui.accent,
      tab: ui.tab,
      module: ui.module,
      // the API key never leaves the machine
      ai: { provider: ui.ai.provider, model: ui.ai.model, baseUrl: ui.ai.baseUrl },
    },
    watches: w.watches,
    bookmarks: w.bookmarks,
    names: useNames.getState().names,
    struct,
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
    ai: { ...ui.ai, provider: (data.ui?.ai?.provider ?? ui.ai.provider) as AiProvider, model: data.ui?.ai?.model ?? ui.ai.model, baseUrl: data.ui?.ai?.baseUrl ?? ui.ai.baseUrl },
  });
  const w = useWatch.getState();
  w.setWatches(data.watches ?? [], data.bookmarks ?? []);
  useNames.getState().setNames(data.names ?? []);
  if (data.struct) localStorage.setItem(kStructKey, JSON.stringify(data.struct));
  log("info", "session", `imported (${(data.watches ?? []).length} watches, ${(data.names ?? []).length} names)`);
  return true;
}
