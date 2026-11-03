// Save a text file: the native dialog in the app, a download in the browser.
import { invoke } from "@tauri-apps/api/core";
import { isTauri } from "./tauri";
import { log } from "@/store/output";

export async function saveText(defaultName: string, text: string, filter?: { name: string; extensions: string[] }): Promise<string | null> {
  if (!isTauri()) {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: defaultName });
    a.click();
    URL.revokeObjectURL(url);
    return defaultName;
  }
  const { save } = await import("@tauri-apps/plugin-dialog");
  const path = await save({ defaultPath: defaultName, filters: filter ? [filter] : undefined });
  if (!path) return null;
  await invoke("write_text_file", { path, contents: text });
  log("info", "save", `wrote ${path}`);
  return path;
}

/** Binary save (rebuilt images, dumps). */
export async function saveBinary(defaultName: string, bytes: Uint8Array): Promise<string | null> {
  if (!isTauri()) {
    const url = URL.createObjectURL(new Blob([bytes as BlobPart], { type: "application/octet-stream" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: defaultName });
    a.click();
    URL.revokeObjectURL(url);
    return defaultName;
  }
  const { save } = await import("@tauri-apps/plugin-dialog");
  const path = await save({ defaultPath: defaultName });
  if (!path) return null;
  await invoke("write_binary_file", { path, contents: Array.from(bytes) });
  log("info", "save", `wrote ${path} (${bytes.length} bytes)`);
  return path;
}
