// Tauri-only calls, every one guarded so the UI also runs in a plain browser
import { invoke, isTauri as coreIsTauri } from "@tauri-apps/api/core";

export const isTauri = (): boolean => typeof window !== "undefined" && coreIsTauri();

export type RelayInfo = { port: number; error?: string | null; token?: string | null };
export type InstallResult = { path: string; changed: boolean };

export async function relayInfo(): Promise<RelayInfo> {
  if (!isTauri()) {
    // Browser dev: ?port=&token= on the URL, else the token saved in Settings.
    const q = new URLSearchParams(location.search);
    let token = q.get("token");
    try {
      if (token) localStorage.setItem("echodebug.token", token);
      else token = localStorage.getItem("echodebug.token");
    } catch { /* storage blocked */ }
    return { port: Number(q.get("port")) || 47110, token };
  }
  return invoke<RelayInfo>("relay_info");
}

/** Host OS of the desktop app ("windows" | "linux" | "macos" | …); "browser" outside Tauri. */
export async function hostOs(): Promise<string> {
  if (!isTauri()) return "browser";
  return invoke<string>("host_os");
}

export function isWindowsOs(os: string): boolean {
  return os === "windows";
}

export async function installAgent(): Promise<InstallResult | null> {
  if (!isTauri()) return null;
  return invoke<InstallResult>("install_agent");
}

export async function openScriptsFolder(): Promise<void> {
  if (!isTauri()) return;
  const dir = await invoke<string>("scripts_dir");
  const { openPath } = await import("@tauri-apps/plugin-opener");
  await openPath(dir);
}

export async function openUrl(url: string): Promise<void> {
  if (!isTauri()) {
    window.open(url, "_blank", "noopener");
    return;
  }
  const { openUrl: open } = await import("@tauri-apps/plugin-opener");
  await open(url);
}

/**
 * Picks a file and returns its bytes. In the desktop app the native picker is
 * used; in a browser the caller falls back to a file input.
 */
export async function pickBinaryFile(extensions: string[], title: string): Promise<{ bytes: Uint8Array; name: string } | null> {
  if (!isTauri()) return null;
  const { open } = await import("@tauri-apps/plugin-dialog");
  const path = await open({ title, multiple: false, filters: [{ name: title, extensions }] });
  if (!path || typeof path !== "string") return null;
  const bytes = await invoke<number[]>("read_binary_file", { path });
  const name = path.split(/[\\/]/).pop() ?? path;
  return { bytes: new Uint8Array(bytes), name };
}
