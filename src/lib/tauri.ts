// Tauri-only calls, every one guarded so the UI also runs in a plain browser
import { invoke, isTauri as coreIsTauri } from "@tauri-apps/api/core";

export const isTauri = (): boolean => typeof window !== "undefined" && coreIsTauri();

export type RelayInfo = { port: number; error?: string | null };
export type InstallResult = { path: string; changed: boolean };

export async function relayInfo(): Promise<RelayInfo> {
  if (!isTauri()) return { port: Number(new URLSearchParams(location.search).get("port")) || 47110 }; // ?port= for browser dev
  return invoke<RelayInfo>("relay_info");
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
