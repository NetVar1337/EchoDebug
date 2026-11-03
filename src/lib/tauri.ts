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

/** New per-install MCP/relay token (desktop app only). */
export async function regenerateToken(): Promise<string> {
  return invoke<string>("regenerate_token");
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

// ---- MCP client setup (desktop app: src-tauri/src/lib.rs → relay/src/mcp_clients.rs) ----

export type McpTransport = "http" | "stdio";
export type McpClientRow = {
  id: string;
  name: string;
  path: string;
  exists: boolean;
  installed: boolean;
  configured: McpTransport | "other" | null;
  error: string | null;
  transports: McpTransport[];
  docs: string;
  note: string;
  snippets: Partial<Record<McpTransport, string>>;
};
export type McpClients = { clients: McpClientRow[]; stdio: { command: string; args: string[] } };
export type McpPlan = { path: string; exists: boolean; deletes: boolean; changes: boolean; diff: string };
export type McpApplied = { path: string; backup: string | null };

/** Detected clients and what EchoDebug's entry would be; null outside the desktop app. */
export async function mcpClients(): Promise<McpClients | null> {
  if (!isTauri()) return null;
  return invoke<McpClients>("mcp_clients");
}

/** The change one-click setup would make (nothing is written). */
export async function mcpClientPreview(id: string, action: "install" | "uninstall", transport?: McpTransport): Promise<McpPlan> {
  return invoke<McpPlan>("mcp_client_preview", { id, action, transport: transport ?? null });
}

/** Writes the previewed change (refused when the file no longer matches `diff`). */
export async function mcpClientApply(id: string, action: "install" | "uninstall", transport: McpTransport | undefined, diff: string): Promise<McpApplied> {
  return invoke<McpApplied>("mcp_client_apply", { id, action, transport: transport ?? null, diff });
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
