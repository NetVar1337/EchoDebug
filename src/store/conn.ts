// relay / agent / target state, fed by the client's status broadcasts
import { create } from "zustand";
import { client, request, type Frame } from "@/lib/client";
import { hexDump, type Module } from "@/lib/hex";
import { hostOs, regenerateToken, relayInfo, type RelayInfo } from "@/lib/tauri";
import { clearImages } from "@/lib/memory";
import { clearArchCache, installArchHook } from "@/lib/archlive";
import { log } from "./output";
import pkg from "../../package.json";

export type Target = { pid: number; base: string; peb?: string; name?: string; arch?: string };
export type Progress = { job: string; done: number; total: number } | null;

type ConnStore = {
  port: number;
  /** relay bearer token, shown in the MCP panel's connect command */
  token: string;
  relay: boolean;
  relayError: string;
  agent: boolean;
  ext: boolean;
  /** this or another app window serves the ui_* MCP verbs */
  provider: boolean;
  /** the relay can attach on its own (Linux local backend) */
  localAvailable: boolean;
  /** memory verbs work: Echo's memory server, or the local backend */
  mem: boolean;
  /** agent verbs work: the Echo agent, or the local backend */
  extOk: boolean;
  extVersion: string;
  appVersion: string;
  /** the native debugger the dbg_* verbs reach: "ptrace" (Linux local backend), "windows" (Win32 debug API, a process on this machine) or "" */
  debugger: string;
  /** "echo" (Windows memory server), "local" (Linux /proc backend) or "none" */
  backend: string;
  /** host OS of the desktop app ("browser" in a plain browser) */
  os: string;
  target: Target | null;
  modules: Module[];
  progress: Progress;
  /** the boot splash stays until the user continues or the target is attached */
  splash: boolean;
  dismissSplash: () => void;
  init: () => Promise<void>;
  refreshStatus: () => Promise<void>;
  refreshModules: () => Promise<void>;
  attach: (by: { name?: string; pid?: number }) => Promise<void>;
  detach: () => Promise<void>;
  /** desktop app: new token; MCP clients must be re-added with it */
  regenerateToken: () => Promise<void>;
};

let started = false;
const eventListeners = new Set<(f: Frame) => void>();
/** Subscribe to `{type:"event"}` frames from the agent. */
export function onAgentEvent(l: (f: Frame) => void): () => void {
  eventListeners.add(l);
  return () => eventListeners.delete(l);
}

/** `claude mcp add` command for this relay, with the bearer token header. */
export function mcpAddCommand(port: number, token: string): string {
  const header = token ? ` --header "Authorization: Bearer ${token}"` : "";
  return `claude mcp add --transport http echodebug http://127.0.0.1:${port}/mcp${header}`;
}

function targetFrom(f: Frame): Target | null {
  const t = f.target as Target | null | undefined;
  return t && typeof t === "object" && t.pid ? t : null;
}

export const useConn = create<ConnStore>((set, get) => ({
  port: 47110,
  token: "",
  relay: false,
  relayError: "",
  agent: false,
  ext: false,
  provider: false,
  localAvailable: false,
  mem: false,
  extOk: false,
  extVersion: "",
  appVersion: pkg.version,
  backend: "none",
  debugger: "",
  os: "browser",
  target: null,
  modules: [],
  progress: null,
  splash: true,
  dismissSplash: () => set({ splash: false }),

  init: async () => {
    if (started) return; // StrictMode mounts effects twice in dev
    started = true;
    const info: RelayInfo = await relayInfo().catch((e) => ({ port: 47110, error: String(e) }));
    const os = await hostOs().catch(() => "browser");
    set({ port: info.port, token: info.token ?? "", relayError: info.error ?? "", os });
    if (info.error) log("error", "relay", info.error);
    client.onState((up) => {
      set({ relay: up });
      log(up ? "info" : "warn", "relay", up ? `connected to 127.0.0.1:${info.port}` : "relay disconnected, retrying");
      if (up) void get().refreshStatus();
      else set({ agent: false, ext: false });
    });
    client.on((f) => {
      if (f.type === "status") applyStatus(f);
      else if (f.type === "event") {
        const ev = String(f.event ?? "");
        if (ev === "progress") set({ progress: { job: String(f.job), done: Number(f.done), total: Number(f.total) } });
        else if (ev === "log") log((f.level as "info") ?? "info", "agent", String(f.message ?? ""));
        else if (ev === "hello") {
          log("info", "agent", `EchoDebug agent v${f.version} connected (user ${f.user ?? "?"})`);
          if (f.version && f.version !== pkg.version) log("warn", "agent", `agent v${f.version} differs from app v${pkg.version}; reload echo_debug.as in Echo`);
        } else if (ev === "freeze_error") log("warn", "freeze", `write failed at ${f.address}`);
        else if (ev === "alert_event") logAlert(f);
        else if (ev === "attached" || ev === "detached") log("info", "agent", ev);
        for (const l of eventListeners) l(f);
      }
    });
    client.connect(info.port, info.token);
  },

  refreshStatus: async () => {
    try {
      applyStatus(await request("status"));
    } catch (e) {
      log("warn", "status", String(e));
    }
  },

  refreshModules: async () => {
    if (!get().agent && get().backend !== "local") return set({ modules: [] });
    try {
      const r = await request<{ modules: Module[] }>("modules");
      set({ modules: [...r.modules].sort((a, b) => a.name.localeCompare(b.name)) });
    } catch (e) {
      log("error", "modules", String(e));
    }
  },

  attach: async (by) => {
    const r = await request<Target & { native_socket?: boolean }>("attach", by);
    log("info", "attach", `attached ${r.name ?? by.name ?? r.pid} pid ${r.pid} base ${r.base}${r.native_socket === false ? " (memory server already open)" : ""}`);
    clearImages();
    clearArchCache();
    set({ target: { pid: r.pid, base: r.base, peb: r.peb, name: r.name ?? by.name, arch: r.arch }, splash: false });
    setTimeout(() => void get().refreshStatus().then(() => get().refreshModules()), 600);
  },

  detach: async () => {
    await request("detach");
    set({ target: null, modules: [] });
  },

  regenerateToken: async () => {
    const token = await regenerateToken();
    client.setToken(token);
    set({ token });
    log("info", "mcp", "token regenerated; re-add MCP clients with the new header");
  },
}));

// arm64 modules: disassembly requests carry the module's arch (see archlive.ts)
installArchHook(() => useConn.getState().modules);

/** A fired conditional alert: one Output line, its memory snapshot as the clickable detail. */
function logAlert(f: Frame): void {
  const snap = f.snapshot as { address?: string; data?: string } | undefined;
  const name = f.label ? `${f.label} (${f.address})` : String(f.address);
  const detail = snap?.address && snap.data ? hexDump(snap.address, snap.data) : undefined;
  log("warn", "alert", `#${f.alert_id} ${name} ${f.condition}: ${f.old || "?"} → ${f.new} (${f.value})${f.once ? " · one-shot, removed" : ""}`, detail);
}

function applyStatus(f: Frame): void {
  const s = useConn.getState();
  const agent = Boolean(f.agent);
  const backend = String(f.backend ?? (agent ? "echo" : "none"));
  const target = targetFrom(f) ?? (agent || backend === "local" ? s.target : null);
  const changed = agent !== s.agent || target?.pid !== s.target?.pid;
  const debuggerKind = typeof f.debugger === "string" ? f.debugger : "";
  useConn.setState({ debugger: debuggerKind, agent, mem: agent || backend === "local", extOk: Boolean(f.ext) || backend === "local", provider: Boolean(f.provider), localAvailable: Boolean(f.local_available), ext: Boolean(f.ext), extVersion: String(f.ext_version ?? ""), backend, target });
  if (changed) {
    clearImages();
    clearArchCache();
    void s.refreshModules();
  }
}
