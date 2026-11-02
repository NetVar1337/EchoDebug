// relay / agent / target state, fed by the client's status broadcasts
import { create } from "zustand";
import { client, request, type Frame } from "@/lib/client";
import { type Module } from "@/lib/hex";
import { hostOs, relayInfo } from "@/lib/tauri";
import { clearImages } from "@/lib/memory";
import { log } from "./output";
import pkg from "../../package.json";

export type Target = { pid: number; base: string; peb?: string; name?: string };
export type Progress = { job: string; done: number; total: number } | null;

type ConnStore = {
  port: number;
  relay: boolean;
  relayError: string;
  agent: boolean;
  ext: boolean;
  extVersion: string;
  appVersion: string;
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
};

let started = false;
const eventListeners = new Set<(f: Frame) => void>();
/** Subscribe to `{type:"event"}` frames from the agent. */
export function onAgentEvent(l: (f: Frame) => void): () => void {
  eventListeners.add(l);
  return () => eventListeners.delete(l);
}

function targetFrom(f: Frame): Target | null {
  const t = f.target as Target | null | undefined;
  return t && typeof t === "object" && t.pid ? t : null;
}

export const useConn = create<ConnStore>((set, get) => ({
  port: 47110,
  relay: false,
  relayError: "",
  agent: false,
  ext: false,
  extVersion: "",
  appVersion: pkg.version,
  backend: "none",
  os: "browser",
  target: null,
  modules: [],
  progress: null,
  splash: true,
  dismissSplash: () => set({ splash: false }),

  init: async () => {
    if (started) return; // StrictMode mounts effects twice in dev
    started = true;
    const info = await relayInfo().catch((e) => ({ port: 47110, error: String(e) }));
    const os = await hostOs().catch(() => "browser");
    set({ port: info.port, relayError: info.error ?? "", os });
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
        else if (ev === "attached" || ev === "detached") log("info", "agent", ev);
        for (const l of eventListeners) l(f);
      }
    });
    client.connect(info.port);
  },

  refreshStatus: async () => {
    try {
      applyStatus(await request("status"));
    } catch (e) {
      log("warn", "status", String(e));
    }
  },

  refreshModules: async () => {
    if (!get().agent) return set({ modules: [] });
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
    set({ target: { pid: r.pid, base: r.base, peb: r.peb, name: r.name ?? by.name }, splash: false });
    setTimeout(() => void get().refreshStatus().then(() => get().refreshModules()), 600);
  },

  detach: async () => {
    await request("detach");
    set({ target: null, modules: [] });
  },
}));

function applyStatus(f: Frame): void {
  const s = useConn.getState();
  const agent = Boolean(f.agent);
  const backend = String(f.backend ?? (agent ? "echo" : "none"));
  const target = targetFrom(f) ?? (agent || backend === "local" ? s.target : null);
  const changed = agent !== s.agent || target?.pid !== s.target?.pid;
  useConn.setState({ agent, ext: Boolean(f.ext), extVersion: String(f.ext_version ?? ""), backend, target });
  if (changed) {
    clearImages();
    void s.refreshModules();
  }
}
