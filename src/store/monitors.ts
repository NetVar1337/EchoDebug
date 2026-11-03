// Module load/unload timeline and page-change log, fed by the relay's monitors (monitor.rs).
import { create } from "zustand";
import { client, request } from "@/lib/client";
import { useConn } from "./conn";
import { log } from "./output";

export type ModuleEvent = { ts: number; event: "module_loaded" | "module_unloaded"; name: string; base: string; size: number };
export type PageEvent = { ts: number; address: string; size: number; label: string; count: number; pages: string[] };
export type PageWatch = { address: string; size: number; label: string; interval_ms: number; changes: number; last_change: number };

type MonStore = {
  moduleOn: boolean;
  timeline: ModuleEvent[];
  pageEvents: PageEvent[];
  pages: PageWatch[];
  setModuleMonitor: (on: boolean, intervalMs?: number) => Promise<void>;
  watchPages: (address: string, size: number, label: string, intervalMs?: number) => Promise<void>;
  unwatchPages: (address: string) => Promise<void>;
  refresh: () => Promise<void>;
  clear: () => void;
};

const kMax = 500;

export const useMonitors = create<MonStore>((set, get) => ({
  moduleOn: false,
  timeline: [],
  pageEvents: [],
  pages: [],
  setModuleMonitor: async (on, intervalMs = 1000) => {
    await request("module_monitor", { enabled: on, interval_ms: intervalMs });
    set({ moduleOn: on });
  },
  watchPages: async (address, size, label, intervalMs = 1000) => {
    await request("page_monitor", { address, size, label, interval_ms: intervalMs });
    await get().refresh();
  },
  unwatchPages: async (address) => {
    await request("page_monitor", { address, enabled: false });
    await get().refresh();
  },
  refresh: async () => {
    const [t, p] = await Promise.all([
      request<{ enabled: boolean; entries: ModuleEvent[] }>("module_timeline", {}, true).catch(() => null),
      request<{ entries: PageWatch[] }>("page_monitor_list", {}, true).catch(() => null),
    ]);
    set({ ...(t ? { moduleOn: t.enabled, timeline: t.entries.slice().reverse() } : {}), ...(p ? { pages: p.entries } : {}) });
  },
  clear: () => set({ timeline: [], pageEvents: [] }),
}));

let started = false;

export function startMonitors(): void {
  if (started) return;
  started = true;
  client.on((f) => {
    if (f.type !== "event") return;
    if (f.event === "module_loaded" || f.event === "module_unloaded") {
      const e = f as unknown as ModuleEvent;
      useMonitors.setState((s) => ({ timeline: [e, ...s.timeline].slice(0, kMax) }));
      log("info", "modules", `${e.event === "module_loaded" ? "loaded" : "unloaded"} ${e.name} at ${e.base}`);
      void useConn.getState().refreshModules();
    } else if (f.event === "page_changed") {
      const e = f as unknown as PageEvent;
      useMonitors.setState((s) => ({
        pageEvents: [e, ...s.pageEvents].slice(0, kMax),
        pages: s.pages.map((p) => (p.address === e.address ? { ...p, changes: p.changes + e.count, last_change: e.ts } : p)),
      }));
    }
  });
  client.onState((up) => up && void useMonitors.getState().refresh());
}
