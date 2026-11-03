// Installed plugins, which ones are enabled (persisted) and their load state.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { show } from "@/lib/scripting";
import { discoverPlugins, loadPlugin, unloadPlugin, type Active, type Discovered } from "@/lib/plugins/loader";
import { log } from "./output";

export type PluginState = { state: "active" | "error" | "off"; message?: string };

type PluginsStore = {
  /** plugin ids the user enabled (they load at startup) */
  enabled: string[];
  found: Discovered[];
  status: Record<string, PluginState>;
  scanned: boolean;
  scan: () => Promise<void>;
  enable: (id: string) => Promise<void>;
  disable: (id: string) => Promise<void>;
  /** rescans the folder and reloads every enabled plugin */
  reload: () => Promise<void>;
};

const active = new Map<string, Active>();

const printer = (id: string) => (...a: unknown[]) => log("info", `plugin:${id}`, a.map(show).join(" "));

async function start(d: Discovered): Promise<PluginState> {
  const id = d.manifest!.id;
  try {
    active.set(id, await loadPlugin(d, printer(id)));
    log("info", "plugins", `${d.manifest!.name} ${d.manifest!.version} enabled${d.manifest!.permissions.length ? ` (${d.manifest!.permissions.join(", ")})` : " (read-only)"}`);
    return { state: "active" };
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    log("error", "plugins", `${id}: ${message}`);
    return { state: "error", message };
  }
}

async function stop(id: string): Promise<void> {
  const a = active.get(id);
  if (!a) return;
  active.delete(id);
  await unloadPlugin(a).catch((e) => log("warn", "plugins", `${id}: deactivate failed: ${e}`));
}

export const usePlugins = create<PluginsStore>()(
  persist(
    (set, get) => ({
      enabled: [],
      found: [],
      status: {},
      scanned: false,
      scan: async () => {
        const found = await discoverPlugins();
        set({ found, scanned: true });
      },
      enable: async (id) => {
        const d = get().found.find((x) => x.manifest?.id === id);
        if (!d) throw new Error(`plugin ${id} not found`);
        await stop(id);
        const st = await start(d);
        set((s) => ({ enabled: st.state === "active" ? [...new Set([...s.enabled, id])] : s.enabled, status: { ...s.status, [id]: st } }));
      },
      disable: async (id) => {
        await stop(id);
        set((s) => ({ enabled: s.enabled.filter((x) => x !== id), status: { ...s.status, [id]: { state: "off" } } }));
      },
      reload: async () => {
        for (const id of [...active.keys()]) await stop(id);
        await get().scan();
        const status: Record<string, PluginState> = {};
        for (const d of get().found) {
          const id = d.manifest?.id;
          if (!id || d.errors.length) continue;
          status[id] = get().enabled.includes(id) ? await start(d) : { state: "off" };
        }
        set({ status });
      },
    }),
    { name: "echodebug.plugins", partialize: (s) => ({ enabled: s.enabled }) },
  ),
);

let started = false;

/** Loads the enabled plugins once at startup (desktop app). */
export function startPlugins(): void {
  if (started) return;
  started = true;
  void usePlugins.getState().reload().catch((e) => log("warn", "plugins", String(e)));
}
