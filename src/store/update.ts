// auto-update via tauri-plugin-updater (GitHub releases latest.json)
import { create } from "zustand";
import { isTauri } from "@/lib/tauri";
import { log } from "./output";

type UpdateStore = { status: string; busy: boolean; check: (manual?: boolean) => Promise<void> };

export const useUpdate = create<UpdateStore>((set, get) => ({
  status: "",
  busy: false,
  check: async (manual = false) => {
    if (!isTauri()) {
      if (manual) log("info", "update", "updates are only available in the desktop app");
      return;
    }
    if (get().busy) return;
    set({ busy: true, status: "checking…" });
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const upd = await check();
      if (!upd) {
        set({ status: "" });
        if (manual) log("info", "update", "EchoDebug is up to date");
        return;
      }
      log("info", "update", `downloading v${upd.version}`);
      let total = 0;
      let got = 0;
      await upd.downloadAndInstall((ev) => {
        if (ev.event === "Started") total = ev.data.contentLength ?? 0;
        else if (ev.event === "Progress") {
          got += ev.data.chunkLength;
          set({ status: total ? `updating ${Math.round((got / total) * 100)}%` : "updating…" });
        } else set({ status: "restarting…" });
      });
      const { relaunch } = await import("@tauri-apps/plugin-process");
      await relaunch();
    } catch (e) {
      set({ status: "" });
      log(manual ? "error" : "warn", "update", `update check failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      set({ busy: false });
    }
  },
}));
