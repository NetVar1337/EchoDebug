// Auto-update via tauri-plugin-updater (signed latest.json on GitHub releases).
// Flow: check (startup + every 30 min) -> download in the background -> "Restart to update".
// If the user never restarts, the downloaded version is remembered and applied right at the
// next launch, so nobody stays more than one launch behind.
import { create } from "zustand";
import type { Update } from "@tauri-apps/plugin-updater";
import { isTauri } from "@/lib/tauri";
import { log } from "./output";

export type UpdatePhase =
  | "idle"
  | "checking"
  | "available" // found, auto-update off: waiting for the user to download
  | "downloading"
  | "ready" // downloaded, waiting for "Restart to update"
  | "installing"
  | "uptodate"
  | "error";

type UpdateStore = {
  phase: UpdatePhase;
  version: string;
  notes: string;
  progress: number | null; // 0..1, null when the size is unknown
  error: string;
  lastChecked: number | null;
  check: (opts?: { manual?: boolean; auto?: boolean }) => Promise<void>;
  download: () => Promise<void>;
  restart: () => Promise<void>;
};

export const kCheckIntervalMs = 30 * 60 * 1000;
const kDeferredKey = "echodebug.update.deferred";

let pending: Update | null = null;
// Read once per launch: an update downloaded in an earlier session but never applied
let applyOnLaunch = typeof localStorage !== "undefined" && localStorage.getItem(kDeferredKey) !== null;
let clearTimer: ReturnType<typeof setTimeout> | undefined;

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

export const useUpdate = create<UpdateStore>((set, get) => ({
  phase: "idle",
  version: "",
  notes: "",
  progress: null,
  error: "",
  lastChecked: null,

  check: async ({ manual = false, auto = true } = {}) => {
    if (!isTauri()) {
      if (manual) set({ phase: "error", error: "Updates are only available in the desktop app." });
      return;
    }
    const { phase, version } = get();
    if (phase === "checking" || phase === "downloading" || phase === "installing") return;
    if (phase === "ready") {
      if (manual) log("info", "update", `v${version} is downloaded, restart to update`);
      return;
    }
    clearTimeout(clearTimer);
    set({ phase: manual ? "checking" : phase === "available" ? "available" : "idle", error: "" });
    try {
      const { check } = await import("@tauri-apps/plugin-updater");
      const upd = await check();
      set({ lastChecked: Date.now() });
      if (!upd) {
        localStorage.removeItem(kDeferredKey);
        applyOnLaunch = false;
        if (manual) {
          log("info", "update", "EchoDebug is up to date");
          set({ phase: "uptodate" });
          clearTimer = setTimeout(() => get().phase === "uptodate" && set({ phase: "idle" }), 5000);
        } else set({ phase: "idle" });
        return;
      }
      await pending?.close().catch(() => undefined);
      pending = upd;
      set({ phase: "available", version: upd.version, notes: upd.body ?? "" });
      log("info", "update", `v${upd.version} available (current v${upd.currentVersion})`);
      // A manual check means "get it now"; otherwise follow the auto-update setting
      if (manual || auto) await get().download();
      // Downloaded in an earlier session but never restarted: apply it now, at launch
      const deferred = applyOnLaunch;
      applyOnLaunch = false;
      if (deferred && get().phase === "ready") {
        log("info", "update", `applying v${upd.version}, downloaded in a previous session`);
        await get().restart();
      }
    } catch (e) {
      set({ phase: manual ? "error" : "idle", error: errText(e) });
      log(manual ? "error" : "warn", "update", `update check failed: ${errText(e)}`);
    }
  },

  download: async () => {
    if (!pending || get().phase === "downloading") return;
    let total = 0;
    let got = 0;
    set({ phase: "downloading", progress: null, error: "" });
    try {
      await pending.download((ev) => {
        if (ev.event === "Started") total = ev.data.contentLength ?? 0;
        else if (ev.event === "Progress") {
          got += ev.data.chunkLength;
          if (total) set({ progress: Math.min(1, got / total) });
        }
      });
      set({ phase: "ready", progress: 1 });
      log("info", "update", `v${pending.version} downloaded, restart to update`);
      // Remember it so the next launch applies it if this session never restarts
      localStorage.setItem(kDeferredKey, pending.version);
    } catch (e) {
      set({ phase: "error", error: `download failed: ${errText(e)}`, progress: null });
      log("error", "update", `download failed: ${errText(e)}`);
    }
  },

  restart: async () => {
    if (!pending || get().phase !== "ready") return;
    set({ phase: "installing" });
    try {
      localStorage.removeItem(kDeferredKey);
      // On Windows install() runs the signed NSIS installer in passive mode and exits this
      // process; the installer starts the new version. relaunch() covers the other platforms.
      await pending.install();
      const { relaunch } = await import("@tauri-apps/plugin-process");
      await relaunch();
    } catch (e) {
      set({ phase: "ready", error: `install failed: ${errText(e)}` });
      log("error", "update", `install failed: ${errText(e)}`);
    }
  },
}));

/** Startup check plus a periodic one; returns a cleanup. Manual checks work regardless. */
export function startUpdateLoop(autoUpdate: () => boolean): () => void {
  if (!isTauri()) return () => undefined;
  const run = () => void useUpdate.getState().check({ auto: autoUpdate() });
  run();
  const t = setInterval(run, kCheckIntervalMs);
  return () => clearInterval(t);
}
