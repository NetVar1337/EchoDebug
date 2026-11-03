import { beforeEach, describe, expect, it, vi } from "vitest";

const store = new Map<string, string>();
vi.stubGlobal("localStorage", {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
});

const install = vi.fn(async () => undefined);
const relaunch = vi.fn(async () => undefined);
let next: unknown = null;
vi.mock("@/lib/tauri", () => ({ isTauri: () => true }));
vi.mock("./output", () => ({ log: () => undefined }));
vi.mock("@tauri-apps/plugin-process", () => ({ relaunch }));
vi.mock("@tauri-apps/plugin-updater", () => ({ check: async () => next }));

function fakeUpdate(version: string) {
  return {
    version,
    currentVersion: "0.1.0",
    body: "notes",
    close: async () => undefined,
    install,
    download: async (cb: (e: unknown) => void) => {
      cb({ event: "Started", data: { contentLength: 10 } });
      cb({ event: "Progress", data: { chunkLength: 10 } });
      cb({ event: "Finished" });
    },
  };
}

async function load() {
  vi.resetModules();
  return (await import("./update")).useUpdate;
}

describe("update flow", () => {
  beforeEach(() => {
    store.clear();
    install.mockClear();
    relaunch.mockClear();
  });

  it("downloads in the background and waits for restart", async () => {
    const u = await load();
    next = fakeUpdate("0.2.0");
    await u.getState().check();
    expect(u.getState().phase).toBe("ready");
    expect(u.getState().progress).toBe(1);
    expect(install).not.toHaveBeenCalled();
    await u.getState().restart();
    expect(install).toHaveBeenCalledOnce();
    expect(relaunch).toHaveBeenCalledOnce();
  });

  it("only offers the update when auto-update is off", async () => {
    const u = await load();
    next = fakeUpdate("0.2.0");
    await u.getState().check({ auto: false });
    expect(u.getState().phase).toBe("available");
  });

  it("applies an update deferred by a previous session at launch", async () => {
    store.set("echodebug.update.deferred", "0.2.0");
    const u = await load();
    next = fakeUpdate("0.2.0");
    await u.getState().check();
    expect(install).toHaveBeenCalledOnce();
  });

  it("reports up to date on a manual check and clears the deferred marker", async () => {
    store.set("echodebug.update.deferred", "0.2.0");
    const u = await load();
    next = null;
    await u.getState().check({ manual: true });
    expect(u.getState().phase).toBe("uptodate");
    expect(store.has("echodebug.update.deferred")).toBe(false);
  });
});
