import { describe, expect, it } from "vitest";
import { isSnapshot, latestSnapshot, rollbackAgent, snapshotAgentPruned, snapshotName, type PruneFs } from "./agentsnap";

function memFs(files: Record<string, string> = {}): PruneFs & { files: Record<string, string> } {
  const f = { ...files };
  return {
    files: f,
    readFile: async (p) => {
      if (!(p in f)) throw new Error(`ENOENT ${p}`);
      return f[p];
    },
    writeFile: async (p, d) => {
      f[p] = d;
    },
    mkdir: async () => undefined,
    list: async (dir) => Object.keys(f).filter((k) => k.startsWith(dir + "/")).map((k) => k.slice(dir.length + 1)),
    rm: async (p) => {
      delete f[p];
    },
  };
}

describe("agent snapshots", () => {
  it("names snapshots sortably and recognizes them", () => {
    const n = snapshotName(new Date("2026-07-28T12:00:00.000Z"));
    expect(n).toBe("echo_debug.2026-07-28T12-00-00-000Z.as.snap");
    expect(isSnapshot(n)).toBe(true);
    expect(isSnapshot("echo_debug.as")).toBe(false);
  });

  it("snapshots the agent and prunes to keep the newest N", async () => {
    const fs = memFs({ "scripts/echo_debug.as": "v-current" });
    for (let i = 0; i < 7; i++) {
      await new Promise((r) => setTimeout(r, 2));
      await snapshotAgentPruned(fs, "scripts/echo_debug.as", "scripts/snapshots", 3);
    }
    const snaps = await fs.list("scripts/snapshots");
    expect(snaps).toHaveLength(3);
    expect(await fs.readFile("scripts/echo_debug.as")).toBe("v-current");
  });

  it("rolls back to the newest snapshot", async () => {
    const fs = memFs({ "scripts/echo_debug.as": "v-broken" });
    await snapshotAgentPruned(fs, "scripts/echo_debug.as", "scripts/snapshots", 5);
    fs.files["scripts/echo_debug.as"] = "v-current-broken";
    expect(await rollbackAgent(fs, "scripts/echo_debug.as", "scripts/snapshots")).toBe(true);
    expect(fs.files["scripts/echo_debug.as"]).toBe("v-broken");
  });

  it("rollback returns false with no snapshots", async () => {
    const fs = memFs({ "scripts/echo_debug.as": "v1" });
    expect(await latestSnapshot(fs, "scripts/snapshots")).toBeNull();
    expect(await rollbackAgent(fs, "scripts/echo_debug.as", "scripts/snapshots")).toBe(false);
  });
});
