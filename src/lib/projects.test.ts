import { beforeEach, describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { apply, collect, moduleKeyFromHeader, previousBuild, relocateProject, type Project } from "./projects";
import { useNames } from "@/store/names";
import { useWatch } from "@/store/watch";

describe("per-module projects", () => {
  beforeEach(() => {
    useNames.setState({ names: [] });
    useWatch.setState({ bookmarks: [] });
  });

  it("keys a PE build by timestamp + SizeOfImage and an ELF by its build-id", () => {
    const pe = new Uint8Array(readFileSync(new URL("./analysis/fixtures/fix.exe", import.meta.url))).subarray(0, 0x1000);
    expect(moduleKeyFromHeader("Fix.EXE", 0x8000, pe)).toMatch(/^pe:fix\.exe:[0-9a-f]+:[0-9a-f]+$/);
    if (existsSync("/bin/ls")) {
      const elf = new Uint8Array(readFileSync("/bin/ls")).subarray(0, 0x1000);
      expect(moduleKeyFromHeader("ls", 1, elf)).toMatch(/^elf:ls:[0-9a-f]{40}$/);
    }
    expect(moduleKeyFromHeader("x.dll", 0x1000, null)).toBe("mod:x.dll:1000");
  });

  it("stores names relative to the module and restores them at a new base", () => {
    const run1 = { name: "game.exe", base: "0x7ff600000000", size: 0x100000 };
    useNames.getState().rename("0x7ff600001234", "UpdatePlayer");
    useNames.getState().comment("0x7ff600001234", "called every frame");
    useNames.getState().rename("0x7ffa00000000", "outside");
    useWatch.getState().addBookmark("0x7ff600002000", "health");
    const p = collect(run1, "pe:game.exe:1:2", useNames.getState().names, useWatch.getState().bookmarks);
    expect(p.names).toEqual([{ rva: 0x1234, name: "UpdatePlayer", comment: "called every frame" }]);
    expect(p.bookmarks.map((b) => b.rva)).toEqual([0x2000]);

    useNames.setState({ names: [] });
    useWatch.setState({ bookmarks: [] });
    const run2 = { ...run1, base: "0x7ff700000000" }; // ASLR moved it
    expect(apply(p, run2)).toEqual({ names: 1, bookmarks: 1 });
    expect(useNames.getState().nameOf("0x7ff700001234")).toBe("UpdatePlayer");
    expect(useWatch.getState().bookmarks[0].address.toLowerCase()).toBe("0x7ff700002000");
    expect(apply(p, run2)).toEqual({ names: 0, bookmarks: 0 }); // idempotent
  });

  it("keeps relocation signatures for entries still at the same RVA", () => {
    const m = { name: "game.exe", base: "0x140000000", size: 0x10000 };
    useNames.getState().rename("0x140001000", "a");
    useNames.getState().rename("0x140002000", "b");
    useWatch.getState().addBookmark("0x140003000", "hp");
    const prev: Project = {
      key: "k", module: "game.exe", updated: 1,
      names: [{ rva: 0x1000, name: "old", comment: "", sig: "E8 ? ? ? ?" }, { rva: 0x5000, name: "gone", comment: "", sig: "90" }],
      bookmarks: [{ rva: 0x3000, label: "hp", sig: "48 8B" }],
    };
    const p = collect(m, "k", useNames.getState().names, useWatch.getState().bookmarks, prev);
    expect(p.names).toEqual([{ rva: 0x1000, name: "a", comment: "", sig: "E8 ? ? ? ?" }, { rva: 0x2000, name: "b", comment: "" }]);
    expect(p.bookmarks).toEqual([{ rva: 0x3000, label: "hp", sig: "48 8B" }]);
  });

  it("finds the project of an older build of the same module", () => {
    const mk = (key: string, module: string, updated: number, n = 1): Project => ({ key, module, updated, names: Array.from({ length: n }, () => ({ rva: 1, name: "x", comment: "" })), bookmarks: [] });
    const projects = { a: mk("a", "game.exe", 1), b: mk("b", "Game.exe", 5), c: mk("c", "game.exe", 9, 0), d: mk("d", "other.dll", 9), cur: mk("cur", "game.exe", 10) };
    expect(previousBuild(projects, "GAME.EXE", "cur")?.key).toBe("b");
    expect(previousBuild(projects, "new.dll", "x")).toBeNull();
  });

  it("re-locates signed entries into a new build", async () => {
    const m = { name: "game.exe", base: "0x7ff600000000", size: 0x100000 };
    const old: Project = {
      key: "pe:game.exe:1:2", module: "game.exe", updated: 1,
      names: [
        { rva: 0x1000, name: "same", comment: "", sig: "AA" },
        { rva: 0x2000, name: "moved", comment: "c", sig: "BB" },
        { rva: 0x3000, name: "many", comment: "", sig: "CC" },
        { rva: 0x4000, name: "unsigned", comment: "" },
      ],
      bookmarks: [{ rva: 0x5000, label: "gone", sig: "DD" }],
    };
    const hits: Record<string, string[]> = { AA: ["0x7ff600001000"], BB: ["0x7ff600002400"], CC: ["0x7ff600003000", "0x7ff600009000"], DD: [] };
    const { project, rows } = await relocateProject(old, "pe:game.exe:3:4", m, async (ida) => hits[ida] ?? []);
    expect(project.key).toBe("pe:game.exe:3:4");
    expect(project.names.map((e) => e.rva)).toEqual([0x1000, 0x2400, 0x3000, 0x4000]);
    expect(project.names[1]).toEqual({ rva: 0x2400, name: "moved", comment: "c", sig: "BB" });
    expect(project.bookmarks[0].rva).toBe(0x5000);
    expect(rows.map((r) => r.status)).toEqual(["ok", "moved", "ambiguous", "nosig", "missing"]);
    expect(rows[1]).toMatchObject({ kind: "name", oldRva: 0x2000, newRva: 0x2400 });
    expect(old.names[1].rva).toBe(0x2000); // the old build's project is left as it was
  });
});
