import { beforeEach, describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { apply, collect, moduleKeyFromHeader } from "./projects";
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
});
