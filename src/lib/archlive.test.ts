import { describe, expect, it } from "vitest";
import { knownArch, withArch } from "./archlive";

const mods = [
  { name: "libgame.so", base: "0x400000", size: 0x10000, arch: "arm64" },
  { name: "game.exe", base: "0x140000000", size: 0x10000, arch: "x86_64" },
];

describe("arch request hook", () => {
  it("adds arch for arm64 modules only", async () => {
    expect(await withArch({ address: "0x401000", size: 0 }, mods)).toEqual({ address: "0x401000", size: 0, arch: "arm64" });
    expect(await withArch({ address: "0x140001000", size: 0 }, mods)).toEqual({ address: "0x140001000", size: 0 });
    // outside every module, an explicit arch, or no usable address: untouched
    expect(await withArch({ address: "0x10", size: 0 }, mods)).toEqual({ address: "0x10", size: 0 });
    expect(await withArch({ address: "0x401000", arch: "x86_64" }, mods)).toEqual({ address: "0x401000", arch: "x86_64" });
    expect(await withArch({ address: "nonsense" }, mods)).toEqual({ address: "nonsense" });
  });

  it("knows the backend's arch without a read", () => {
    expect(knownArch(mods[0])).toBe("arm64");
    expect(knownArch({ name: "x", base: "0x1", size: 1 })).toBeNull();
  });
});
