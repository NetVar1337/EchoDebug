import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";

vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => undefined, removeItem: () => undefined });
vi.mock("./client", () => ({ client: { send: () => undefined }, request: async () => ({}) }));
const fileImage = await (async () => {
  const { mapPeFile } = await import("./analysis/pe");
  return mapPeFile(new Uint8Array(readFileSync(new URL("./analysis/fixtures/fix-seh.exe", import.meta.url))));
})();
vi.mock("./memory", () => ({ loadImage: async () => fileImage }));

const { frameName, sehForMcp } = await import("./threadslive");
const { useNames } = await import("@/store/names");
type Frame = Parameters<typeof frameName>[0];

const mods = [{ name: "game.exe", base: "0x140000000", size: 0x10000 }];
const frame = (over: Partial<Frame>): Frame => ({ index: 1, address: "0x140001234", sp: "0x1000", module: "game.exe", offset: "0x1234", symbol: null, symbol_offset: null, method: "pdata", guessed: false, ...over });

describe("stack frame names", () => {
  it("prefers user names (at the address or the symbol start), then the backend symbol, then module+offset", () => {
    expect(frameName(frame({}), mods)).toBe("game.exe+0x1234");
    expect(frameName(frame({ symbol: "Tick", symbol_offset: 0x34 }), mods)).toBe("Tick+0x34");
    useNames.getState().rename("0x140001200", "UpdatePlayer");
    expect(frameName(frame({ symbol: "Tick", symbol_offset: 0x34 }), mods)).toBe("UpdatePlayer+0x34");
    useNames.getState().rename("0x140001234", "here");
    expect(frameName(frame({ symbol: "Tick", symbol_offset: 0x34 }), mods)).toBe("here");
  });
});

describe("exception_handlers MCP shape", () => {
  it("returns absolute addresses for functions, handlers and scopes", async () => {
    const r = await sehForMcp({ name: "fix-seh.exe", base: "0x140000000", size: fileImage.length }, 10);
    expect(r.count).toBe(1);
    expect(r.handler_routines).toEqual([{ address: "0x1400010c0", name: "__C_specific_handler", kind: "C (__try/__except/__finally)", functions: 1 }]);
    const f = r.functions[0];
    expect(f.function).toBe("0x140001010");
    expect(f.scopes?.[1]).toMatchObject({ kind: "finally", finally: "0x140001060" });
    expect(f.scopes?.[2]).toMatchObject({ kind: "except", filter: 1, target: "0x14000104e" });
    expect(r.vectored_handlers).toMatch(/not listed/);
  });
});
