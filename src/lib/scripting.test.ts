import { describe, expect, it } from "vitest";
import { runScript, show } from "./scripting";
import { useNames } from "@/store/names";

describe("scripting", () => {
  it("runs async code against the ed object and prints", async () => {
    useNames.setState({ names: [] });
    const out: string[] = [];
    const r = await runScript(`ed.names.set("0x401000", "main"); await ed.sleep(1); ed.print("named", ed.names.get(0x401000)); return ed.hex(0x10n + 1n);`, (...a) => out.push(a.map(show).join(" ")), { aborted: false });
    expect(out).toEqual(["named main"]);
    expect(r).toBe("0x11");
  });
  it("reports errors and stops", async () => {
    await expect(runScript("throw new Error('boom')", () => undefined, { aborted: false })).rejects.toThrow("boom");
    await expect(runScript("return ed.modules().length + ed.module().name", () => undefined, { aborted: false })).rejects.toThrow(/no modules/);
    await expect(runScript("await ed.read('0x1000', 4)", () => undefined, { aborted: true })).rejects.toThrow(/stopped/);
  });
});
