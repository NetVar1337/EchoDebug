import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { mapPeFile } from "./pe";
import { summarizeResources } from "./resources";

const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));

describe("PE resources (llvm-rc fixture, see fixtures/fix.rc)", () => {
  const r = summarizeResources(mapPeFile(fixture("fix-res.exe")));

  it("walks the type/name/language tree", () => {
    expect([...new Set(r.leaves.map((l) => l.typeName))].sort()).toEqual(["DIALOG", "GROUP_ICON", "ICON", "MANIFEST", "STRING", "VERSION"]);
  });
  it("reads version info", () => {
    expect(r.version).toMatchObject({ fileVersion: "1.2.3.4", productVersion: "1.2.0.0", fileOS: 0x40004, fileType: 1, translations: ["040904b0"] });
    expect(r.version!.strings["040904b0"]).toEqual({ CompanyName: "EchoDebug Tests", FileDescription: "Resource fixture", FileVersion: "1.2.3.4", ProductName: "EchoDebug" });
  });
  it("reads string tables, the manifest and the dialog", () => {
    expect(r.strings).toEqual([{ id: 1, text: "first string" }, { id: 17, text: "seventeenth" }]);
    expect(r.manifest).toContain('name="EchoDebug.Fixture"');
    const d = r.dialogs[0].dialog;
    expect(d).toMatchObject({ extended: true, title: "EchoDebug Fixture", font: "Segoe UI", cx: 200, cy: 80 });
    expect(d.controls.map((c) => [c.cls, c.text, c.id])).toEqual([["Button", "OK", 1], ["Static", "Hello", 2]]);
  });
  it("re-assembles the icon into the original .ico", () => {
    expect(r.icons).toHaveLength(1);
    expect(Array.from(r.icons[0].ico)).toEqual(Array.from(fixture("app.ico")));
  });
});
