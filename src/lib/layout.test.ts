import { describe, expect, it } from "vitest";
import { autoHidden, visiblePanels } from "./layout";
import { kTabs, kViewGroups } from "@/store/ui";

describe("layout", () => {
  const all = { left: true, scanner: true, inspector: true, output: true };
  it("auto-hides the scanner, then the inspector, as the window narrows", () => {
    expect(visiblePanels(all, 1600, {})).toEqual(all);
    expect(visiblePanels(all, 1300, {})).toEqual({ ...all, scanner: false });
    expect(visiblePanels(all, 1000, {})).toEqual({ ...all, scanner: false, inspector: false });
    expect(visiblePanels(all, 1000, { scanner: true })).toEqual({ ...all, inspector: false });
    expect(visiblePanels({ ...all, output: false }, 1600, {}).output).toBe(false);
    expect(autoHidden("left", 400)).toBe(false);
  });
  it("puts every view in exactly one group", () => {
    const grouped = Object.values(kViewGroups).flatMap((g) => g.tabs);
    expect(new Set(grouped).size).toBe(grouped.length);
    expect([...grouped].sort()).toEqual(kTabs.map((t) => t.id).sort());
  });
});
