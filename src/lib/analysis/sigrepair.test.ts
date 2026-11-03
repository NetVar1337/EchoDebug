import { describe, expect, it } from "vitest";
import { classify, countRelocation, health, locate } from "./sigrepair";

describe("signature repair", () => {
  it("classifies hit counts", () => {
    expect(health(1)).toBe("ok");
    expect(health(0)).toBe("missing");
    expect(health(3)).toBe("ambiguous");
  });

  it("shortens a broken pattern until the function is found again", async () => {
    // the build changed byte 9; prefixes up to 8 bytes still find the function once
    const pattern = [0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, null, 0x8b];
    const tried: string[] = [];
    const r = await locate(pattern, async (ida) => {
      tried.push(ida);
      return ida.split(" ").length <= 9 ? ["0x1400a1000"] : [];
    });
    expect(r.status).toBe("repaired");
    expect(r.at).toBe("0x1400a1000");
    expect(r.prefix).toBe(9);
    expect(tried[0]).toBe("48 89 5C 24 08 57 48 83 EC 20 ? 8B");
    expect(tried).toContain("48 89 5C 24 08 57 48 83 EC 20"); // trailing wildcard trimmed
  });

  it("reports ambiguity and loss", async () => {
    const p = [1, 2, 3, 4, 5, 6, 7, 8];
    expect((await locate(p, async (ida) => (ida.split(" ").length <= 7 ? ["0x1", "0x2"] : []))).status).toBe("ambiguous");
    expect((await locate(p, async () => [])).status).toBe("lost");
  });
});

describe("relocation / health classification", () => {
  it("classifies scan results against the saved RVA", () => {
    expect(classify(0x10n, [0x10n])).toEqual({ status: "ok", rva: 0x10n });
    expect(classify(0x10n, [0x20n])).toEqual({ status: "moved", rva: 0x20n });
    expect(classify(undefined, [0x20n])).toEqual({ status: "ok", rva: 0x20n });
    expect(classify(0x10n, [0x10n, 0x20n])).toEqual({ status: "ambiguous" });
    expect(classify(0x10n, [])).toEqual({ status: "missing" });
  });

  it("counts matched / moved / lost", () => {
    expect(countRelocation(["ok", "moved", "moved", "ambiguous", "missing", "nosig"])).toEqual({ matched: 1, moved: 2, lost: 3 });
  });
});
