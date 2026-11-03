import { describe, expect, it } from "vitest";
import { classify } from "./patchsets";

describe("patch sets", () => {
  it("applies only over the original bytes", () => {
    const e = { module: "game.exe", key: "k", rva: 0x10, before: "7405", written: "eb05", note: "" };
    expect(classify(e, "7405")).toBe("apply");
    expect(classify(e, "eb05")).toBe("already");
    expect(classify(e, "9090")).toBe("conflict");
  });
});
