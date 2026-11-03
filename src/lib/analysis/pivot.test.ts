import { describe, expect, it } from "vitest";
import { analyzeControlFlow, findMissingEndbr, findStackPivots } from "./pivot";
import type { ListingLine } from "./listing";

const lines: ListingLine[] = [
  { address: "0x1000", bytes: "94", text: "xchg eax, esp" },
  { address: "0x1001", bytes: "4889c4", text: "mov rsp, rax" },
  { address: "0x1004", bytes: "5c", text: "pop rsp" },
  { address: "0x1005", bytes: "c9", text: "leave" },
  { address: "0x1006", bytes: "c3", text: "ret" },
  { address: "0x2000", bytes: "f30f1efa", text: "endbr64" },
  { address: "0x2004", bytes: "55", text: "push rbp" },
  { address: "0x3000", bytes: "55", text: "push rbp" }, // no endbr64
];

describe("stack pivots", () => {
  it("finds xchg/mov/pop/leave pivots with severity", () => {
    const p = findStackPivots(lines);
    expect(p.map((x) => x.kind)).toEqual(["xchg-rsp", "mov-rsp", "pop-rsp", "leave"]);
    expect(p.filter((x) => x.severity === "high")).toHaveLength(2);
  });
});

describe("CET / ENDBR64", () => {
  it("flags indirect targets missing endbr64", () => {
    expect(findMissingEndbr(lines, ["0x2000", "0x3000", "0x9999"])).toEqual(["0x3000"]);
  });

  it("reports pivots and missing endbr together", () => {
    const rep = analyzeControlFlow(lines, ["0x2000", "0x3000"]);
    expect(rep.pivots).toHaveLength(4);
    expect(rep.missingEndbr).toEqual(["0x3000"]);
    expect(rep.checked).toBe(2);
  });
});
