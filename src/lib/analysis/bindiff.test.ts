import { describe, expect, it } from "vitest";
import { diffFunctions, jaccard, type DiffFunction, type DiffInsn } from "./bindiff";

let at = 0;
const I = (bytes: string, text: string): DiffInsn => ({ address: "0x" + (at++).toString(16), length: bytes.length / 2, bytes, text });
const F = (rva: number, name: string, insns: DiffInsn[]): DiffFunction => ({ rva, name, insns, size: insns.reduce((n, i) => n + i.length, 0) });

const body = (k: number) => [I("55", "push rbp"), I("4889e5", "mov rbp, rsp"), I(`83c7${k.toString(16).padStart(2, "0")}`, `add edi, ${k}`), I("89f8", "mov eax, edi"), I("5d", "pop rbp"), I("c3", "ret")];

describe("binary diff", () => {
  it("matches identical, renamed, moved, edited and new functions", () => {
    const oldFns = [
      F(0x1000, "sub_1000", body(1)),
      F(0x1100, "Parse", [I("31c0", "xor eax, eax"), I("c3", "ret")]),
      // caller of 0x1300 (callee matched through the call graph)
      F(0x1200, "sub_1200", [I("e8fb000000", "call 0x140001300"), I("e8f6000000", "call 0x140001300"), I("c3", "ret")]),
      F(0x1300, "sub_1300", [I("b801000000", "mov eax, 1"), I("c3", "ret")]),
      F(0x1400, "sub_1400", [...body(9), I("90", "nop"), I("90", "nop")]),
      F(0x1500, "sub_1500", body(77).slice(0, 3)),
    ];
    const newFns = [
      F(0x2000, "sub_2000", body(1)), // moved, same bytes
      F(0x2100, "Parse", [I("b8ffffffff", "mov eax, -1"), I("c3", "ret")]), // same name, new body
      F(0x2200, "sub_2200", [I("e8fb000000", "call 0x140002300"), I("e8f6000000", "call 0x140002300"), I("c3", "ret")]),
      F(0x2300, "sub_2300", [I("b802000000", "mov eax, 2"), I("c3", "ret")]),
      F(0x2400, "sub_2400", [...body(9), I("90", "nop"), I("cc", "int3")]), // one instruction changed
      F(0x2600, "sub_2600", [I("0f0b", "ud2")]), // new
    ];
    const r = diffFunctions(oldFns, newFns, 0x140000000, 0x140000000);
    const by = new Map(r.pairs.map((p) => [p.old.rva, p]));
    expect(by.get(0x1000)).toMatchObject({ kind: "identical", changed: false, new: { rva: 0x2000 } });
    expect(by.get(0x1100)).toMatchObject({ kind: "name", changed: true, new: { rva: 0x2100 } });
    expect(by.get(0x1200)?.new.rva).toBe(0x2200);
    expect(by.get(0x1300)).toMatchObject({ kind: "callgraph", new: { rva: 0x2300 } });
    expect(by.get(0x1400)?.new.rva).toBe(0x2400);
    expect(by.get(0x1400)?.changed).toBe(true);
    expect(r.onlyNew.map((f) => f.rva)).toEqual([0x2600]);
    expect(r.onlyOld.map((f) => f.rva)).toEqual([0x1500]);
  });

  it("computes Jaccard similarity", () => {
    expect(jaccard(new Set(["a", "b"]), new Set(["b", "c"]))).toBeCloseTo(1 / 3);
    expect(jaccard(new Set(), new Set())).toBe(1);
  });
});
