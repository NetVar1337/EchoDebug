import { describe, expect, it } from "vitest";
import { branchOf, buildStructure, postDominators, type Insn } from "./structure";

/** Hand-written listing: each entry is `[address, text]`, length 2 unless the next address says otherwise. */
function listing(rows: [number, string][]): Insn[] {
  return rows.map(([a, text], i) => ({ address: "0x" + a.toString(16), length: (rows[i + 1]?.[0] ?? a + 2) - a, text }));
}

const edgesOf = (cfg: ReturnType<typeof buildStructure>) => cfg.edges.map((e) => `${e.from}->${e.to}:${e.kind}${e.back ? "!" : ""}`);

describe("branchOf", () => {
  it("classifies intel and at&t branches", () => {
    expect(branchOf("ret")).toEqual({ kind: "ret" });
    expect(branchOf("retq")).toEqual({ kind: "ret" });
    expect(branchOf("jmp 0x401000")).toEqual({ kind: "jmp", target: 0x401000n });
    expect(branchOf("bnd jmp 0x401000")).toEqual({ kind: "jmp", target: 0x401000n });
    expect(branchOf("jmp rax")).toEqual({ kind: "jmp", target: null });
    expect(branchOf("jmp *%rax")).toEqual({ kind: "jmp", target: null });
    expect(branchOf("jne short 0x10")).toEqual({ kind: "jcc", mnemonic: "jne", target: 0x10n });
    expect(branchOf("int3")).toEqual({ kind: "stop" });
    expect(branchOf("call 0x401000")).toBeNull();
    expect(branchOf("mov rax, rbx")).toBeNull();
  });
});

describe("buildStructure", () => {
  it("if/else diamond", () => {
    const cfg = buildStructure(listing([
      [0x10, "cmp ecx, 0x5"],
      [0x12, "jle 0x18"],
      [0x14, "mov eax, 0x1"],
      [0x16, "jmp 0x1a"],
      [0x18, "mov eax, 0x2"],
      [0x1a, "ret"],
    ]));
    expect(cfg.blocks.map((b) => b.insns.length)).toEqual([2, 2, 1, 1]);
    expect(edgesOf(cfg)).toEqual(["0->2:true", "0->1:false", "1->3:jump", "2->3:fall"]);
    expect(cfg.loops).toHaveLength(0);
    expect(postDominators(cfg)).toEqual([3, 3, 3, -1]);
  });

  it("while loop: back edge, header and body", () => {
    const cfg = buildStructure(listing([
      [0x10, "xor eax, eax"],
      [0x12, "cmp eax, ecx"], // header
      [0x14, "jge 0x1a"],
      [0x16, "inc eax"],
      [0x18, "jmp 0x12"],
      [0x1a, "ret"],
    ]));
    expect(edgesOf(cfg)).toEqual(["0->1:fall", "1->3:true", "1->2:false", "2->1:jump!"]);
    expect(cfg.loops).toHaveLength(1);
    expect(cfg.loops[0].header).toBe(1);
    expect([...cfg.loops[0].body].sort()).toEqual([1, 2]);
    expect(cfg.blocks.map((b) => b.inLoop)).toEqual([false, true, true, false]);
    expect(cfg.blocks[1].loopHeader).toBe(true);
  });

  it("switch-like compare chain", () => {
    const cfg = buildStructure(listing([
      [0x10, "cmp ecx, 0x1"],
      [0x12, "je 0x20"],
      [0x14, "cmp ecx, 0x2"],
      [0x16, "je 0x24"],
      [0x18, "cmp ecx, 0x3"],
      [0x1a, "je 0x28"],
      [0x1c, "xor eax, eax"],
      [0x1e, "ret"],
      [0x20, "mov eax, 0xa"],
      [0x22, "ret"],
      [0x24, "mov eax, 0xb"],
      [0x26, "ret"],
      [0x28, "mov eax, 0xc"],
      [0x2a, "ret"],
    ]));
    expect(cfg.blocks).toHaveLength(7);
    expect(cfg.blocks.filter((b) => b.succ.length === 0)).toHaveLength(4);
    expect(edgesOf(cfg).filter((e) => e.endsWith("true"))).toEqual(["0->4:true", "1->5:true", "2->6:true"]);
  });

  it("early return and tail call leave no edge", () => {
    const cfg = buildStructure(listing([
      [0x10, "test rcx, rcx"],
      [0x12, "jne 0x16"],
      [0x14, "ret"],
      [0x16, "jmp 0x9000"], // tail call out of the function
    ]));
    expect(edgesOf(cfg)).toEqual(["0->2:true", "0->1:false"]);
    expect(cfg.blocks[2].succ).toHaveLength(0);
  });

  it("do-while self loop and unreachable code", () => {
    const cfg = buildStructure(listing([
      [0x10, "dec ecx"],
      [0x12, "jne 0x10"],
      [0x14, "ret"],
      [0x16, "int3"],
    ]));
    expect(edgesOf(cfg)).toEqual(["0->0:true!", "0->1:false"]);
    expect(cfg.blocks[0].loopHeader).toBe(true);
    expect(cfg.blocks.map((b) => b.reachable)).toEqual([true, true, false]);
  });
});
