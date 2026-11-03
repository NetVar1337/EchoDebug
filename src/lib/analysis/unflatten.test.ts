import { describe, expect, it } from "vitest";
import { buildStructure, type Insn } from "./structure";
import { buildIr, decompile, irGraph } from "./decompile";

const listing = (rows: [number, string][]): Insn[] =>
  rows.map(([a, text], i) => ({ address: "0x" + a.toString(16), length: (rows[i + 1]?.[0] ?? a + 2) - a, text }));
const text = (rows: [number, string][], unflatten: boolean, switches?: Map<bigint, bigint[]>) =>
  decompile(buildStructure(listing(rows), { switches }), { abi: "win64", unflatten }).lines.map((l) => "  ".repeat(l.indent) + l.text);

/** Are two graphs the same up to block numbering (and the order of a branch's two targets)? */
function sameShape(a: ReturnType<typeof irGraph>, b: ReturnType<typeof irGraph>): boolean {
  if (a.blocks.length !== b.blocks.length || a.edges.length !== b.edges.length) return false;
  const succ = (g: ReturnType<typeof irGraph>, n: number) => g.edges.filter((e) => e.from === n).map((e) => e.to);
  const map = new Map<number, number>();
  const used = new Set<number>();
  const match = (x: number, y: number): boolean => {
    if (map.has(x)) return map.get(x) === y;
    if (used.has(y)) return false;
    const sx = succ(a, x);
    const sy = succ(b, y);
    if (sx.length !== sy.length) return false;
    map.set(x, y);
    used.add(y);
    const orders = sy.length === 2 ? [sy, [sy[1], sy[0]]] : [sy];
    for (const o of orders) {
      const snapshot = new Map(map);
      const snapUsed = new Set(used);
      if (sx.every((s, i) => match(s, o[i]))) return true;
      map.clear();
      snapshot.forEach((v, k) => map.set(k, v));
      used.clear();
      snapUsed.forEach((v) => used.add(v));
    }
    map.delete(x);
    used.delete(y);
    return false;
  };
  return match(a.blocks[0].id, b.blocks[0].id);
}

// int f(int n) { int s = 0; for (int i = 0; i < n; i++) if (i & 1) s += i; else s -= 1; return s; }
const original: [number, string][] = [
  [0x00, "xor eax, eax"],
  [0x02, "xor edx, edx"],
  [0x04, "cmp edx, ecx"],
  [0x06, "jge 0x1a"],
  [0x08, "test dl, 0x1"],
  [0x0b, "je 0x12"],
  [0x0d, "add eax, edx"],
  [0x0f, "jmp 0x15"],
  [0x12, "sub eax, 0x1"],
  [0x15, "inc edx"],
  [0x17, "jmp 0x4"],
  [0x1a, "ret"],
];

// the same function flattened OLLVM style: a state variable on the stack, a binary compare tree as
// dispatcher, cmov-selected states for the two conditional branches
const flattened: [number, string][] = [
  [0x00, "sub rsp, 0x18"],
  [0x04, "xor eax, eax"],
  [0x06, "xor edx, edx"],
  [0x08, "mov dword ptr [rsp+0xc], 0x1111"],
  [0x10, "mov r8d, dword ptr [rsp+0xc]"], // dispatcher
  [0x15, "cmp r8d, 0x3333"],
  [0x1c, "jg 0x40"],
  [0x1e, "cmp r8d, 0x1111"],
  [0x25, "je 0x60"],
  [0x27, "cmp r8d, 0x2222"],
  [0x2e, "je 0x80"],
  [0x30, "cmp r8d, 0x3333"],
  [0x37, "je 0xa0"],
  [0x39, "jmp 0x10"],
  [0x40, "cmp r8d, 0x4444"],
  [0x47, "je 0xb0"],
  [0x49, "cmp r8d, 0x5555"],
  [0x50, "je 0xd0"],
  [0x52, "cmp r8d, 0x6666"],
  [0x59, "je 0xc0"],
  [0x5b, "jmp 0x10"],
  [0x60, "mov r9d, 0x5555"], // loop test: i < n ? body : exit
  [0x66, "mov r10d, 0x2222"],
  [0x6c, "cmp edx, ecx"],
  [0x6e, "cmovl r9d, r10d"],
  [0x72, "mov dword ptr [rsp+0xc], r9d"],
  [0x77, "jmp 0xe0"],
  [0x80, "mov r9d, 0x4444"], // i & 1 ? add : sub
  [0x86, "mov r10d, 0x3333"],
  [0x8c, "test dl, 0x1"],
  [0x8f, "cmovne r9d, r10d"],
  [0x93, "mov dword ptr [rsp+0xc], r9d"],
  [0x98, "jmp 0xe0"],
  [0xa0, "add eax, edx"],
  [0xa2, "mov dword ptr [rsp+0xc], 0x6666"],
  [0xaa, "jmp 0xe0"],
  [0xb0, "sub eax, 0x1"],
  [0xb3, "mov dword ptr [rsp+0xc], 0x6666"],
  [0xbb, "jmp 0xe0"],
  [0xc0, "inc edx"],
  [0xc2, "mov dword ptr [rsp+0xc], 0x1111"],
  [0xca, "jmp 0xe0"],
  [0xd0, "add rsp, 0x18"],
  [0xd4, "ret"],
  [0xe0, "jmp 0x10"], // the loop latch back to the dispatcher
];

describe("control-flow flattening removal", () => {
  it("a flattened function comes back to the original shape", () => {
    const orig = buildIr(buildStructure(listing(original)));
    const flat = buildIr(buildStructure(listing(flattened)), { unflatten: true });
    expect(flat.report?.flattened).toBe(true);
    expect(sameShape(irGraph(orig.ir), irGraph(flat.ir))).toBe(true);
    // without the pass the dispatcher is all there is
    const raw = buildIr(buildStructure(listing(flattened)));
    expect(sameShape(irGraph(orig.ir), irGraph(raw.ir))).toBe(false);
    // and the pseudocode is the same
    expect(text(flattened, true)).toEqual(text(original, false));
    expect(text(original, false)).toEqual([
      "int __fastcall sub_0(int a1)",
      "{",
      "  int v1; // rax",
      "  int v2; // rdx",
      "  ",
      "  v1 = 0;",
      "  for (v2 = 0; v2 < a1; ++v2) {",
      "    if ((v2 & 1) != 0) {",
      "      v1 += v2;",
      "    } else {",
      "      --v1;",
      "    }",
      "  }",
      "  return v1;",
      "}",
    ]);
  });

  it("reports the dispatcher, the state variable and what was recovered", () => {
    const { report } = buildIr(buildStructure(listing(flattened)), { unflatten: true });
    expect(report).toMatchObject({ flattened: true, dispatcher: "0x10", state: "var_c", states: 6, unresolved: [] });
    expect(report!.dispatcherBlocks).toEqual(["0x10", "0x1e", "0x27", "0x30", "0x39", "0x40", "0x49", "0x52", "0x5b", "0xe0"]);
    const by = Object.fromEntries(report!.recovered.map((r) => [r.block, r]));
    expect(by["0x0"]).toEqual({ block: "0x0", next: ["0x60"], via: "const" });
    expect(by["0x60"]).toEqual({ block: "0x60", next: ["0x80", "0xd0"], via: "select" });
    expect(by["0x80"]).toEqual({ block: "0x80", next: ["0xa0", "0xb0"], via: "select" });
    expect(by["0xc0"].next).toEqual(["0x60"]);
  });

  it("a switch-table dispatcher on a register, with a block whose state is unknown", () => {
    // state in ebx; the dispatcher is jmp [rbx*8+table]; block 0x50 takes its next state from memory
    const rows: [number, string][] = [
      [0x00, "push rbx"],
      [0x01, "xor ebx, ebx"],
      [0x03, "xor eax, eax"],
      [0x05, "cmp ebx, 0x3"], // dispatcher
      [0x08, "ja 0x70"],
      [0x0a, "jmp qword ptr [rbx*8+0x1000]"],
      [0x20, "add eax, 0x1"], // state 0
      [0x23, "mov ebx, 0x2"],
      [0x28, "jmp 0x5"],
      [0x30, "add eax, 0x2"], // state 1
      [0x33, "mov ebx, 0x3"],
      [0x38, "jmp 0x5"],
      [0x40, "add eax, 0x4"], // state 2
      [0x43, "mov ebx, 0x1"],
      [0x48, "jmp 0x5"],
      [0x50, "mov ebx, dword ptr [rcx]"], // state 3: next state not constant
      [0x52, "jmp 0x5"],
      [0x70, "pop rbx"],
      [0x71, "ret"],
    ];
    const switches = new Map([[0xan, [0x20n, 0x30n, 0x40n, 0x50n]]]);
    const { report, ir } = buildIr(buildStructure(listing(rows), { switches }), { unflatten: true });
    expect(report).toMatchObject({ flattened: true, state: "rbx" });
    expect(report!.recovered.map((r) => [r.block, r.next])).toEqual([["0x0", ["0x20"]], ["0x20", ["0x40"]], ["0x30", ["0x50"]], ["0x40", ["0x30"]]]);
    expect(report!.unresolved).toEqual([{ block: "0x50", reason: "the state is not a constant here" }]);
    // the unresolved block still goes through the dispatcher, which therefore stays
    const g = irGraph(ir);
    expect(g.blocks.some((b) => b.addr === "0x5")).toBe(true);
    const out = text(rows, true, switches);
    expect(out.join("\n")).toContain("switch (");
  });

  it("leaves ordinary functions alone", () => {
    const { report } = buildIr(buildStructure(listing(original)), { unflatten: true });
    expect(report?.flattened).toBe(false);
    expect(report?.note).toMatch(/no dispatcher/);
    // a plain compare chain is not a dispatcher: nothing loops back into it
    const chain = buildIr(buildStructure(listing([
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
    ])), { unflatten: true });
    expect(chain.report?.flattened).toBe(false);
  });
});
