import { describe, expect, it } from "vitest";
import { buildStructure, type Insn } from "./structure";
import { argRegs, conditionOf, condText, normalize, protoHeader, pseudocode, translate, type Proto } from "./pseudocode";

const listing = (rows: [number, string][]): Insn[] =>
  rows.map(([a, text], i) => ({ address: "0x" + a.toString(16), length: (rows[i + 1]?.[0] ?? a + 2) - a, text }));
const tr = (text: string, address = "0x1000", length = 7) => translate({ address, length, text });
const code = (rows: [number, string][]) => pseudocode(buildStructure(listing(rows))).map((l) => "  ".repeat(l.indent - 1) + l.text);

describe("normalize", () => {
  it("keeps intel and converts at&t", () => {
    expect(normalize("mov rax, qword ptr [rbp-0x8]")).toEqual({ mn: "mov", ops: ["rax", "qword ptr [rbp-0x8]"], ripTarget: null });
    expect(normalize("mov -0x8(%rbp),%rax").ops).toEqual(["rax", "[rbp-0x8]"]);
    expect(normalize("movl $0x1,0x10(%rax,%rcx,4)")).toEqual({ mn: "mov", ops: ["dword ptr [rax+rcx*4+0x10]", "0x1"], ripTarget: null });
    expect(normalize("lea 0x2f5e(%rip),%rdi  ; 0x404010")).toEqual({ mn: "lea", ops: ["rdi", "[rip+0x2f5e]"], ripTarget: 0x404010n });
    expect(normalize("movzbl (%rdi),%eax")).toEqual({ mn: "movzx", ops: ["eax", "[rdi]"], ripTarget: null });
  });
});

describe("translate", () => {
  it("common x64 patterns", () => {
    expect(tr("mov eax, 0x1")).toBe("eax = 0x1;");
    expect(tr("mov rax, qword ptr [rcx+0x10]")).toBe("rax = *(u64*)(rcx + 0x10);");
    expect(tr("mov dword ptr [rbp-0x4], ecx")).toBe("*(u32*)(rbp - 0x4) = ecx;");
    expect(tr("mov rax, [rcx]")).toBe("rax = *(u64*)rcx;");
    expect(tr("lea rdx, [rcx+rax*8]")).toBe("rdx = rcx + rax*8;");
    expect(tr("lea rcx, [rip+0x10]", "0x1000", 7)).toBe("rcx = 0x1017;");
    expect(tr("mov eax, dword ptr [rip+0x20]", "0x1000", 6)).toBe("eax = *(u32*)0x1026;");
    expect(tr("xor eax, eax")).toBe("eax = 0;");
    expect(tr("xor eax, ecx")).toBe("eax ^= ecx;");
    expect(tr("add rsp, 0x28")).toBe("rsp += 0x28;");
    expect(tr("and ecx, 0xff")).toBe("ecx &= 0xff;");
    expect(tr("shl rax, 0x3")).toBe("rax <<= 0x3;");
    expect(tr("shr edx, 1")).toBe("edx >>= 1;");
    expect(tr("imul eax, ecx, 0xc")).toBe("eax = ecx * 0xc;");
    expect(tr("inc dword ptr [rax]")).toBe("(*(u32*)rax)++;");
    expect(tr("ret")).toBe("return rax;");
    expect(tr("nop")).toBeNull();
    expect(tr("nopw 0x0(%rax,%rax,1)")).toBeNull();
    expect(tr("xchg %ax,%ax")).toBeNull();
    expect(tr("cpuid")).toBe("// cpuid");
    expect(tr("push rbx")).toBe("// push rbx");
    expect(tr("mov %rsp,%rbp")).toBe("rbp = rsp;");
    expect(tr("lea 0x402004,%r14  ; 0x402004")).toBe("r14 = 0x402004;");
    expect(tr("mov $-1,%rsi")).toBe("rsi = -1;");
  });

  it("calls pass the argument registers written before them", () => {
    const w = new Set<string>();
    expect(translate({ address: "0x1", length: 3, text: "mov ecx, 0x1" }, "win64", w)).toBe("ecx = 0x1;");
    expect(translate({ address: "0x4", length: 3, text: "xor r8d, r8d" }, "win64", w)).toBe("r8d = 0;");
    expect(translate({ address: "0x7", length: 5, text: "call 0x401000" }, "win64", w, (a) => (a === "0x401000" ? "CreateFileW" : ""))).toBe("rax = CreateFileW(rcx, rdx, r8);");
    expect(translate({ address: "0xc", length: 5, text: "call 0x402000" }, "win64", w)).toBe("rax = sub_402000();");
    expect(translate({ address: "0x11", length: 3, text: "mov %eax,%edi" }, "sysv", w)).toBe("edi = eax;");
    expect(translate({ address: "0x14", length: 2, text: "call *%rax" }, "sysv", w)).toBe("rax = rax(rdi);");
    expect(translate({ address: "0x16", length: 5, text: "jmp 0x403000" }, "win64", new Set())).toBe("return sub_403000(); // tail call");
    expect(translate({ address: "0x1b", length: 5, text: "call 0x0000000000401050" }, "sysv", new Set())).toBe("rax = sub_401050();");
  });
});

describe("conditionOf", () => {
  const ins = (...texts: string[]) => texts.map((text, i) => ({ address: "0x" + i.toString(16), length: 1, text }));
  const c = (...texts: string[]) => condText(conditionOf(ins(...texts)).cond);
  it("folds cmp/test into the jcc", () => {
    expect(c("cmp ecx, 0x5", "jle 0x10")).toBe("ecx <= 0x5");
    expect(c("cmp ecx, 0x5", "jb 0x10")).toBe("(u32)ecx < 0x5");
    expect(c("test rax, rax", "je 0x10")).toBe("rax == 0");
    expect(c("test al, 0x1", "jne 0x10")).toBe("(al & 0x1) != 0");
    expect(c("cmp ecx, 0x5", "mov eax, 0x1", "jg 0x10")).toBe("ecx > 0x5");
    expect(c("dec ecx", "jne 0x10")).toBe("ecx != 0");
    expect(c("test %edi,%edi", "mov %edi,%eax", "je 0x10")).toBe("edi == 0");
    expect(conditionOf(ins("cmp ecx, 0x5", "je 0x10")).consumed).toBe(0);
    expect(conditionOf(ins("dec ecx", "jne 0x10")).consumed).toBe(-1);
  });
  it("gives up honestly", () => {
    expect(c("cmp ecx, 0x5", "call 0x1000", "je 0x10")).toBe("COND(je)");
    expect(c("jo 0x10")).toBe("COND(jo)");
    // the mov overwrites what the cmp compared
    expect(c("cmp eax, 0x1", "mov eax, 0x5", "je 0x10")).toBe("COND(je)");
  });
});

describe("structuring", () => {
  it("if/else", () => {
    expect(code([
      [0x10, "cmp ecx, 0x5"],
      [0x12, "jle 0x18"],
      [0x14, "mov eax, 0x1"],
      [0x16, "jmp 0x1a"],
      [0x18, "mov eax, 0x2"],
      [0x1a, "ret"],
    ])).toEqual([
      "if (ecx <= 0x5) {",
      "  eax = 0x2;",
      "} else {",
      "  eax = 0x1;",
      "}",
      "return rax;",
    ]);
  });

  it("if without else and early return", () => {
    expect(code([
      [0x10, "test rcx, rcx"],
      [0x12, "jne 0x16"],
      [0x14, "ret"],
      [0x16, "mov eax, 0x1"],
      [0x18, "ret"],
    ])).toEqual(["if (rcx != 0) {", "  eax = 0x1;", "  return rax;", "} else {", "  return rax;", "}"]);
    expect(code([
      [0x10, "test rcx, rcx"],
      [0x12, "je 0x16"],
      [0x14, "inc eax"],
      [0x16, "ret"],
    ])).toEqual(["if (rcx != 0) {", "  eax++;", "}", "return rax;"]);
  });

  it("while loop", () => {
    expect(code([
      [0x10, "xor eax, eax"],
      [0x12, "cmp eax, ecx"],
      [0x14, "jge 0x1a"],
      [0x16, "inc eax"],
      [0x18, "jmp 0x12"],
      [0x1a, "ret"],
    ])).toEqual(["eax = 0;", "while (eax < ecx) {", "  eax++;", "}", "return rax;"]);
  });

  it("do-while loop", () => {
    expect(code([
      [0x10, "add eax, edx"],
      [0x12, "dec ecx"],
      [0x14, "jne 0x10"],
      [0x16, "ret"],
    ])).toEqual(["do {", "  eax += edx;", "  ecx--;", "} while (ecx != 0);", "return rax;"]);
  });

  it("loop with a break in the middle", () => {
    expect(code([
      [0x10, "mov eax, dword ptr [rcx]"],
      [0x12, "test eax, eax"],
      [0x14, "je 0x1c"],
      [0x16, "add rcx, 0x4"],
      [0x18, "inc edx"],
      [0x1a, "jmp 0x10"],
      [0x1c, "mov eax, edx"],
      [0x1e, "ret"],
    ])).toEqual([
      "while (1) {",
      "  eax = *(u32*)rcx;",
      "  if (eax == 0) {",
      "    break;",
      "  }",
      "  rcx += 0x4;",
      "  edx++;",
      "}",
      "eax = edx;",
      "return rax;",
    ]);
  });

  it("switch-like compare chain becomes nested ifs", () => {
    const out = code([
      [0x10, "cmp ecx, 0x1"],
      [0x12, "je 0x1c"],
      [0x14, "cmp ecx, 0x2"],
      [0x16, "je 0x20"],
      [0x18, "xor eax, eax"],
      [0x1a, "ret"],
      [0x1c, "mov eax, 0xa"],
      [0x1e, "ret"],
      [0x20, "mov eax, 0xb"],
      [0x22, "ret"],
    ]);
    expect(out[0]).toBe("if (ecx == 0x1) {");
    expect(out).toContain("  if (ecx == 0x2) {");
    expect(out.filter((l) => l.trim() === "return rax;")).toHaveLength(3);
  });

  it("falls back to goto for an irreducible jump into a loop", () => {
    const out = code([
      [0x10, "test ecx, ecx"],
      [0x12, "je 0x18"],
      [0x14, "inc eax"], // A
      [0x16, "jmp 0x1a"],
      [0x18, "dec eax"], // B
      [0x1a, "cmp eax, edx"], // C, jumps back to A or B
      [0x1c, "jl 0x14"],
      [0x1e, "jg 0x18"],
      [0x20, "ret"],
    ]);
    expect(out.some((l) => l.includes("goto loc_"))).toBe(true);
    expect(out.some((l) => /^loc_[0-9a-f]+:$/.test(l.trim()))).toBe(true);
    expect(out[out.length - 1].trim()).toBe("return rax;");
    // the lone `jg` reuses the flags of the cmp in the block before it
    expect(out).toContain("if (eax > edx) {");
  });
});

describe("prototypes from debug info", () => {
  const score: Proto = { name: "entity_score", ret: "int", params: [{ name: "e", type: "Entity*" }, { name: "bonus", type: "int" }] };
  const init: Proto = { name: "entity_init", ret: "void", params: [{ name: "e", type: "Entity*" }, { name: "id", type: "unsigned __int64" }] };
  const protoOf = (a: string) => (a === "0x401000" ? score : a === "0x402000" ? init : undefined);

  it("places arguments per ABI", () => {
    const mixed: Proto = { name: "f", ret: "double", params: [{ name: "a", type: "int" }, { name: "x", type: "double" }, { name: "b", type: "char*" }] };
    expect(argRegs(mixed, "win64")).toEqual(["rcx", "xmm1", "r8"]);
    expect(argRegs(mixed, "sysv")).toEqual(["rdi", "xmm0", "rsi"]);
    expect(argRegs({ name: "g", ret: "int", params: Array.from({ length: 5 }, (_, i) => ({ name: `p${i}`, type: "int" })) }, "win64")[4]).toBe("arg_5");
    expect(protoHeader(score)).toEqual(["int entity_score(Entity* e, int bonus)", "// e = rcx, bonus = rdx"]);
  });

  it("uses the callee's argument count and void returns", () => {
    const w = new Set<string>(["rcx", "rdx", "r8", "r9"]);
    expect(translate({ address: "0x1", length: 5, text: "call 0x401000" }, "win64", w, undefined, protoOf)).toBe("rax = sub_401000(rcx, rdx);");
    expect(translate({ address: "0x6", length: 5, text: "call 0x402000" }, "win64", new Set(), (a) => (a === "0x402000" ? "entity_init" : ""), protoOf)).toBe("entity_init(rcx, rdx);");
    expect(translate({ address: "0xb", length: 5, text: "jmp 0x402000" }, "sysv", new Set(), undefined, protoOf)).toBe("return sub_402000(rdi, rsi); // tail call");
  });

  it("heads the function with its signature", () => {
    const out = pseudocode(buildStructure(listing([[0x401000, "mov eax, ecx"], [0x401002, "ret"]])), { protoOf });
    expect(out[0]).toMatchObject({ indent: 0, text: "int entity_score(Entity* e, int bonus)" });
    expect(out[1].text).toBe("// e = rcx, bonus = rdx");
    expect(out.at(-1)!.text).toBe("return rax;");
  });
});
