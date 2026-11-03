import { describe, expect, it } from "vitest";
import { buildStructure, type Insn } from "./structure";
import { buildIr, decompile, irGraph, type DecompileOptions } from "./decompile";
import { liftFunction } from "./irlift";
import { analyze, analyzeSignature, optimize } from "./dataflow";
import { c, ccCond, loc, negate, simp, type Expr } from "./ir";
import { lookupPrototype, registerPrototypeProvider } from "./prototypes";

/** Hand-written listing: `[address, text]`, each instruction's length runs to the next address. */
const listing = (rows: [number, string][]): Insn[] =>
  rows.map(([a, text], i) => ({ address: "0x" + a.toString(16), length: (rows[i + 1]?.[0] ?? a + 2) - a, text }));
/** The function body (between the braces), declarations and blank lines left out, two spaces per level. */
const body = (rows: [number, string][], o: DecompileOptions & { switches?: Map<bigint, bigint[]> } = {}) => {
  const d = decompile(buildStructure(listing(rows), { switches: o.switches }), { abi: "win64", ...o });
  return d.lines.filter((l) => l.indent > 0 && l.text && !/; \/\/ (\w+|stack|temp)$/.test(l.text) && !l.text.startsWith("// ")).map((l) => "  ".repeat(l.indent - 1) + l.text);
};
const all = (rows: [number, string][], o: DecompileOptions = {}) => decompile(buildStructure(listing(rows)), { abi: "win64", ...o });

describe("ir simplification", () => {
  it("folds constants and conditions", () => {
    expect(simp({ k: "b", op: "+", a: { k: "b", op: "+", a: loc("rcx"), b: c(8), w: 64 }, b: c(-8), w: 64 })).toEqual(loc("rcx"));
    expect(simp({ k: "b", op: "^", a: loc("rax", 32), b: loc("rax", 32), w: 32 })).toEqual(c(0, 32));
    expect(simp({ k: "b", op: "*", a: c(6, 32), b: c(7, 32), w: 32 })).toEqual(c(42, 32));
    const f: Expr = { k: "flags", kind: "cmp", a: loc("rcx", 32), b: c(5, 32), w: 32 };
    expect(simp({ k: "cc", cc: "le", f })).toEqual({ k: "cmp", op: "<=", a: loc("rcx", 32), b: c(5, 32) });
    expect(ccCond("b", f)).toMatchObject({ op: "<u" });
    expect(ccCond("o", f).k).toBe("cc"); // overflow is not expressible
    const t: Expr = { k: "flags", kind: "test", a: loc("rax"), b: loc("rax"), w: 64 };
    expect(simp({ k: "cc", cc: "e", f: t })).toEqual({ k: "cmp", op: "==", a: loc("rax"), b: c(0) });
    expect(simp({ k: "cc", cc: "b", f: t })).toEqual(c(0, 1)); // CF is clear after test
    expect(simp({ k: "cc", cc: "e", f: { k: "flags", kind: "cmp", a: c(0x1111, 32), b: c(0x1111, 32), w: 32 } })).toEqual(c(1, 1));
    expect(negate({ k: "b", op: "&&", a: { k: "cmp", op: "<", a: loc("rcx"), b: c(0) }, b: { k: "cmp", op: "==", a: loc("rdx"), b: c(1) }, w: 1 }))
      .toEqual({ k: "b", op: "||", a: { k: "cmp", op: ">=", a: loc("rcx"), b: c(0) }, b: { k: "cmp", op: "!=", a: loc("rdx"), b: c(1) }, w: 1 });
    expect(simp({ k: "cmp", op: "<", a: { k: "b", op: "+", a: loc("rcx", 32), b: c(1, 32), w: 32 }, b: c(1, 32) })).toEqual({ k: "cmp", op: "<", a: loc("rcx", 32), b: c(0, 32) });
    expect(simp({ k: "sel", c: c(1, 1), a: c(5), b: c(6), w: 64 })).toEqual(c(5));
    expect(simp({ k: "part", old: c(0), v: { k: "cmp", op: "<", a: loc("rcx"), b: loc("rdx") }, w: 8 })).toMatchObject({ k: "cast", w: 64 });
  });
});

describe("lifting and propagation", () => {
  it("stack frames become slots, pushes and pops disappear", () => {
    const ir = liftFunction(buildStructure(listing([
      [0x10, "push rbx"],
      [0x11, "sub rsp, 0x20"],
      [0x15, "mov dword ptr [rsp+0x18], edx"],
      [0x19, "lea rcx, [rsp+0x8]"],
      [0x1e, "add rsp, 0x20"],
      [0x22, "pop rbx"],
      [0x23, "ret"],
    ])));
    // the push slot (-8) is a variable; [rsp+0x18] (-0x10) lies just above [rsp+0x8] (-0x20),
    // whose address was taken, so it stays memory
    expect([...ir.slots].sort((a, b) => a - b)).toEqual([-8]);
    expect(ir.blocks[0].stmts.some((s) => s.k === "set" && s.dst === "rcx" && s.src.k === "sa" && s.src.off === -0x20)).toBe(true);
  });

  it("copy, constant and expression propagation with dead-code removal", () => {
    const ir = liftFunction(buildStructure(listing([
      [0x0, "mov eax, 0x5"],
      [0x5, "mov edx, eax"],
      [0x7, "add edx, 0x3"],
      [0xa, "mov r8, rcx"],
      [0xd, "mov eax, dword ptr [r8+0x10]"],
      [0x11, "imul eax, edx"],
      [0x14, "ret"],
    ])));
    analyzeSignature(ir);
    optimize(ir);
    // everything folds into the return value
    expect(ir.blocks[0].stmts).toHaveLength(0);
    const t = ir.blocks[0].term;
    expect(t.k === "ret" && t.v && t.v.k === "b" && t.v.op === "*" && t.v.b).toEqual(c(8, 32));
    expect(ir.sig).toEqual({ args: ["rcx"], ret: "int" });
  });

  it("loads do not move past stores", () => {
    const out = body([
      [0x0, "mov eax, dword ptr [rcx]"],
      [0x2, "mov dword ptr [rcx], 0x0"],
      [0x8, "ret"],
    ]);
    expect(out).toEqual(["v1 = a1->field_0;", "a1->field_0 = 0;", "return v1;"]);
  });

  it("a read after the register was reused still sees the old variable", () => {
    expect(body([
      [0x0, "push rbx"],
      [0x1, "sub rsp, 0x20"],
      [0x5, "mov rbx, rcx"],
      [0x8, "mov ecx, dword ptr [rbx+0x10]"],
      [0xb, "call 0x401000"],
      [0x10, "mov dword ptr [rbx+0x18], eax"],
      [0x13, "add rsp, 0x20"],
      [0x17, "pop rbx"],
      [0x18, "ret"],
    ])).toEqual(["v1 = sub_401000(a1->field_10);", "a1->field_18 = v1;", "return v1;"]);
  });

  it("webs merged at a loop are one variable", () => {
    const d = all([
      [0x00, "xor eax, eax"],
      [0x02, "add eax, ecx"],
      [0x04, "dec ecx"],
      [0x06, "jne 0x2"],
      [0x08, "ret"],
    ]);
    const text = d.lines.map((l) => l.text);
    expect(text).toContain("v1 += a1;");
    expect(text).toContain("--a1;");
    expect(text).toContain("} while (a1 != 0);");
  });
});

describe("calling conventions", () => {
  it("win64 arguments, stack arguments and a prototype from the built-in table", () => {
    expect(body([
      [0x00, "sub rsp, 0x48"],
      [0x04, "mov dword ptr [rsp+0x30], 0x0"],
      [0x0c, "mov dword ptr [rsp+0x28], 0x80"],
      [0x14, "mov dword ptr [rsp+0x20], 0x3"],
      [0x1c, "xor r9d, r9d"],
      [0x1f, "mov r8d, 0x1"],
      [0x25, "mov edx, 0x80000000"],
      [0x2a, "call 0x3000"],
      [0x2f, "add rsp, 0x48"],
      [0x33, "ret"],
    ], { nameOf: (a) => (a === "0x3000" ? "CreateFileW" : "") })).toEqual(["return CreateFileW(a1, 0x80000000, 1, 0, 3, 0x80, 0);"]);
  });

  it("unknown callees take the argument registers written before them; unused results are dropped", () => {
    expect(body([
      [0x00, "sub rsp, 0x28"],
      [0x04, "mov ecx, 0x1"],
      [0x09, "lea rdx, [rsp+0x30]"],
      [0x0e, "call 0x401000"],
      [0x13, "xor ecx, ecx"],
      [0x15, "call 0x402000"],
      [0x1a, "add rsp, 0x28"],
      [0x1e, "ret"],
    ])).toEqual(["sub_401000(1, &arg_0);", "return sub_402000(0);"]);
  });

  it("sysv, AT&T syntax, variadic printf and a string literal", () => {
    const out = body([
      [0x00, "push %rbp"],
      [0x01, "mov %rsp,%rbp"],
      [0x04, "sub $0x10,%rsp"],
      [0x08, "mov %edi,-0x14(%rbp)"],
      [0x0b, "movl $0x0,-0x4(%rbp)"],
      [0x12, "jmp 0x24"],
      [0x14, "mov -0x4(%rbp),%eax"],
      [0x17, "mov %eax,%esi"],
      [0x19, "lea 0x100(%rip),%rdi  ; 0x2004"],
      [0x20, "call 0x2000"],
      [0x22, "addl $0x1,-0x4(%rbp)"],
      [0x24, "mov -0x4(%rbp),%eax"],
      [0x27, "cmp -0x14(%rbp),%eax"],
      [0x2a, "jl 0x14"],
      [0x2c, "mov $0x0,%eax"],
      [0x31, "leave"],
      [0x32, "ret"],
    ], { abi: "sysv", nameOf: (a) => (a === "0x2000" ? "printf" : ""), stringAt: (a) => (a === 0x2004n ? "%d\n" : null) });
    expect(out).toEqual(["for (var_c = 0; var_c < a1; ++var_c) {", '  printf("%d\\n", var_c);', "}", "return 0;"]);
  });

  it("signature: argument count, float arguments, void and value returns", () => {
    expect(all([[0x0, "mov dword ptr [rcx], edx"], [0x2, "ret"]]).signature).toBe("void __fastcall sub_0(void *a1, int a2)");
    expect(all([[0x0, "mulsd %xmm1,%xmm0"], [0x4, "cvtsi2sd %edi,%xmm1"], [0x8, "addsd %xmm1,%xmm0"], [0xc, "ret"]], { abi: "sysv" }).signature).toBe("double sub_0(int a1, double a2, double a3)");
    expect(all([[0x0, "movss xmm0, xmm1"], [0x4, "ret"]]).signature).toBe("float __fastcall sub_0(__int64 a1, float a2)");
    // a path that never writes rax: no return value
    expect(all([[0x0, "test ecx, ecx"], [0x2, "je 0x9"], [0x4, "call 0x1000"], [0x9, "ret"]]).signature).toMatch(/^void /);
  });

  it("prototype providers name the function, its arguments and the return type", () => {
    const off = registerPrototypeProvider("test", (a) => (a === "0x500" ? { name: "Do_Thing", args: [{ name: "ctx", type: "ptr" }], returns: "void" } : null));
    try {
      expect(lookupPrototype("0x500", null)?.name).toBe("Do_Thing");
      const d = all([[0x500, "mov dword ptr [rcx+0x4], 0x1"], [0x507, "ret"]], { entry: "0x500" });
      expect(d.signature).toBe("void __fastcall Do_Thing(void *ctx)");
      expect(d.lines.map((l) => l.text)).toContain("ctx->field_4 = 1;");
    } finally {
      off();
    }
    expect(lookupPrototype("0x500", null)).toBeNull();
    expect(lookupPrototype(null, "__imp_memcpy")?.args).toHaveLength(3);
  });
});

describe("types and fields", () => {
  it("pointer arguments get fields; a mapped struct gives field names", () => {
    const rows: [number, string][] = [
      [0x00, "mov eax, dword ptr [rcx+0x10]"],
      [0x03, "add eax, dword ptr [rcx+0x14]"],
      [0x06, "mov qword ptr [rcx+0x8], rdx"],
      [0x0a, "ret"],
    ];
    const plain = all(rows);
    expect(plain.vars.find((v) => v.name === "a1")).toMatchObject({ type: "void *", fields: [{ offset: 8, size: 8 }, { offset: 0x10, size: 4 }, { offset: 0x14, size: 4 }] });
    expect(plain.lines.map((l) => l.text)).toContain("a1->field_8 = a2;");
    const mapped = all(rows, { varTypes: { a1: "Player" }, fieldsOf: () => [{ offset: 8, size: 8, name: "next" }, { offset: 0x10, size: 4, name: "health" }, { offset: 0x14, size: 4, name: "armor" }] });
    expect(mapped.signature).toBe("int __fastcall sub_0(Player *a1, __int64 a2)");
    expect(mapped.lines.map((l) => l.text)).toEqual(expect.arrayContaining(["a1->next = a2;", "return v1;", "v1 = a1->health + a1->armor;"]));
  });

  it("floats, unsigned compares and array indexing", () => {
    expect(body([
      [0x00, "movss xmm0, dword ptr [rcx+0x8]"],
      [0x05, "mulss xmm0, xmm1"],
      [0x09, "ucomiss xmm0, dword ptr [rip+0x100]"],
      [0x10, "jbe 0x18"],
      [0x12, "movss dword ptr [rcx+0x8], xmm0"],
      [0x18, "ret"],
    ])).toEqual(["v1 = a1->field_8 * a2;", "if (v1 > flt_110) {", "  a1->field_8 = v1;", "}", "return v1;"]);
    const d = all([
      [0x0, "cmp edx, 0x10"],
      [0x3, "jae 0xb"],
      [0x5, "mov dword ptr [rcx+rdx*4], 0x0"],
      [0xb, "ret"],
    ]);
    expect(d.signature).toBe("void __fastcall sub_0(void *a1, unsigned __int64 a2)");
    expect(d.lines.map((l) => l.text)).toContain("((_DWORD *)a1)[a2] = 0;");
  });

  it("setcc, cmov, division and a tail call through the import table", () => {
    expect(body([
      [0x00, "xor eax, eax"],
      [0x02, "cmp ecx, edx"],
      [0x04, "setl al"],
      [0x07, "mov r8d, ecx"],
      [0x0a, "cmovg r8d, edx"],
      [0x0e, "add eax, r8d"],
      [0x11, "cdq"],
      [0x12, "idiv ecx"],
      [0x14, "mov ecx, eax"],
      [0x16, "jmp qword ptr [rip+0x1000]"],
    ], { nameOf: (a) => (a === "0x1018" ? "ExitProcess" : "") })).toEqual(["return ExitProcess(((a1 < a2) + (a1 > a2 ? a2 : a1)) / a1); // tail call"]);
  });
});

describe("structuring", () => {
  it("if/else", () => {
    expect(body([
      [0x10, "cmp ecx, 0x5"],
      [0x12, "jle 0x18"],
      [0x14, "mov eax, 0x1"],
      [0x16, "jmp 0x1a"],
      [0x18, "mov eax, 0x2"],
      [0x1a, "ret"],
    ])).toEqual(["if (a1 <= 5) {", "  v1 = 2;", "} else {", "  v1 = 1;", "}", "return v1;"]);
  });

  it("early returns lose their else", () => {
    expect(body([
      [0x10, "test rcx, rcx"],
      [0x12, "jne 0x16"],
      [0x14, "ret"],
      [0x16, "mov dword ptr [rcx], 0x1"],
      [0x1c, "ret"],
    ])).toEqual(["if (a1 == 0) {", "  return;", "}", "a1->field_0 = 1;"]);
  });

  it("&& with a load in the second test; small return blocks are duplicated instead of goto", () => {
    expect(body([
      [0x00, "test ecx, ecx"],
      [0x02, "je 0x10"],
      [0x04, "cmp dword ptr [rdx], 0x0"],
      [0x07, "je 0x10"],
      [0x09, "mov eax, ecx"],
      [0x0b, "ret"],
      [0x10, "xor eax, eax"],
      [0x12, "ret"],
    ])).toEqual(["if (a1 == 0 || a2->field_0 == 0) {", "  return 0;", "}", "return a1;"]);
    const out = body([
      [0x00, "test ecx, ecx"],
      [0x02, "je 0x20"],
      [0x04, "mov eax, dword ptr [rdx]"],
      [0x06, "test eax, eax"],
      [0x08, "je 0x20"],
      [0x0a, "add eax, ecx"],
      [0x0c, "jmp 0x22"],
      [0x20, "xor eax, eax"],
      [0x22, "ret"],
    ]);
    expect(out[0]).toBe("if (a1 != 0) {");
    expect(out[out.length - 1]).toBe("return v2;");
  });

  it("short-circuit && and ||", () => {
    expect(body([
      [0x00, "test ecx, ecx"],
      [0x02, "jle 0x0c"],
      [0x04, "test edx, edx"],
      [0x06, "jle 0x0c"],
      [0x08, "mov eax, 0x1"],
      [0x0b, "ret"],
      [0x0c, "xor eax, eax"],
      [0x0e, "ret"],
    ])).toEqual(["if (a1 <= 0 || a2 <= 0) {", "  return 0;", "}", "return 1;"]);
    expect(body([
      [0x00, "sub rsp, 0x28"],
      [0x04, "cmp ecx, 0x1"],
      [0x07, "je 0x0e"],
      [0x09, "cmp ecx, 0x7"],
      [0x0c, "jne 0x13"],
      [0x0e, "call 0x1000"],
      [0x13, "add rsp, 0x28"],
      [0x17, "ret"],
    ])).toEqual(["if (a1 == 1 || a1 == 7) {", "  sub_1000();", "}"]);
  });

  it("else-if chains", () => {
    expect(body([
      [0x10, "cmp ecx, 0x1"],
      [0x12, "jne 0x18"],
      [0x14, "mov eax, 0xa"],
      [0x16, "jmp 0x26"],
      [0x18, "cmp ecx, 0x2"],
      [0x1a, "jne 0x20"],
      [0x1c, "mov eax, 0xb"],
      [0x1e, "jmp 0x26"],
      [0x20, "cmp ecx, 0x3"],
      [0x22, "jne 0x24"],
      [0x23, "jmp 0x24"],
      [0x24, "xor eax, eax"],
      [0x26, "ret"],
    ])).toEqual(["if (a1 == 1) {", "  v1 = 0xa;", "} else if (a1 == 2) {", "  v1 = 0xb;", "} else {", "  v1 = 0;", "}", "return v1;"]);
  });

  it("while becomes for when it has an initializer and a step", () => {
    expect(body([
      [0x10, "xor eax, eax"],
      [0x12, "cmp eax, ecx"],
      [0x14, "jge 0x1a"],
      [0x16, "inc eax"],
      [0x18, "jmp 0x12"],
      [0x1a, "ret"],
    ])).toEqual(["for (v1 = 0; v1 < a1; ++v1) {", "}", "return v1;"]);
  });

  it("a loop that tests first and breaks becomes while", () => {
    expect(body([
      [0x10, "mov eax, dword ptr [rcx]"],
      [0x12, "test eax, eax"],
      [0x14, "je 0x1c"],
      [0x16, "add rcx, 0x4"],
      [0x18, "inc edx"],
      [0x1a, "jmp 0x10"],
      [0x1c, "mov eax, edx"],
      [0x1e, "ret"],
    ])).toEqual(["while (a1->field_0 != 0) {", "  a1 += 4;", "  ++a2;", "}", "return a2;"]);
  });

  it("nested do-while loops", () => {
    expect(body([
      [0x00, "xor eax, eax"],
      [0x02, "xor r8d, r8d"],
      [0x05, "mov r9d, edx"],
      [0x08, "add eax, r8d"],
      [0x0b, "dec r9d"],
      [0x0e, "jne 0x8"],
      [0x10, "inc r8d"],
      [0x13, "cmp r8d, ecx"],
      [0x16, "jl 0x5"],
      [0x18, "ret"],
    ])).toEqual(["v1 = 0;", "v2 = 0;", "do {", "  v3 = a2;", "  do {", "    v1 += v2;", "    --v3;", "  } while (v3 != 0);", "  ++v2;", "} while (v2 < a1);", "return v1;"]);
  });

  it("switch from a jump table, bound check as default, shared case bodies, biased index", () => {
    expect(body([
      [0x00, "sub edi, 0x1"],
      [0x03, "cmp edi, 0x3"],
      [0x06, "ja 0x40"],
      [0x08, "lea rdx, [rip+0x100]"],
      [0x0f, "movsxd rax, dword ptr [rdx+rdi*4]"],
      [0x13, "add rax, rdx"],
      [0x16, "jmp rax"],
      [0x20, "mov eax, 0xa"],
      [0x25, "ret"],
      [0x28, "mov eax, 0x14"],
      [0x2d, "ret"],
      [0x30, "mov eax, 0x1e"],
      [0x35, "ret"],
      [0x40, "xor eax, eax"],
      [0x42, "ret"],
    ], { abi: "sysv", switches: new Map([[0x16n, [0x20n, 0x28n, 0x30n, 0x28n]]]) })).toEqual([
      "switch (a1) {",
      "  case 1:",
      "    return 0xa;",
      "  case 2:",
      "  case 4:",
      "    return 0x14;",
      "  case 3:",
      "    return 0x1e;",
      "  default:",
      "    return 0;",
      "}",
    ]);
  });

  it("switch cases that fall to a common join end in break", () => {
    const out = body([
      [0x00, "cmp ecx, 0x2"],
      [0x03, "ja 0x30"],
      [0x05, "mov eax, ecx"],
      [0x07, "jmp qword ptr [rax*8+0x1000]"],
      [0x10, "mov edx, 0x5"],
      [0x15, "jmp 0x30"],
      [0x20, "mov edx, 0x7"],
      [0x25, "jmp 0x30"],
      [0x30, "mov eax, edx"],
      [0x32, "ret"],
    ], { switches: new Map([[0x7n, [0x10n, 0x20n, 0x30n]]]) });
    expect(out[0]).toBe("switch (a1) {");
    // case 2 goes straight to the join: edx keeps the incoming a2 there
    expect(out).toEqual(["switch (a1) {", "  case 0:", "    a2 = 5;", "    break;", "  case 1:", "    a2 = 7;", "    break;", "}", "return a2;"]);
  });

  it("irreducible flow still falls back to goto", () => {
    const out = body([
      [0x10, "test ecx, ecx"],
      [0x12, "je 0x18"],
      [0x14, "inc eax"],
      [0x16, "jmp 0x1a"],
      [0x18, "dec eax"],
      [0x1a, "cmp eax, edx"],
      [0x1c, "jl 0x14"],
      [0x1e, "jg 0x18"],
      [0x20, "ret"],
    ]);
    expect(out.some((l) => l.includes("goto loc_"))).toBe(true);
    expect(out.some((l) => /^loc_[0-9a-f]+:$/.test(l.trim()))).toBe(true);
  });

  it("opaque predicates fold away and every line keeps its address", () => {
    const d = all([
      [0x0, "mov eax, 0x1"],
      [0x5, "test eax, eax"],
      [0x7, "je 0xe"],
      [0x9, "mov eax, 0x2a"],
      [0xe, "ret"],
    ]);
    expect(d.lines.map((l) => l.text)).toContain("return 0x2a;");
    expect(d.lines.find((l) => l.text === "return 0x2a;")?.addr).toBe("0xe");
  });

  it("instructions the lifter does not model stay as inline asm", () => {
    const out = body([[0x0, "cpuid"], [0x2, "mov eax, ebx"], [0x4, "ret"]]);
    expect(out[0]).toBe("__asm { cpuid }");
    expect(out[1]).toMatch(/^return v\d+;$/);
  });
});

describe("graph of the IR", () => {
  it("lists the live blocks and edges", () => {
    const { ir } = buildIr(buildStructure(listing([
      [0x10, "cmp ecx, 0x5"],
      [0x12, "jle 0x18"],
      [0x14, "mov eax, 0x1"],
      [0x16, "jmp 0x1a"],
      [0x18, "mov eax, 0x2"],
      [0x1a, "ret"],
    ])));
    const g = irGraph(ir);
    expect(g.blocks.map((b) => b.addr)).toEqual(["0x10", "0x14", "0x18", "0x1a"]);
    expect(g.edges.map((e) => `${e.from}>${e.to}:${e.kind}`)).toEqual(["0>2:taken", "0>1:fallthrough", "1>3:jump", "2>3:jump"]);
    expect(analyze(ir).defs.size).toBeGreaterThan(0);
  });
});
