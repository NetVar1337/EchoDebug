// Semantic checks of the optimizer and the unflattener: an interpreter runs the IR right after
// lifting and the IR after propagation / dead-code removal / clean-up (and unflattening) on the
// same random inputs; the return value, the calls made and the memory written must agree.
import { describe, expect, it } from "vitest";
import { buildStructure, type Insn } from "./structure";
import { liftFunction } from "./irlift";
import { analyzeSignature, baseLoc, optimize } from "./dataflow";
import { cleanup } from "./decompile";
import { unflatten } from "./unflatten";
import { c, mapKids, mask, simp, width, type Expr, type IrFunc, type Term } from "./ir";

const kStack = 0x7fff0000n;

type Outcome = { ret: bigint | null; calls: string[]; stores: string[] };

function mix(...xs: bigint[]): bigint {
  let h = 0xcbf29ce484222325n;
  for (const x of xs) h = BigInt.asUintN(64, (h ^ x) * 0x100000001b3n);
  return h;
}

/** Runs `f` from its entry. Unknown memory reads a deterministic function of the address. */
function run(f: IrFunc, seed: bigint, maxSteps = 5000): Outcome {
  const env = new Map<string, bigint | Expr>();
  const mem = new Map<bigint, number>();
  const calls: string[] = [];
  const stores: string[] = [];
  const entry = (l: string) => mix(seed, BigInt([...baseLoc(l)].reduce((a, ch) => a * 31 + ch.charCodeAt(0), 7)));
  const readMem = (a: bigint, w: number): bigint => {
    let v = 0n;
    for (let i = 0; i < w / 8; i++) {
      const at = a + BigInt(i);
      const byte = mem.get(at) ?? Number(mix(seed, at) & 0xffn);
      v |= BigInt(byte) << BigInt(8 * i);
    }
    return v;
  };
  const writeMem = (a: bigint, w: number, v: bigint) => {
    for (let i = 0; i < w / 8; i++) mem.set(a + BigInt(i), Number((v >> BigInt(8 * i)) & 0xffn));
    if (a < kStack - 0x10000n || a > kStack + 0x10000n) stores.push(`${a.toString(16)}:${w}=${(v & mask(w)).toString(16)}`);
  };
  const get = (l: string): bigint | Expr => (env.has(l) ? env.get(l)! : entry(l));
  const ev = (e: Expr): Expr => {
    switch (e.k) {
      case "c":
        return e;
      case "l": {
        const v = get(e.loc);
        if (typeof v !== "bigint") return v; // a flags value
        return c(v, e.w);
      }
      case "sa":
        return c(kStack + BigInt(e.off));
      case "raw":
        return c(mix(seed, BigInt(e.text.length)), e.w);
      case "ld": {
        const a = ev(e.a);
        return c(readMem((a as { v: bigint }).v, e.w), e.w);
      }
      case "call": {
        const args = e.args.map((x) => (ev(x) as { v: bigint }).v);
        const t = (ev(e.target) as { v: bigint }).v;
        calls.push(`${t.toString(16)}(${args.map((x) => x.toString(16)).join(",")})`);
        return c(mix(t, ...args), e.w);
      }
      case "b":
        if (e.op === "rol" || e.op === "ror") {
          const a = (ev(e.a) as { v: bigint }).v;
          const n = Number((ev(e.b) as { v: bigint }).v) % e.w;
          const w = BigInt(e.w);
          const r = e.op === "rol" ? ((a << BigInt(n)) | (a >> (w - BigInt(n)))) : ((a >> BigInt(n)) | (a << (w - BigInt(n))));
          return c(r, e.w);
        }
        break;
    }
    const r = simp(mapKids(e, ev));
    if (r.k !== "c" && r.k !== "flags") throw new Error(`not constant: ${JSON.stringify(r, (_, v) => (typeof v === "bigint" ? v.toString() : v))}`);
    return r;
  };
  const val = (e: Expr) => (ev(e) as { v: bigint }).v;
  let b = 0;
  for (let steps = 0; steps < maxSteps; steps++) {
    const blk = f.blocks[b];
    for (const s of blk.stmts) {
      switch (s.k) {
        case "set": {
          const v = ev(s.src);
          env.set(s.dst, v.k === "c" ? v.v & mask(s.w) : v);
          break;
        }
        case "st":
          writeMem(val(s.a), s.w, val(s.v));
          break;
        case "call": {
          const v = val(s.call);
          if (s.dst) env.set(s.dst, v & mask(s.call.w));
          break;
        }
        case "clob":
          for (const l of s.locs) env.set(l, mix(seed, 0xdeadn, BigInt(l.length)));
          break;
        case "asm":
          for (const l of s.defs) env.set(l, mix(seed, 0xa5a5n));
          break;
      }
    }
    const t: Term = blk.term;
    switch (t.k) {
      case "jump":
        b = t.to;
        break;
      case "cond":
        b = val(t.c) !== 0n ? t.t : t.f;
        break;
      case "switch": {
        const x = val(t.x);
        const hit = t.cases.find((cs) => cs.vals.includes(x));
        if (hit) b = hit.to;
        else if (t.def !== null) b = t.def;
        else return { ret: 0xbadn, calls, stores };
        break;
      }
      case "ret":
        return { ret: t.v ? val(t.v) & mask(width(t.v)) : null, calls, stores };
      case "tail":
        val(t.call);
        return { ret: null, calls, stores };
      default:
        return { ret: null, calls, stores };
    }
  }
  return { ret: null, calls: [...calls, "(step limit)"], stores };
}

const listing = (rows: [number, string][]): Insn[] =>
  rows.map(([a, text], i) => ({ address: "0x" + a.toString(16), length: (rows[i + 1]?.[0] ?? a + 2) - a, text }));

/** Lifted IR before and after the optimizer (and optionally the unflattener). */
function versions(rows: [number, string][], o: { abi?: "win64" | "sysv"; unflatten?: boolean; switches?: Map<bigint, bigint[]> } = {}) {
  const ir = liftFunction(buildStructure(listing(rows), { switches: o.switches }), { abi: o.abi ?? "win64" });
  analyzeSignature(ir);
  const before = structuredClone(ir);
  optimize(ir);
  if (o.unflatten) {
    const r = unflatten(ir);
    expect(r.flattened).toBe(true);
    optimize(ir);
  }
  cleanup(ir);
  optimize(ir);
  return { before, after: ir };
}

function agree(rows: [number, string][], o: Parameters<typeof versions>[1] = {}, runs = 40) {
  const { before, after } = versions(rows, o);
  for (let i = 0; i < runs; i++) {
    const seed = BigInt(i * 7919 + 13);
    const x = run(before, seed);
    const y = run(after, seed);
    const w = after.blocks.find((b) => b.term.k === "ret" && b.term.v)?.term;
    const rw = w && w.k === "ret" && w.v ? width(w.v) : 64;
    expect({ ...y, ret: y.ret === null ? null : y.ret & mask(rw) }).toEqual({ ...x, ret: x.ret === null ? null : x.ret & mask(rw) });
  }
}

describe("optimized IR computes what the lifted IR computes", () => {
  it("straight-line code, calls and stores", () => {
    agree([
      [0x0, "push rbx"],
      [0x1, "sub rsp, 0x20"],
      [0x5, "mov rbx, rcx"],
      [0x8, "mov dword ptr [rsp+0x18], edx"],
      [0xc, "mov ecx, dword ptr [rbx+0x10]"],
      [0xf, "call 0x401000"],
      [0x14, "mov edx, dword ptr [rsp+0x18]"],
      [0x18, "add eax, edx"],
      [0x1a, "mov dword ptr [rbx+0x18], eax"],
      [0x1d, "lea r8, [rax+rax*4]"],
      [0x21, "shl r8, 0x3"],
      [0x25, "mov qword ptr [rbx], r8"],
      [0x28, "add rsp, 0x20"],
      [0x2c, "pop rbx"],
      [0x2d, "ret"],
    ]);
    // a load must not move past a store to the same place
    agree([
      [0x0, "mov eax, dword ptr [rcx]"],
      [0x2, "mov dword ptr [rcx], 0x5"],
      [0x8, "add eax, 0x1"],
      [0xb, "ret"],
    ]);
  });

  it("branches, setcc, cmov and division", () => {
    agree([
      [0x00, "xor eax, eax"],
      [0x02, "cmp ecx, edx"],
      [0x04, "setl al"],
      [0x07, "mov r8d, ecx"],
      [0x0a, "cmovg r8d, edx"],
      [0x0e, "add eax, r8d"],
      [0x11, "test ecx, ecx"],
      [0x13, "je 0x1c"],
      [0x15, "cdq"],
      [0x16, "idiv ecx"],
      [0x18, "jmp 0x1e"],
      [0x1c, "neg eax"],
      [0x1e, "ret"],
    ]);
  });

  it("loops: counted, nested, with memory", () => {
    agree([
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
    ].map(([a, t]) => [a, t] as [number, string]).map(([a, t]) => [a, t.replace("mov r9d, edx", "mov r9d, 0x3")] as [number, string]).map(([a, t]) => [a, t.replace("cmp r8d, ecx", "cmp r8d, 0x4")] as [number, string]));
    agree([
      [0x00, "xor eax, eax"],
      [0x02, "mov edx, dword ptr [rcx]"],
      [0x04, "test edx, edx"],
      [0x06, "je 0x14"],
      [0x08, "add eax, edx"],
      [0x0a, "mov dword ptr [rcx], eax"],
      [0x0c, "add rcx, 0x4"],
      [0x10, "cmp eax, 0x100"],
      [0x12, "jb 0x2"],
      [0x14, "ret"],
    ]);
  });

  it("a loop with continue and break, and a switch inside a loop", () => {
    agree([
      [0x00, "xor eax, eax"],
      [0x02, "xor r8d, r8d"],
      [0x05, "cmp r8d, 0x6"],
      [0x09, "jge 0x30"],
      [0x0b, "mov r9d, dword ptr [rcx+r8*4]"],
      [0x0f, "test r9d, 0x3"],
      [0x16, "je 0x20"],
      [0x18, "cmp r9d, 0x10000000"],
      [0x1f, "jl 0x30"],
      [0x21, "add eax, r9d"],
      [0x24, "inc r8d"],
      [0x27, "jmp 0x5"],
      [0x30, "ret"],
    ].map(([a, t]) => [a, t] as [number, string]));
    agree([
      [0x00, "xor eax, eax"],
      [0x02, "movzx edx, byte ptr [rcx]"],
      [0x05, "and edx, 0x3"],
      [0x08, "inc rcx"],
      [0x0b, "cmp edx, 0x2"],
      [0x0e, "ja 0x2"],
      [0x10, "jmp qword ptr [rdx*8+0x1000]"],
      [0x20, "ret"],
      [0x30, "inc eax"],
      [0x32, "jmp 0x2"],
      [0x40, "dec eax"],
      [0x42, "jmp 0x2"],
    ], { switches: new Map([[0x10n, [0x20n, 0x30n, 0x40n]]]) });
  });

  it("-O0 frames with spills and a frame pointer (sysv)", () => {
    agree([
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
      [0x27, "cmpl $0x5,-0x4(%rbp)"],
      [0x2a, "jl 0x14"],
      [0x2c, "mov $0x0,%eax"],
      [0x31, "leave"],
      [0x32, "ret"],
    ], { abi: "sysv" });
  });

  it("short-circuit conditions and a switch with a bound check", () => {
    agree([
      [0x00, "test ecx, ecx"],
      [0x02, "je 0x10"],
      [0x04, "cmp dword ptr [rdx], 0x0"],
      [0x07, "je 0x10"],
      [0x09, "mov eax, ecx"],
      [0x0b, "ret"],
      [0x10, "xor eax, eax"],
      [0x12, "ret"],
    ]);
    agree([
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
    ], { abi: "sysv", switches: new Map([[0x16n, [0x20n, 0x28n, 0x30n, 0x28n]]]) });
  });

  it("an -O0 flattened function with branch-selected states", () => {
    agree([
      [0x00, "push rbp"],
      [0x01, "mov rbp, rsp"],
      [0x04, "mov dword ptr [rbp-0x4], ecx"],
      [0x07, "mov dword ptr [rbp-0x8], 0x3"],
      [0x0e, "mov dword ptr [rbp-0xc], 0xaaaa"],
      [0x15, "mov eax, dword ptr [rbp-0xc]"],
      [0x18, "mov dword ptr [rbp-0x10], eax"],
      [0x1b, "sub eax, 0xaaaa"],
      [0x20, "je 0x40"],
      [0x22, "jmp 0x24"],
      [0x24, "mov eax, dword ptr [rbp-0x10]"],
      [0x27, "sub eax, 0xbbbb"],
      [0x2c, "je 0x50"],
      [0x2e, "jmp 0x30"],
      [0x30, "mov eax, dword ptr [rbp-0x10]"],
      [0x33, "sub eax, 0xcccc"],
      [0x38, "je 0x70"],
      [0x3a, "jmp 0x80"],
      [0x40, "cmp dword ptr [rbp-0x4], 0x0"],
      [0x44, "jle 0x4c"],
      [0x46, "mov dword ptr [rbp-0xc], 0xbbbb"],
      [0x4a, "jmp 0x80"],
      [0x4c, "mov dword ptr [rbp-0xc], 0xcccc"],
      [0x4e, "jmp 0x80"],
      [0x50, "mov eax, dword ptr [rbp-0x8]"],
      [0x53, "imul eax, dword ptr [rbp-0x4]"],
      [0x56, "mov dword ptr [rbp-0x8], eax"],
      [0x59, "mov dword ptr [rbp-0xc], 0xcccc"],
      [0x60, "jmp 0x80"],
      [0x70, "mov eax, dword ptr [rbp-0x8]"],
      [0x73, "pop rbp"],
      [0x74, "ret"],
      [0x80, "jmp 0x15"],
    ], { unflatten: true });
  });

  it("an unflattened function behaves like the flattened one", () => {
    agree([
      [0x00, "sub rsp, 0x18"],
      [0x04, "xor eax, eax"],
      [0x06, "xor edx, edx"],
      [0x08, "mov dword ptr [rsp+0xc], 0x1111"],
      [0x10, "mov r8d, dword ptr [rsp+0xc]"],
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
      [0x60, "mov r9d, 0x5555"],
      [0x66, "mov r10d, 0x2222"],
      [0x6c, "cmp edx, 0x7"],
      [0x6f, "cmovl r9d, r10d"],
      [0x73, "mov dword ptr [rsp+0xc], r9d"],
      [0x78, "jmp 0xe0"],
      [0x80, "mov r9d, 0x4444"],
      [0x86, "mov r10d, 0x3333"],
      [0x8c, "test dl, 0x1"],
      [0x8f, "cmovne r9d, r10d"],
      [0x93, "mov dword ptr [rsp+0xc], r9d"],
      [0x98, "jmp 0xe0"],
      [0xa0, "add eax, edx"],
      [0xa2, "mov dword ptr [rsp+0xc], 0x6666"],
      [0xaa, "jmp 0xe0"],
      [0xb0, "sub eax, ecx"],
      [0xb3, "mov dword ptr [rsp+0xc], 0x6666"],
      [0xbb, "jmp 0xe0"],
      [0xc0, "inc edx"],
      [0xc2, "mov dword ptr [rsp+0xc], 0x1111"],
      [0xca, "jmp 0xe0"],
      [0xd0, "add rsp, 0x18"],
      [0xd4, "ret"],
      [0xe0, "jmp 0x10"],
    ], { unflatten: true });
  });
});
