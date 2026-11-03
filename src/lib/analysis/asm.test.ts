import { describe, expect, it } from "vitest";
import { assemble, AsmError, forceJmp, invertJcc, nops } from "./asm";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(" ");

// expected bytes from GNU as (objdump -M intel)
const kGas: [string, string][] = [
  ["mov rax, 1", "48 c7 c0 01 00 00 00"],
  ["mov eax, 0xffffffff", "b8 ff ff ff ff"],
  ["mov r9, 0x123456789", "49 b9 89 67 45 23 01 00 00 00"],
  ["mov rcx, -1", "48 c7 c1 ff ff ff ff"],
  ["xor eax, eax", "31 c0"],
  ["xor r10, r11", "4d 31 da"],
  ["add rsp, 0x28", "48 83 c4 28"],
  ["sub rsp, 0x1000", "48 81 ec 00 10 00 00"],
  ["cmp ecx, 5", "83 f9 05"],
  ["test rax, rax", "48 85 c0"],
  ["push r12", "41 54"],
  ["pop rbx", "5b"],
  ["inc r15", "49 ff c7"],
  ["dec ecx", "ff c9"],
  ["mov rdx, r8", "4c 89 c2"],
  ["ret 8", "c2 08 00"],
  ["jmp rax", "ff e0"],
  ["call r11", "41 ff d3"],
  ["and r13d, 0x7f", "41 83 e5 7f"],
];

describe("assembler", () => {
  it.each(kGas)("%s matches GNU as", (src, want) => {
    expect(hex(assemble(src, 0x1000n))).toBe(want);
  });

  it("encodes branches relative to their own address", () => {
    expect(hex(assemble("jmp 0x1010", 0x1000n))).toBe("eb 0e");
    expect(hex(assemble("jmp 0x2000", 0x1000n))).toBe("e9 fb 0f 00 00");
    expect(hex(assemble("jmp near 0x1010", 0x1000n))).toBe("e9 0b 00 00 00");
    expect(hex(assemble("call 0x1000", 0x1000n))).toBe("e8 fb ff ff ff");
    expect(hex(assemble("jne 0x1000", 0x1000n))).toBe("75 fe");
    expect(hex(assemble("je 0x5000", 0x1000n))).toBe("0f 84 fa 3f 00 00");
    expect(() => assemble("jmp short 0x9000", 0x1000n)).toThrow(AsmError);
  });

  it("assembles sequences and raw bytes", () => {
    expect(hex(assemble("xor eax, eax; inc eax\nret", 0x1000n))).toBe("31 c0 ff c0 c3");
    expect(hex(assemble("db 90 cc", 0n))).toBe("90 cc");
    expect(() => assemble("vfmadd231ps ymm0, ymm1, ymm2", 0n)).toThrow(/unsupported/);
  });

  it("builds NOP runs, inverts and forces conditional jumps", () => {
    expect(nops(1)).toEqual(new Uint8Array([0x90]));
    expect(nops(12).length).toBe(12);
    expect(hex(invertJcc(new Uint8Array([0x74, 0x10]))!)).toBe("75 10");
    expect(hex(invertJcc(new Uint8Array([0x0f, 0x85, 1, 0, 0, 0]))!)).toBe("0f 84 01 00 00 00");
    expect(invertJcc(new Uint8Array([0x90]))).toBeNull();
    expect(hex(forceJmp(new Uint8Array([0x74, 0x10]), 0n)!)).toBe("eb 10");
    // je +0x10 at 0x1000 (target 0x1016) -> jmp rel32 to the same target + nop
    expect(hex(forceJmp(new Uint8Array([0x0f, 0x84, 0x10, 0, 0, 0]), 0x1000n)!)).toBe("e9 11 00 00 00 90");
  });
});
