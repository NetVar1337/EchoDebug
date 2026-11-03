import { describe, expect, it } from "vitest";
import { buildTestPe } from "./testpe";
import { parsePe } from "./pe";
import { decodeStub, diffCode, iatHooks, inlineHooks, rebase } from "./hooks";

describe("hook scanner", () => {
  it("decodes hook stubs", () => {
    expect(decodeStub(new Uint8Array([0xe9, 0x10, 0, 0, 0]), 0x1000n)).toEqual({ kind: "jmp rel32", target: 0x1015n });
    const abs = new Uint8Array([0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xff, 0xe0]);
    expect(decodeStub(abs, 0n)).toEqual({ kind: "mov rax, imm64; jmp rax", target: 0x1122334455667788n });
    expect(decodeStub(new Uint8Array([0x68, 0x00, 0x10, 0x40, 0x00, 0xc3]), 0n)?.target).toBe(0x401000n);
    expect(decodeStub(new Uint8Array([0x48, 0x89, 0x5c, 0x24, 0x08]), 0n)).toBeNull();
  });

  it("rebases with relocations, then finds patched code and inline / IAT hooks", () => {
    const text = new Uint8Array(0x100).fill(0x90);
    // an absolute pointer the loader fixes up (DIR64 at .text+0x20)
    new DataView(text.buffer).setBigUint64(0x20, 0x140001000n, true);
    const reloc = new Uint8Array(12);
    const rv = new DataView(reloc.buffer);
    rv.setUint32(0, 0x1000, true);
    rv.setUint32(4, 12, true);
    rv.setUint16(8, (10 << 12) | 0x20, true);
    const file = buildTestPe([{ name: ".text", rva: 0x1000, bytes: text }, { name: ".reloc", rva: 0x2000, bytes: reloc, chars: 0x42000040 }], { 5: { rva: 0x2000, size: 12 } });
    const pe = parsePe(file);
    const base = 0x7ff600000000n;
    const loaded = rebase(file, pe, base);
    expect(new DataView(loaded.buffer).getBigUint64(0x1020, true)).toBe(0x7ff600001000n);
    // a clean load differs from the raw file only where relocations apply: nothing reported
    expect(diffCode(loaded, rebase(file, pe, base), pe, base)).toEqual([]);
    // hook at .text+0x40: jmp rel32 out of the module
    const mem = loaded.slice();
    mem.set([0xe9, 0x00, 0x00, 0x00, 0x10], 0x1040);
    const d = diffCode(mem, loaded, pe, base);
    expect(d).toHaveLength(1);
    expect(d[0]).toMatchObject({ rva: 0x1040, size: 5, kind: "jmp rel32", section: ".text" });
    expect(d[0].target).toBe(base + 0x1045n + 0x10000000n);
    // the same stub at an export is an inline hook
    const fake = { ...pe, exports: [{ name: "Hooked", ordinal: 1, rva: 0x1040 }, { name: "Clean", ordinal: 2, rva: 0x1080 }] };
    const ih = inlineHooks(mem, fake, base, mem.length, [{ name: "evil.dll", base: base + 0x10001000n, size: 0x10000 }]);
    expect(ih).toEqual([{ name: "Hooked", rva: 0x1040, kind: "jmp rel32", target: base + 0x10001045n, targetModule: "evil.dll" }]);
    // IAT: one slot into kernel32 (fine), one into unbacked memory, one forwarded
    const iat = mem.slice();
    const dv = new DataView(iat.buffer);
    dv.setBigUint64(0x1100 - 0x100 + 0x00, 0x7ffa00001000n, true);
    dv.setBigUint64(0x1100 - 0x100 + 0x08, 0x12345678n, true);
    dv.setBigUint64(0x1100 - 0x100 + 0x10, 0x7ffb00001000n, true);
    const withImports = { ...pe, imports: [{ dll: "KERNEL32.dll", funcs: [{ name: "Sleep", iatRva: 0x1000 }, { name: "GetTickCount", iatRva: 0x1008 }, { name: "HeapAlloc", iatRva: 0x1010 }] }] };
    const mods = [{ name: "kernel32.dll", base: 0x7ffa00000000n, size: 0x100000 }, { name: "ntdll.dll", base: 0x7ffb00000000n, size: 0x100000 }];
    const h = iatHooks(iat, withImports, mods);
    expect(h.map((x) => [x.func, x.severity, x.module])).toEqual([["GetTickCount", "high", ""], ["HeapAlloc", "info", "ntdll.dll"]]);
  });
});
