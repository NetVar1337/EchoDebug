import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { elfBias, isElf, parseElf, relocTypeName, ElfError } from "./elf";

const kSample = ["/bin/ls", "/usr/bin/ls", process.execPath].find((p) => existsSync(p) && isElf(new Uint8Array(readFileSync(p).subarray(0, 4))));

describe("ELF parser", () => {
  it("rejects non-ELF input", () => {
    expect(() => parseElf(new Uint8Array([0x4d, 0x5a, 0, 0]))).toThrow(ElfError);
    expect(isElf(new Uint8Array([0x7f, 0x45, 0x4c, 0x46]))).toBe(true);
  });

  it.skipIf(!kSample)("parses a real system binary", () => {
    const info = parseElf(new Uint8Array(readFileSync(kSample!)));
    expect(info.header.class).toBe(64);
    expect(["EXEC", "DYN"]).toContain(info.header.typeName);
    const names = info.sections.map((s) => s.name);
    expect(names).toContain(".text");
    expect(names).toContain(".dynsym");
    expect(info.segments.some((s) => s.typeName === "LOAD" && s.flags.includes("X"))).toBe(true);
    expect(info.needed.some((n) => n.startsWith("libc.so"))).toBe(true);
    expect(info.interp).toMatch(/ld-linux|ld\.so/);
    expect(info.symbols.some((s) => s.dynamic && s.type === "FUNC")).toBe(true);
    expect(info.relocs.length).toBeGreaterThan(0);
    const text = info.sections.find((s) => s.name === ".text")!;
    expect(text.flags).toContain("X");
    expect(elfBias(info, 0x7f0000000000n) % 0x1000n).toBe(0n);
  });

  it("names x86-64 relocations", () => {
    expect(relocTypeName(62, 7)).toBe("JUMP_SLOT");
    expect(relocTypeName(62, 8)).toBe("RELATIVE");
    expect(relocTypeName(183, 1025)).toBe("1025");
  });
});
