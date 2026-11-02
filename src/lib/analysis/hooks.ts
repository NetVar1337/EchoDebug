// Hook / tamper scanner. Three checks over one module:
//   1. code integrity: executable sections in memory vs the file on disk (rebased with the
//      file's relocations, so ASLR fixups are not reported), grouped into patched ranges;
//   2. inline hooks: exported functions whose first instruction transfers control out of the
//      module (jmp rel32, jmp [rip], mov rax,imm64 + jmp rax, push imm32 + ret, int3);
//   3. IAT hooks: import slots that point outside every loaded module (unbacked memory) or into
//      a module other than the one they import from (forwarded APIs are reported as info).
import type { PeInfo } from "./pe";
import { parseRelocs } from "./peextra";

export type ModuleRange = { name: string; base: bigint; size: number };
export type Patch = { rva: number; size: number; file: string; memory: string; section: string; symbol: string; kind: string; target?: bigint };
export type InlineHook = { name: string; rva: number; kind: string; target: bigint; targetModule: string };
export type IatHook = { dll: string; func: string; iatRva: number; pointer: bigint; module: string; severity: "high" | "info" };

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const i32 = (b: Uint8Array, o: number) => new DataView(b.buffer, b.byteOffset + o, 4).getInt32(0, true);

export function moduleAt(a: bigint, mods: readonly ModuleRange[]): ModuleRange | undefined {
  return mods.find((m) => a >= m.base && a < m.base + BigInt(m.size));
}

/** Applies DIR64 / HIGHLOW fixups to a mapped file image so it matches a load at `base`. */
export function rebase(fileImg: Uint8Array, pe: PeInfo, base: bigint): Uint8Array {
  const out = fileImg.slice();
  const delta = base - pe.imageBase;
  if (delta === 0n) return out;
  const dv = new DataView(out.buffer);
  for (const b of parseRelocs(out, pe).blocks) {
    for (const e of b.entries) {
      const o = b.page + e.offset;
      if (e.type === 10 && o + 8 <= out.length) dv.setBigUint64(o, BigInt.asUintN(64, dv.getBigUint64(o, true) + delta), true);
      else if (e.type === 3 && o + 4 <= out.length) dv.setUint32(o, Number(BigInt.asUintN(32, BigInt(dv.getUint32(o, true)) + delta)), true);
    }
  }
  return out;
}

/** Control transfer at the start of `code` (at address `ip`), if it is a hook-style stub. */
export function decodeStub(code: Uint8Array, ip: bigint, read64?: (a: bigint) => bigint | null): { kind: string; target: bigint } | null {
  if (code.length >= 5 && code[0] === 0xe9) return { kind: "jmp rel32", target: ip + 5n + BigInt(i32(code, 1)) };
  if (code.length >= 2 && code[0] === 0xeb) return { kind: "jmp rel8", target: ip + 2n + BigInt((code[1] << 24) >> 24) };
  if (code.length >= 6 && code[0] === 0xff && code[1] === 0x25) {
    const slot = ip + 6n + BigInt(i32(code, 2));
    const t = read64?.(slot);
    return t === null || t === undefined ? { kind: "jmp [rip]", target: slot } : { kind: "jmp [rip]", target: t };
  }
  if (code.length >= 12 && code[0] === 0x48 && code[1] === 0xb8 && code[10] === 0xff && code[11] === 0xe0) {
    return { kind: "mov rax, imm64; jmp rax", target: new DataView(code.buffer, code.byteOffset + 2, 8).getBigUint64(0, true) };
  }
  if (code.length >= 13 && code[0] === 0x49 && code[1] === 0xbb && code[10] === 0x41 && code[11] === 0xff && code[12] === 0xe3) {
    return { kind: "mov r11, imm64; jmp r11", target: new DataView(code.buffer, code.byteOffset + 2, 8).getBigUint64(0, true) };
  }
  if (code.length >= 6 && code[0] === 0x68 && code[5] === 0xc3) return { kind: "push imm32; ret", target: BigInt(i32(code, 1) >>> 0) };
  if (code.length >= 1 && code[0] === 0xcc) return { kind: "int3", target: ip };
  return null;
}

/** Nearest export at or below `rva`, as "name+0x12". */
function symbolAt(pe: PeInfo, rva: number): string {
  let best: { name: string; rva: number } | null = null;
  for (const e of pe.exports) if (!e.forwarder && e.rva <= rva && (!best || e.rva > best.rva)) best = e;
  if (!best) return "";
  return rva === best.rva ? best.name : `${best.name}+0x${(rva - best.rva).toString(16)}`;
}

/** Differences between memory and the rebased file in executable sections, merged when ≤ 8 bytes apart. */
export function diffCode(mem: Uint8Array, file: Uint8Array, pe: PeInfo, base: bigint, maxPatches = 2000): Patch[] {
  const out: Patch[] = [];
  for (const s of pe.sections.filter((x) => x.x)) {
    const end = Math.min(s.rva + Math.max(s.vsize, s.rawSize), mem.length, file.length);
    let i = s.rva;
    while (i < end && out.length < maxPatches) {
      if (mem[i] === file[i]) { i++; continue; }
      let j = i + 1;
      let gap = 0;
      while (j < end && gap <= 8) {
        if (mem[j] !== file[j]) gap = 0;
        else gap++;
        j++;
      }
      const stop = j - gap;
      const m = mem.subarray(i, stop);
      const stub = decodeStub(m, base + BigInt(i));
      out.push({ rva: i, size: stop - i, file: hex(file.subarray(i, Math.min(stop, i + 64))), memory: hex(m.subarray(0, 64)), section: s.name, symbol: symbolAt(pe, i), kind: stub ? stub.kind : "patched bytes", target: stub?.target });
      i = stop;
    }
  }
  return out;
}

/** Exports whose first bytes jump out of the module. */
export function inlineHooks(mem: Uint8Array, pe: PeInfo, base: bigint, size: number, mods: readonly ModuleRange[]): InlineHook[] {
  const out: InlineHook[] = [];
  const dv = new DataView(mem.buffer, mem.byteOffset, mem.byteLength);
  const read64 = (a: bigint) => {
    const o = Number(a - base);
    return o >= 0 && o + 8 <= mem.length ? dv.getBigUint64(o, true) : null;
  };
  const exec = pe.sections.filter((s) => s.x);
  for (const e of pe.exports) {
    if (e.forwarder || !exec.some((s) => e.rva >= s.rva && e.rva < s.rva + Math.max(s.vsize, s.rawSize))) continue;
    const stub = decodeStub(mem.subarray(e.rva, e.rva + 16), base + BigInt(e.rva), read64);
    if (!stub) continue;
    const inside = stub.target >= base && stub.target < base + BigInt(size);
    if (inside && stub.kind !== "int3") continue; // a thunk within the module is normal
    out.push({ name: e.name || `#${e.ordinal}`, rva: e.rva, kind: stub.kind, target: stub.target, targetModule: moduleAt(stub.target, mods)?.name ?? "" });
  }
  return out;
}

const apiSet = (dll: string) => /^(api|ext)-ms-/i.test(dll);
const stem = (n: string) => n.toLowerCase().replace(/\.(dll|exe|sys)$/, "");

/** IAT slots that point outside every module (high) or into an unexpected module (info). */
export function iatHooks(mem: Uint8Array, pe: PeInfo, mods: readonly ModuleRange[]): IatHook[] {
  const out: IatHook[] = [];
  const dv = new DataView(mem.buffer, mem.byteOffset, mem.byteLength);
  for (const d of pe.imports) {
    for (const f of d.funcs) {
      if (f.iatRva + 8 > mem.length) continue;
      const p = pe.is64 ? dv.getBigUint64(f.iatRva, true) : BigInt(dv.getUint32(f.iatRva, true));
      if (p === 0n) continue;
      const m = moduleAt(p, mods);
      const func = f.name ?? `#${f.ordinal}`;
      if (!m) out.push({ dll: d.dll, func, iatRva: f.iatRva, pointer: p, module: "", severity: "high" });
      else if (!apiSet(d.dll) && stem(m.name) !== stem(d.dll)) out.push({ dll: d.dll, func, iatRva: f.iatRva, pointer: p, module: m.name, severity: "info" });
    }
  }
  return out;
}
