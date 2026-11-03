// AArch64 at the bit level: direct branch targets, PC-relative address materialisation
// (adrp + add, adrp + ldr/str, adr, ldr literal), the reference scanner behind the xref views,
// and the operand wildcards the signature maker needs. Every instruction is one little-endian
// 32-bit word; addresses here are RVAs (or anything else, as long as the image base is 4 KiB
// aligned, which adrp pages require).

export type A64Branch = { kind: "call" | "jmp" | "jcc"; target: number };

const sext = (v: number, bits: number) => (v << (32 - bits)) >> (32 - bits);

/** b / bl / b.cond / cbz / cbnz / tbz / tbnz → kind and target; null for anything else. */
export function a64Branch(word: number, pc: number): A64Branch | null {
  const w = word >>> 0;
  if (((w & 0x7c000000) >>> 0) === 0x14000000) {
    // b (op 0) / bl (op 1): imm26
    return { kind: w & 0x80000000 ? "call" : "jmp", target: pc + sext(w & 0x3ffffff, 26) * 4 };
  }
  if (((w & 0xff000010) >>> 0) === 0x54000000) return { kind: "jcc", target: pc + sext((w >>> 5) & 0x7ffff, 19) * 4 }; // b.cond
  if (((w & 0x7e000000) >>> 0) === 0x34000000) return { kind: "jcc", target: pc + sext((w >>> 5) & 0x7ffff, 19) * 4 }; // cbz/cbnz
  if (((w & 0x7e000000) >>> 0) === 0x36000000) return { kind: "jcc", target: pc + sext((w >>> 5) & 0x3fff, 14) * 4 }; // tbz/tbnz
  return null;
}

/** br / blr / ret (and the pointer-authentication forms): "indirect-jmp" | "indirect-call" | "ret". */
export function a64Indirect(word: number): "indirect-jmp" | "indirect-call" | "ret" | null {
  const w = word >>> 0;
  if (((w & 0xfe000000) >>> 0) !== 0xd6000000) return null;
  const opc = (w >>> 21) & 0xf;
  if (opc === 0 || opc === 8) return "indirect-jmp"; // br, braa/brab
  if (opc === 1 || opc === 9) return "indirect-call"; // blr, blraa/blrab
  if (opc === 2 || opc === 4) return "ret"; // ret / retaa / retab, eret
  return null;
}

/** adrp → { rd, page }. */
export function a64Adrp(word: number, pc: number): { rd: number; page: number } | null {
  const w = word >>> 0;
  if (((w & 0x9f000000) >>> 0) !== 0x90000000) return null;
  const imm = sext((((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3), 21);
  return { rd: w & 0x1f, page: Math.floor(pc / 4096) * 4096 + imm * 4096 };
}

/** adr → { rd, target }. */
export function a64Adr(word: number, pc: number): { rd: number; target: number } | null {
  const w = word >>> 0;
  if (((w & 0x9f000000) >>> 0) !== 0x10000000) return null;
  return { rd: w & 0x1f, target: pc + sext((((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3), 21) };
}

/** add Xd, Xn, #imm{, lsl #12} → { rd, rn, imm }. */
export function a64AddImm(word: number): { rd: number; rn: number; imm: number } | null {
  const w = word >>> 0;
  if (((w & 0xff800000) >>> 0) !== 0x91000000) return null;
  const imm = ((w >>> 10) & 0xfff) * (w & 0x400000 ? 4096 : 1);
  return { rd: w & 0x1f, rn: (w >>> 5) & 0x1f, imm };
}

/** Load/store register, unsigned offset (GPR and SIMD&FP) → { rt, rn, offset, load }. */
export function a64LdstUimm(word: number): { rt: number; rn: number; offset: number; load: boolean } | null {
  const w = word >>> 0;
  if (((w & 0x3b000000) >>> 0) !== 0x39000000) return null;
  const size = w >>> 30;
  const simd = (w & 0x04000000) !== 0;
  const opc = (w >>> 22) & 3;
  const scale = simd && size === 0 && opc & 2 ? 4 : size;
  return { rt: w & 0x1f, rn: (w >>> 5) & 0x1f, offset: ((w >>> 10) & 0xfff) * 2 ** scale, load: opc !== 0 };
}

/** ldr (literal), GPR / SIMD&FP / ldrsw / prfm → target. */
export function a64LdrLiteral(word: number, pc: number): number | null {
  const w = word >>> 0;
  if (((w & 0x3b000000) >>> 0) !== 0x18000000) return null;
  return pc + sext((w >>> 5) & 0x7ffff, 19) * 4;
}

export type A64Ref = { fromRva: number; toRva: number; kind: "call" | "jmp" | "jcc" | "rip" };

/**
 * Every direct reference in the given ranges: branches (call/jmp/jcc) and PC-relative data
 * references ("rip", the same kind x86-64 uses): adr, ldr literal, and adrp followed by an add
 * or a load/store through the same register within the next 16 instructions (the pair is
 * reported at the adrp, once per target). A register is forgotten when another instruction
 * writes it, at an unconditional branch, and (x0-x18, x29, x30) at a call.
 */
export function a64Refs(img: Uint8Array, ranges: readonly { rva: number; size: number }[], limit = Infinity): A64Ref[] {
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const out: A64Ref[] = [];
  const seen = new Set<string>();
  const ref = (fromRva: number, toRva: number, kind: A64Ref["kind"]) => {
    const k = `${fromRva}>${toRva}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ fromRva, toRva, kind });
  };
  let left = 2 * img.length + 0x10000; // overlapping section ranges cannot multiply the scan
  for (const r of ranges) {
    // align up without 32-bit bit operations: `(rva + 3) & ~3` went negative for an RVA >= 2^31
    const start = Math.max(0, r.rva + ((4 - (r.rva % 4)) % 4));
    const end = Math.min(img.length, r.rva + r.size);
    if (end - start > left) continue;
    left -= Math.max(0, end - start);
    // adrp register → { page, at, age }
    const pending = new Map<number, { page: number; at: number; age: number }>();
    for (let i = start; i + 4 <= end && out.length < limit; i += 4) {
      const w = dv.getUint32(i, true);
      for (const [reg, p] of pending) if (++p.age > 16) pending.delete(reg);
      const br = a64Branch(w, i);
      if (br) {
        ref(i, br.target >>> 0, br.kind);
        if (br.kind === "jmp") pending.clear();
        // a call keeps the callee-saved registers (x19-x28) only
        if (br.kind === "call") for (const reg of [...pending.keys()]) if (reg < 19 || reg > 28) pending.delete(reg);
        continue;
      }
      const ind = a64Indirect(w);
      if (ind) {
        if (ind === "indirect-call") {
          for (const reg of [...pending.keys()]) if (reg < 19 || reg > 28) pending.delete(reg);
        } else {
          pending.clear();
        }
        continue;
      }
      const adrp = a64Adrp(w, i);
      if (adrp) {
        pending.set(adrp.rd, { page: adrp.page, at: i, age: 0 });
        continue;
      }
      const adr = a64Adr(w, i);
      if (adr) {
        ref(i, adr.target >>> 0, "rip");
        pending.delete(adr.rd);
        continue;
      }
      const lit = a64LdrLiteral(w, i);
      if (lit !== null) {
        ref(i, lit >>> 0, "rip");
        pending.delete(w & 0x1f);
        continue;
      }
      const add = a64AddImm(w);
      if (add) {
        const p = pending.get(add.rn);
        if (p) ref(p.at, (p.page + add.imm) >>> 0, "rip");
        pending.delete(add.rd);
        continue;
      }
      const ls = a64LdstUimm(w);
      if (ls) {
        const p = pending.get(ls.rn);
        if (p) ref(p.at, (p.page + ls.offset) >>> 0, "rip");
        if (ls.load) pending.delete(ls.rt);
        continue;
      }
      // anything else that writes Rd (bits 0-4) ends that register's pairing; stores and
      // compares (Rd = zr) do not write it
      const isStore = ((w & 0x0a000000) >>> 0) === 0x08000000 && (w & 0x00400000) === 0;
      if (!isStore) pending.delete(w & 0x1f);
    }
  }
  return out;
}

/**
 * Signature wildcards for one instruction word (bytes are little-endian, so byte 0 holds bits
 * 0-7): `true` marks a byte that depends on where the code or its data lands.
 * - b / bl (imm26): all four bytes
 * - adrp / adr (immhi:immlo + Rd): all four bytes
 * - b.cond / cbz / cbnz / ldr literal (imm19 at bits 5-23): bytes 0-2
 * - tbz / tbnz (imm14 at bits 5-18): bytes 0-2
 * - add / ldr / str immediate after an adrp (imm12 at bits 10-21): bytes 1-2, when `afterAdrp`
 */
export function a64Wildcards(word: number, afterAdrp = false): [boolean, boolean, boolean, boolean] {
  const w = word >>> 0;
  if (((w & 0x7c000000) >>> 0) === 0x14000000 || ((w & 0x1f000000) >>> 0) === 0x10000000) return [true, true, true, true];
  if (((w & 0xff000010) >>> 0) === 0x54000000 || ((w & 0x7e000000) >>> 0) === 0x34000000 || ((w & 0x7e000000) >>> 0) === 0x36000000 || ((w & 0x3b000000) >>> 0) === 0x18000000) {
    return [true, true, true, false];
  }
  if (afterAdrp && (a64AddImm(w) || a64LdstUimm(w))) return [false, true, true, false];
  return [false, false, false, false];
}
