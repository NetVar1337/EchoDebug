// A small x86-64 assembler for in-place patches. It covers what patches are made of:
//   nop, ret [imm16], int3, leave, jmp/call/jcc to an address (short or near), push/pop r64,
//   mov r,imm / mov r,r, add/sub/and/or/xor/cmp/test r,r and r,imm, inc/dec r,
//   db <hex bytes>.
// Instructions are separated by ';' or newlines. Branch targets are absolute addresses; the
// assembler encodes them relative to where each instruction lands.

export class AsmError extends Error {}

const kRegs64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
const kRegs32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"];
const kCond: Record<string, number> = {
  o: 0, no: 1, b: 2, c: 2, nae: 2, ae: 3, nb: 3, nc: 3, e: 4, z: 4, ne: 5, nz: 5, be: 6, na: 6, a: 7, nbe: 7,
  s: 8, ns: 9, p: 10, pe: 10, np: 11, po: 11, l: 12, nge: 12, ge: 13, nl: 13, le: 14, ng: 14, g: 15, nle: 15,
};
const kAlu: Record<string, { rr: number; ext: number }> = {
  add: { rr: 0x01, ext: 0 }, or: { rr: 0x09, ext: 1 }, and: { rr: 0x21, ext: 4 }, sub: { rr: 0x29, ext: 5 },
  xor: { rr: 0x31, ext: 6 }, cmp: { rr: 0x39, ext: 7 },
};

type Reg = { n: number; w: 64 | 32 };

function reg(s: string): Reg | null {
  const t = s.trim().toLowerCase();
  let i = kRegs64.indexOf(t);
  if (i >= 0) return { n: i, w: 64 };
  i = kRegs32.indexOf(t);
  return i >= 0 ? { n: i, w: 32 } : null;
}

function imm(s: string): bigint | null {
  const t = s.trim().toLowerCase();
  if (!/^-?(0x[0-9a-f]+|\d+)$/.test(t)) return null;
  return t.startsWith("-") ? -BigInt(t.slice(1)) : BigInt(t);
}

function le(v: bigint, bytes: number): number[] {
  const out: number[] = [];
  let x = BigInt.asUintN(bytes * 8, v);
  for (let i = 0; i < bytes; i++) {
    out.push(Number(x & 0xffn));
    x >>= 8n;
  }
  return out;
}

const fits = (v: bigint, bits: number) => v >= -(1n << BigInt(bits - 1)) && v < 1n << BigInt(bits - 1);

function rex(w: boolean, r: number, b: number): number[] {
  const v = 0x40 | (w ? 8 : 0) | (r >= 8 ? 4 : 0) | (b >= 8 ? 1 : 0);
  return v === 0x40 ? [] : [v];
}

/** Encodes one instruction located at `at`. */
export function assembleOne(text: string, at: bigint): number[] {
  const t = text.trim().toLowerCase().replace(/\s+/g, " ");
  if (!t) return [];
  const sp = t.indexOf(" ");
  const mn = sp < 0 ? t : t.slice(0, sp);
  const rest = sp < 0 ? "" : t.slice(sp + 1).trim();
  const ops = rest ? rest.split(",").map((x) => x.trim()) : [];

  switch (mn) {
    case "nop":
      if (!ops.length) return [0x90];
      break;
    case "ret":
    case "retn":
      if (!ops.length) return [0xc3];
      {
        const v = imm(ops[0]);
        if (v !== null && v >= 0n && v < 0x10000n) return [0xc2, ...le(v, 2)];
      }
      break;
    case "int3":
      return [0xcc];
    case "leave":
      return [0xc9];
    case "db":
    case ".byte": {
      const hex = rest.replace(/0x/g, "").replace(/[\s,]+/g, "");
      if (!hex || hex.length % 2 || /[^0-9a-f]/.test(hex)) throw new AsmError(`bad bytes: ${rest}`);
      return hex.match(/../g)!.map((h) => parseInt(h, 16));
    }
  }

  // branches
  const branch = (forceShort: boolean, forceNear: boolean, short: (rel: number) => number[], near: (rel: bigint) => number[], nearLen: number): number[] => {
    const target = imm(ops[0]?.replace(/^(short|near) /, "") ?? "");
    if (target === null) throw new AsmError(`${mn} needs an absolute target address`);
    const rel8 = target - (at + 2n);
    if (!forceNear && fits(rel8, 8)) return short(Number(rel8));
    if (forceShort) throw new AsmError(`target out of short range`);
    const rel32 = target - (at + BigInt(nearLen));
    if (!fits(rel32, 32)) throw new AsmError(`target out of rel32 range`);
    return near(rel32);
  };
  const isShort = rest.startsWith("short ");
  const isNear = rest.startsWith("near ");
  if (mn === "jmp" && ops.length === 1 && !reg(ops[0])) return branch(isShort, isNear, (r) => [0xeb, r & 0xff], (r) => [0xe9, ...le(r, 4)], 5);
  if (mn === "call" && ops.length === 1 && !reg(ops[0])) {
    const target = imm(ops[0]);
    if (target === null) throw new AsmError("call needs an absolute target address");
    const rel = target - (at + 5n);
    if (!fits(rel, 32)) throw new AsmError("target out of rel32 range");
    return [0xe8, ...le(rel, 4)];
  }
  if (mn.startsWith("j") && kCond[mn.slice(1)] !== undefined && ops.length === 1) {
    const cc = kCond[mn.slice(1)];
    return branch(isShort, isNear, (r) => [0x70 + cc, r & 0xff], (r) => [0x0f, 0x80 + cc, ...le(r, 4)], 6);
  }
  if ((mn === "jmp" || mn === "call") && ops.length === 1 && reg(ops[0])?.w === 64) {
    const r = reg(ops[0])!;
    return [...rex(false, 0, r.n), 0xff, 0xc0 | ((mn === "jmp" ? 4 : 2) << 3) | (r.n & 7)];
  }

  if ((mn === "push" || mn === "pop") && ops.length === 1) {
    const r = reg(ops[0]);
    if (!r || r.w !== 64) throw new AsmError(`${mn} takes a 64-bit register`);
    return [...rex(false, 0, r.n), (mn === "push" ? 0x50 : 0x58) + (r.n & 7)];
  }

  if ((mn === "inc" || mn === "dec") && ops.length === 1) {
    const r = reg(ops[0]);
    if (!r) throw new AsmError(`${mn} takes a register`);
    return [...rex(r.w === 64, 0, r.n), 0xff, 0xc0 | ((mn === "inc" ? 0 : 1) << 3) | (r.n & 7)];
  }

  if (mn === "mov" && ops.length === 2) {
    const d = reg(ops[0]);
    const s = reg(ops[1]);
    if (d && s) {
      if (d.w !== s.w) throw new AsmError("operand sizes differ");
      return [...rex(d.w === 64, s.n, d.n), 0x89, 0xc0 | ((s.n & 7) << 3) | (d.n & 7)];
    }
    const v = imm(ops[1]);
    if (d && v !== null) {
      if (d.w === 32) {
        if (v < -(1n << 31n) || v >= 1n << 32n) throw new AsmError("immediate does not fit 32 bits");
        return [...rex(false, 0, d.n), 0xb8 + (d.n & 7), ...le(v, 4)];
      }
      if (fits(v, 32)) return [...rex(true, 0, d.n), 0xc7, 0xc0 | (d.n & 7), ...le(v, 4)];
      return [...rex(true, 0, d.n), 0xb8 + (d.n & 7), ...le(v, 8)];
    }
  }

  if ((kAlu[mn] || mn === "test") && ops.length === 2) {
    const d = reg(ops[0]);
    const s = reg(ops[1]);
    if (d && s) {
      if (d.w !== s.w) throw new AsmError("operand sizes differ");
      const op = mn === "test" ? 0x85 : kAlu[mn].rr;
      return [...rex(d.w === 64, s.n, d.n), op, 0xc0 | ((s.n & 7) << 3) | (d.n & 7)];
    }
    const v = imm(ops[1]);
    if (d && v !== null) {
      if (!fits(v, 32) && !(d.w === 32 && v >= 0n && v < 1n << 32n)) throw new AsmError("immediate does not fit 32 bits");
      if (mn === "test") return [...rex(d.w === 64, 0, d.n), 0xf7, 0xc0 | (d.n & 7), ...le(v, 4)];
      const ext = kAlu[mn].ext;
      if (fits(v, 8)) return [...rex(d.w === 64, 0, d.n), 0x83, 0xc0 | (ext << 3) | (d.n & 7), ...le(v, 1)];
      return [...rex(d.w === 64, 0, d.n), 0x81, 0xc0 | (ext << 3) | (d.n & 7), ...le(v, 4)];
    }
  }

  throw new AsmError(`unsupported instruction: ${text.trim()}`);
}

/** Assembles a sequence at `at`; returns the bytes. */
export function assemble(text: string, at: bigint): Uint8Array {
  const out: number[] = [];
  for (const line of text.split(/[;\n]/)) {
    const b = assembleOne(line.replace(/\/\/.*$|#.*$/, ""), at + BigInt(out.length));
    out.push(...b);
  }
  if (!out.length) throw new AsmError("nothing to assemble");
  return new Uint8Array(out);
}

/** `len` bytes of NOPs using the recommended multi-byte forms (Intel SDM table 4-12). */
export function nops(len: number): Uint8Array {
  const forms = [
    [0x90], [0x66, 0x90], [0x0f, 0x1f, 0x00], [0x0f, 0x1f, 0x40, 0x00], [0x0f, 0x1f, 0x44, 0x00, 0x00],
    [0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00], [0x0f, 0x1f, 0x80, 0, 0, 0, 0], [0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0],
    [0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0],
  ];
  const out: number[] = [];
  while (out.length < len) out.push(...forms[Math.min(9, len - out.length) - 1]);
  return new Uint8Array(out);
}

/** Flips a conditional jump (je ↔ jne, …). Returns null for anything else. */
export function invertJcc(bytes: Uint8Array): Uint8Array | null {
  const b = Uint8Array.from(bytes);
  if (b.length >= 2 && b[0] >= 0x70 && b[0] <= 0x7f) {
    b[0] ^= 1;
    return b;
  }
  if (b.length >= 6 && b[0] === 0x0f && b[1] >= 0x80 && b[1] <= 0x8f) {
    b[1] ^= 1;
    return b;
  }
  return null;
}

/** Turns a conditional jump at `at` into an unconditional jump to the same target, same length. */
export function forceJmp(bytes: Uint8Array, at: bigint): Uint8Array | null {
  if (bytes.length >= 2 && bytes[0] >= 0x70 && bytes[0] <= 0x7f) return new Uint8Array([0xeb, bytes[1]]);
  if (bytes.length >= 6 && bytes[0] === 0x0f && bytes[1] >= 0x80 && bytes[1] <= 0x8f) {
    const rel = BigInt(new DataView(bytes.buffer, bytes.byteOffset + 2, 4).getInt32(0, true));
    const target = at + 6n + rel;
    const nrel = target - (at + 5n);
    return new Uint8Array([0xe9, ...le(nrel, 4), 0x90]);
  }
  return null;
}
