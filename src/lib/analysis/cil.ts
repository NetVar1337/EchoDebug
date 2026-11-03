// CIL (ECMA-335 III) method-body disassembler: tiny and fat headers, every opcode, exception
// clauses, tokens resolved through the metadata.

type Operand = "none" | "i8" | "u8" | "u16" | "i32" | "i64" | "r4" | "r8" | "tok" | "br8" | "br32" | "switch";

const one: Record<number, [string, Operand]> = {
  0x00: ["nop", "none"], 0x01: ["break", "none"], 0x02: ["ldarg.0", "none"], 0x03: ["ldarg.1", "none"],
  0x04: ["ldarg.2", "none"], 0x05: ["ldarg.3", "none"], 0x06: ["ldloc.0", "none"], 0x07: ["ldloc.1", "none"],
  0x08: ["ldloc.2", "none"], 0x09: ["ldloc.3", "none"], 0x0a: ["stloc.0", "none"], 0x0b: ["stloc.1", "none"],
  0x0c: ["stloc.2", "none"], 0x0d: ["stloc.3", "none"], 0x0e: ["ldarg.s", "u8"], 0x0f: ["ldarga.s", "u8"],
  0x10: ["starg.s", "u8"], 0x11: ["ldloc.s", "u8"], 0x12: ["ldloca.s", "u8"], 0x13: ["stloc.s", "u8"],
  0x14: ["ldnull", "none"], 0x15: ["ldc.i4.m1", "none"], 0x16: ["ldc.i4.0", "none"], 0x17: ["ldc.i4.1", "none"],
  0x18: ["ldc.i4.2", "none"], 0x19: ["ldc.i4.3", "none"], 0x1a: ["ldc.i4.4", "none"], 0x1b: ["ldc.i4.5", "none"],
  0x1c: ["ldc.i4.6", "none"], 0x1d: ["ldc.i4.7", "none"], 0x1e: ["ldc.i4.8", "none"], 0x1f: ["ldc.i4.s", "i8"],
  0x20: ["ldc.i4", "i32"], 0x21: ["ldc.i8", "i64"], 0x22: ["ldc.r4", "r4"], 0x23: ["ldc.r8", "r8"],
  0x25: ["dup", "none"], 0x26: ["pop", "none"], 0x27: ["jmp", "tok"], 0x28: ["call", "tok"],
  0x29: ["calli", "tok"], 0x2a: ["ret", "none"], 0x2b: ["br.s", "br8"], 0x2c: ["brfalse.s", "br8"],
  0x2d: ["brtrue.s", "br8"], 0x2e: ["beq.s", "br8"], 0x2f: ["bge.s", "br8"], 0x30: ["bgt.s", "br8"],
  0x31: ["ble.s", "br8"], 0x32: ["blt.s", "br8"], 0x33: ["bne.un.s", "br8"], 0x34: ["bge.un.s", "br8"],
  0x35: ["bgt.un.s", "br8"], 0x36: ["ble.un.s", "br8"], 0x37: ["blt.un.s", "br8"], 0x38: ["br", "br32"],
  0x39: ["brfalse", "br32"], 0x3a: ["brtrue", "br32"], 0x3b: ["beq", "br32"], 0x3c: ["bge", "br32"],
  0x3d: ["bgt", "br32"], 0x3e: ["ble", "br32"], 0x3f: ["blt", "br32"], 0x40: ["bne.un", "br32"],
  0x41: ["bge.un", "br32"], 0x42: ["bgt.un", "br32"], 0x43: ["ble.un", "br32"], 0x44: ["blt.un", "br32"],
  0x45: ["switch", "switch"], 0x46: ["ldind.i1", "none"], 0x47: ["ldind.u1", "none"], 0x48: ["ldind.i2", "none"],
  0x49: ["ldind.u2", "none"], 0x4a: ["ldind.i4", "none"], 0x4b: ["ldind.u4", "none"], 0x4c: ["ldind.i8", "none"],
  0x4d: ["ldind.i", "none"], 0x4e: ["ldind.r4", "none"], 0x4f: ["ldind.r8", "none"], 0x50: ["ldind.ref", "none"],
  0x51: ["stind.ref", "none"], 0x52: ["stind.i1", "none"], 0x53: ["stind.i2", "none"], 0x54: ["stind.i4", "none"],
  0x55: ["stind.i8", "none"], 0x56: ["stind.r4", "none"], 0x57: ["stind.r8", "none"], 0x58: ["add", "none"],
  0x59: ["sub", "none"], 0x5a: ["mul", "none"], 0x5b: ["div", "none"], 0x5c: ["div.un", "none"],
  0x5d: ["rem", "none"], 0x5e: ["rem.un", "none"], 0x5f: ["and", "none"], 0x60: ["or", "none"],
  0x61: ["xor", "none"], 0x62: ["shl", "none"], 0x63: ["shr", "none"], 0x64: ["shr.un", "none"],
  0x65: ["neg", "none"], 0x66: ["not", "none"], 0x67: ["conv.i1", "none"], 0x68: ["conv.i2", "none"],
  0x69: ["conv.i4", "none"], 0x6a: ["conv.i8", "none"], 0x6b: ["conv.r4", "none"], 0x6c: ["conv.r8", "none"],
  0x6d: ["conv.u4", "none"], 0x6e: ["conv.u8", "none"], 0x6f: ["callvirt", "tok"], 0x70: ["cpobj", "tok"],
  0x71: ["ldobj", "tok"], 0x72: ["ldstr", "tok"], 0x73: ["newobj", "tok"], 0x74: ["castclass", "tok"],
  0x75: ["isinst", "tok"], 0x76: ["conv.r.un", "none"], 0x79: ["unbox", "tok"], 0x7a: ["throw", "none"],
  0x7b: ["ldfld", "tok"], 0x7c: ["ldflda", "tok"], 0x7d: ["stfld", "tok"], 0x7e: ["ldsfld", "tok"],
  0x7f: ["ldsflda", "tok"], 0x80: ["stsfld", "tok"], 0x81: ["stobj", "tok"], 0x82: ["conv.ovf.i1.un", "none"],
  0x83: ["conv.ovf.i2.un", "none"], 0x84: ["conv.ovf.i4.un", "none"], 0x85: ["conv.ovf.i8.un", "none"],
  0x86: ["conv.ovf.u1.un", "none"], 0x87: ["conv.ovf.u2.un", "none"], 0x88: ["conv.ovf.u4.un", "none"],
  0x89: ["conv.ovf.u8.un", "none"], 0x8a: ["conv.ovf.i.un", "none"], 0x8b: ["conv.ovf.u.un", "none"],
  0x8c: ["box", "tok"], 0x8d: ["newarr", "tok"], 0x8e: ["ldlen", "none"], 0x8f: ["ldelema", "tok"],
  0x90: ["ldelem.i1", "none"], 0x91: ["ldelem.u1", "none"], 0x92: ["ldelem.i2", "none"], 0x93: ["ldelem.u2", "none"],
  0x94: ["ldelem.i4", "none"], 0x95: ["ldelem.u4", "none"], 0x96: ["ldelem.i8", "none"], 0x97: ["ldelem.i", "none"],
  0x98: ["ldelem.r4", "none"], 0x99: ["ldelem.r8", "none"], 0x9a: ["ldelem.ref", "none"], 0x9b: ["stelem.i", "none"],
  0x9c: ["stelem.i1", "none"], 0x9d: ["stelem.i2", "none"], 0x9e: ["stelem.i4", "none"], 0x9f: ["stelem.i8", "none"],
  0xa0: ["stelem.r4", "none"], 0xa1: ["stelem.r8", "none"], 0xa2: ["stelem.ref", "none"], 0xa3: ["ldelem", "tok"],
  0xa4: ["stelem", "tok"], 0xa5: ["unbox.any", "tok"], 0xb3: ["conv.ovf.i1", "none"], 0xb4: ["conv.ovf.u1", "none"],
  0xb5: ["conv.ovf.i2", "none"], 0xb6: ["conv.ovf.u2", "none"], 0xb7: ["conv.ovf.i4", "none"], 0xb8: ["conv.ovf.u4", "none"],
  0xb9: ["conv.ovf.i8", "none"], 0xba: ["conv.ovf.u8", "none"], 0xc2: ["refanyval", "tok"], 0xc3: ["ckfinite", "none"],
  0xc6: ["mkrefany", "tok"], 0xd0: ["ldtoken", "tok"], 0xd1: ["conv.u2", "none"], 0xd2: ["conv.u1", "none"],
  0xd3: ["conv.i", "none"], 0xd4: ["conv.ovf.i", "none"], 0xd5: ["conv.ovf.u", "none"], 0xd6: ["add.ovf", "none"],
  0xd7: ["add.ovf.un", "none"], 0xd8: ["mul.ovf", "none"], 0xd9: ["mul.ovf.un", "none"], 0xda: ["sub.ovf", "none"],
  0xdb: ["sub.ovf.un", "none"], 0xdc: ["endfinally", "none"], 0xdd: ["leave", "br32"], 0xde: ["leave.s", "br8"],
  0xdf: ["stind.i", "none"], 0xe0: ["conv.u", "none"],
};

const two: Record<number, [string, Operand]> = {
  0x00: ["arglist", "none"], 0x01: ["ceq", "none"], 0x02: ["cgt", "none"], 0x03: ["cgt.un", "none"],
  0x04: ["clt", "none"], 0x05: ["clt.un", "none"], 0x06: ["ldftn", "tok"], 0x07: ["ldvirtftn", "tok"],
  0x09: ["ldarg", "u16"], 0x0a: ["ldarga", "u16"], 0x0b: ["starg", "u16"], 0x0c: ["ldloc", "u16"],
  0x0d: ["ldloca", "u16"], 0x0e: ["stloc", "u16"], 0x0f: ["localloc", "none"], 0x11: ["endfilter", "none"],
  0x12: ["unaligned.", "u8"], 0x13: ["volatile.", "none"], 0x14: ["tail.", "none"], 0x15: ["initobj", "tok"],
  0x16: ["constrained.", "tok"], 0x17: ["cpblk", "none"], 0x18: ["initblk", "none"], 0x19: ["no.", "u8"],
  0x1a: ["rethrow", "none"], 0x1c: ["sizeof", "tok"], 0x1d: ["refanytype", "none"], 0x1e: ["readonly.", "none"],
};

export type IlInsn = { offset: number; size: number; bytes: string; opcode: string; operand: string; token?: number; targets?: number[] };
export type IlClause = { kind: "catch" | "filter" | "finally" | "fault"; tryStart: number; tryEnd: number; handlerStart: number; handlerEnd: number; catchType?: string };
export type IlBody = { headerSize: number; codeSize: number; maxStack: number; localsToken: number; initLocals: boolean; code: IlInsn[]; clauses: IlClause[] };

export class IlError extends Error {}

/**
 * Decodes the method body at `rva` of a mapped image. `name(token)` renders metadata tokens
 * (types, methods, fields, user strings).
 */
export function disassembleIl(img: Uint8Array, rva: number, name: (token: number) => string = (t) => `0x${t.toString(16).padStart(8, "0")}`): IlBody {
  if (rva <= 0 || rva >= img.length) throw new IlError("method has no body (abstract, extern or runtime-implemented)");
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const h = img[rva];
  let headerSize: number, codeSize: number, maxStack = 8, localsToken = 0, flags = 0;
  if ((h & 3) === 2) {
    headerSize = 1;
    codeSize = h >> 2;
  } else if ((h & 3) === 3) {
    if (rva + 12 > img.length) throw new IlError("fat method header runs past the image");
    flags = dv.getUint16(rva, true);
    headerSize = (flags >> 12) * 4;
    maxStack = dv.getUint16(rva + 2, true);
    codeSize = dv.getUint32(rva + 4, true);
    localsToken = dv.getUint32(rva + 8, true);
  } else throw new IlError(`bad method header byte 0x${h.toString(16)}`);
  const start = rva + headerSize;
  if (start + codeSize > img.length) throw new IlError("method body runs past the image");

  const code: IlInsn[] = [];
  let p = 0;
  const hex = (a: number, b: number) => Array.from(img.subarray(start + a, start + b), (x) => x.toString(16).padStart(2, "0")).join("");
  const kOperandSize: Record<Operand, number> = { none: 0, i8: 1, u8: 1, u16: 2, i32: 4, i64: 8, r4: 4, r8: 8, tok: 4, br8: 1, br32: 4, switch: 4 };
  while (p < codeSize) {
    const at = p;
    let op = img[start + p++];
    let entry: [string, Operand] | undefined;
    if (op === 0xfe && p < codeSize) {
      op = img[start + p++];
      entry = two[op];
    } else entry = op === 0xfe ? undefined : one[op];
    if (!entry) {
      code.push({ offset: at, size: p - at, bytes: hex(at, p), opcode: `.byte 0x${op.toString(16)}`, operand: "" });
      continue;
    }
    const [mn, kind] = entry;
    // an operand cut off by the end of the body (or a switch table longer than it) ends the listing
    const need = kOperandSize[kind] + (kind === "switch" && p + 4 <= codeSize ? dv.getUint32(start + p, true) * 4 : 0);
    if (p + need > codeSize) {
      code.push({ offset: at, size: codeSize - at, bytes: hex(at, codeSize), opcode: mn, operand: "<truncated>" });
      break;
    }
    let operand = "";
    let token: number | undefined;
    let targets: number[] | undefined;
    const o = start + p;
    switch (kind) {
      case "i8": operand = String(dv.getInt8(o)); p += 1; break;
      case "u8": operand = String(dv.getUint8(o)); p += 1; break;
      case "u16": operand = String(dv.getUint16(o, true)); p += 2; break;
      case "i32": operand = String(dv.getInt32(o, true)); p += 4; break;
      case "i64": operand = dv.getBigInt64(o, true).toString(); p += 8; break;
      case "r4": operand = String(dv.getFloat32(o, true)); p += 4; break;
      case "r8": operand = String(dv.getFloat64(o, true)); p += 8; break;
      case "tok": token = dv.getUint32(o, true); operand = name(token); p += 4; break;
      case "br8": { const t = p + 1 + dv.getInt8(o); targets = [t]; operand = `IL_${t.toString(16).padStart(4, "0")}`; p += 1; break; }
      case "br32": { const t = p + 4 + dv.getInt32(o, true); targets = [t]; operand = `IL_${t.toString(16).padStart(4, "0")}`; p += 4; break; }
      case "switch": {
        const n = dv.getUint32(o, true);
        if (n > 4096) throw new IlError("switch table too large");
        const base = p + 4 + n * 4;
        targets = Array.from({ length: n }, (_, i) => base + dv.getInt32(o + 4 + i * 4, true));
        operand = `(${targets.map((t) => `IL_${t.toString(16).padStart(4, "0")}`).join(", ")})`;
        p = base;
        break;
      }
    }
    code.push({ offset: at, size: p - at, bytes: hex(at, p), opcode: mn, operand, token, targets });
  }

  // extra sections: exception handling clauses (II.25.4.5)
  const clauses: IlClause[] = [];
  if (flags & 0x08) {
    let s = (start + codeSize + 3) & ~3;
    for (let guard = 0; guard < 16 && s + 4 <= img.length; guard++) {
      const kind = img[s];
      const fat = (kind & 0x40) !== 0;
      const size = fat ? img[s + 1] | (img[s + 2] << 8) | (img[s + 3] << 16) : img[s + 1];
      if ((kind & 0x01) !== 0) {
        const stride = fat ? 24 : 12;
        const n = Math.min(Math.floor((size - 4) / stride), Math.floor((img.length - s - 4) / stride));
        for (let i = 0; i < n; i++) {
          const c = s + 4 + i * stride;
          const f = fat ? dv.getUint32(c, true) : dv.getUint16(c, true);
          const tryStart = fat ? dv.getUint32(c + 4, true) : dv.getUint16(c + 2, true);
          const tryLen = fat ? dv.getUint32(c + 8, true) : img[c + 4];
          const hStart = fat ? dv.getUint32(c + 12, true) : dv.getUint16(c + 5, true);
          const hLen = fat ? dv.getUint32(c + 16, true) : img[c + 7];
          const extra = dv.getUint32(c + (fat ? 20 : 8), true);
          const k = (["catch", "filter", "finally", "fault"] as const)[f === 1 ? 1 : f === 2 ? 2 : f === 4 ? 3 : 0];
          clauses.push({ kind: k, tryStart, tryEnd: tryStart + tryLen, handlerStart: hStart, handlerEnd: hStart + hLen, ...(k === "catch" ? { catchType: name(extra) } : {}) });
        }
      }
      if ((kind & 0x80) === 0) break; // no more sections
      s += (size + 3) & ~3;
    }
  }
  return { headerSize, codeSize, maxStack, localsToken, initLocals: (flags & 0x10) !== 0, code, clauses };
}

/** `IL_0000: ldstr "hi"` lines. */
export function formatIl(body: IlBody): string[] {
  const lines = body.clauses.map((c) => `// .try IL_${c.tryStart.toString(16).padStart(4, "0")}-IL_${c.tryEnd.toString(16).padStart(4, "0")} ${c.kind}${c.catchType ? ` ${c.catchType}` : ""} IL_${c.handlerStart.toString(16).padStart(4, "0")}-IL_${c.handlerEnd.toString(16).padStart(4, "0")}`);
  for (const i of body.code) lines.push(`IL_${i.offset.toString(16).padStart(4, "0")}: ${i.opcode}${i.operand ? " " + i.operand : ""}`);
  return lines;
}

export type UserStringRef = { token: number; method: string; methodToken: number; offset: number };

/** Every `ldstr` in every method body: user-string token → the places that load it. */
export function userStringRefs(img: Uint8Array, methods: readonly { token: number; rva: number; name: string; type: string }[]): Map<number, UserStringRef[]> {
  const out = new Map<number, UserStringRef[]>();
  // methods may share a body (hostile metadata points thousands at one huge one): decode each once
  const bodies = new Map<number, IlBody | null>();
  for (const m of methods) {
    if (!m.rva) continue;
    let body = bodies.get(m.rva);
    if (body === undefined) {
      try { body = disassembleIl(img, m.rva); } catch { body = null; }
      bodies.set(m.rva, body);
    }
    if (!body) continue;
    for (const i of body.code) {
      if (i.opcode !== "ldstr" || i.token === undefined) continue;
      const list = out.get(i.token) ?? [];
      list.push({ token: i.token, method: `${m.type}::${m.name}`, methodToken: m.token, offset: i.offset });
      out.set(i.token, list);
    }
  }
  return out;
}
