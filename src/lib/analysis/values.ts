// typed views over a byte buffer, used by the data inspector, watchlist and struct view

export type ValueType = "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "f32" | "f64" | "ptr" | "ascii" | "utf16";

export const kSizes: Record<ValueType, number> = {
  u8: 1, u16: 2, u32: 4, u64: 8, i8: 1, i16: 2, i32: 4, i64: 8, f32: 4, f64: 8, ptr: 8, ascii: 32, utf16: 64,
};

export function decode(buf: Uint8Array, off: number, t: ValueType): string {
  const need = t === "ascii" || t === "utf16" ? 1 : kSizes[t];
  if (off < 0 || off + need > buf.length) return "??";
  const dv = new DataView(buf.buffer, buf.byteOffset + off, buf.byteLength - off);
  switch (t) {
    case "u8": return String(dv.getUint8(0));
    case "u16": return String(dv.getUint16(0, true));
    case "u32": return String(dv.getUint32(0, true));
    case "u64": return dv.getBigUint64(0, true).toString();
    case "i8": return String(dv.getInt8(0));
    case "i16": return String(dv.getInt16(0, true));
    case "i32": return String(dv.getInt32(0, true));
    case "i64": return dv.getBigInt64(0, true).toString();
    case "f32": return fmtFloat(dv.getFloat32(0, true));
    case "f64": return fmtFloat(dv.getFloat64(0, true));
    case "ptr": return "0x" + dv.getBigUint64(0, true).toString(16).toUpperCase();
    case "ascii": {
      let s = "";
      for (let i = off; i < buf.length && buf[i] !== 0 && s.length < 256; i++) s += buf[i] >= 0x20 && buf[i] < 0x7f ? String.fromCharCode(buf[i]) : ".";
      return s;
    }
    case "utf16": {
      let s = "";
      for (let i = off; i + 1 < buf.length && s.length < 256; i += 2) {
        const c = buf[i] | (buf[i + 1] << 8);
        if (c === 0) break;
        s += String.fromCharCode(c);
      }
      return s;
    }
  }
}

function fmtFloat(v: number): string {
  if (!Number.isFinite(v)) return String(v);
  const a = Math.abs(v);
  return a !== 0 && (a < 1e-4 || a >= 1e9) ? v.toExponential(4) : String(Math.round(v * 1e6) / 1e6);
}

/** Encode a user-entered value for writing. Throws on garbage. */
export function encode(text: string, t: ValueType): Uint8Array {
  const s = text.trim();
  if (t === "ascii") return new TextEncoder().encode(s);
  if (t === "utf16") {
    const out = new Uint8Array(s.length * 2);
    for (let i = 0; i < s.length; i++) {
      out[i * 2] = s.charCodeAt(i) & 0xff;
      out[i * 2 + 1] = s.charCodeAt(i) >> 8;
    }
    return out;
  }
  const out = new Uint8Array(kSizes[t]);
  const dv = new DataView(out.buffer);
  if (t === "f32" || t === "f64") {
    const v = Number(s);
    if (!Number.isFinite(v)) throw new Error(`not a number: ${s}`);
    if (t === "f32") dv.setFloat32(0, v, true);
    else dv.setFloat64(0, v, true);
    return out;
  }
  if (!/^-?(0x[0-9a-f]+|\d+)$/i.test(s)) throw new Error(`not an integer: ${s}`);
  const neg = s.startsWith("-");
  let v = BigInt(neg ? s.slice(1) : s);
  if (neg) v = -v;
  const bits = BigInt(kSizes[t] * 8);
  const signed = t.startsWith("i");
  const min = signed ? -(1n << (bits - 1n)) : 0n;
  const max = signed ? (1n << (bits - 1n)) - 1n : (1n << bits) - 1n;
  if (v < min || v > max) throw new Error(`${s} out of range for ${t}`);
  writeInt(dv, BigInt.asUintN(Number(bits), v), kSizes[t]);
  return out;
}

function writeInt(dv: DataView, v: bigint, n: number): void {
  for (let i = 0; i < n; i++) dv.setUint8(i, Number((v >> BigInt(i * 8)) & 0xffn));
}
