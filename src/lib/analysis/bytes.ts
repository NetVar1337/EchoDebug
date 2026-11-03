// Byte-level helpers for the memory view: search needles, in-buffer search, copy-as formats and
// a data inspector with endianness.

export type NeedleMode = "hex" | "ascii" | "utf16" | "i8" | "u8" | "i16" | "u16" | "i32" | "u32" | "i64" | "u64" | "f32" | "f64";
export type Needle = { bytes: Uint8Array; mask: boolean[] };

/** Builds a search needle. `hex` accepts `48 8b ?? 05`, `488b??05` and single `?` wildcards. */
export function buildNeedle(text: string, mode: NeedleMode, littleEndian = true): Needle {
  const s = text.trim();
  if (!s) throw new Error("empty search");
  if (mode === "hex") {
    const toks = s.includes(" ") ? s.split(/\s+/) : s.replace(/\?\?|\?/g, " ?? ").trim().split(/\s+/).flatMap((t) => (t === "??" ? [t] : t.match(/../g) ?? []));
    const bytes: number[] = [];
    const mask: boolean[] = [];
    for (const t of toks) {
      if (t === "?" || t === "??") {
        bytes.push(0);
        mask.push(false);
      } else if (/^[0-9a-f]{2}$/i.test(t)) {
        bytes.push(parseInt(t, 16));
        mask.push(true);
      } else throw new Error(`bad hex byte: ${t}`);
    }
    return { bytes: new Uint8Array(bytes), mask };
  }
  if (mode === "ascii") {
    const b = new TextEncoder().encode(s);
    return { bytes: b, mask: Array(b.length).fill(true) };
  }
  if (mode === "utf16") {
    const b = new Uint8Array(s.length * 2);
    for (let i = 0; i < s.length; i++) {
      b[i * 2] = s.charCodeAt(i) & 0xff;
      b[i * 2 + 1] = s.charCodeAt(i) >> 8;
    }
    return { bytes: b, mask: Array(b.length).fill(true) };
  }
  const size = { i8: 1, u8: 1, i16: 2, u16: 2, i32: 4, u32: 4, i64: 8, u64: 8, f32: 4, f64: 8 }[mode];
  const b = new Uint8Array(size);
  const dv = new DataView(b.buffer);
  if (mode === "f32" || mode === "f64") {
    const v = Number(s);
    if (!Number.isFinite(v)) throw new Error(`not a number: ${s}`);
    if (mode === "f32") dv.setFloat32(0, v, littleEndian);
    else dv.setFloat64(0, v, littleEndian);
  } else {
    if (!/^-?(0x[0-9a-f]+|\d+)$/i.test(s)) throw new Error(`not an integer: ${s}`);
    const neg = s.startsWith("-");
    const v = BigInt.asUintN(size * 8, (neg ? -1n : 1n) * BigInt(neg ? s.slice(1) : s));
    for (let i = 0; i < size; i++) b[littleEndian ? i : size - 1 - i] = Number((v >> BigInt(8 * i)) & 0xffn);
  }
  return { bytes: b, mask: Array(size).fill(true) };
}

/** Index of the first match at or after `from` (dir 1) or at or before `from` (dir -1); -1 if none. */
export function findIn(buf: Uint8Array, n: Needle, from: number, dir: 1 | -1 = 1): number {
  const len = n.bytes.length;
  const match = (o: number) => {
    for (let k = 0; k < len; k++) if (n.mask[k] && buf[o + k] !== n.bytes[k]) return false;
    return true;
  };
  if (dir === 1) {
    for (let o = Math.max(0, from); o + len <= buf.length; o++) if (match(o)) return o;
  } else {
    for (let o = Math.min(from, buf.length - len); o >= 0; o--) if (match(o)) return o;
  }
  return -1;
}

export type CopyFormat = "hex" | "spaced" | "c" | "python" | "base64" | "ida" | "escaped" | "rust";

export const kCopyFormats: { id: CopyFormat; label: string }[] = [
  { id: "spaced", label: "Hex (spaced)" },
  { id: "hex", label: "Hex (compact)" },
  { id: "c", label: "C array" },
  { id: "rust", label: "Rust array" },
  { id: "python", label: "Python bytes" },
  { id: "escaped", label: "\\x escaped string" },
  { id: "base64", label: "Base64" },
  { id: "ida", label: "IDA pattern" },
];

export function formatAs(b: Uint8Array, fmt: CopyFormat, name = "data"): string {
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0"));
  switch (fmt) {
    case "hex": return h.join("");
    case "spaced": return h.join(" ");
    case "ida": return h.map((x) => x.toUpperCase()).join(" ");
    case "escaped": return h.map((x) => `\\x${x}`).join("");
    case "python": return `b"${h.map((x) => `\\x${x}`).join("")}"`;
    case "base64": {
      let s = "";
      for (const x of b) s += String.fromCharCode(x);
      return btoa(s);
    }
    case "c":
    case "rust": {
      const rows: string[] = [];
      for (let i = 0; i < h.length; i += 16) rows.push("    " + h.slice(i, i + 16).map((x) => `0x${x}`).join(", ") + ",");
      return fmt === "c"
        ? `unsigned char ${name}[${b.length}] = {\n${rows.join("\n")}\n};`
        : `const ${name.toUpperCase()}: [u8; ${b.length}] = [\n${rows.join("\n")}\n];`;
    }
  }
}

export type InspectRow = { type: string; value: string };

/** Every interpretation of the bytes at the cursor. */
export function inspect(b: Uint8Array, littleEndian = true): InspectRow[] {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const rows: InspectRow[] = [];
  const add = (type: string, need: number, f: () => string) => rows.push({ type, value: b.length >= need ? f() : "??" });
  const flt = (v: number) => (Number.isFinite(v) && Math.abs(v) !== 0 && (Math.abs(v) < 1e-4 || Math.abs(v) >= 1e9) ? v.toExponential(6) : String(Math.round(v * 1e6) / 1e6));
  add("u8", 1, () => String(dv.getUint8(0)));
  add("i8", 1, () => String(dv.getInt8(0)));
  add("u16", 2, () => String(dv.getUint16(0, littleEndian)));
  add("i16", 2, () => String(dv.getInt16(0, littleEndian)));
  add("u32", 4, () => String(dv.getUint32(0, littleEndian)));
  add("i32", 4, () => String(dv.getInt32(0, littleEndian)));
  add("u64", 8, () => dv.getBigUint64(0, littleEndian).toString());
  add("i64", 8, () => dv.getBigInt64(0, littleEndian).toString());
  add("f32", 4, () => flt(dv.getFloat32(0, littleEndian)));
  add("f64", 8, () => flt(dv.getFloat64(0, littleEndian)));
  add("hex32", 4, () => "0x" + dv.getUint32(0, littleEndian).toString(16).toUpperCase());
  add("ptr", 8, () => "0x" + dv.getBigUint64(0, littleEndian).toString(16).toUpperCase());
  add("binary", 1, () => dv.getUint8(0).toString(2).padStart(8, "0"));
  add("unix time", 4, () => {
    const t = dv.getUint32(0, littleEndian);
    return t > 0x386d4380 && t < 0x7fffffff ? new Date(t * 1000).toISOString().replace(".000Z", "Z") : "—";
  });
  add("ascii", 1, () => {
    let s = "";
    for (let i = 0; i < b.length && b[i] !== 0 && s.length < 48; i++) s += b[i] >= 0x20 && b[i] < 0x7f ? String.fromCharCode(b[i]) : ".";
    return s;
  });
  add("utf16", 2, () => {
    let s = "";
    for (let i = 0; i + 1 < b.length && s.length < 48; i += 2) {
      const c = littleEndian ? b[i] | (b[i + 1] << 8) : (b[i] << 8) | b[i + 1];
      if (!c) break;
      s += String.fromCharCode(c);
    }
    return s;
  });
  return rows;
}
