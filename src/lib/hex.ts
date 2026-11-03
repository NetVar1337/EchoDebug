// hex / address helpers shared by every view

export type Module = {
  name: string;
  base: string;
  size: number;
  /** "x86_64" | "x86" | "arm64" when the backend reports it (the Linux local backend does) */
  arch?: string;
};

export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function hexToBytes(h: string): Uint8Array {
  const clean = h.replace(/^0x/i, "").replace(/\s+/g, "");
  if (clean.length % 2 !== 0 || /[^0-9a-f]/i.test(clean)) throw new Error(`bad hex: ${h.slice(0, 32)}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** 0x-prefixed lowercase hex, the wire format for addresses. */
export function fmtAddr(a: bigint | number): string {
  return "0x" + BigInt(a).toString(16);
}

/** Padded uppercase display form, like the disassembly gutter. */
export function showAddr(a: bigint | number | string): string {
  const v = typeof a === "string" ? BigInt(a) : BigInt(a);
  return v.toString(16).toUpperCase().padStart(16, "0");
}

export function toBig(a: string | number | bigint): bigint {
  if (typeof a === "bigint") return a;
  if (typeof a === "number") return BigInt(a);
  return BigInt(a.startsWith("0x") || a.startsWith("0X") ? a : "0x" + a);
}

/**
 * Parse user address input: `0x7ff6..`, bare hex, `game.exe+0x1234`, `game.exe` (module base),
 * and simple `a+b-c` sums of those. Returns null when it does not parse.
 */
export function parseAddress(input: string, modules: readonly Module[] = []): bigint | null {
  let s = input.trim();
  if (!s) return null;
  // substitute module names first (longest first) so names containing '-' survive the split
  for (const m of [...modules].sort((a, b) => b.name.length - a.name.length)) {
    const i = s.toLowerCase().indexOf(m.name.toLowerCase());
    if (i >= 0) s = s.slice(0, i) + m.base + s.slice(i + m.name.length);
  }
  const parts = s.match(/[+-]?[^+-]+/g);
  if (!parts) return null;
  let total = 0n;
  for (const raw of parts) {
    const neg = raw.startsWith("-");
    const term = raw.replace(/^[+-]/, "").trim();
    let v: bigint | null = null;
    if (/^(0x)?[0-9a-f]+$/i.test(term)) v = toBig(term);
    if (v === null) return null;
    total += neg ? -v : v;
  }
  return total < 0n ? null : total;
}

/** `module+0xrva` when the address falls inside a module, else plain hex. */
export function labelAddr(a: bigint | string, modules: readonly Module[]): string {
  const v = toBig(a);
  for (const m of modules) {
    const b = toBig(m.base);
    if (v >= b && v < b + BigInt(m.size)) return `${m.name}+0x${(v - b).toString(16)}`;
  }
  return fmtAddr(v);
}

export function moduleOf(a: bigint, modules: readonly Module[]): Module | undefined {
  return modules.find((m) => {
    const b = toBig(m.base);
    return a >= b && a < b + BigInt(m.size);
  });
}

/** Classic 16-bytes-per-line dump of a hex string starting at `base`: address, bytes, ASCII. */
export function hexDump(base: string, hex: string): string {
  const b = hexToBytes(hex);
  const start = toBig(base);
  const lines: string[] = [];
  for (let o = 0; o < b.length; o += 16) {
    const row = b.subarray(o, o + 16);
    const bytes = Array.from(row, (x) => x.toString(16).padStart(2, "0")).join(" ").padEnd(47);
    const ascii = Array.from(row, (x) => (x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : ".")).join("");
    lines.push(`${fmtAddr(start + BigInt(o))}  ${bytes}  ${ascii}`);
  }
  return lines.join("\n");
}
