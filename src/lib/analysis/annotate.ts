// Inline annotations for a disassembly listing: the string an operand points at, and how many
// references point at an instruction.

/** Printable string at `rva` of a mapped image: `"text"` (ASCII) or `L"text"` (UTF-16), else null. */
export function stringAt(img: Uint8Array, rva: number, max = 64): string | null {
  if (rva < 0 || rva >= img.length) return null;
  const printable = (c: number) => (c >= 0x20 && c < 0x7f) || c === 9 || c === 10 || c === 13;
  const esc = (s: string) => s.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t").replace(/"/g, '\\"');
  let a = "";
  for (let i = rva; i < img.length && img[i] !== 0 && a.length <= max; i++) {
    if (!printable(img[i])) {
      a = "";
      break;
    }
    a += String.fromCharCode(img[i]);
  }
  if (a.length >= 4) return `"${esc(a.length > max ? a.slice(0, max) + "…" : a)}"`;
  let w = "";
  for (let i = rva; i + 1 < img.length && a.length <= max; i += 2) {
    const c = img[i] | (img[i + 1] << 8);
    if (c === 0) break;
    if (!printable(c)) return null;
    w += String.fromCharCode(c);
    if (w.length > max) break;
  }
  return w.length >= 4 ? `L"${esc(w.length > max ? w.slice(0, max) + "…" : w)}"` : null;
}

/** Every absolute address an instruction mentions: explicit hex operands and `; 0x..` annotations. */
export function operandAddresses(text: string, address: bigint, length: number): bigint[] {
  const out: bigint[] = [];
  const rip = /\[rip\s*([+-])\s*(0x[0-9a-f]+)\]/i.exec(text);
  if (rip) {
    const d = BigInt(rip[2]);
    out.push(address + BigInt(length) + (rip[1] === "-" ? -d : d));
  }
  for (const m of text.matchAll(/0x[0-9a-f]{5,16}/gi)) out.push(BigInt(m[0]));
  return [...new Set(out)];
}
