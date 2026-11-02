// Batch string decryption with the emulator: for every call site of a decryption routine, run the
// enclosing function from its start up to the instruction after the call, then rebuild the
// buffers the run wrote (from the emulator's memory log) and decode the most string-like one.

export type LogEntry = { rip: string; address: string; size: number; access: string; before: string; after?: string };
export type Buffer = { address: bigint; bytes: Uint8Array };

/** Contiguous byte runs written during the emulation (later writes win). */
export function buffersFromLog(log: readonly LogEntry[], ignore?: (address: bigint) => boolean): Buffer[] {
  const bytes = new Map<bigint, number>();
  for (const e of log) {
    if (!e.access.includes("w") || !e.after) continue;
    const a = BigInt(e.address);
    if (ignore?.(a)) continue;
    for (let i = 0; i < e.size && i * 2 + 1 < e.after.length; i++) bytes.set(a + BigInt(i), parseInt(e.after.slice(i * 2, i * 2 + 2), 16));
  }
  const addrs = [...bytes.keys()].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  const out: Buffer[] = [];
  let start = -1n;
  let cur: number[] = [];
  for (const a of addrs) {
    if (cur.length && a === start + BigInt(cur.length)) cur.push(bytes.get(a)!);
    else {
      if (cur.length) out.push({ address: start, bytes: Uint8Array.from(cur) });
      start = a;
      cur = [bytes.get(a)!];
    }
  }
  if (cur.length) out.push({ address: start, bytes: Uint8Array.from(cur) });
  return out;
}

export type Decoded = { text: string; encoding: "ascii" | "utf16"; address: bigint; score: number };

/** The most plausible string in the buffers: NUL-terminated ASCII or UTF-16 with printable text. */
export function bestString(buffers: readonly Buffer[], minLen = 3): Decoded | null {
  let best: Decoded | null = null;
  const printable = (c: number) => (c >= 0x20 && c < 0x7f) || c === 9 || c === 10 || c === 13;
  for (const b of buffers) {
    let a = "";
    for (const c of b.bytes) { if (c === 0) break; if (!printable(c)) { a = ""; break; } a += String.fromCharCode(c); }
    let w = "";
    for (let i = 0; i + 1 < b.bytes.length; i += 2) {
      const c = b.bytes[i] | (b.bytes[i + 1] << 8);
      if (c === 0) break;
      if (!printable(c)) { w = ""; break; }
      w += String.fromCharCode(c);
    }
    const cands: Decoded[] = [];
    if (a.length >= minLen) cands.push({ text: a, encoding: "ascii", address: b.address, score: a.length });
    if (w.length >= minLen) cands.push({ text: w, encoding: "utf16", address: b.address, score: w.length * 1.1 });
    for (const c of cands) if (!best || c.score > best.score) best = c;
  }
  return best;
}
