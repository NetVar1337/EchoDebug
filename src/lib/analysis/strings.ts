// printable ASCII and UTF-16LE runs, like IDA's strings window

export type FoundString = { rva: number; text: string; wide: boolean };

const printable = (c: number) => (c >= 0x20 && c <= 0x7e) || c === 0x09;

export function extractStrings(buf: Uint8Array, minLen = 5, limit = 200_000): FoundString[] {
  const out: FoundString[] = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    if (i < buf.length && printable(buf[i])) {
      if (start < 0) start = i;
      continue;
    }
    if (start >= 0 && i - start >= minLen) {
      out.push({ rva: start, text: String.fromCharCode(...buf.subarray(start, Math.min(i, start + 1024))), wide: false });
      if (out.length >= limit) return out;
    }
    start = -1;
  }
  for (const align of [0, 1]) {
    start = -1;
    let text = "";
    for (let i = align; i + 1 <= buf.length; i += 2) {
      const ok = i + 1 < buf.length && buf[i + 1] === 0 && printable(buf[i]);
      if (ok) {
        if (start < 0) start = i;
        if (text.length < 1024) text += String.fromCharCode(buf[i]);
        continue;
      }
      if (start >= 0 && text.length >= minLen) {
        out.push({ rva: start, text, wide: true });
        if (out.length >= limit) return out;
      }
      start = -1;
      text = "";
    }
  }
  return out.sort((a, b) => a.rva - b.rva);
}
