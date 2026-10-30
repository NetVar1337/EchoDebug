// byte-level reference finder: rel32 call/jmp/jcc and RIP-relative disp32 operands

export type Xref = { rva: number; kind: "call" | "jmp" | "jcc" | "rip" };
export type Range = { rva: number; size: number };

export function findXrefs(img: Uint8Array, ranges: readonly Range[], target: number, limit = 5000): Xref[] {
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const out: Xref[] = [];
  const seen = new Set<number>();
  const push = (rva: number, kind: Xref["kind"]) => {
    if (!seen.has(rva)) {
      seen.add(rva);
      out.push({ rva, kind });
    }
  };
  for (const r of ranges) {
    const end = Math.min(img.length - 4, r.rva + r.size);
    for (let i = r.rva; i < end && out.length < limit; i++) {
      const b = img[i];
      if ((b === 0xe8 || b === 0xe9) && i + 5 <= img.length && i + 5 + dv.getInt32(i + 1, true) === target) {
        push(i, b === 0xe8 ? "call" : "jmp");
      } else if (b === 0x0f && (img[i + 1] & 0xf0) === 0x80 && i + 6 <= img.length && i + 6 + dv.getInt32(i + 2, true) === target) {
        push(i, "jcc");
      } else if ((b & 0xc7) === 0x05 && i >= 1 && i + 5 <= img.length) {
        // ModRM mod=00 rm=101 → [rip+disp32]; trailing immediate is 0, 1, 2 or 4 bytes
        const disp = dv.getInt32(i + 1, true);
        for (const imm of [0, 1, 2, 4]) {
          if (i + 5 + imm + disp === target) {
            push(Math.max(r.rva, i - (img[i - 2] >= 0x40 && img[i - 2] <= 0x4f ? 2 : 1)), "rip");
            break;
          }
        }
      }
    }
  }
  return out;
}
