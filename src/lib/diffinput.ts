// Functions of an image as BinDiff input: bytes sliced from the image, disassembled by the relay
// (disasm_bytes) so a live module and a file on disk go through the same formatter.
import { request } from "./client";
import { bytesToHex } from "./hex";
import type { DiffFunction, DiffInsn } from "./analysis/bindiff";

export async function functionsFromImage(img: Uint8Array, base: bigint, fns: readonly { rva: number; size: number; name: string }[], onProgress?: (done: number) => void, signal?: { aborted: boolean }): Promise<DiffFunction[]> {
  const out: DiffFunction[] = [];
  let done = 0;
  for (const f of fns) {
    if (signal?.aborted) break;
    const size = Math.min(Math.max(1, f.size), 0x4000, img.length - f.rva);
    if (size <= 0) continue;
    const r = await request<{ results: DiffInsn[] }>("disasm_bytes", { address: "0x" + (base + BigInt(f.rva)).toString(16), data: bytesToHex(img.subarray(f.rva, f.rva + size)) }, true).catch(() => null);
    out.push({ rva: f.rva, size, name: f.name, insns: r?.results ?? [] });
    onProgress?.(++done);
  }
  return out;
}
