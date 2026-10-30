// memory reads on top of Echo's native `read` route
import { request } from "./client";
import { fmtAddr, hexToBytes, toBig, type Module } from "./hex";

const kChunk = 0x100000; // Echo caps one read at 1 MiB

export async function readBytes(address: bigint, size: number): Promise<Uint8Array | null> {
  const r = await request<{ data: string; success: boolean }>("read", { address: fmtAddr(address), size }, true);
  return r.success && r.data ? hexToBytes(r.data) : null;
}

export async function readU64(address: bigint): Promise<bigint | null> {
  const b = await readBytes(address, 8);
  return b && b.length === 8 ? new DataView(b.buffer).getBigUint64(0, true) : null;
}

/** Read [address, address+size) in 1 MiB chunks; unreadable chunks stay zero. */
export async function readRange(address: bigint, size: number, onProgress?: (done: number, total: number) => void): Promise<Uint8Array> {
  const out = new Uint8Array(size);
  const chunks: number[] = [];
  for (let off = 0; off < size; off += kChunk) chunks.push(off);
  let done = 0;
  const worker = async () => {
    for (let off = chunks.shift(); off !== undefined; off = chunks.shift()) {
      const n = Math.min(kChunk, size - off);
      const b = await readBytes(address + BigInt(off), n).catch(() => null);
      if (b) out.set(b.subarray(0, n), off);
      onProgress?.(++done, Math.ceil(size / kChunk));
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);
  return out;
}

const images = new Map<string, Promise<Uint8Array>>();

/**
 * Whole module image, cached per base. shortcut: cache grows with every module opened and is only
 * dropped on reattach (clearImages), fine for a handful of modules, add an LRU if users open dozens.
 */
export function loadImage(m: Module, onProgress?: (done: number, total: number) => void): Promise<Uint8Array> {
  const key = `${m.name}@${m.base}`;
  let p = images.get(key);
  if (!p) {
    p = readRange(toBig(m.base), m.size, onProgress);
    images.set(key, p);
    p.catch(() => images.delete(key));
  }
  return p;
}

export function clearImages(): void {
  images.clear();
}
