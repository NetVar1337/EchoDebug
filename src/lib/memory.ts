// memory reads on top of Echo's native `read` / `read_batch` routes
import { request } from "./client";
import { readMany } from "./batch";
import { fmtAddr, hexToBytes, toBig, type Module } from "./hex";

export async function readBytes(address: bigint, size: number): Promise<Uint8Array | null> {
  const r = await request<{ data: string; success: boolean }>("read", { address: fmtAddr(address), size }, true);
  return r.success && r.data ? hexToBytes(r.data) : null;
}

export async function readU64(address: bigint): Promise<bigint | null> {
  const b = await readBytes(address, 8);
  return b && b.length === 8 ? new DataView(b.buffer).getBigUint64(0, true) : null;
}

/**
 * Read [address, address+size). Uses `read_batch` in rounds (Echo caps one entry at 64 KiB, one
 * plain read at 1 MiB), so a large range costs a handful of WebSocket round trips instead of one
 * per MiB; unreadable entries stay zero.
 */
export async function readRange(address: bigint, size: number, onProgress?: (done: number, total: number) => void): Promise<Uint8Array> {
  const out = new Uint8Array(size);
  const kEntry = 0x10000; // Echo caps one read_batch entry at 64 KiB
  const kRound = 256; // 16 MiB per round trip
  const offsets: number[] = [];
  for (let off = 0; off < size; off += kEntry) offsets.push(off);
  for (let i = 0; i < offsets.length; i += kRound) {
    const round = offsets.slice(i, i + kRound);
    const reads = round.map((off) => ({ address: fmtAddr(address + BigInt(off)), size: Math.min(kEntry, size - off) }));
    const bufs = await readMany(reads).catch(() => reads.map(() => null));
    bufs.forEach((b, j) => {
      if (b) out.set(b.subarray(0, reads[j].size), round[j]);
    });
    onProgress?.(Math.min(offsets.length, i + kRound), offsets.length);
  }
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
