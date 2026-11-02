import { request } from "./client";
import { hexToBytes } from "./hex";

type BatchResult = { results: { success: boolean; address: string; data: string }[] };

/** Many small reads in one round trip (Echo caps each entry at 64 KiB). */
export async function readMany(reads: { address: string; size: number }[]): Promise<(Uint8Array | null)[]> {
  if (reads.length === 0) return [];
  const r = await request<BatchResult>("read_batch", { reads });
  return r.results.map((x) => (x.success && x.data ? hexToBytes(x.data) : null));
}

/** readMany in rounds of `chunk` entries, for candidate lists of any length. */
export async function readManyChunked(reads: { address: string; size: number }[], chunk = 1024, onProgress?: (done: number) => void): Promise<(Uint8Array | null)[]> {
  const out: (Uint8Array | null)[] = [];
  for (let i = 0; i < reads.length; i += chunk) {
    out.push(...(await readMany(reads.slice(i, i + chunk)).catch(() => reads.slice(i, i + chunk).map(() => null))));
    onProgress?.(Math.min(reads.length, i + chunk));
  }
  return out;
}
