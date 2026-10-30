import { request } from "./client";
import { hexToBytes } from "./hex";

type BatchResult = { results: { success: boolean; address: string; data: string }[] };

/** Many small reads in one round trip (Echo caps each entry at 64 KiB). */
export async function readMany(reads: { address: string; size: number }[]): Promise<(Uint8Array | null)[]> {
  if (reads.length === 0) return [];
  const r = await request<BatchResult>("read_batch", { reads });
  return r.results.map((x) => (x.success && x.data ? hexToBytes(x.data) : null));
}
