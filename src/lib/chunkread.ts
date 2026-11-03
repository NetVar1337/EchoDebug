// Chunked memory reads with a hard cap, so a huge region request can never pull an unbounded
// payload over the WebSocket in one frame (memory-pressure guard).
import { request } from "./client";
import { hexToBytes } from "./hex";

/** Reads larger than this are split into chunks and flagged `truncated` when cut short. */
export const kMaxReadBytes = 8 * 1024 * 1024;
export const kReadChunk = 1024 * 1024;

export type ChunkedRead = {
  bytes: Uint8Array;
  /** bytes actually returned; < requested when the cap truncated the read */
  returned: number;
  requested: number;
  truncated: boolean;
  /** number of individual read frames sent */
  frames: number;
};

type ReadFn = (addr: bigint, size: number) => Promise<Uint8Array>;

/** Default reader: the relay's `read` verb, hex payload in, bytes out. */
export const relayRead: ReadFn = async (addr, size) => {
  const r = await request<{ data?: string }>("read", { address: `0x${addr.toString(16)}`, size });
  return hexToBytes(r.data ?? "");
};

/**
 * Read `size` bytes at `addr` in `chunk`-sized frames, stopping at `kMaxReadBytes`.
 * `onProgress(done, total)` is called after every frame. A failing frame never rejects the
 * whole read: the gap is zero-filled and counted in `gaps`.
 */
export async function readChunked(
  read: ReadFn,
  addr: bigint,
  size: number,
  opts: { chunk?: number; maxBytes?: number; onProgress?: (done: number, total: number) => void; signal?: { aborted: boolean } } = {},
): Promise<ChunkedRead & { gaps: number }> {
  const chunk = Math.min(opts.chunk ?? kReadChunk, kMaxReadBytes);
  const max = Math.min(opts.maxBytes ?? kMaxReadBytes, kMaxReadBytes);
  const out = new Uint8Array(Math.min(size, max));
  let done = 0;
  let frames = 0;
  let gaps = 0;
  while (done < out.length && !opts.signal?.aborted) {
    const n = Math.min(chunk, out.length - done);
    try {
      const piece = await read(addr + BigInt(done), n);
      out.set(piece.subarray(0, n), done);
      if (piece.length < n) gaps += n - piece.length;
    } catch {
      gaps += n; // leave zeros
    }
    done += n;
    frames++;
    opts.onProgress?.(done, size);
  }
  return { bytes: out, returned: done, requested: size, truncated: done < size, frames, gaps };
}
