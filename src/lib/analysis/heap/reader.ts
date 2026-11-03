// Cached, bounded memory reader shared by the heap parsers. Every parser reads the target through
// a `MemRead` callback only, so the same code runs against the live process (the relay's `read`
// verb), a synthetic image in the unit tests, or /proc/<pid>/mem in the Linux integration test.

/** Reads `size` bytes at `addr`; null (or a short array) when the memory is not readable. */
export type MemRead = (addr: bigint, size: number) => Promise<Uint8Array | null>;

const kBlock = 0x10000; // one request covers 64 KiB…
const kPage = 0x1000; // …and falls back to single pages at region edges

export class HeapMem {
  private blocks = new Map<bigint, Uint8Array | null>();
  private cached = 0;
  /** bytes requested from the target so far */
  readBytes = 0;

  constructor(private readonly raw: MemRead, private readonly opts: { maxCache?: number; maxRead?: number } = {}) {}

  /** True once the read budget is used up: parsers stop and report a truncated walk. */
  get exhausted(): boolean {
    return this.opts.maxRead !== undefined && this.readBytes >= this.opts.maxRead;
  }

  private async block(key: bigint): Promise<Uint8Array | null> {
    if (this.blocks.has(key)) return this.blocks.get(key) ?? null;
    if (this.exhausted) return null;
    if (this.cached > (this.opts.maxCache ?? 96 * 1024 * 1024)) {
      this.blocks.clear();
      this.cached = 0;
    }
    const base = key * BigInt(kBlock);
    let b = await this.raw(base, kBlock).catch(() => null);
    this.readBytes += kBlock;
    if (!b || b.length < kBlock) {
      // part of the block is unmapped: read it page by page and keep what is there
      const out = new Uint8Array(kBlock);
      const ok = new Uint8Array(kBlock / kPage);
      let any = false;
      for (let p = 0; p < kBlock / kPage; p++) {
        const pg = await this.raw(base + BigInt(p * kPage), kPage).catch(() => null);
        if (pg && pg.length >= kPage) {
          out.set(pg.subarray(0, kPage), p * kPage);
          ok[p] = 1;
          any = true;
        }
      }
      b = any ? out : null;
      if (b) this.holes.set(key, ok);
    }
    this.blocks.set(key, b);
    this.cached += kBlock;
    return b;
  }

  /** per-page validity of blocks that were only partly readable */
  private holes = new Map<bigint, Uint8Array>();

  private pageOk(key: bigint, off: number): boolean {
    const h = this.holes.get(key);
    return !h || h[Math.floor(off / kPage)] === 1;
  }

  /** `n` bytes at `addr`, or null when any of them is unreadable. */
  async bytes(addr: bigint, n: number): Promise<Uint8Array | null> {
    if (addr < 0n || n < 0) return null;
    const out = new Uint8Array(n);
    let done = 0;
    while (done < n) {
      const a = addr + BigInt(done);
      const key = a / BigInt(kBlock);
      const off = Number(a % BigInt(kBlock));
      const b = await this.block(key);
      if (!b || !this.pageOk(key, off)) return null;
      const take = Math.min(n - done, kBlock - off, kPage - (off % kPage));
      out.set(b.subarray(off, off + take), done);
      done += take;
    }
    return out;
  }

  /** Bytes already in the cache (no request); null when not cached. */
  peek(addr: bigint, n: number): Uint8Array | null {
    const key = addr / BigInt(kBlock);
    const off = Number(addr % BigInt(kBlock));
    const b = this.blocks.get(key);
    if (!b || off + n > kBlock || !this.pageOk(key, off) || !this.pageOk(key, off + n - 1)) return null;
    return b.slice(off, off + n);
  }

  async u64(addr: bigint): Promise<bigint | null> {
    const b = await this.bytes(addr, 8);
    return b ? new DataView(b.buffer).getBigUint64(0, true) : null;
  }

  async u32(addr: bigint): Promise<number | null> {
    const b = await this.bytes(addr, 4);
    return b ? new DataView(b.buffer).getUint32(0, true) : null;
  }

  async u16(addr: bigint): Promise<number | null> {
    const b = await this.bytes(addr, 2);
    return b ? new DataView(b.buffer).getUint16(0, true) : null;
  }

  async u8(addr: bigint): Promise<number | null> {
    const b = await this.bytes(addr, 1);
    return b ? b[0] : null;
  }
}

export const u64At = (b: Uint8Array, off: number): bigint => new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(off, true);
export const u32At = (b: Uint8Array, off: number): number => new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, true);
export const u16At = (b: Uint8Array, off: number): number => new DataView(b.buffer, b.byteOffset, b.byteLength).getUint16(off, true);
