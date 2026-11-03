// Synthetic process memory for the heap parser tests: a few mapped regions backed by byte arrays.
import type { MemRead } from "./reader";

export class FakeMem {
  regions: { base: bigint; bytes: Uint8Array; writable: boolean }[] = [];

  map(base: bigint, size: number, writable = true): this {
    this.regions.push({ base, bytes: new Uint8Array(size), writable });
    return this;
  }

  private at(a: bigint): { r: { base: bigint; bytes: Uint8Array }; off: number } {
    const r = this.regions.find((x) => a >= x.base && a < x.base + BigInt(x.bytes.length));
    if (!r) throw new Error(`unmapped 0x${a.toString(16)}`);
    return { r, off: Number(a - r.base) };
  }

  put(a: bigint, b: Uint8Array | number[]): this {
    const { r, off } = this.at(a);
    r.bytes.set(b, off);
    return this;
  }

  q(a: bigint, v: bigint): this {
    const { r, off } = this.at(a);
    new DataView(r.bytes.buffer).setBigUint64(off, BigInt.asUintN(64, v), true);
    return this;
  }

  d(a: bigint, v: number): this {
    const { r, off } = this.at(a);
    new DataView(r.bytes.buffer).setUint32(off, v >>> 0, true);
    return this;
  }

  w(a: bigint, v: number): this {
    const { r, off } = this.at(a);
    new DataView(r.bytes.buffer).setUint16(off, v, true);
    return this;
  }

  /** Reads like the target: a range is readable only while it stays inside one region. */
  read: MemRead = async (a, n) => {
    const r = this.regions.find((x) => a >= x.base && a + BigInt(n) <= x.base + BigInt(x.bytes.length));
    return r ? r.bytes.slice(Number(a - r.base), Number(a - r.base) + n) : null;
  };

  list(): { base: bigint; size: number; writable: boolean }[] {
    return this.regions.map((r) => ({ base: r.base, size: r.bytes.length, writable: r.writable }));
  }
}
