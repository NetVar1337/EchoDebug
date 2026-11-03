export type Snapshot = {
  id: string;
  name: string;
  address: string;
  size: number;
  bytes: Uint8Array;
  created: number;
};

export type DiffEntry = {
  offset: number;
  address: string;
  before: number;
  after: number;
};

function parseAddress(text: string): bigint {
  const t = text.trim();
  if (/^0x[0-9a-f]+$/i.test(t)) return BigInt(t);
  if (/^[0-9a-f]+$/i.test(t)) return BigInt(`0x${t}`);
  return BigInt(t);
}

/**
 * Byte-wise diff of two buffers.  Only the common prefix length is compared;
 * bytes are addressed relative to `baseAddress`.
 */
export function diffRange(a: Uint8Array, b: Uint8Array, baseAddress: string): DiffEntry[] {
  const base = parseAddress(baseAddress);
  const out: DiffEntry[] = [];
  const n = Math.min(a.length, b.length);

  for (let i = 0; i < n; i++) {
    if (a[i] === b[i]) continue;
    out.push({
      offset: i,
      address: `0x${(base + BigInt(i)).toString(16)}`,
      before: a[i],
      after: b[i],
    });
  }

  return out;
}

/**
 * Byte-wise diff of two snapshots.  Snapshots are compared by offset even when
 * they were taken at different addresses; entry addresses are relative to the
 * first snapshot's base address.
 */
export function diffSnapshots(a: Snapshot, b: Snapshot): DiffEntry[] {
  return diffRange(a.bytes, b.bytes, a.address);
}
