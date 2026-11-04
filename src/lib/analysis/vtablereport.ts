// Full vtable enumeration with base-class diff — the "305 slots, 31 overrides" report.
//
// Given a vtable address (or an object whose head is one), read every slot, resolve the class
// from the RTTI complete-object locator, optionally diff a base class's vtable slot-by-slot
// (INHERIT vs OVERRIDE), and capture the first bytes of every distinct implementation so the
// reader can tell shared stubs (nullsubs) from real functions without opening a disassembler.
// The readers are injected so the same code runs live (readBytes/readMany) and in tests.
export type VtReader = (addr: bigint, size: number) => Promise<Uint8Array | null>;
export type VtBatch = (reads: { addr: bigint; size: number }[]) => Promise<(Uint8Array | null)[]>;

export type VtableRow = {
  index: number;
  /** slot offset in the vtable, hex */
  offset: string;
  /** function address, 0 when the slot does not hold a code pointer */
  function: bigint;
  /** base-class function at the same slot (0 = none/none-read) */
  base: bigint;
  /** OVERRIDE when this class replaces the base implementation, INHERIT when identical, BASE when no base given */
  status: "OVERRIDE" | "INHERIT" | "BASE";
  /** first bytes of the function (lowercase hex), "" when unreadable */
  prefix: string;
  /** true when the same function address appears at an earlier slot too (shared stub) */
  duplicate: boolean;
};

export type VtableReport = {
  vtable: bigint;
  class: string;
  base_class: string;
  slots: number;
  overrides: number;
  rows: VtableRow[];
  /** true when the vtable extent is exact: read stopped at the first non-slot value, or an exact count was given */
  complete: boolean;
};

const kPtrMax = 0x7fffffffffffn;
const kChunk = 64; // slots per read, so a vtable near a mapping edge still yields most slots

function u64(b: Uint8Array, o: number): bigint {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(o, true);
}

async function readU64(read: VtReader, addr: bigint): Promise<bigint> {
  const b = await read(addr, 8);
  return b && b.length === 8 ? u64(b, 0) : 0n;
}

async function readCString(read: VtReader, addr: bigint): Promise<string> {
  if (addr < 0x1000n) return "";
  const b = await read(addr, 256);
  if (!b) return "";
  let s = "";
  for (const c of b) {
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

/** "class C_WeaponX" / ".?AVC_WeaponX@@" -> "C_WeaponX"; anything else passes through. */
export function classOnly(mangled: string): string {
  if (!mangled) return "";
  const plain = /^(?:class|struct|union)\s+(.+)$/.exec(mangled)?.[1] ?? mangled;
  const angle = /^\.\?A[VUW]<(.+)>@@$/.exec(plain)?.[1];
  const bare = /^\.\?A[VUW](.+)@@$/.exec(plain)?.[1];
  let s = (angle ?? bare ?? plain).replace(/^\?\$/, "").replace(/@H@$/, "");
  return s.replace(/@/g, "::");
}

/**
 * Class name behind a vtable: vtable-8 -> complete-object locator -> type descriptor -> name,
 * with the base-class descriptor (just before the type descriptor) when present.
 */
export async function rttiClassOf(read: VtReader, vtable: bigint): Promise<{ name: string; base: string }> {
  const loc = await readU64(read, vtable - 8n);
  if (loc < 0x1000n) return { name: "", base: "" };
  const col = await read(loc, 32);
  if (!col || col.length < 32) return { name: "", base: "" };
  const dv = new DataView(col.buffer, col.byteOffset, col.byteLength);
  if (dv.getUint32(0, true) !== 1) return { name: "", base: "" };
  const td = dv.getBigUint64(16, true);
  const name = classOnly(await readCString(read, await readU64(read, td + 8n)));
  let base = "";
  const bcd = await readU64(read, td - 0x10n);
  if (bcd > 0x1000n) base = classOnly(await readCString(read, await readU64(read, bcd + 8n)));
  return { name, base };
}

/** Read up to `want` slots starting at `from`, shrinking the read when it falls off the mapped end. */
async function readSlotChunk(read: VtReader, vt: bigint, from: number, want: number): Promise<bigint[]> {
  let size = want * 8;
  while (size >= 8) {
    const raw = await read(vt + BigInt(from * 8), size);
    if (raw) {
      const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
      return Array.from({ length: Math.floor(raw.length / 8) }, (_, i) => dv.getBigUint64(i * 8, true));
    }
    size >>= 1;
  }
  return [];
}

export type VtableReportOpts = {
  /** exact slot count; without it slots are read until the first non-pointer */
  slots?: number;
  /** base-class vtable to diff against */
  base?: bigint;
  /** bytes captured at the start of every distinct function (0 disables) */
  prefixBytes?: number;
  /** is `addr` an object address whose first qword is the vtable? default false */
  fromObject?: boolean;
  /** slot validity predicate (e.g. does the target land in an executable module?) */
  code?: (addr: bigint) => boolean;
  /** batched reader for the prefix captures (live: read_memory_batch) */
  batch?: VtBatch;
};

export async function vtableReport(read: VtReader, addr: bigint, opts: VtableReportOpts = {}): Promise<VtableReport> {
  let vtable = addr;
  if (opts.fromObject) {
    const head = await readU64(read, addr);
    if (head < 0x1000n || head > kPtrMax) throw new Error("the object does not start with a vtable pointer");
    vtable = head;
  }
  const { name, base } = await rttiClassOf(read, vtable);
  const isCode = opts.code ?? (() => true);
  const max = Math.min(opts.slots ?? 4096, 4096);
  const rows: VtableRow[] = [];
  const seen = new Map<bigint, number>();
  let complete = opts.slots !== undefined;

  // the vtable itself, chunk by chunk
  const values: bigint[] = [];
  for (let from = 0; from < max; from += kChunk) {
    const chunk = await readSlotChunk(read, vtable, from, Math.min(kChunk, max - from));
    if (!chunk.length) break;
    values.push(...chunk);
    if (chunk.length < Math.min(kChunk, max - from)) break; // read fell off the end
    if (opts.slots === undefined) {
      const end = values.findIndex((v) => v < 0x1000n || v > kPtrMax || !isCode(v));
      if (end >= 0) { values.length = end; complete = true; break; }
    }
  }
  if (opts.slots !== undefined) values.length = Math.min(values.length, opts.slots);
  else {
    const end = values.findIndex((v) => v < 0x1000n || v > kPtrMax || !isCode(v));
    if (end >= 0) { values.length = end; complete = true; }
  }

  // the base vtable, same extent
  let baseRows: bigint[] = [];
  if (opts.base !== undefined) {
    for (let from = 0; from < values.length; from += kChunk) {
      const chunk = await readSlotChunk(read, opts.base, from, Math.min(kChunk, values.length - from));
      if (!chunk.length) break;
      baseRows.push(...chunk);
    }
  }

  for (let i = 0; i < values.length; i++) {
    const fn = values[i];
    const baseFn = baseRows[i] ?? 0n;
    const status = opts.base === undefined ? "BASE" : baseRows.length > i && baseFn === fn ? "INHERIT" : "OVERRIDE";
    const duplicate = seen.has(fn);
    if (!duplicate) seen.set(fn, i);
    rows.push({
      index: i,
      offset: `0x${(i * 8).toString(16).padStart(3, "0")}`,
      function: fn,
      base: baseFn,
      status,
      prefix: "",
      duplicate,
    });
  }

  const prefixBytes = opts.prefixBytes ?? 0;
  if (prefixBytes > 0 && seen.size) {
    const targets = [...seen.keys()];
    const blobs = opts.batch
      ? await opts.batch(targets.map((t) => ({ addr: t, size: prefixBytes })))
      : await Promise.all(targets.map((t) => read(t, prefixBytes)));
    blobs.forEach((b, i) => {
      if (b && b.length) {
        const text = Array.from(b.subarray(0, prefixBytes), (x) => x.toString(16).padStart(2, "0")).join("");
        for (const r of rows) if (r.function === targets[i]) r.prefix = text;
      }
    });
  }
  return {
    vtable,
    class: name,
    base_class: base,
    slots: rows.length,
    overrides: rows.filter((r) => r.status === "OVERRIDE").length,
    rows,
    complete,
  };
}
