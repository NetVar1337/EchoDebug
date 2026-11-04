// Apex Legends / Respawn-Source "find every offset after an update" scanner.
//
// The whole pipeline is signature-free: game updates shuffle code (and so byte patterns) but
// keep member-name strings and descriptor-table structures. Everything here re-derives from
// those stable anchors:
//
// - enumerateNetvars:   walk every descriptor entry in the module image (DataDesc + compact
//                       RecvProp layouts), cluster them into tables, cross-confirm offsets
//                       both layouts agree on. This is the full netvar dump.
// - findEntityList:     scan the process's writable memory for the CGameEntitySystem global:
//                       a pointer to a block whose first slots are entity pointers with vtables
//                       in the module's read-only range.
// - findViewMatrix:     frame-differ: a 4x4 float block that changes every frame and looks like
//                       a camera matrix (zero projection row, unit-ish basis).
// Readers are injected (live readBytes in the app/tests, plain arrays in unit tests).
import type { PeInfo, Section } from "../pe";
import { extractStrings } from "../strings";
import { kRespawnPresetFields } from "./respawn";

export type MemReader = (addr: bigint, size: number) => Promise<Uint8Array | null>;
export type MemBatch = (reads: { addr: bigint; size: number }[]) => Promise<(Uint8Array | null)[]>;

// -------------------------------------------------------------------------------------------------
// Full netvar enumeration
// -------------------------------------------------------------------------------------------------

export type ApexNetvarEntry = {
  name: string;
  offset: number;
  /** DataDesc type (0 = plain, 1 = composite, 0x0A = array/handle); -1 for the compact table */
  type: number;
  layout: "table1" | "table2";
  site: bigint;
  confirmed: boolean;
};

export type ApexTable = {
  /** address of the first descriptor in the run */
  address: bigint;
  entries: ApexNetvarEntry[];
  /** well-known member names in this table (the canaries people grep for) */
  anchors: string[];
};

export type NetvarScan = { tables: ApexTable[]; entries: number; confirmed: number; strings: number };

const kMemberName = /^[a-zA-Z_][A-Za-z0-9_]{2,47}$/;

/**
 * A pointer-sized qword in an image is either an absolute address (live memory dumps, where
 * descriptor tables hold real char- and code-pointers) or a bare RVA (disk files, tests). Map both
 * to an image offset; -1 when it points nowhere in the image.
 */
export function ptrToRva(v: bigint, base: bigint, len: number): number {
  if (v >= base && v < base + BigInt(len)) return Number(v - base);
  if (v >= 8n && v < BigInt(len)) return Number(v);
  return -1;
}

function asciiAt(img: Uint8Array, rva: number, max = 48): string {
  if (rva < 0 || rva >= img.length) return "";
  let s = "";
  for (let i = rva; i < Math.min(img.length, rva + max); i++) {
    const c = img[i];
    if (c === 0) return s.length >= 3 ? s : "";
    if (c < 0x20 || c > 0x7e) return "";
    s += String.fromCharCode(c);
  }
  return "";
}

export function dataSections(pe: PeInfo): Section[] {
  return pe.sections.filter((s) => !s.x && s.vsize > 0);
}

/** Member-name-like strings (and their rvas) anywhere in the image — the live descriptor scan
 *  anchors on these addresses, so strings with no in-image pointer must be found too. */
export function collectMemberNames(img: Uint8Array, cap = 400000): Map<string, number[]> {
  const names = new Map<string, number[]>();
  for (const s of extractStrings(img, 3, 8_000_000)) {
    if (s.wide || !kMemberName.test(s.text)) continue;
    const list = names.get(s.text);
    if (list) list.push(s.rva);
    else if (names.size < cap) names.set(s.text, [s.rva]);
  }
  // the canaries must never fall off the cap
  for (const n of kRespawnPresetFields) if (!names.has(n)) {
    const rvas: number[] = [];
    const needle = new TextEncoder().encode(n + "\0");
    outer: for (let i = 0; i + needle.length <= img.length; i++) {
      for (let j = 0; j < needle.length; j++) if (img[i + j] !== needle[j]) continue outer;
      rvas.push(i);
    }
    if (rvas.length) names.set(n, rvas);
  }
  return names;
}

/** Validate the descriptor layouts at a site (qword `o` inside `buf` points at `name`). */
function descriptorEntriesAt(dv: DataView, buf: Uint8Array, o: number, site: bigint, name: string): ApexNetvarEntry[] {
  const out: ApexNetvarEntry[] = [];
  // DataDesc: [type:i32][offset:i32]…[string@+0x28|+0x38]
  for (const delta of [0x28, 0x38]) {
    const b = o - delta;
    if (b < 0) continue;
    const type = dv.getUint32(b, true);
    if (type !== 0 && type !== 1 && type !== 0x0a) continue;
    const off = dv.getInt32(b + 4, true);
    if (off <= 0 || off >= 0x20000) continue;
    out.push({ name, offset: off, type, layout: "table2", site, confirmed: false });
    break;
  }
  // compact RecvProp-style: [string_ptr:8][offset:i32][flags:i32]
  if (o + 12 <= buf.length) {
    const off1 = dv.getInt32(o + 8, true);
    if (off1 > 0 && off1 < 0x20000) out.push({ name, offset: off1, type: -1, layout: "table1", site, confirmed: false });
  }
  return out;
}

/** Cross-layout confirmation and proximity clustering into tables. */
export function clusterAndConfirm(found: ApexNetvarEntry[], minCluster = 4): NetvarScan {
  // cross-layout confirmation: same name + same offset via both layouts
  const t2 = new Set(found.filter((e) => e.layout === "table2").map((e) => `${e.name}=${e.offset}`));
  for (const e of found) if (e.layout === "table1" && t2.has(`${e.name}=${e.offset}`)) e.confirmed = true;
  for (const e of found) if (e.layout === "table2" && t2.has(`${e.name}=${e.offset}`)) e.confirmed = true;
  // cluster by proximity
  found.sort((a, b) => (a.site < b.site ? -1 : 1));
  const clusters: ApexNetvarEntry[][] = [];
  for (const e of found) {
    const last = clusters[clusters.length - 1];
    if (last && e.site - last[last.length - 1].site <= 0x40n) last.push(e);
    else clusters.push([e]);
  }
  const preset = new Set(kRespawnPresetFields);
  const tables: ApexTable[] = clusters
    .filter((c) => c.length >= minCluster)
    .map((entries) => ({
      address: entries[0].site,
      entries,
      anchors: [...new Set(entries.map((e) => e.name))].filter((n) => preset.has(n)),
    }));
  return {
    tables,
    entries: tables.reduce((a, t) => a + t.entries.length, 0),
    confirmed: tables.reduce((a, t) => a + t.entries.filter((e) => e.confirmed).length, 0),
    strings: 0,
  };
}

/** Raw descriptor entries found in the module image (cluster with `clusterAndConfirm`). */
export function collectImageEntries(img: Uint8Array, base: bigint, pe: PeInfo): { found: ApexNetvarEntry[]; strings: number } {
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const found: ApexNetvarEntry[] = [];
  let strings = 0;
  for (const s of dataSections(pe)) {
    const end = Math.min(img.length, s.rva + s.vsize) & ~7;
    for (let o = s.rva & ~7; o + 8 <= end; o += 8) {
      const strRva = ptrToRva(dv.getBigUint64(o, true), base, img.length);
      if (strRva < 0) continue;
      const name = asciiAt(img, strRva);
      if (!kMemberName.test(name)) continue;
      strings++;
      found.push(...descriptorEntriesAt(dv, img, o, base + BigInt(o), name));
    }
  }
  return { found, strings };
}

/**
 * Enumerate every descriptor entry in the module image. One pass over the data sections finds
 * all qwords pointing at identifier strings; each is validated against both descriptor layouts.
 * Entries closer than 0x40 bytes form a table; runs of ≥4 entries are kept (smaller runs are
 * indistinguishable from coincidences).
 */
export function enumerateNetvars(img: Uint8Array, base: bigint, pe: PeInfo, minCluster = 4): NetvarScan {
  const { found, strings } = collectImageEntries(img, base, pe);
  const scan = clusterAndConfirm(found, minCluster);
  scan.strings = strings;
  return scan;
}

/**
 * The complement to the image scan for builds that construct their descriptor tables at
 * runtime: scan the process's writable memory for qwords pointing at the module's member-name
 * strings (tables hold absolute pointers into the module) and validate the same layouts.
 * Spans are read lowest-address-first — early engine allocations come first — and the scan
 * stops once `enoughNames` distinct members validated.
 */
export async function enumerateLiveNetvars(
  read: MemReader,
  spans: readonly { addr: bigint; size: number }[],
  base: bigint,
  names: ReadonlyMap<string, readonly number[]>,
  opts: { budgetBytes?: number; chunkBytes?: number; onProgress?: (scanned: number, total: number) => void; enoughNames?: number } = {},
): Promise<{ found: ApexNetvarEntry[]; scanned: number }> {
  const budget = opts.budgetBytes ?? 512 * 1024 * 1024;
  const chunk = Math.max(0x1000, (opts.chunkBytes ?? 4 * 1024 * 1024) + 0x40); // +0x40 overlap so -0x28 fields read at chunk edges
  const addrs = new Map<bigint, string>();
  for (const [n, rvas] of names) for (const r of rvas) addrs.set(base + BigInt(r), n);
  const found: ApexNetvarEntry[] = [];
  const seenNames = new Set<string>();
  let scanned = 0;
  const ordered = [...spans].filter((s) => s.size > 0).sort((a, b) => (a.addr < b.addr ? -1 : 1));
  const total = Math.min(budget, ordered.reduce((a, s) => a + s.size, 0));
  outer: for (const span of ordered) {
    for (let off = 0; off < span.size && scanned < budget; off += chunk - 0x40) {
      const size = Math.min(chunk, span.size - off);
      const buf = await read(span.addr + BigInt(off), size);
      scanned += size - 0x40;
      opts.onProgress?.(Math.min(scanned, total), total);
      if (!buf) continue;
      const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      const stepEnd = Math.min(buf.length, size - 0x40);
      for (let o = 0; o + 8 <= stepEnd; o += 8) {
        const name = addrs.get(dv.getBigUint64(o, true));
        if (name === undefined) continue;
        for (const e of descriptorEntriesAt(dv, buf, o, span.addr + BigInt(off) + BigInt(o), name)) {
          found.push(e);
          seenNames.add(e.name);
        }
        if (opts.enoughNames && seenNames.size >= opts.enoughNames) break outer;
      }
    }
  }
  return { found, scanned };
}

/** Flat {name: best offset} map: confirmed entries win, then table2, then table1. */
export function offsetMap(scan: NetvarScan): Map<string, number> {
  const rank = (e: ApexNetvarEntry) => (e.confirmed ? 0 : e.layout === "table2" ? 1 : 2);
  const best = new Map<string, { off: number; r: number }>();
  for (const t of scan.tables)
    for (const e of t.entries) {
      const cur = best.get(e.name);
      if (!cur || rank(e) < cur.r) best.set(e.name, { off: e.offset, r: rank(e) });
    }
  return new Map([...best].map(([k, v]) => [k, v.off]));
}

// -------------------------------------------------------------------------------------------------
// Entity list (CGameEntitySystem global)
// -------------------------------------------------------------------------------------------------

export type EntityListHit = { address: bigint; score: number };

function inSpans(addr: bigint, spans: readonly { addr: bigint; size: number }[]): boolean {
  for (const s of spans) if (addr >= s.addr && addr < s.addr + BigInt(s.size)) return true;
  return false;
}

/**
 * Scan writable memory for the entity-list global: an aligned qword pointing into a writable
 * span, whose target block starts with entity pointers (vtables in `rdata`). Candidates are
 * scored by how many consecutive 0x20-strided slots (CEntInfo-sized) also hold valid entities.
 */
export async function findEntityList(
  read: MemReader,
  batch: MemBatch,
  writable: readonly { addr: bigint; size: number }[],
  rdata: readonly { addr: bigint; size: number }[],
  opts: { budgetBytes?: number; maxCandidates?: number } = {},
): Promise<EntityListHit[]> {
  const budget = opts.budgetBytes ?? 32 * 1024 * 1024;
  const maxCand = opts.maxCandidates ?? 16;
  // level 1: qwords in writable spans whose value is an aligned, plausible pointer
  const sites: bigint[] = [];
  let scanned = 0;
  outer: for (const span of writable) {
    for (let off = 0; off < span.size && scanned < budget; off += 0x100000) {
      const size = Math.min(0x100000, span.size - off);
      const buf = await read(span.addr + BigInt(off), size);
      scanned += size;
      if (!buf) continue;
      const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      for (let i = 0; i + 8 <= buf.length; i += 8) {
        const p = dv.getBigUint64(i, true);
        if (p < 0x10000n || p > 0x7fffffffffffn || p % 8n !== 0n) continue;
        sites.push(span.addr + BigInt(off) + BigInt(i));
        if (sites.length >= 200_000) break outer;
      }
    }
  }
  const u64of = (b: Uint8Array | null): bigint => (b && b.length >= 8 ? new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(0, true) : 0n);
  // level 2: the value at the site is the entity block; its head must be an entity pointer
  const t1 = await batch(sites.map((p) => ({ addr: p, size: 8 })));
  const blocks: { siteIdx: number; block: bigint }[] = [];
  t1.forEach((b, i) => {
    const t = u64of(b);
    if (t >= 0x10000n) blocks.push({ siteIdx: i, block: t });
  });
  // level 3: entity0 -> vtable must land in the module's read-only range
  const eReads = blocks.map((c) => ({ addr: c.block, size: 8 }));
  const t2 = await batch(eReads);
  const ents: { siteIdx: number; block: bigint; ent: bigint }[] = [];
  t2.forEach((b, k) => {
    const e = u64of(b);
    if (e >= 0x10000n) ents.push({ ...blocks[k], ent: e });
  });
  const vReads = ents.map((c) => ({ addr: c.ent, size: 8 }));
  const t3 = await batch(vReads);
  const cand: { site: bigint; block: bigint }[] = [];
  t3.forEach((b, m) => {
    if (inSpans(u64of(b), rdata)) cand.push({ site: sites[ents[m].siteIdx], block: ents[m].block });
  });
  const sibReads: { addr: bigint; size: number }[] = [];
  for (const c of cand) for (let k = 1; k <= 7; k++) sibReads.push({ addr: c.block + BigInt(k * 0x20), size: 8 });
  const sibs = await batch(sibReads);
  const hits: EntityListHit[] = cand.map((c, ci) => {
    let score = 1;
    for (let k = 1; k <= 7; k++) if (u64of(sibs[ci * 7 + (k - 1)]) !== 0n) score++;
    return { address: c.site, score };
  });
  return hits.sort((a, b) => b.score - a.score).slice(0, maxCand);
}

// -------------------------------------------------------------------------------------------------
// View matrix (frame-diff)
// --------------------------------------------------------------------------------------------------

export type ViewMatrixHit = { address: bigint; checked: number };

function looksLikeMatrix(a: Uint8Array, b: Uint8Array, off: number): boolean {
  const da = new DataView(a.buffer, a.byteOffset, a.byteLength);
  const db = new DataView(b.buffer, b.byteOffset, b.byteLength);
  // the camera matrix is alive: most of its floats change frame to frame (the structural
  // zeros/ones don't, so 12 of 16 is a practical bar); the last row must look like a camera
  // basis: w components ~0, translations finite, basis lengths sane
  let changed = 0;
  for (let i = 0; i < 16; i++) {
    const fa = da.getFloat32(off + i * 4, true);
    const fb = db.getFloat32(off + i * 4, true);
    if (!Number.isFinite(fa) || !Number.isFinite(fb)) return false;
    if (Math.abs(fa - fb) > 1e-6) changed++;
  }
  if (changed < 12) return false;
  for (const i of [3, 7, 11]) if (Math.abs(da.getFloat32(off + i * 4, true)) > 0.01) return false;
  for (const base of [0, 4, 8]) {
    const x = da.getFloat32(off + base * 4, true);
    const y = da.getFloat32(off + (base + 1) * 4, true);
    const z = da.getFloat32(off + (base + 2) * 4, true);
    const len = Math.sqrt(x * x + y * y + z * z);
    if (len < 0.1 || len > 10) return false;
  }
  return true;
}

/**
 * Find the view matrix: read each span twice a frame apart and keep the first 64-byte block
 * that fully changes between reads while looking like a camera matrix. `delayMs` can be 0 when
 * the caller knows a frame boundary happens between the two reads.
 */
export async function findViewMatrix(
  read: MemReader,
  spans: readonly { addr: bigint; size: number }[],
  opts: { delayMs?: number; budgetBytes?: number; onProgress?: (done: number, total: number) => void } = {},
): Promise<ViewMatrixHit | null> {
  const budget = opts.budgetBytes ?? 24 * 1024 * 1024;
  const delay = opts.delayMs ?? 60;
  const total = Math.min(budget, spans.reduce((a, s) => a + s.size, 0));
  let scanned = 0;
  for (const span of spans) {
    for (let off = 0; off < span.size && scanned < budget; off += 0x100000) {
      const size = Math.min(0x100000, span.size - off, budget - scanned);
      const a = await read(span.addr + BigInt(off), size);
      if (delay) await new Promise((r) => setTimeout(r, delay));
      const b = a ? await read(span.addr + BigInt(off), size) : null;
      scanned += size;
      opts.onProgress?.(scanned, total);
      if (!a || !b) continue;
      for (let i = 0; i + 64 <= a.length; i += 8) {
        if (a[i] === b[i] && a[i + 8] === b[i + 8] && a[i + 16] === b[i + 16] && a[i + 24] === b[i + 24] && a[i + 32] === b[i + 32] && a[i + 40] === b[i + 40] && a[i + 48] === b[i + 48] && a[i + 56] === b[i + 56]) continue;
        if (looksLikeMatrix(a, b, i)) return { address: span.addr + BigInt(off) + BigInt(i), checked: scanned };
      }
    }
  }
  return null;
}
