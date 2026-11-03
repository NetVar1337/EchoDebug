// Items for "search everything": what the stores already hold (names, comments, bookmarks,
// signatures, struct types) plus two caches filled on demand: module exports (read from the
// export directory only, not the whole image) and the strings of modules the Strings view or an
// explicit "search strings in all modules" has extracted. Nothing here starts a large scan by itself.
import { fmtAddr, moduleOf, toBig, type Module } from "./hex";
import { readBytes, readRange, loadImage } from "./memory";
import { extractStrings, type FoundString } from "./analysis/strings";
import type { SearchItem } from "./search";
import { useNames } from "@/store/names";
import { useWatch } from "@/store/watch";
import { useSigs } from "@/store/sigs";
import { useTypes } from "@/store/types";
import { useConn } from "@/store/conn";

const keyOf = (m: Module) => `${m.name}@${m.base}`;

// ---- exports ------------------------------------------------------------------------------------

/** RVA and size of the export directory from the first page of a PE image; null for non-PE. */
export function exportDirOf(hdr: Uint8Array): { rva: number; size: number } | null {
  if (hdr.length < 0x40 || hdr[0] !== 0x4d || hdr[1] !== 0x5a) return null;
  const dv = new DataView(hdr.buffer, hdr.byteOffset, hdr.byteLength);
  const pe = dv.getUint32(0x3c, true);
  if (pe + 24 + 0x70 + 8 > hdr.length || dv.getUint32(pe, true) !== 0x4550) return null;
  const oh = pe + 24;
  const magic = dv.getUint16(oh, true);
  const dirs = magic === 0x20b ? oh + 112 : magic === 0x10b ? oh + 96 : -1;
  if (dirs < 0 || dirs + 8 > hdr.length) return null;
  const rva = dv.getUint32(dirs, true);
  const size = dv.getUint32(dirs + 4, true);
  return rva && size ? { rva, size } : null;
}

/**
 * Named, non-forwarded exports from a chunk of the image that starts at `chunkRva` and contains
 * the export directory (and, normally, its name tables). Entries whose tables fall outside the
 * chunk are skipped.
 */
export function parseExportChunk(chunk: Uint8Array, chunkRva: number, dir: { rva: number; size: number }): { name: string; rva: number }[] {
  const dv = new DataView(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  const off = (rva: number) => (rva >= chunkRva && rva < chunkRva + chunk.length ? rva - chunkRva : -1);
  const d = off(dir.rva);
  if (d < 0 || d + 40 > chunk.length) return [];
  const nFuncs = dv.getUint32(d + 0x14, true);
  const nNames = Math.min(dv.getUint32(d + 0x18, true), 1 << 20);
  const funcs = off(dv.getUint32(d + 0x1c, true));
  const names = off(dv.getUint32(d + 0x20, true));
  const ords = off(dv.getUint32(d + 0x24, true));
  if (funcs < 0 || names < 0 || ords < 0) return [];
  const out: { name: string; rva: number }[] = [];
  for (let i = 0; i < nNames; i++) {
    if (names + i * 4 + 4 > chunk.length || ords + i * 2 + 2 > chunk.length) break;
    const ord = dv.getUint16(ords + i * 2, true);
    if (ord >= nFuncs || funcs + ord * 4 + 4 > chunk.length) continue;
    const rva = dv.getUint32(funcs + ord * 4, true);
    if (!rva || (rva >= dir.rva && rva < dir.rva + dir.size)) continue; // forwarder string
    const s = off(dv.getUint32(names + i * 4, true));
    if (s < 0) continue;
    let e = s;
    while (e < chunk.length && chunk[e] !== 0 && e - s < 512) e++;
    out.push({ name: new TextDecoder("latin1").decode(chunk.subarray(s, e)), rva });
  }
  return out;
}

const exportCache = new Map<string, { module: string; base: string; list: { name: string; rva: number }[] }>();
const exportLoading = new Map<string, Promise<void>>();

/** Reads the export directory of each module not cached yet (a page plus the directory each). */
export async function loadExports(modules: readonly Module[]): Promise<number> {
  await Promise.all(modules.map((m) => {
    const k = keyOf(m);
    if (exportCache.has(k)) return Promise.resolve();
    let p = exportLoading.get(k);
    if (!p) {
      p = (async () => {
        const hdr = await readBytes(toBig(m.base), 0x1000).catch(() => null);
        const dir = hdr ? exportDirOf(hdr) : null;
        let list: { name: string; rva: number }[] = [];
        if (dir && dir.rva < m.size) {
          // the name strings normally follow the directory; read a little past it for the rest
          const len = Math.min(m.size - dir.rva, Math.max(dir.size, 0x10000) + 0x10000, 16 << 20);
          const chunk = await readRange(toBig(m.base) + BigInt(dir.rva), len).catch(() => null);
          if (chunk) list = parseExportChunk(chunk, dir.rva, dir);
        }
        exportCache.set(k, { module: m.name, base: m.base, list });
      })().finally(() => exportLoading.delete(k));
      exportLoading.set(k, p);
    }
    return p;
  }));
  return [...exportCache.values()].reduce((n, e) => n + e.list.length, 0);
}

// ---- strings ------------------------------------------------------------------------------------

const stringCache = new Map<string, { module: string; base: string; list: FoundString[] }>();

/** The Strings view hands over what it extracted, so search can include it. */
export function rememberStrings(m: Module, list: FoundString[]): void {
  stringCache.set(keyOf(m), { module: m.name, base: m.base, list });
}

export function stringModules(): number {
  return stringCache.size;
}

/** Explicit action: extract strings from every module (skipping huge ones). */
export async function extractAllStrings(modules: readonly Module[], onProgress?: (done: number, total: number) => void, signal?: { aborted: boolean }, maxSize = 256 << 20): Promise<number> {
  const list = modules.filter((m) => !stringCache.has(keyOf(m)) && m.size <= maxSize);
  let n = 0;
  for (const [i, m] of list.entries()) {
    if (signal?.aborted) break;
    const img = await loadImage(m).catch(() => null);
    if (img) {
      const s = extractStrings(img, 5);
      rememberStrings(m, s);
      n += s.length;
    }
    onProgress?.(i + 1, list.length);
  }
  return n;
}

/** Drops cached exports and strings (new target). */
export function clearSearchCaches(): void {
  exportCache.clear();
  stringCache.clear();
}

let started = false;
/** Clears the caches whenever another target is attached. */
export function startSearchCaches(): void {
  if (started) return;
  started = true;
  useConn.subscribe((s, prev) => {
    if (s.target?.pid !== prev.target?.pid) clearSearchCaches();
  });
}

// ---- items --------------------------------------------------------------------------------------

/** Everything searchable right now, from the stores and the caches above. */
export function collectItems(modules: readonly Module[]): SearchItem[] {
  const out: SearchItem[] = [];
  const live = new Set(modules.map(keyOf));
  // names saved for an earlier base of a module (or another target) point nowhere now
  const stale = (a: string) => modules.length > 0 && !moduleOf(toBig(a), modules);
  for (const n of useNames.getState().names) {
    const address = "0x" + n.address.replace(/^0x/, "").replace(/^0+(?=.)/, "");
    const st = stale(address);
    const where = st ? `${address} · not in a loaded module` : address;
    if (n.name) out.push({ kind: "name", text: n.name, address, detail: where, stale: st });
    if (n.comment) out.push({ kind: "comment", text: n.comment, address, detail: n.name ? `${n.name}${st ? " · not loaded" : ""}` : where, stale: st });
  }
  for (const b of useWatch.getState().bookmarks) out.push({ kind: "bookmark", text: b.label || b.address, address: b.address, detail: b.label ? b.address : undefined });
  for (const w of useWatch.getState().watches) if (w.label) out.push({ kind: "bookmark", text: w.label, address: w.address, detail: `watch · ${w.type}`, ref: "watch" });
  for (const s of useSigs.getState().sigs) out.push({ kind: "signature", text: s.name || s.ida, address: s.address, detail: s.name ? s.ida : s.module, ref: s.id });
  for (const t of useTypes.getState().types) {
    out.push({ kind: "type", text: t.name, detail: `${t.fields.length} fields`, ref: t.id });
    for (const f of t.fields) if (f.name && !/^(field_|pad_|unk)/i.test(f.name)) out.push({ kind: "field", text: `${t.name}::${f.name}`, detail: f.type, ref: t.id });
  }
  for (const m of modules) out.push({ kind: "module", text: m.name, address: m.base, detail: m.base, ref: m.name });
  for (const [k, e] of exportCache) {
    if (!live.has(k)) continue;
    const base = toBig(e.base);
    for (const x of e.list) out.push({ kind: "export", text: x.name, detail: e.module, address: fmtAddr(base + BigInt(x.rva)) });
  }
  for (const [k, e] of stringCache) {
    if (!live.has(k)) continue;
    const base = toBig(e.base);
    for (const s of e.list) out.push({ kind: "string", text: s.text.length > 200 ? s.text.slice(0, 200) + "…" : s.text, detail: `${e.module}${s.wide ? " · utf16" : ""}`, address: fmtAddr(base + BigInt(s.rva)) });
  }
  return out;
}
