// PDB support in the app: find a module's PDB by its CodeView identity, load it through the relay
// (local folders / symbol stores / cache first; symbol servers only when the user asks or enabled
// auto-download), name its functions and data, and answer prototype / source-line / type queries.
import { request } from "./client";
import { labelAddr, moduleOf, toBig, type Module } from "./hex";
import { readBytes } from "./memory";
import { readCodeView } from "./analysis/peextra";
import { pdbCatalog, type PdbLayout } from "./analysis/pdbtypes";
import type { Proto } from "./analysis/pseudocode";
import { modulePath } from "./modfile";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { log } from "@/store/output";
import { entryId, pdbFunctionAt, pdbSymbolAt, useSymbols, type PdbEntry, type PdbSym } from "@/store/symbols";
import { useTypes } from "@/store/types";

export type CodeViewId = { pdb: string; key: string; guid: string; age: number; path: string };

const cvCache = new Map<string, Promise<CodeViewId | null>>();

/** The RSDS record of a loaded module, read from its headers in memory (three small reads). */
export function codeviewOf(m: Module): Promise<CodeViewId | null> {
  const key = entryId(m);
  let p = cvCache.get(key);
  if (!p) {
    const base = toBig(m.base);
    p = readCodeView((rva, size) => (rva + size <= m.size || !m.size ? readBytes(base + BigInt(rva), size) : Promise.resolve(null))).then((cv) =>
      cv ? { pdb: cv.path.split(/[\\/]/).pop() ?? cv.path, key: cv.symbolKey, guid: cv.guid, age: cv.age, path: cv.path } : null,
    );
    cvCache.set(key, p);
    p.catch(() => cvCache.delete(key));
  }
  return p;
}

function settingsArgs() {
  const s = useSymbols.getState();
  return { symbol_path: s.symbolPath, use_env: s.useEnv, servers: s.servers.filter((x) => x.trim()) };
}

type SymbolsReply = {
  success: boolean; found?: boolean; code?: number; message?: string; detail?: string; tried?: string[]; mismatches?: { path: string; key: string }[];
  path: string; source: string; guid: string; age: number; key: string; matched: boolean;
  count: number; functions: number; types: number; lines: number; files: number; symbols: PdbSym[];
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const inflight = new Map<string, Promise<PdbEntry>>();

/** Downloads the PDB in the background (pdb_fetch) and follows its progress in the store. */
async function download(id: string, cv: CodeViewId, extra: Record<string, unknown>): Promise<void> {
  const st = useSymbols.getState();
  const job = `${cv.pdb}/${cv.key}`;
  const r = await request<{ state: string; job?: string }>("pdb_fetch", { pdb: cv.pdb, key: cv.key, ...settingsArgs(), ...extra });
  if (r.state === "done") return;
  log("info", "symbols", `downloading ${cv.pdb} (${cv.key}) from ${st.servers.join(", ") || "the symbol servers"}`);
  for (;;) {
    await sleep(250);
    const p = await request<{ jobs: { job: string; state: string; done: number; total: number | null; url: string; error?: string }[] }>("pdb_progress");
    const j = p.jobs.find((x) => x.job === (r.job ?? job));
    if (!j) throw new Error("the download job disappeared (relay restarted?)");
    const cur = useSymbols.getState().entries[id];
    useSymbols.getState().upsert(id, { module: cur.module, base: cur.base, status: "downloading", progress: { done: j.done, total: j.total, url: j.url } });
    if (j.state === "error") throw new Error(j.error ?? "download failed");
    if (j.state === "done") return;
  }
}

export type LoadOpts = {
  /** ask the symbol servers when no local copy matches (default: the auto-download setting) */
  download?: boolean;
  /** with applyNames: replace names the user already gave */
  overwrite?: boolean;
  /** load a PDB of another build when that is all there is */
  allowMismatch?: boolean;
  /** also copy the symbol names into the (persisted, exported) names store; lookups already fall
   *  back to the loaded PDB, so this is only for exporting them with the user's names */
  applyNames?: boolean;
};

/** Finds, loads and applies the module's PDB; the store entry tracks every step. */
export function loadPdb(m: Module, opts: LoadOpts = {}): Promise<PdbEntry> {
  const id = entryId(m);
  const running = inflight.get(id);
  if (running) return running;
  const p = doLoad(m, id, opts).finally(() => inflight.delete(id));
  inflight.set(id, p);
  return p;
}

async function doLoad(m: Module, id: string, opts: LoadOpts): Promise<PdbEntry> {
  const st = useSymbols.getState();
  const base = { module: m.name, base: "0x" + toBig(m.base).toString(16), size: m.size };
  st.upsert(id, { ...base, status: "loading", error: undefined, progress: undefined });
  try {
    const cv = await codeviewOf(m);
    if (!cv) throw new Error(`${m.name} has no CodeView (RSDS) debug entry: it does not name a PDB`);
    st.upsert(id, { ...base, pdb: cv.pdb, expected: cv.key, guid: cv.guid, age: cv.age });
    const image = await modulePath(m).catch(() => null);
    const extra: Record<string, unknown> = { ...(image ? { image_path: image } : {}), ...(opts.allowMismatch ? { allow_mismatch: true } : {}) };
    const ask = () => request<SymbolsReply>("pdb_symbols", { pdb: cv.pdb, key: cv.key, ...settingsArgs(), ...extra }, true);
    let r = await ask();
    if (!r.success && r.found === false && (opts.download ?? st.autoDownload)) {
      st.upsert(id, { ...base, status: "downloading", progress: { done: 0, total: null, url: "" } });
      await download(id, cv, extra);
      r = await ask();
    }
    if (!r.success) {
      const missing = r.found === false;
      useSymbols.getState().upsert(id, { ...base, status: missing ? "missing" : "error", error: r.detail ? `${r.message}: ${r.detail}` : r.message ?? "symbols unavailable", tried: r.tried, mismatches: r.mismatches, progress: undefined });
      return useSymbols.getState().entries[id];
    }
    useSymbols.getState().upsert(id, {
      ...base, status: "loaded", error: undefined, progress: undefined, tried: r.tried, mismatches: undefined,
      path: r.path, key: r.key, loadedGuid: r.guid, loadedAge: r.age, matched: r.matched, source: r.source,
      counts: { symbols: r.count, functions: r.functions, types: r.types, lines: r.lines, files: r.files },
      symbols: r.symbols,
    });
    let applied = 0;
    if (opts.applyNames) {
      const b = toBig(m.base);
      applied = useNames.getState().bulkRename(r.symbols.map((s) => ({ address: "0x" + (b + BigInt(s.rva)).toString(16), name: s.name })), opts.overwrite, `PDB names for ${m.name}`);
    }
    log("info", "symbols", `${m.name}: ${r.count} symbols from ${r.path} (${r.source}${r.matched ? "" : ", OTHER BUILD"})${opts.applyNames ? `, ${applied} names copied` : ""}`);
    return useSymbols.getState().entries[id];
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    useSymbols.getState().upsert(id, { ...base, status: "error", error: msg, progress: undefined });
    throw e;
  }
}

let started = false;

/** "Load on attach": PDBs for every module with a CodeView entry, local copies first, the servers
 *  only with auto-download on. */
export function startSymbols(): void {
  if (started) return;
  started = true;
  const tried = new Set<string>();
  let running = false;
  const run = async () => {
    if (running || !useSymbols.getState().autoLoad) return;
    running = true;
    try {
      for (const m of useConn.getState().modules) {
        const id = entryId(m);
        if (tried.has(id) || useSymbols.getState().entries[id]) continue;
        tried.add(id);
        if (!(await codeviewOf(m).catch(() => null))) continue;
        await loadPdb(m).catch(() => undefined);
      }
    } finally {
      running = false;
    }
  };
  useConn.subscribe((s, prev) => {
    if (s.target?.pid !== prev.target?.pid) {
      tried.clear();
      cvCache.clear();
      useSymbols.getState().clear();
    }
    if (s.modules !== prev.modules) void run();
  });
  useSymbols.subscribe((s, prev) => s.autoLoad && !prev.autoLoad && void run());
}

/** The loaded entry for a module, loading from local copies (never the network) when needed. */
export async function ensurePdb(m: Module): Promise<PdbEntry> {
  const e = useSymbols.getState().entries[entryId(m)];
  if (e?.status === "loaded") return e;
  const r = await loadPdb(m, { download: false });
  if (r.status !== "loaded") throw new Error(`${m.name}: no PDB loaded (${r.error ?? r.status}); load or download it in the Symbols view`);
  return r;
}

// ------------------------------------------------------------------------------------------------
// queries

/** `module!function+0x10` when a PDB names the address, else `module+0xrva`. */
export function symAddr(a: bigint | string, modules: readonly Module[]): string {
  const v = toBig(a);
  const d = pdbSymbolAt(v);
  if (d) return `${d.entry.module}!${d.sym.name}`;
  const f = pdbFunctionAt(v);
  if (f) return `${f.entry.module}!${f.sym.name}${f.offset ? `+0x${f.offset.toString(16)}` : ""}`;
  return labelAddr(v, modules);
}

/** Prototype of the function starting at `address`, for the pseudocode. */
export function protoAt(address: string): Proto | undefined {
  const s = pdbSymbolAt(toBig(address))?.sym;
  if (!s || s.kind !== "function" || !s.params) return undefined;
  return { name: s.name, ret: s.ret ?? "int", params: s.params.map((p) => ({ name: p.name, type: p.type })) };
}

/** `ret name(type a, type b)` of a PDB function symbol. */
export function protoText(s: PdbSym): string {
  if (!s.params) return s.type ? `${s.name} : ${s.type}` : s.name;
  return `${s.ret ?? "void"} ${s.name}(${s.params.map((p) => (p.type === "..." ? "..." : `${p.type} ${p.name}`)).join(", ") || "void"})`;
}

export type SourceLine = { rva: number; size: number; file: string; line: number };
const lineCache = new Map<string, Promise<SourceLine[]>>();

/** Source lines overlapping [from, to) inside one module. */
export async function sourceLines(m: Module, from: bigint, to: bigint): Promise<{ address: bigint; file: string; line: number }[]> {
  const e = useSymbols.getState().entries[entryId(m)];
  if (e?.status !== "loaded" || !e.path || !e.counts?.lines) return [];
  const b = toBig(m.base);
  const rva = Number(from - b);
  const size = Math.max(1, Number(to - from));
  const key = `${e.path}:${rva}:${size}`;
  let p = lineCache.get(key);
  if (!p) {
    p = request<{ lines: SourceLine[] }>("pdb_lines", { path: e.path, rva, size }).then((r) => r.lines);
    lineCache.set(key, p);
    p.catch(() => lineCache.delete(key));
    if (lineCache.size > 500) lineCache.delete(lineCache.keys().next().value!);
  }
  return (await p).map((l) => ({ address: b + BigInt(l.rva), file: l.file, line: l.line }));
}

export type PdbTypeRow = { index: number; name: string; kind: string; size: number; fields?: number; target?: string };

export async function pdbTypes(e: PdbEntry, filter: string, max = 2000): Promise<{ total: number; types: PdbTypeRow[] }> {
  return request<{ total: number; types: PdbTypeRow[] }>("pdb_types", { path: e.path, filter, max });
}

export async function pdbType(e: PdbEntry, which: { name?: string; index?: number }): Promise<PdbLayout & { text: string }> {
  return request<PdbLayout & { text: string }>("pdb_type", { path: e.path, ...which });
}

/** Adds the type (and, unless `nested:false`, every struct/union it embeds) to the Structs catalog. */
export async function importPdbType(e: PdbEntry, which: { name?: string; index?: number }, opts: { nested?: boolean } = {}): Promise<{ id: string; name: string; imported: string[] }> {
  const l = await pdbType(e, which);
  const all = pdbCatalog(l);
  const list = opts.nested === false ? all.slice(0, 1) : all;
  const types = useTypes.getState();
  let rootId = "";
  for (const t of list) {
    const hit = types.find(t.name);
    const id = hit ? (types.update(hit.id, { fields: t.fields }), hit.id) : types.add(t.name, t.fields);
    if (!rootId) rootId = id;
  }
  return { id: rootId, name: l.name, imported: list.map((t) => t.name) };
}

/** Module and loaded entry for an address. */
export function entryForAddress(a: bigint, modules: readonly Module[]): { m: Module; e: PdbEntry | undefined } | null {
  const m = moduleOf(a, modules);
  return m ? { m, e: useSymbols.getState().entries[entryId(m)] } : null;
}
