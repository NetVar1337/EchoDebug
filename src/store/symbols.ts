// PDB symbols per loaded module (not persisted: they are re-read from the cache) and the symbol
// settings (persisted). Lookups by address go through a per-module sorted index kept outside the
// reactive state; `version` bumps whenever it changes so views re-render.
import { create } from "zustand";
import { persist } from "zustand/middleware";

export const kDefaultServer = "https://msdl.microsoft.com/download/symbols";

export type PdbParam = { name: string; type: string; size: number };
export type PdbSym = { rva: number; name: string; kind: "function" | "data"; size: number; type?: string; ret?: string; params?: PdbParam[]; mangled?: string };
export type PdbStatus = "idle" | "loading" | "downloading" | "loaded" | "missing" | "error";
export type PdbEntry = {
  /** `${name}@${base}` */
  id: string;
  module: string;
  base: string;
  size: number;
  /** what the image's CodeView entry asks for */
  pdb: string;
  expected: string;
  guid: string;
  age: number;
  status: PdbStatus;
  error?: string;
  tried?: string[];
  mismatches?: { path: string; key: string }[];
  progress?: { done: number; total: number | null; url: string };
  /** what was loaded */
  path?: string;
  key?: string;
  loadedGuid?: string;
  loadedAge?: number;
  matched?: boolean;
  source?: string;
  counts?: { symbols: number; functions: number; types: number; lines: number; files: number };
  symbols: PdbSym[];
};

export type SymbolSettings = {
  /** `_NT_SYMBOL_PATH`-style list: folders, `srv*<store>*<url>`, `cache*<dir>` */
  symbolPath: string;
  servers: string[];
  /** also read `_NT_SYMBOL_PATH` from the relay's environment */
  useEnv: boolean;
  /** download missing PDBs from the servers without asking (network access) */
  autoDownload: boolean;
  /** load PDBs that are already on this machine when modules appear */
  autoLoad: boolean;
};

type Index = { base: bigint; fnStarts: number[]; fns: PdbSym[]; byRva: Map<number, PdbSym> };
const indexes = new Map<string, Index>();

type SymbolsStore = SymbolSettings & {
  entries: Record<string, PdbEntry>;
  version: number;
  setSettings: (p: Partial<SymbolSettings>) => void;
  upsert: (id: string, p: Partial<PdbEntry> & Pick<PdbEntry, "module" | "base">) => void;
  remove: (id: string) => void;
  clear: () => void;
};

function buildIndex(e: PdbEntry): Index {
  const fns = e.symbols.filter((s) => s.kind === "function").sort((a, b) => a.rva - b.rva);
  return { base: BigInt(e.base), fnStarts: fns.map((f) => f.rva), fns, byRva: new Map(e.symbols.map((s) => [s.rva, s])) };
}

export const useSymbols = create<SymbolsStore>()(
  persist(
    (set) => ({
      symbolPath: "",
      servers: [kDefaultServer],
      useEnv: true,
      autoDownload: false,
      autoLoad: false,
      entries: {},
      version: 0,
      setSettings: (p) => set(p),
      upsert: (id, p) =>
        set((s) => {
          const prev: PdbEntry = s.entries[id] ?? { id, module: p.module, base: p.base, size: 0, pdb: "", expected: "", guid: "", age: 0, status: "idle", symbols: [] };
          const next: PdbEntry = { ...prev, ...p, id };
          if (p.symbols) indexes.set(id, buildIndex(next));
          return { entries: { ...s.entries, [id]: next }, version: s.version + (p.symbols ? 1 : 0) };
        }),
      remove: (id) =>
        set((s) => {
          indexes.delete(id);
          const rest = { ...s.entries };
          delete rest[id];
          return { entries: rest, version: s.version + 1 };
        }),
      clear: () => {
        indexes.clear();
        set((s) => ({ entries: {}, version: s.version + 1 }));
      },
    }),
    {
      name: "echodebug.symbols",
      partialize: (s) => ({ symbolPath: s.symbolPath, servers: s.servers, useEnv: s.useEnv, autoDownload: s.autoDownload, autoLoad: s.autoLoad }),
    },
  ),
);

export const entryId = (m: { name: string; base: string }) => `${m.name}@${BigInt(m.base).toString(16)}`;

/** The PDB function containing `addr` (any loaded module), with the offset into it. */
export function pdbFunctionAt(addr: bigint): { entry: PdbEntry; sym: PdbSym; offset: number } | null {
  const entries = useSymbols.getState().entries;
  for (const [id, ix] of indexes) {
    const e = entries[id];
    if (!e || addr < ix.base || addr >= ix.base + BigInt(Math.max(e.size, 1))) continue;
    const rva = Number(addr - ix.base);
    let lo = 0;
    let hi = ix.fnStarts.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (ix.fnStarts[mid] <= rva) lo = mid + 1;
      else hi = mid;
    }
    // nearest start at or before; sizeless publics count up to the next start (at most 4 KiB for the last)
    for (let i = lo - 1; i >= 0 && i >= lo - 8; i--) {
      const f = ix.fns[i];
      const end = f.size ? f.rva + f.size : ix.fnStarts[i + 1] ?? f.rva + 0x1000;
      if (rva < end) return { entry: e, sym: f, offset: rva - f.rva };
      if (f.size) break;
    }
    return null;
  }
  return null;
}

/** The PDB symbol (function or data) starting exactly at `addr`. */
export function pdbSymbolAt(addr: bigint): { entry: PdbEntry; sym: PdbSym } | null {
  const entries = useSymbols.getState().entries;
  for (const [id, ix] of indexes) {
    const e = entries[id];
    if (!e || addr < ix.base || addr >= ix.base + BigInt(Math.max(e.size, 1))) continue;
    const s = ix.byRva.get(Number(addr - ix.base));
    return s ? { entry: e, sym: s } : null;
  }
  return null;
}

/** Function symbols of one module as absolute addresses (for the disassembly's function list). */
export function pdbFunctions(m: { name: string; base: string }): { address: bigint; size: number; name: string }[] {
  const ix = indexes.get(entryId(m));
  if (!ix) return [];
  return ix.fns.map((f, i) => ({ address: ix.base + BigInt(f.rva), size: f.size || Math.max(0, (ix.fnStarts[i + 1] ?? f.rva) - f.rva), name: f.name }));
}
