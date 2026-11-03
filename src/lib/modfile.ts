// Whole module *file* via the local backend's module_file verb (1 MiB per request), cached.
import { request } from "./client";
import { hexToBytes, toBig, type Module } from "./hex";
import { invoke } from "@tauri-apps/api/core";
import { isTauri } from "./tauri";
import { loadImage } from "./memory";
import { parsePe } from "./analysis/pe";
import { parseDebug } from "./analysis/peextra";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";

const files = new Map<string, Promise<{ bytes: Uint8Array; path: string }>>();

export function loadModuleFile(m: Module, onProgress?: (done: number, total: number) => void): Promise<{ bytes: Uint8Array; path: string }> {
  const key = `${m.name}@${m.base}`;
  let p = files.get(key);
  if (!p) {
    p = (async () => {
      const first = await request<{ data: string; file_size: number; path: string }>("module_file", { module: m.name, offset: 0, size: 0x100000 });
      const total = first.file_size;
      const out = new Uint8Array(total);
      out.set(hexToBytes(first.data));
      const chunks = Math.ceil(total / 0x100000);
      onProgress?.(1, chunks);
      for (let i = 1; i < chunks; i++) {
        const r = await request<{ data: string }>("module_file", { module: m.name, offset: i * 0x100000, size: 0x100000 });
        out.set(hexToBytes(r.data), i * 0x100000);
        onProgress?.(i + 1, chunks);
      }
      return { bytes: out, path: first.path };
    })();
    files.set(key, p);
    p.catch(() => files.delete(key));
  }
  return p;
}


/** Full path of a module: the loader's list (PEB walk / link_map), else the module_file verb. */
export async function modulePath(m: Module): Promise<string | null> {
  const r = await request<{ modules: { name: string; base: string }[] }>("peb_walk", {}, true).catch(() => null);
  const hit = r?.modules?.find((x) => toBig(x.base) === toBig(m.base) || x.name.split(/[\\/]/).pop()?.toLowerCase() === m.name.toLowerCase());
  if (hit?.name && /[\\/]/.test(hit.name)) return hit.name;
  const f = await request<{ path: string }>("module_file", { module: m.name, offset: 0, size: 1 }, true).catch(() => null);
  return f?.path ?? null;
}

/** The module's file on disk: via the relay on the local backend, via the app on Windows. */
export async function readModuleFileBytes(m: Module): Promise<{ bytes: Uint8Array; path: string }> {
  if (useConn.getState().backend === "local") return loadModuleFile(m);
  const path = await modulePath(m);
  if (!path) throw new Error(`cannot find the file behind ${m.name}`);
  if (!isTauri()) throw new Error("reading module files needs the desktop app");
  const bytes = await invoke<number[]>("read_binary_file", { path });
  return { bytes: new Uint8Array(bytes), path };
}

export type SymbolLoad = { path: string; guid: string; count: number; named: number };

/** Fetches the module's PDB (by its CodeView identity) and names every function and data symbol. */
export async function loadPdbSymbols(m: Module, opts: { overwrite?: boolean; servers?: string[] } = {}): Promise<SymbolLoad> {
  const img = await loadImage(m);
  const cv = parseDebug(img, parsePe(img)).find((d) => d.codeview)?.codeview;
  if (!cv) throw new Error(`${m.name} has no CodeView debug entry (no PDB reference)`);
  const pdb = cv.path.split(/[\\/]/).pop() ?? cv.path;
  const r = await request<{ path: string; guid: string; symbols: { rva: number; name: string; kind: string }[] }>("pdb_symbols", { pdb, key: cv.symbolKey, ...(opts.servers ? { servers: opts.servers } : {}) });
  const names = useNames.getState();
  const base = toBig(m.base);
  let named = 0;
  for (const s of r.symbols) {
    const a = "0x" + (base + BigInt(s.rva)).toString(16);
    if (!opts.overwrite && names.nameOf(a)) continue;
    names.rename(a, s.name);
    named++;
  }
  return { path: r.path, guid: r.guid, count: r.symbols.length, named };
}
