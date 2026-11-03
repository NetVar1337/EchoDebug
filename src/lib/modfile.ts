// Whole module *file* via the local backend's module_file verb (1 MiB per request), cached.
import { request } from "./client";
import { hexToBytes, toBig, type Module } from "./hex";
import { invoke } from "@tauri-apps/api/core";
import { isTauri } from "./tauri";
import { useConn } from "@/store/conn";

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
