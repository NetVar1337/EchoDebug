// Whole module *file* via the local backend's module_file verb (1 MiB per request), cached.
import { request } from "./client";
import { hexToBytes, type Module } from "./hex";

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
