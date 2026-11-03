// Disassembly cache (#36): keyed by module identity + the patch set applied on top, so a
// re-attach to an unmodified module hits the cache and a patched one never sees stale bytes.
// Bytes live in IndexedDB (large listings); keys and hashing are pure and unit-tested.

/** FNV-1a 64-bit over bytes, hex — fast, dependency-free, fine for cache keys. */
export function hashBytes(b: Uint8Array): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (const x of b) {
    h ^= BigInt(x);
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, "0");
}

/** Hash of the applied patches (address + bytes), so a changed patch set changes the key. */
export function patchsetHash(patches: readonly { address: string; bytes: string }[]): string {
  const h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  let acc = h;
  const mix = (s: string) => {
    for (let i = 0; i < s.length; i++) {
      acc ^= BigInt(s.charCodeAt(i));
      acc = (acc * prime) & 0xffffffffffffffffn;
    }
  };
  for (const p of [...patches].sort((a, b) => (a.address < b.address ? -1 : 1))) {
    mix(p.address);
    mix(":");
    mix(p.bytes);
    mix(";");
  }
  return acc.toString(16).padStart(16, "0");
}

export function disasmCacheKey(module: { base: string; size: number; hash?: string }, patches: readonly { address: string; bytes: string }[] = []): string {
  const ident = module.hash ?? `${module.base}:${module.size}`;
  return `dis:${ident}:${patchsetHash(patches)}`;
}

export type CachedDisasm = {
  key: string;
  module: string;
  base: string;
  /** disassembled lines, one JSON object per line: { address, bytes, text } */
  lines: { address: string; bytes: string; text: string }[];
  cachedAt: number;
};

export async function getCachedDisasm(key: string): Promise<CachedDisasm | null> {
  const { idbGet, idbSet } = await import("./idb");
  void idbSet;
  const raw = await idbGet(key);
  if (!raw) return null;
  try {
    return JSON.parse(new TextDecoder().decode(raw)) as CachedDisasm;
  } catch {
    return null;
  }
}

export async function setCachedDisasm(entry: CachedDisasm): Promise<void> {
  const { idbSet } = await import("./idb");
  await idbSet(entry.key, new TextEncoder().encode(JSON.stringify(entry)));
}
