// Resumable scanner checkpoints (#9): a value scan over thousands of regions is checkpointed
// after every region so a crash, detach or relay restart can resume where it stopped instead of
// starting over. Pure serialization + progress math; storage is pluggable.

export type ScanRegion = { base: string; size: number };

export type ScanCheckpoint = {
  format: "echodebug.scan";
  version: 1;
  id: string;
  /** what is being looked for */
  needle: string; // hex
  vtype: string;
  scanType: "exact" | "changed" | "increased" | "decreased" | "unknown";
  regions: ScanRegion[];
  /** index into `regions` of the next region to scan */
  cursor: number;
  /** result addresses, hex with 0x */
  results: string[];
  done: boolean;
  updatedAt: number;
};

export function newCheckpoint(id: string, needle: string, vtype: string, scanType: ScanCheckpoint["scanType"], regions: ScanRegion[]): ScanCheckpoint {
  return { format: "echodebug.scan", version: 1, id, needle, vtype, scanType, regions, cursor: 0, results: [], done: false, updatedAt: Date.now() };
}

export function serializeCheckpoint(c: ScanCheckpoint): string {
  return JSON.stringify(c);
}

export function deserializeCheckpoint(raw: string): ScanCheckpoint {
  const c = JSON.parse(raw) as ScanCheckpoint;
  if (c.format !== "echodebug.scan" || c.version !== 1) throw new Error("not an echodebug.scan v1 checkpoint");
  if (!Array.isArray(c.regions) || typeof c.cursor !== "number" || !Array.isArray(c.results)) throw new Error("corrupt checkpoint");
  return c;
}

/** Marks `n` more regions scanned, appending found addresses. Sets `done` at the end. */
export function advanceCheckpoint(c: ScanCheckpoint, n: number, found: string[] = []): ScanCheckpoint {
  const cursor = Math.min(c.regions.length, c.cursor + n);
  const seen = new Set(c.results);
  const results = c.results.slice();
  for (const a of found) if (!seen.has(a)) {
    seen.add(a);
    results.push(a);
  }
  return { ...c, cursor, results, done: cursor >= c.regions.length, updatedAt: Date.now() };
}

/** Regions still to scan (the resume point). */
export function remainingRegions(c: ScanCheckpoint): ScanRegion[] {
  return c.regions.slice(c.cursor);
}

export function progress(c: ScanCheckpoint): { done: number; total: number; pct: number } {
  const total = c.regions.length;
  const done = c.cursor;
  return { done, total, pct: total ? done / total : 1 };
}

export type ScanStore = {
  save(id: string, raw: string): Promise<void>;
  load(id: string): Promise<string | null>;
  remove(id: string): Promise<void>;
  list(): Promise<string[]>;
};

/** Default store: IndexedDB under `scan:<id>`. */
export function idbScanStore(): ScanStore {
  return {
    save: async (id, raw) => {
      const { idbSet } = await import("./idb");
      await idbSet(`scan:${id}`, new TextEncoder().encode(raw));
    },
    load: async (id) => {
      const { idbGet } = await import("./idb");
      const b = await idbGet(`scan:${id}`);
      return b ? new TextDecoder().decode(b) : null;
    },
    remove: async (id) => {
      const { idbDel } = await import("./idb");
      await idbDel(`scan:${id}`);
    },
    list: async () => [], // IndexedDB has no cheap key listing here; the UI tracks ids in the session
  };
}
