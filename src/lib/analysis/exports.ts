// Export table resolution: the names a module exports and the address each
// one lives at. Used to label calls that land in another module's export.
import { parsePe, type PeInfo } from "./pe";

export type ExportEntry = {
  name: string;
  ordinal: number;
  rva: number;
  /** absolute address of the export */
  address: string;
  forwarder?: string;
};

export type ExportMap = {
  /** lowercase name -> entry */
  byName: Map<string, ExportEntry>;
  /** absolute address -> entry */
  byAddress: Map<string, ExportEntry>;
  entries: ExportEntry[];
};

export function buildExports(img: Uint8Array, base: bigint, pe?: PeInfo): ExportMap {
  const byName = new Map<string, ExportEntry>();
  const byAddress = new Map<string, ExportEntry>();
  const entries: ExportEntry[] = [];
  let info = pe;
  if (!info) {
    try {
      info = parsePe(img);
    } catch {
      return { byName, byAddress, entries };
    }
  }
  for (const e of info.exports) {
    if (!e.name) continue; // ordinal-only exports have no symbol name
    const entry: ExportEntry = {
      name: e.name,
      ordinal: e.ordinal,
      rva: e.rva,
      address: "0x" + (base + BigInt(e.rva)).toString(16),
    };
    if (e.forwarder) entry.forwarder = e.forwarder;
    byName.set(e.name.toLowerCase(), entry);
    byAddress.set(entry.address, entry);
    entries.push(entry);
  }
  entries.sort((a, b) => a.rva - b.rva);
  return { byName, byAddress, entries };
}

/** Case-insensitive lookup that also accepts a `dll!name` spelling. */
export function findExport(map: ExportMap, query: string): ExportEntry | null {
  const q = query.trim().toLowerCase();
  if (!q) return null;
  const bang = q.lastIndexOf("!");
  const name = bang >= 0 ? q.slice(bang + 1) : q;
  return map.byName.get(name) ?? null;
}
