// Saved projects: user analysis state anchored to module-relative RVAs, so
// names, bookmarks, signatures and patches survive ASLR rebases, restarts and
// (with a signature per item) a rebuilt module. Pure helpers; the glue that
// keeps the stores in sync lives in store/projects.ts.
import { fmtAddr, moduleOf, parseAddress, toBig, type Module } from "./hex";

/** Where an entry lives inside a module. `base` is the module base the entry was last resolved against. */
export type Anchor = { module: string; rva: string; base: string; sig?: string };
export type Anchored = { address: string; anchor?: Anchor };
/** Identity of one build of a module: SizeOfImage plus the PE header timestamp (0 when unknown, e.g. ELF). */
export type Build = { size: number; timestamp: number };

export const findModule = (name: string, modules: readonly Module[]) =>
  modules.find((m) => m.name.toLowerCase() === name.toLowerCase());

/** Module-relative form of an absolute address, or null outside every module. */
export function toRva(address: bigint, modules: readonly Module[]): { module: string; rva: bigint; base: string } | null {
  const m = moduleOf(address, modules);
  return m ? { module: m.name, rva: address - toBig(m.base), base: m.base } : null;
}

/** Absolute address of `module+rva` in the current process, or null when the module is not loaded. */
export function fromRva(module: string, rva: bigint, modules: readonly Module[]): bigint | null {
  const m = findModule(module, modules);
  return m ? toBig(m.base) + rva : null;
}

/**
 * Keeps one entry's address and anchor consistent with the loaded modules. Returns the same object
 * when nothing changes. An address still equal to anchor.base + rva was not edited, so it follows a
 * rebase; any other address was changed by the user and is anchored afresh.
 */
export function syncEntry<T extends Anchored>(e: T, modules: readonly Module[], fmt: (a: bigint) => string): T {
  const a = e.anchor;
  const cur = parseAddress(e.address, modules);
  if (a) {
    const m = findModule(a.module, modules);
    if (!m) return e; // module not loaded: keep the last known address
    if (cur === toBig(a.base) + toBig(a.rva)) {
      if (toBig(m.base) === toBig(a.base)) return e;
      return { ...e, address: fmt(toBig(m.base) + toBig(a.rva)), anchor: { ...a, base: m.base } };
    }
  }
  if (cur === null) return e;
  const r = toRva(cur, modules);
  if (!r) return a ? { ...e, anchor: undefined } : e;
  const rva = fmtAddr(r.rva);
  const same = a && a.module === r.module && a.rva === rva;
  if (same && a.base === r.base) return e;
  return { ...e, anchor: { module: r.module, rva, base: r.base, sig: same ? a.sig : undefined } };
}

/** Syncs a list, returning the same array when no entry changed (so store subscribers don't loop). */
export function syncList<T extends Anchored>(list: readonly T[], modules: readonly Module[], fmt: (a: bigint) => string): T[] {
  let changed = false;
  const out = list.map((e) => {
    const n = syncEntry(e, modules, fmt);
    if (n !== e) changed = true;
    return n;
  });
  return changed ? out : (list as T[]);
}

/**
 * zustand persist migration for a store holding an anchored list under `key`. v0 data had absolute
 * addresses only: entries are kept (malformed ones dropped) and get their anchor when their module loads.
 */
export function migrateAnchored(key: string) {
  return (persisted: unknown, version: number): unknown => {
    const s = { ...((persisted ?? {}) as Record<string, unknown>) };
    if (version < 1) {
      const list = Array.isArray(s[key]) ? (s[key] as unknown[]) : [];
      s[key] = list.filter((e) => !!e && typeof (e as Anchored).address === "string");
    }
    return s;
  };
}

export type ScanStatus = "same" | "moved" | "multiple" | "broken";

/** Where a signature that used to match at `oldRva` matches now. */
export function classify(oldRva: bigint | null, hitRvas: readonly bigint[]): { status: ScanStatus; newRva?: bigint } {
  if (hitRvas.length === 0) return { status: "broken" };
  if (hitRvas.length > 1) return { status: "multiple" };
  return { status: oldRva !== null && hitRvas[0] === oldRva ? "same" : "moved", newRva: hitRvas[0] };
}

/** Relocation summary: matched = same RVA, moved = unique new RVA, lost = no signature, no match or ambiguous. */
export function countRelocation(statuses: readonly (ScanStatus | "nosig")[]): { matched: number; moved: number; lost: number } {
  const c = { matched: 0, moved: 0, lost: 0 };
  for (const s of statuses) {
    if (s === "same") c.matched++;
    else if (s === "moved") c.moved++;
    else c.lost++;
  }
  return c;
}

/** PE header TimeDateStamp from the first bytes of a mapped image, 0 if it is not a PE. */
export function peTimestamp(head: Uint8Array): number {
  if (head.length < 0x40 || head[0] !== 0x4d || head[1] !== 0x5a) return 0;
  const v = new DataView(head.buffer, head.byteOffset, head.byteLength);
  const pe = v.getUint32(0x3c, true);
  if (pe + 12 > head.length || v.getUint32(pe, true) !== 0x4550) return 0;
  return v.getUint32(pe + 8, true);
}

export const sameBuild = (a: Build, b: Build) => a.size === b.size && a.timestamp === b.timestamp;

/** One module's items in a project file: store entries with `address` replaced by `rva` (+ relocation `sig`). */
export type ProjectItem = Record<string, unknown> & { rva: string; sig?: string };
export type ProjectFile = {
  format: "echodebug.project";
  version: 1;
  savedAt: string;
  modules: Record<string, Build & { items: Record<string, ProjectItem[]> }>;
  types: unknown[];
};

/** Project-file form of an anchored entry. */
export function toItem(e: Anchored): ProjectItem | null {
  if (!e.anchor) return null;
  const { address: _a, anchor, ...rest } = e;
  return { ...rest, rva: anchor.rva, ...(anchor.sig ? { sig: anchor.sig } : {}) };
}

/**
 * Store entry for a project-file item. When the module is not loaded the address is the bare RVA with
 * base 0, which syncEntry rebases as soon as the module appears.
 */
export function fromItem<T extends Anchored>(module: string, item: ProjectItem, modules: readonly Module[], fmt: (a: bigint) => string): T {
  const { rva, sig, ...rest } = item;
  const m = findModule(module, modules);
  const base = m?.base ?? "0x0";
  return { ...rest, address: fmt(toBig(base) + toBig(rva)), anchor: { module: m?.name ?? module, rva: fmtAddr(toBig(rva)), base, sig } } as unknown as T;
}
