// Per-module projects: names, comments and bookmarks stored relative to their module (RVA) under a
// key that identifies the build (PE timestamp + SizeOfImage, or the ELF build-id). They are saved
// as you work and re-applied when the same build is loaded again, wherever ASLR puts it.
import { create } from "zustand";
import { persist } from "zustand/middleware";
//
// When a module's build changes (a new key for a module that has a project under an older key),
// saved items can be re-located: every name and bookmark that was given a relocation signature
// (`sig`, made by signProjects) is searched for in the new build and moved to where it matches now.
import { toBig, fmtAddr, type Module } from "./hex";
import { readBytes } from "./memory";
import { request } from "./client";
import { makeSignature, toIda, type Insn } from "./analysis/sigmaker";
import { classify, countRelocation, type Located } from "./analysis/sigrepair";
import { useConn } from "@/store/conn";
import { useNames, type NameEntry } from "@/store/names";
import { log } from "@/store/output";
import { useSigs, type Signature } from "@/store/sigs";
import { useWatch, type Bookmark } from "@/store/watch";

/** `sig`: optional IDA pattern unique at the entry, used to re-locate it in a different build. */
export type ProjectEntry = { rva: number; name: string; comment: string; sig?: string };
export type ProjectBookmark = { rva: number; label: string; sig?: string };
export type Project = { key: string; module: string; updated: number; names: ProjectEntry[]; bookmarks: ProjectBookmark[] };
/** `signatures` (optional) carries the signature catalog along with the module projects. */
export type ProjectFile = { format: "echodebug.project"; version: 1; projects: Project[]; signatures?: Signature[] };

type ProjectStore = {
  projects: Record<string, Project>;
  enabled: boolean;
  put: (p: Project) => void;
  remove: (key: string) => void;
  setEnabled: (on: boolean) => void;
};

export const useProjects = create<ProjectStore>()(
  persist(
    (set) => ({
      projects: {},
      enabled: true,
      put: (p) => set((s) => ({ projects: { ...s.projects, [p.key]: p } })),
      remove: (key) => set((s) => {
        const next = { ...s.projects };
        delete next[key];
        return { projects: next };
      }),
      setEnabled: (enabled) => set({ enabled }),
    }),
    { name: "echodebug.projects" },
  ),
);

/** Build identity from the mapped headers. */
export function moduleKeyFromHeader(name: string, size: number, h: Uint8Array | null): string {
  const lower = name.toLowerCase();
  if (h && h.length >= 0x200) {
    const dv = new DataView(h.buffer, h.byteOffset, h.byteLength);
    if (dv.getUint16(0, true) === 0x5a4d) {
      const nt = dv.getUint32(0x3c, true);
      if (nt + 0x58 <= h.length && dv.getUint32(nt, true) === 0x4550) {
        const ts = dv.getUint32(nt + 8, true);
        const soi = dv.getUint32(nt + 24 + 56, true);
        return `pe:${lower}:${ts.toString(16)}:${soi.toString(16)}`;
      }
    }
    if (h[0] === 0x7f && h[1] === 0x45 && h[2] === 0x4c && h[3] === 0x46 && h[4] === 2) {
      const phoff = Number(dv.getBigUint64(32, true));
      const phnum = dv.getUint16(56, true);
      for (let i = 0; i < phnum; i++) {
        const o = phoff + i * 56;
        if (o + 56 > h.length || dv.getUint32(o, true) !== 4) continue; // PT_NOTE
        let p = Number(dv.getBigUint64(o + 16, true)) - lowestLoad(dv, phoff, phnum);
        const end = p + Number(dv.getBigUint64(o + 40, true));
        while (p + 12 <= end && p + 12 <= h.length) {
          const nsz = dv.getUint32(p, true), dsz = dv.getUint32(p + 4, true), type = dv.getUint32(p + 8, true);
          const desc = p + 12 + ((nsz + 3) & ~3);
          if (type === 3 && desc + dsz <= h.length) return `elf:${lower}:${Array.from(h.subarray(desc, desc + dsz), (x) => x.toString(16).padStart(2, "0")).join("")}`;
          p = desc + ((dsz + 3) & ~3);
        }
      }
    }
  }
  return `mod:${lower}:${size.toString(16)}`;
}

function lowestLoad(dv: DataView, phoff: number, phnum: number): number {
  let lo = Number.MAX_SAFE_INTEGER;
  for (let i = 0; i < phnum; i++) {
    const o = phoff + i * 56;
    if (o + 56 > dv.byteLength) break;
    if (dv.getUint32(o, true) === 1) lo = Math.min(lo, Number(dv.getBigUint64(o + 16, true)));
  }
  return lo === Number.MAX_SAFE_INTEGER ? 0 : lo & ~0xfff;
}

const keys = new Map<string, string>(); // module base → key

export async function moduleKey(m: Module): Promise<string> {
  const hit = keys.get(m.base);
  if (hit) return hit;
  const h = await readBytes(toBig(m.base), 0x1000).catch(() => null);
  const k = moduleKeyFromHeader(m.name, m.size, h);
  keys.set(m.base, k);
  return k;
}

const norm = (a: bigint) => a.toString(16).padStart(16, "0");

/**
 * Names/bookmarks of one module as a project (relative to its base). Relocation signatures of
 * `prev` (the stored project) are kept for entries still at the same RVA.
 */
export function collect(m: Module, key: string, names: readonly NameEntry[], bookmarks: readonly Bookmark[], prev?: Project): Project {
  const base = toBig(m.base);
  const end = base + BigInt(m.size);
  const inMod = (a: bigint) => a >= base && a < end;
  const nameSig = new Map(prev?.names.filter((e) => e.sig).map((e) => [e.rva, e.sig!]));
  const markSig = new Map(prev?.bookmarks.filter((e) => e.sig).map((e) => [e.rva, e.sig!]));
  const withSig = <T extends { rva: number }>(e: T, sigs: Map<number, string>): T => {
    const sig = sigs.get(e.rva);
    return sig ? { ...e, sig } : e;
  };
  return {
    key, module: m.name, updated: Date.now(),
    names: names.map((n) => ({ a: toBig("0x" + n.address), n })).filter((x) => inMod(x.a)).map((x) => withSig({ rva: Number(x.a - base), name: x.n.name, comment: x.n.comment }, nameSig)),
    bookmarks: bookmarks.map((b) => ({ a: toBig(b.address), b })).filter((x) => inMod(x.a)).map((x) => withSig({ rva: Number(x.a - base), label: x.b.label }, markSig)),
  };
}

/** The most recently updated project of the same module under a different build key, if it has entries. */
export function previousBuild(projects: Record<string, Project>, module: string, key: string): Project | null {
  const lower = module.toLowerCase();
  let best: Project | null = null;
  for (const p of Object.values(projects)) {
    if (p.key === key || p.module.toLowerCase() !== lower || !(p.names.length || p.bookmarks.length)) continue;
    if (!best || p.updated > best.updated) best = p;
  }
  return best;
}

export type Relocation = { kind: "name" | "bookmark"; label: string; oldRva: number; newRva?: number; status: Located["status"] | "nosig" };

/**
 * A project moved to another build of its module: every entry with a relocation signature is
 * searched for (`find` returns absolute hit addresses) and moved when it matches once at a new
 * RVA. Entries without a signature, or whose signature is missing or ambiguous, keep their RVA.
 */
export async function relocateProject(p: Project, key: string, m: Module, find: (ida: string) => Promise<string[]>): Promise<{ project: Project; rows: Relocation[] }> {
  const base = toBig(m.base);
  const rows: Relocation[] = [];
  const move = async <T extends { rva: number; sig?: string }>(kind: Relocation["kind"], e: T, label: string): Promise<T> => {
    if (!e.sig) {
      rows.push({ kind, label, oldRva: e.rva, status: "nosig" });
      return e;
    }
    const hits = await find(e.sig).catch(() => [] as string[]);
    const c = classify(BigInt(e.rva), hits.map((h) => toBig(h) - base));
    const row: Relocation = { kind, label, oldRva: e.rva, status: c.status };
    rows.push(row);
    if (c.status !== "moved" || c.rva === undefined) return e;
    row.newRva = Number(c.rva);
    return { ...e, rva: row.newRva };
  };
  const names: ProjectEntry[] = [];
  for (const e of p.names) names.push(await move("name", e, e.name || e.comment));
  const bookmarks: ProjectBookmark[] = [];
  for (const b of p.bookmarks) bookmarks.push(await move("bookmark", b, b.label));
  return { project: { key, module: m.name, updated: Date.now(), names, bookmarks }, rows };
}

/** Merges a project into the live stores at the module's current base (existing entries win). */
export function apply(p: Project, m: Module): { names: number; bookmarks: number } {
  const base = toBig(m.base);
  const cur = useNames.getState().names;
  const have = new Set(cur.map((n) => n.address));
  const add: NameEntry[] = [];
  for (const e of p.names) {
    const addr = norm(base + BigInt(e.rva));
    if (!have.has(addr)) add.push({ address: addr, name: e.name, comment: e.comment });
  }
  // a restore is not an edit: bypass the undo history
  if (add.length) useNames.setState({ names: [...cur, ...add] });
  const w = useWatch.getState();
  const haveB = new Set(w.bookmarks.map((b) => toBig(b.address)));
  let nb = 0;
  for (const b of p.bookmarks) {
    const a = base + BigInt(b.rva);
    if (haveB.has(a)) continue;
    w.addBookmark("0x" + a.toString(16), b.label);
    nb++;
  }
  return { names: add.length, bookmarks: nb };
}

let started = false;
let timer: ReturnType<typeof setTimeout> | null = null;
const applied = new Set<string>(); // module base:key already restored this run

/** Restores projects when modules appear and saves them (debounced) as names/bookmarks change. */
export function startProjects(): void {
  if (started) return;
  started = true;
  const restore = async () => {
    if (!useProjects.getState().enabled) return;
    for (const m of useConn.getState().modules) {
      const k = await moduleKey(m).catch(() => null);
      if (!k || applied.has(`${m.base}:${k}`)) continue;
      applied.add(`${m.base}:${k}`);
      const p = useProjects.getState().projects[k];
      if (p && (p.names.length || p.bookmarks.length)) {
        const r = apply(p, m);
        if (r.names || r.bookmarks) log("info", "project", `${m.name}: restored ${r.names} names and ${r.bookmarks} bookmarks`);
      } else {
        const old = previousBuild(useProjects.getState().projects, m.name, k);
        if (old && !useRelocation.getState().changed.some((c) => c.toKey === k)) {
          useRelocation.setState((s) => ({ changed: [...s.changed, { module: m.name, base: m.base, fromKey: old.key, toKey: k }] }));
          log("warn", "project", `${m.name} is a different build than its saved project; re-locate the saved items from the Names panel`);
        }
      }
    }
  };
  const save = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!useProjects.getState().enabled) return;
      const names = useNames.getState().names;
      const bookmarks = useWatch.getState().bookmarks;
      for (const m of useConn.getState().modules) {
        const k = await moduleKey(m).catch(() => null);
        if (!k) continue;
        const old = useProjects.getState().projects[k];
        const p = collect(m, k, names, bookmarks, old);
        if (p.names.length || p.bookmarks.length || old) useProjects.getState().put(p);
      }
    }, 1500);
  };
  useConn.subscribe((s, prev) => {
    if (s.modules !== prev.modules) {
      if (s.target?.pid !== prev.target?.pid) keys.clear();
      void restore();
    }
  });
  useNames.subscribe((s, prev) => s.names !== prev.names && save());
  useWatch.subscribe((s, prev) => s.bookmarks !== prev.bookmarks && save());
  void restore();
}

export function exportProjects(): ProjectFile {
  return { format: "echodebug.project", version: 1, projects: Object.values(useProjects.getState().projects), signatures: useSigs.getState().sigs };
}

export function importProjects(f: ProjectFile): number {
  if (f?.format !== "echodebug.project" || !Array.isArray(f.projects)) throw new Error("not an EchoDebug project file");
  for (const p of f.projects) useProjects.getState().put(p);
  if (Array.isArray(f.signatures) && f.signatures.length) {
    // saved signatures with the same id are replaced, the rest are added
    const ids = new Set(f.signatures.map((s) => s.id));
    useSigs.setState((s) => ({ sigs: [...f.signatures!, ...s.sigs.filter((x) => !ids.has(x.id))] }));
  }
  applied.clear();
  return f.projects.length;
}

// ---- re-location across builds ----

export type BuildChange = { module: string; base: string; fromKey: string; toKey: string };

type RelocationStore = {
  /** loaded modules whose build has no project yet, but an older build of the same module does */
  changed: BuildChange[];
  busy: string;
  last: { module: string; rows: Relocation[] } | null;
};

export const useRelocation = create<RelocationStore>()(() => ({ changed: [], busy: "", last: null }));

/** Every match of an IDA pattern in a module. */
export async function sigHits(pattern: string, module: string): Promise<string[]> {
  const r = await request<{ results: string[]; success: boolean }>("sig_scan_ida", { pattern, module, find_all: true }, true);
  return r.success ? r.results ?? [] : [];
}

const loaded = (c: BuildChange) => useConn.getState().modules.find((m) => m.base === c.base && m.name.toLowerCase() === c.module.toLowerCase());
const dismiss = (c: BuildChange) => useRelocation.setState((s) => ({ changed: s.changed.filter((x) => x.toKey !== c.toKey) }));

/** Searches the new build for every signed item of the old project, stores the result as the new build's project and applies it. */
export async function relocate(c: BuildChange): Promise<void> {
  const m = loaded(c);
  const old = useProjects.getState().projects[c.fromKey];
  if (!m || !old) return dismiss(c);
  useRelocation.setState({ busy: `re-locating ${m.name}` });
  try {
    const { project, rows } = await relocateProject(old, c.toKey, m, (ida) => sigHits(ida, m.name));
    useProjects.getState().put(project);
    apply(project, m);
    useRelocation.setState({ last: { module: m.name, rows } });
    const n = countRelocation(rows.map((r) => r.status));
    log("info", "project", `${m.name}: ${n.matched} matched, ${n.moved} moved, ${n.lost} lost`);
  } finally {
    useRelocation.setState({ busy: "" });
    dismiss(c);
  }
}

/** Uses the old project's RVAs unchanged in the new build. */
export function keepRvas(c: BuildChange): void {
  const m = loaded(c);
  const old = useProjects.getState().projects[c.fromKey];
  dismiss(c);
  if (!m || !old) return;
  const p = { ...old, key: c.toKey, module: m.name, updated: Date.now() };
  useProjects.getState().put(p);
  apply(p, m);
}

/**
 * Makes a relocation signature for every name, comment and bookmark of the loaded modules that
 * lacks one, so their projects can follow the module into a new build.
 */
export async function signProjects(): Promise<{ made: number; failed: number }> {
  let made = 0;
  let failed = 0;
  try {
    for (const m of useConn.getState().modules) {
      const k = await moduleKey(m).catch(() => null);
      if (!k) continue;
      const p = collect(m, k, useNames.getState().names, useWatch.getState().bookmarks, useProjects.getState().projects[k]);
      const todo = [...p.names, ...p.bookmarks].filter((e) => !e.sig);
      if (!todo.length) continue;
      const base = toBig(m.base);
      for (const [i, e] of todo.entries()) {
        useRelocation.setState({ busy: `signing ${m.name} ${i + 1}/${todo.length}` });
        const listing = await request<{ results: Insn[]; arch?: string }>("disassemble", { address: fmtAddr(base + BigInt(e.rva)), size: 0x200 }, true).catch(() => null);
        const insns = listing?.results ?? [];
        const r = insns.length ? await makeSignature(insns, async (pat) => (await sigHits(pat, m.name)).length, 5, listing?.arch).catch(() => null) : null;
        if (r) {
          e.sig = toIda(r.pattern);
          made++;
        } else failed++;
      }
      useProjects.getState().put({ ...p, updated: Date.now() });
    }
  } finally {
    useRelocation.setState({ busy: "" });
  }
  log("info", "project", `signed: ${made} signature${made === 1 ? "" : "s"} made${failed ? `, ${failed} addresses without a unique signature` : ""}`);
  return { made, failed };
}
