// Per-module projects: names, comments and bookmarks stored relative to their module (RVA) under a
// key that identifies the build (PE timestamp + SizeOfImage, or the ELF build-id). They are saved
// as you work and re-applied when the same build is loaded again, wherever ASLR puts it.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { toBig, type Module } from "./hex";
import { readBytes } from "./memory";
import { useConn } from "@/store/conn";
import { useNames, type NameEntry } from "@/store/names";
import { log } from "@/store/output";
import { useWatch, type Bookmark } from "@/store/watch";

export type ProjectEntry = { rva: number; name: string; comment: string };
export type ProjectBookmark = { rva: number; label: string };
export type Project = { key: string; module: string; updated: number; names: ProjectEntry[]; bookmarks: ProjectBookmark[] };
export type ProjectFile = { format: "echodebug.project"; version: 1; projects: Project[] };

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

/** Names/bookmarks of one module as a project (relative to its base). */
export function collect(m: Module, key: string, names: readonly NameEntry[], bookmarks: readonly Bookmark[]): Project {
  const base = toBig(m.base);
  const end = base + BigInt(m.size);
  const inMod = (a: bigint) => a >= base && a < end;
  return {
    key, module: m.name, updated: Date.now(),
    names: names.map((n) => ({ a: toBig("0x" + n.address), n })).filter((x) => inMod(x.a)).map((x) => ({ rva: Number(x.a - base), name: x.n.name, comment: x.n.comment })),
    bookmarks: bookmarks.map((b) => ({ a: toBig(b.address), b })).filter((x) => inMod(x.a)).map((x) => ({ rva: Number(x.a - base), label: x.b.label })),
  };
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
        const p = collect(m, k, names, bookmarks);
        const old = useProjects.getState().projects[k];
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
  return { format: "echodebug.project", version: 1, projects: Object.values(useProjects.getState().projects) };
}

export function importProjects(f: ProjectFile): number {
  if (f?.format !== "echodebug.project" || !Array.isArray(f.projects)) throw new Error("not an EchoDebug project file");
  for (const p of f.projects) useProjects.getState().put(p);
  applied.clear();
  return f.projects.length;
}
