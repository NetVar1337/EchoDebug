// Saved projects. Names, bookmarks, saved signatures and the patch journal
// keep their absolute `address` (what every view reads) plus an `anchor`
// (module + RVA). This module keeps the two in sync whenever the module list
// or a store changes, remembers each module's build (size + PE timestamp),
// offers to re-locate items by signature when the build changes, and exports
// / imports everything as one project file.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { request } from "@/lib/client";
import { fmtAddr, toBig, type Module } from "@/lib/hex";
import { readBytes } from "@/lib/memory";
import { makeSignature, toIda, type Insn } from "@/lib/analysis/sigmaker";
import {
  classify, countRelocation, findModule, fromItem, peTimestamp, sameBuild, syncList, toItem,
  type Anchored, type Build, type ProjectFile, type ScanStatus,
} from "@/lib/projects";
import { openTextFile, saveTextFile } from "@/lib/session";
import { useConn } from "./conn";
import { useNames, norm } from "./names";
import { usePatches } from "./patches";
import { useSigs } from "./sigs";
import { useTypes, type TypeDef } from "./types";
import { useWatch } from "./watch";
import { log } from "./output";

/** Every match of an IDA pattern in a module, via the native `sig_scan_ida` verb. */
export async function sigHits(pattern: string, module: string): Promise<string[]> {
  const r = await request<{ results: string[]; success: boolean }>("sig_scan_ida", { pattern, module, find_all: true }, true);
  return r.success ? r.results ?? [] : [];
}

type Kind = "name" | "bookmark" | "signature" | "patch";
type Slot = { kind: Kind; get: () => Anchored[]; put: (l: Anchored[]) => void; fmt: (a: bigint) => string; sub: (f: () => void) => void };

const kSlots: Slot[] = [
  { kind: "name", get: () => useNames.getState().names, put: (l) => useNames.setState({ names: l as never }), fmt: (a) => norm(a.toString(16)), sub: (f) => useNames.subscribe(f) },
  { kind: "bookmark", get: () => useWatch.getState().bookmarks, put: (l) => useWatch.setState({ bookmarks: l as never }), fmt: fmtAddr, sub: (f) => useWatch.subscribe(f) },
  { kind: "signature", get: () => useSigs.getState().sigs, put: (l) => useSigs.setState({ sigs: l as never }), fmt: fmtAddr, sub: (f) => useSigs.subscribe(f) },
  { kind: "patch", get: () => usePatches.getState().patches, put: (l) => usePatches.setState({ patches: l as never }), fmt: fmtAddr, sub: (f) => usePatches.subscribe(f) },
];

export type Relocation = { kind: Kind; label: string; module: string; oldRva: string; newRva?: string; status: ScanStatus | "nosig" };
export type BuildChange = { module: string; from: Build; to: Build };

type ProjectsStore = {
  /** lower-cased module name -> the build the saved items belong to */
  builds: Record<string, Build>;
  /** loaded modules whose build differs from the saved one */
  changed: BuildChange[];
  busy: string;
  last: Relocation[] | null;
};

export const useProjects = create<ProjectsStore>()(
  persist((): ProjectsStore => ({ builds: {}, changed: [], busy: "", last: null }), {
    name: "echodebug.projects",
    version: 1,
    partialize: (s) => ({ builds: s.builds }),
  }),
);

const modules = () => useConn.getState().modules;
const label = (e: Anchored) => String((e as { name?: string }).name || (e as { label?: string }).label || (e as { note?: string }).note || e.anchor?.rva || e.address);

function syncAll(): void {
  const mods = modules();
  for (const s of kSlots) {
    const cur = s.get();
    const next = syncList(cur, mods, s.fmt);
    if (next !== cur) s.put(next);
  }
}

/** Modules that have anchored items, so we only read headers we need. */
function usedModules(): Module[] {
  const names = new Set<string>();
  for (const s of kSlots) for (const e of s.get()) if (e.anchor) names.add(e.anchor.module.toLowerCase());
  return modules().filter((m) => names.has(m.name.toLowerCase()));
}

async function buildOf(m: Module): Promise<Build> {
  const head = await readBytes(toBig(m.base), 0x400).catch(() => null);
  return { size: m.size, timestamp: head ? peTimestamp(head) : 0 };
}

/** Records first-seen builds and lists loaded modules whose build changed since the items were saved. */
export async function checkBuilds(): Promise<void> {
  const builds = { ...useProjects.getState().builds };
  const changed: BuildChange[] = [];
  for (const m of usedModules()) {
    const now = await buildOf(m);
    const key = m.name.toLowerCase();
    if (!builds[key]) builds[key] = now;
    else if (!sameBuild(builds[key], now)) changed.push({ module: m.name, from: builds[key], to: now });
  }
  useProjects.setState({ builds, changed });
  for (const c of changed) log("warn", "project", `${c.module} changed build (size 0x${c.from.size.toString(16)} → 0x${c.to.size.toString(16)}); re-locate saved items from the Names panel`);
}

/** Keeps the new build without moving anything. */
export function acceptBuild(module: string, to: Build): void {
  useProjects.setState((s) => ({ builds: { ...s.builds, [module.toLowerCase()]: to }, changed: s.changed.filter((c) => c.module !== module) }));
}

/**
 * Generates the relocation signature for every named/commented address and bookmark that lacks one,
 * and records the current build of each module. Saved signatures relocate with their own pattern.
 */
export async function saveProject(): Promise<void> {
  syncAll();
  const mods = modules();
  let made = 0;
  let failed = 0;
  for (const s of kSlots.filter((x) => x.kind === "name" || x.kind === "bookmark")) {
    const todo = s.get().filter((e) => e.anchor && !e.anchor.sig && findModule(e.anchor.module, mods));
    for (const [i, e] of todo.entries()) {
      useProjects.setState({ busy: `signing ${s.kind}s ${i + 1}/${todo.length}` });
      const a = e.anchor!;
      const addr = fmtAddr(toBig(a.base) + toBig(a.rva));
      const insns = await request<{ results: Insn[] }>("disassemble", { address: addr, size: 0x200 }).then((r) => r.results ?? []).catch(() => []);
      const r = await makeSignature(insns, async (p) => (await sigHits(p, a.module)).length).catch(() => null);
      if (!r) { failed++; continue; }
      made++;
      s.put(s.get().map((x) => (x === e ? { ...x, anchor: { ...a, sig: toIda(r.pattern) } } : x)));
    }
  }
  const builds = { ...useProjects.getState().builds };
  for (const m of usedModules()) builds[m.name.toLowerCase()] = await buildOf(m);
  useProjects.setState({ builds, changed: [], busy: "" });
  log("info", "project", `saved: ${made} signature${made === 1 ? "" : "s"} made${failed ? `, ${failed} addresses without a unique signature` : ""}`);
}

/** Scans every item of a changed module in its new build and moves the ones whose signature now matches elsewhere. */
export async function relocate(change: BuildChange): Promise<void> {
  const m = findModule(change.module, modules());
  if (!m) return;
  const out: Relocation[] = [];
  // Patches keep their RVA: bytes journalled against the old build mean nothing in a new one.
  for (const s of kSlots.filter((x) => x.kind !== "patch")) {
    const items = s.get().filter((e) => e.anchor?.module.toLowerCase() === m.name.toLowerCase());
    const moved = new Map<Anchored, bigint>();
    for (const [i, e] of items.entries()) {
      useProjects.setState({ busy: `re-locating ${s.kind}s ${i + 1}/${items.length}` });
      const a = e.anchor!;
      const sig = a.sig ?? (s.kind === "signature" ? (e as { ida?: string }).ida : undefined);
      const row: Relocation = { kind: s.kind, label: label(e), module: m.name, oldRva: a.rva, status: "nosig" };
      if (sig) {
        const hits = await sigHits(sig, m.name).catch(() => []);
        const c = classify(toBig(a.rva), hits.map((h) => toBig(h) - toBig(m.base)));
        row.status = c.status;
        if (c.status === "moved" && c.newRva !== undefined) {
          row.newRva = fmtAddr(c.newRva);
          moved.set(e, c.newRva);
        }
      }
      out.push(row);
    }
    if (moved.size)
      s.put(s.get().map((e) => {
        const rva = moved.get(e);
        return rva === undefined ? e : { ...e, address: s.fmt(toBig(m.base) + rva), anchor: { ...e.anchor!, rva: fmtAddr(rva), base: m.base } };
      }));
  }
  acceptBuild(m.name, change.to);
  useProjects.setState({ busy: "", last: out });
  const c = countRelocation(out.map((r) => r.status));
  log("info", "project", `${m.name}: ${c.matched} matched, ${c.moved} moved, ${c.lost} lost`);
}

export function buildProject(): ProjectFile {
  syncAll();
  const builds = useProjects.getState().builds;
  const file: ProjectFile = { format: "echodebug.project", version: 1, savedAt: new Date().toISOString(), modules: {}, types: useTypes.getState().types };
  for (const s of kSlots)
    for (const e of s.get()) {
      const item = toItem(e);
      if (!item) continue; // not inside a module: absolute addresses don't survive a restart, so they are not exported
      const key = e.anchor!.module.toLowerCase();
      const mod = (file.modules[key] ??= { ...(builds[key] ?? { size: 0, timestamp: 0 }), items: {} });
      (mod.items[s.kind] ??= []).push(item);
    }
  return file;
}

/** Merges a project file into the stores; items at the same module+RVA (or with the same id) are replaced. */
export function applyProject(data: ProjectFile): boolean {
  if (!data || data.format !== "echodebug.project" || typeof data.modules !== "object") {
    log("error", "project", "not an EchoDebug project file");
    return false;
  }
  const mods = modules();
  const builds = { ...useProjects.getState().builds };
  let n = 0;
  for (const s of kSlots) {
    const incoming: Anchored[] = [];
    for (const [module, m] of Object.entries(data.modules))
      for (const item of m.items?.[s.kind] ?? []) incoming.push(fromItem(module, item, mods, s.fmt));
    if (!incoming.length) continue;
    n += incoming.length;
    const key = (e: Anchored) => (e as { id?: string }).id ?? `${e.anchor?.module.toLowerCase()}+${e.anchor?.rva}`;
    const keys = new Set(incoming.map(key));
    s.put([...s.get().filter((e) => !keys.has(key(e))), ...incoming]);
  }
  for (const [module, m] of Object.entries(data.modules)) if (m.size) builds[module.toLowerCase()] = { size: m.size, timestamp: m.timestamp };
  useProjects.setState({ builds });
  if (Array.isArray(data.types) && data.types.length) {
    const have = new Set(useTypes.getState().types.map((t) => t.id));
    useTypes.getState().setTypes([...useTypes.getState().types, ...(data.types as TypeDef[]).filter((t) => !have.has(t.id))]);
  }
  log("info", "project", `imported ${n} items for ${Object.keys(data.modules).length} modules`);
  void checkBuilds();
  return true;
}

export async function exportProject(): Promise<void> {
  const path = await saveTextFile("echodebug-project.json", JSON.stringify(buildProject(), null, 2), "EchoDebug project");
  if (path) log("info", "project", `exported to ${path}`);
}

export async function importProject(): Promise<boolean> {
  const text = await openTextFile("EchoDebug project");
  return text !== null && applyProject(JSON.parse(text) as ProjectFile);
}

// Keep anchors in sync with the module list and every store, app-wide.
let lastMods: Module[] = [];
useConn.subscribe((s) => {
  if (s.modules === lastMods) return;
  lastMods = s.modules;
  syncAll();
  if (s.modules.length) void checkBuilds().catch((e) => log("warn", "project", String(e)));
});
for (const s of kSlots) s.sub(syncAll);
