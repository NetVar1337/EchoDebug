// Patch sets: the journal's live patches saved module-relative (with the build key), applied
// again later (after checking that each site still holds the original bytes), optionally on every
// attach of that build.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { bytesToHex, moduleOf, toBig, type Module } from "./hex";
import { readBytes } from "./memory";
import { writeJournaled } from "./patch";
import { moduleKey } from "./projects";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import type { Patch } from "@/store/patches";

export type PatchSetEntry = { module: string; key: string; rva: number; before: string; written: string; note: string };
export type PatchSet = { format: "echodebug.patchset"; version: 1; name: string; created: number; entries: PatchSetEntry[] };
export type ApplyReport = { applied: number; already: number; conflicts: { entry: PatchSetEntry; found: string }[]; missing: PatchSetEntry[]; otherBuild: number };

export async function toPatchSet(name: string, patches: readonly Patch[], modules: readonly Module[]): Promise<PatchSet> {
  const entries: PatchSetEntry[] = [];
  for (const p of patches) {
    if (p.reverted) continue;
    const a = toBig(p.address);
    const m = moduleOf(a, modules);
    if (!m) continue; // heap patches have no stable address
    entries.push({ module: m.name, key: await moduleKey(m), rva: Number(a - toBig(m.base)), before: p.before, written: p.written, note: p.note });
  }
  return { format: "echodebug.patchset", version: 1, name, created: Date.now(), entries };
}

/** What to do with one entry given the bytes found at its site. */
export function classify(e: PatchSetEntry, found: string): "apply" | "already" | "conflict" {
  if (found === e.written) return "already";
  return found === e.before ? "apply" : "conflict";
}

export async function applyPatchSet(set: PatchSet, modules: readonly Module[], opts: { force?: boolean } = {}): Promise<ApplyReport> {
  if (set?.format !== "echodebug.patchset") throw new Error("not an EchoDebug patch set");
  const r: ApplyReport = { applied: 0, already: 0, conflicts: [], missing: [], otherBuild: 0 };
  for (const e of set.entries) {
    const m = modules.find((x) => x.name.toLowerCase() === e.module.toLowerCase());
    if (!m) { r.missing.push(e); continue; }
    if ((await moduleKey(m)) !== e.key) r.otherBuild++;
    const a = toBig(m.base) + BigInt(e.rva);
    const cur = await readBytes(a, e.before.length / 2).catch(() => null);
    const found = cur ? bytesToHex(cur) : "";
    const c = classify(e, found);
    if (c === "already") { r.already++; continue; }
    if (c === "conflict" && !opts.force) { r.conflicts.push({ entry: e, found }); continue; }
    if (await writeJournaled(a, e.written, `patch set ${set.name}${e.note ? `: ${e.note}` : ""}`)) r.applied++;
  }
  return r;
}

type AutoStore = { sets: PatchSet[]; add: (s: PatchSet) => void; remove: (name: string) => void };

export const useAutoPatches = create<AutoStore>()(
  persist(
    (set) => ({
      sets: [],
      add: (s) => set((st) => ({ sets: [...st.sets.filter((x) => x.name !== s.name), s] })),
      remove: (name) => set((st) => ({ sets: st.sets.filter((x) => x.name !== name) })),
    }),
    { name: "echodebug.patchsets" },
  ),
);

let started = false;
const done = new Set<string>();

/** Applies the auto sets whose modules (same build) appear, once per attach. */
export function startAutoPatches(): void {
  if (started) return;
  started = true;
  useConn.subscribe(async (s, prev) => {
    if (s.modules === prev.modules || !s.target) return;
    for (const set of useAutoPatches.getState().sets) {
      const id = `${s.target.pid}:${set.name}`;
      if (done.has(id)) continue;
      const needed = [...new Set(set.entries.map((e) => e.module.toLowerCase()))];
      if (!needed.every((n) => s.modules.some((m) => m.name.toLowerCase() === n))) continue;
      done.add(id);
      // only re-apply on the same builds
      const builds = await Promise.all(set.entries.map(async (e) => {
        const m = s.modules.find((x) => x.name.toLowerCase() === e.module.toLowerCase())!;
        return (await moduleKey(m)) === e.key;
      }));
      if (!builds.every(Boolean)) {
        log("warn", "patches", `${set.name}: a different build is loaded; not re-applying`);
        continue;
      }
      const r = await applyPatchSet(set, s.modules);
      log(r.conflicts.length ? "warn" : "info", "patches", `${set.name}: ${r.applied} applied, ${r.already} already in place, ${r.conflicts.length} conflicts`);
    }
  });
}
