// The patch journal in x64dbg's terms: export / import `.1337` patch files, and "Patch file"
// (the patches written into a copy of the module's file on disk). See analysis/patchfile.ts.
import { fmtAddr, moduleOf, toBig, type Module } from "./hex";
import { readBytes } from "./memory";
import { readModuleFileBytes } from "./modfile";
import { writeJournaled } from "./patch";
import { bytePatches, patchFile, type BytePatch, type PatchFileReport } from "./analysis/patchfile";
import type { Patch } from "@/store/patches";

/** Active journal entries inside modules as per-byte patches (heap patches have no RVA). */
export function journalBytePatches(pending: readonly Patch[], modules: readonly Module[]): { patches: BytePatch[]; outside: number } {
  let outside = 0;
  const rows: { module: string; rva: number; before: string; written: string }[] = [];
  for (const p of pending) {
    const a = toBig(p.address);
    const m = moduleOf(a, modules);
    if (!m) { outside++; continue; }
    rows.push({ module: m.name, rva: Number(a - toBig(m.base)), before: p.before, written: p.written });
  }
  return { patches: bytePatches(rows), outside };
}

export type Apply1337Report = { applied: number; already: number; conflicts: { module: string; rva: number; found: number | null; expected: number }[]; missing: string[] };

/** Applies x64dbg patches where the original byte is still there (journalled, so revertible). */
export async function apply1337(patches: readonly BytePatch[], modules: readonly Module[], force = false): Promise<Apply1337Report> {
  const r: Apply1337Report = { applied: 0, already: 0, conflicts: [], missing: [] };
  const byName = (n: string) => modules.find((m) => m.name.toLowerCase() === n.toLowerCase());
  // contiguous runs per module, one read and one write each
  const runs: { m: Module; rva: number; bytes: BytePatch[] }[] = [];
  for (const p of patches) {
    const m = byName(p.module);
    if (!m) { if (!r.missing.includes(p.module)) r.missing.push(p.module); continue; }
    const last = runs[runs.length - 1];
    if (last && last.m === m && last.rva + last.bytes.length === p.rva) last.bytes.push(p);
    else runs.push({ m, rva: p.rva, bytes: [p] });
  }
  for (const run of runs) {
    const at = toBig(run.m.base) + BigInt(run.rva);
    const cur = await readBytes(at, run.bytes.length);
    const write: number[] = [];
    run.bytes.forEach((b, i) => {
      const found = cur?.[i] ?? null;
      if (found === b.new) { r.already++; write.push(b.new); return; }
      if (found !== b.old && !force) { r.conflicts.push({ module: run.m.name, rva: b.rva, found, expected: b.old }); write.push(found ?? b.old); return; }
      write.push(b.new);
      r.applied++;
    });
    if (cur && write.some((v, i) => v !== cur[i])) {
      if (!(await writeJournaled(at, Uint8Array.from(write), `.1337 ${run.m.name}+0x${run.rva.toString(16)}`))) throw new Error(`write failed at ${fmtAddr(at)}`);
    }
  }
  return r;
}

/** The module's file on disk with its patches applied (not written anywhere yet). */
export async function patchedModuleFile(m: Module, patches: readonly BytePatch[]): Promise<{ bytes: Uint8Array; path: string; report: PatchFileReport }> {
  const mine = patches.filter((p) => p.module.toLowerCase() === m.name.toLowerCase());
  if (!mine.length) throw new Error(`no active patches in ${m.name}`);
  const f = await readModuleFileBytes(m);
  const { bytes, report } = patchFile(f.bytes, mine);
  return { bytes, path: f.path, report };
}
