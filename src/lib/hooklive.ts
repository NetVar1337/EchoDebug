// Live hook / tamper scan of one module (see analysis/hooks.ts).
import { toBig, type Module } from "./hex";
import { loadImage } from "./memory";
import { readModuleFileBytes } from "./modfile";
import { mapPeFile, parsePe } from "./analysis/pe";
import { diffCode, iatHooks, inlineHooks, rebase, type IatHook, type InlineHook, type ModuleRange, type Patch } from "./analysis/hooks";
import { useConn } from "@/store/conn";

export type HookReport = { module: string; base: bigint; file: string; fileError: string; patches: Patch[]; inline: InlineHook[]; iat: IatHook[] };

export function moduleRanges(): ModuleRange[] {
  return useConn.getState().modules.map((m) => ({ name: m.name, base: toBig(m.base), size: m.size }));
}

export async function scanModuleHooks(m: Module, opts: { file?: boolean } = {}): Promise<HookReport> {
  const base = toBig(m.base);
  const mem = await loadImage(m);
  const pe = parsePe(mem);
  const mods = moduleRanges();
  let patches: Patch[] = [];
  let file = "";
  let fileError = "";
  if (opts.file !== false) {
    try {
      const f = await readModuleFileBytes(m);
      file = f.path;
      const mapped = mapPeFile(f.bytes);
      const fpe = parsePe(mapped);
      if (fpe.timestamp !== pe.timestamp || fpe.sizeOfImage !== pe.sizeOfImage) throw new Error(`${f.path} is a different build than the loaded module`);
      patches = diffCode(mem, rebase(mapped, fpe, base), fpe, base);
    } catch (e) {
      fileError = e instanceof Error ? e.message : String(e);
    }
  }
  return { module: m.name, base, file, fileError, patches, inline: inlineHooks(mem, pe, base, m.size, mods), iat: iatHooks(mem, pe, mods) };
}
