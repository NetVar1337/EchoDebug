// IAT hook report (#13): compares the on-disk import table (which dll/function each slot should
// resolve to) with the live slot values. A slot whose live target lands outside the exporting
// module, or in no module at all, is a hook (inline or IAT) worth listing — with the bytes at the
// target so the trampoline can be inspected, and a restore suggestion (write the original target).
import { buildIat, type IatMap, type IatEntry } from "./iat";

export type Mod = { name: string; base: string; size: number };

export type IatHookFinding = {
  entry: IatEntry;
  live: string;
  targetModule: string | null;
  kind: "foreign-module" | "unmapped" | "ok";
  detail: string;
};

/** Which module (if any) contains `addr`. */
export function moduleAt(addr: bigint, modules: readonly Mod[]): string | null {
  for (const m of modules) {
    const base = BigInt(m.base);
    if (addr >= base && addr < base + BigInt(m.size)) return m.name;
  }
  return null;
}

/**
 * `liveValues` maps slot address -> current value (read from the process). The expected home of a
 * slot's target is the dll it was imported from (name match, case-insensitive, .dll optional).
 */
export function analyzeIatHooks(iat: IatMap, liveValues: ReadonlyMap<string, bigint>, modules: readonly Mod[]): IatHookFinding[] {
  const out: IatHookFinding[] = [];
  const home = (dll: string) => dll.toLowerCase().replace(/\.dll$/, "");
  for (const e of iat.entries) {
    const v = liveValues.get(e.address.toLowerCase()) ?? liveValues.get(e.address);
    if (v === undefined) continue;
    const target = moduleAt(v, modules);
    let kind: IatHookFinding["kind"] = "ok";
    let detail = `resolves inside ${target ?? "no module"}`;
    if (target === null) {
      kind = "unmapped";
      detail = "target is in no loaded module (cave/heap shellcode)";
    } else if (target.toLowerCase().replace(/\.dll$/, "") !== home(e.dll)) {
      kind = "foreign-module";
      detail = `expected ${e.dll}, target is in ${target}`;
    }
    out.push({ entry: e, live: `0x${v.toString(16)}`, targetModule: target, kind, detail });
  }
  return out.filter((f) => f.kind !== "ok" || true).sort((a, b) => (a.kind === b.kind ? 0 : a.kind === "unmapped" ? -1 : b.kind === "unmapped" ? 1 : a.kind === "foreign-module" ? -1 : 1));
}

/** Reads every IAT slot of a module image from the live process. */
export async function readLiveIat(img: Uint8Array, base: bigint, readU64: (addr: bigint) => Promise<bigint | null>): Promise<Map<string, bigint>> {
  const iat = buildIat(img, base);
  const out = new Map<string, bigint>();
  await Promise.all(
    iat.entries.map(async (e) => {
      const v = await readU64(BigInt(e.address)).catch(() => null);
      if (v !== null) out.set(e.address.toLowerCase(), v);
    }),
  );
  return out;
}
