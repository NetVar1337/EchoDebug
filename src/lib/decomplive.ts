// The decompiler against the live target: builds a function's CFG from the
// backend's disassembly (bounded by .pdata, switch tables resolved from the
// module image), supplies names (user names + imports), string literals and
// struct layouts, and works out how many arguments the direct callees take by
// decompiling their entry signatures (cached, fed back as prototypes).
import { request } from "./client";
import { fmtAddr, moduleOf, toBig, type Module } from "./hex";
import { loadImage } from "./memory";
import { pdataFunctions } from "./live";
import { buildCfg, type Cfg, type CfgLine } from "./analysis/cfg";
import { resolveSwitch } from "./analysis/jumptables";
import { buildStructure, type Cfg as StructCfg } from "./analysis/structure";
import { buildIat } from "./analysis/iat";
import { liftFunction } from "./analysis/irlift";
import { analyzeSignature } from "./analysis/dataflow";
import { layout } from "./analysis/struct";
import { registerPrototypeProvider, type Prototype } from "./analysis/prototypes";
import type { Abi, IrFunc } from "./analysis/ir";
import type { DecompileOptions, StructField } from "./analysis/decompile";
import type { TypeDef } from "@/store/types";

export type LiveFunction = { cfg: Cfg; structure: StructCfg; module: Module | null; img: Uint8Array | null; base: bigint };

const decode = async (a: bigint): Promise<CfgLine[]> =>
  (await request<{ results: CfgLine[] }>("disassemble", { address: fmtAddr(a), size: 0x100 }, true).catch(() => null))?.results ?? [];

/** The function at `entry`: CFG (graph view), the address-ordered structure (decompiler), its module image. */
export async function loadFunction(entry: bigint, modules: readonly Module[], maxInsns = 8000): Promise<LiveFunction> {
  const m = moduleOf(entry, modules) ?? null;
  const img = m ? await loadImage(m).catch(() => null) : null;
  const base = m ? toBig(m.base) : 0n;
  let bounds = m ? { lo: base, hi: base + BigInt(m.size) } : undefined;
  if (m) {
    const fn = (await pdataFunctions(m).catch(() => [])).find((f) => toBig(f.address) <= entry && entry < toBig(f.address) + BigInt(f.size));
    if (fn) bounds = { lo: toBig(fn.address), hi: toBig(fn.address) + BigInt(fn.size) };
  }
  const cfg = await buildCfg(entry, decode, {
    maxInsns,
    bounds,
    switchTargets: img ? (lines, i) => resolveSwitch(lines, i, img, base)?.targets ?? null : undefined,
  });
  return { cfg, structure: structureOf(cfg), module: m, img, base };
}

/** The discovered instructions in address order, re-split into blocks with the switch tables as case edges. */
export function structureOf(cfg: Cfg): StructCfg {
  const lines = cfg.blocks.flatMap((b) => b.lines).sort((a, b) => (toBig(a.address) < toBig(b.address) ? -1 : 1));
  return buildStructure(lines, { switches: cfg.switches });
}

const iats = new WeakMap<Uint8Array, Map<string, string>>();

/** Name lookup: the user's names first, then the module's imports by IAT slot. */
export function liveNameOf(userName: (a: string) => string, img: Uint8Array | null, base: bigint): (a: string) => string {
  let iat: Map<string, string> | undefined;
  if (img) {
    iat = iats.get(img);
    if (!iat) {
      iat = new Map([...buildIat(img, base).byAddress].map(([k, v]) => [k.toLowerCase(), v.name]));
      iats.set(img, iat);
    }
  }
  return (a) => userName(a) || iat?.get("0x" + BigInt(a).toString(16)) || "";
}

/** A printable NUL-terminated ASCII string at `a` inside the image, or null. */
export function imageString(img: Uint8Array | null, base: bigint): (a: bigint) => string | null {
  return (a) => {
    if (!img || a < base || a >= base + BigInt(img.length)) return null;
    const rva = Number(a - base);
    let s = "";
    for (let i = rva; i < img.length && i < rva + 256; i++) {
      const ch = img[i];
      if (ch === 0) return s.length >= 2 ? s : null;
      if (ch === 9 || ch === 10 || ch === 13 || (ch >= 0x20 && ch < 0x7f)) s += String.fromCharCode(ch);
      else return null;
    }
    return null;
  };
}

/** Struct layouts by name, from the Structs view's catalog. */
export function fieldsFrom(types: readonly TypeDef[]): (name: string) => StructField[] | null {
  return (name) => {
    const t = types.find((x) => x.name.toLowerCase() === name.toLowerCase());
    if (!t) return null;
    const lay = layout(t.fields);
    return t.fields.map((f, i) => ({ offset: lay[i].offset, size: lay[i].size, name: f.name || `field_${lay[i].offset.toString(16)}`, type: f.type }));
  };
}

// ---------------------------------------------------------------------------
// callee signatures

const callees = new Map<string, Prototype | null>();
const pending = new Map<string, Promise<void>>();
let providerInstalled = false;

function installProvider(): void {
  if (providerInstalled) return;
  providerInstalled = true;
  // a guess: asked after symbol providers and the built-in table
  registerPrototypeProvider("callee-analysis", (address) => (address ? callees.get(address) ?? null : null), { fallback: true });
}

/** Direct call / tail-call targets of an IR function. */
export function directCallees(ir: IrFunc): string[] {
  const out = new Set<string>();
  const visit = (e: unknown) => {
    const x = e as { k?: string; target?: { k: string; v?: bigint } };
    if (x?.k === "call" && x.target?.k === "c" && x.target.v !== undefined) out.add("0x" + x.target.v.toString(16));
  };
  for (const b of ir.blocks) {
    for (const s of b.stmts) if (s.k === "call") visit(s.call);
    if (b.term.k === "tail") visit(b.term.call);
  }
  return [...out];
}

/**
 * Decompiles the entry signature (argument count, return kind) of up to `limit` direct callees
 * that are not known yet. Resolves when done; the results feed every later decompilation.
 */
export async function analyzeCallees(addresses: readonly string[], modules: readonly Module[], abi: Abi, limit = 24): Promise<number> {
  installProvider();
  const todo = addresses.filter((a) => !callees.has(a)).slice(0, limit);
  await Promise.all(todo.map((a) => {
    let p = pending.get(a);
    if (!p) {
      p = (async () => {
        try {
          const fn = await loadFunction(toBig(a), modules, 3000);
          const ir = liftFunction(fn.structure, { abi });
          analyzeSignature(ir);
          const sig = ir.sig!;
          callees.set(a, { args: sig.args.map((l) => ({ type: l.startsWith("xmm") ? "double" : undefined })), returns: sig.ret === "void" ? "void" : sig.ret === "float" ? "double" : undefined });
        } catch {
          callees.set(a, null);
        } finally {
          pending.delete(a);
        }
      })();
      pending.set(a, p);
    }
    return p;
  }));
  return todo.length;
}

/** The options for decompiling `fn` against the live target. */
export function liveOptions(fn: LiveFunction, o: { abi: Abi; userName: (a: string) => string; types: readonly TypeDef[]; varTypes?: Record<string, string>; unflatten?: boolean }): DecompileOptions {
  installProvider();
  return {
    abi: o.abi,
    entry: fmtAddr(fn.cfg.entry),
    nameOf: liveNameOf(o.userName, fn.img, fn.base),
    stringAt: imageString(fn.img, fn.base),
    fieldsOf: fieldsFrom(o.types),
    varTypes: o.varTypes,
    unflatten: o.unflatten,
  };
}
