// Live drivers for the engine dumpers (analysis/engines/*): Unreal objects + SDK, Unity IL2CPP
// metadata + method RVAs, Source netvars.
import { invoke } from "@tauri-apps/api/core";
import { fmtAddr, toBig, type Module } from "./hex";
import { request } from "./client";
import { loadImage, readBytes, readU64 } from "./memory";
import { readMany } from "./batch";
import { searchMemory } from "./memsearch";
import { parsePe } from "./analysis/pe";
import { dumpObjects, findNamePools, findObjectArrays, kDefaultOffsets, LegacyNames, NamePool, ObjectArray, readStruct, ripTarget, sdkText, type Mem, type Names, type Offsets, type ObjectDump, type SdkStruct, type UnrealSig } from "./analysis/engines/unreal";
import { applyMethodPointers, isMetadata, parseMetadata, type Il2CppMetadata } from "./analysis/engines/il2cpp";
import { dumpNetvars, type NetvarDump } from "./analysis/engines/source";
import { useConn } from "@/store/conn";

const kPage = 0x1000;

/** Mem over the target with a page cache and batched page fetches (read_batch). */
export class CachedMem implements Mem {
  private pages = new Map<bigint, Uint8Array | null>();
  async fetch(pages: bigint[]): Promise<void> {
    const want = [...new Set(pages)].filter((p) => !this.pages.has(p));
    for (let i = 0; i < want.length; i += 256) {
      const chunk = want.slice(i, i + 256);
      const got = await readMany(chunk.map((p) => ({ address: fmtAddr(p), size: kPage }))).catch(() => null);
      if (got) chunk.forEach((p, k) => this.pages.set(p, got[k]));
      else for (const p of chunk) this.pages.set(p, await readBytes(p, kPage).catch(() => null));
    }
  }
  private span(a: bigint, n: number): bigint[] {
    const out: bigint[] = [];
    for (let p = a & ~0xfffn; p < a + BigInt(n); p += BigInt(kPage)) out.push(p);
    return out;
  }
  async read(a: bigint, n: number): Promise<Uint8Array | null> {
    if (n > 0x100000) return readBytes(a, n);
    const pages = this.span(a, n);
    await this.fetch(pages);
    const out = new Uint8Array(n);
    for (const p of pages) {
      const b = this.pages.get(p);
      if (!b) return null;
      const from = a > p ? Number(a - p) : 0;
      const to = Math.min(kPage, Number(a + BigInt(n) - p));
      out.set(b.subarray(from, to), Number(p + BigInt(from) - a));
    }
    return out;
  }
  async readMany(reads: { address: bigint; size: number }[]): Promise<(Uint8Array | null)[]> {
    await this.fetch(reads.flatMap((r) => this.span(r.address, r.size)));
    return Promise.all(reads.map((r) => this.read(r.address, r.size)));
  }
}

function mainModule(): Module | undefined {
  const c = useConn.getState();
  return c.modules.find((m) => m.base === c.target?.base) ?? [...c.modules].sort((a, b) => b.size - a.size)[0];
}

function findModule(re: RegExp): Module | undefined {
  return useConn.getState().modules.find((m) => re.test(m.name));
}

async function dataRanges(m: Module): Promise<{ img: Uint8Array; ranges: { rva: number; size: number }[] }> {
  const img = await loadImage(m);
  const pe = parsePe(img);
  const ranges = pe.sections.filter((s) => !s.x && s.r).map((s) => ({ rva: s.rva, size: Math.max(s.vsize, s.rawSize) }));
  return { img, ranges };
}

export type EngineGuess = { engine: "unreal" | "unity-il2cpp" | "source" | "unknown"; module: string };

export function guessEngine(): EngineGuess {
  if (findModule(/^gameassembly\.dll$/i)) return { engine: "unity-il2cpp", module: "GameAssembly.dll" };
  const client = findModule(/^client(64)?\.(dll|so)$/i);
  if (client && findModule(/^engine(2)?\.(dll|so)$/i)) return { engine: "source", module: client.name };
  const main = mainModule();
  if (main && (findModule(/^(UE4|UE5)/i) || main.size > 40 << 20)) return { engine: "unreal", module: main.name };
  return { engine: "unknown", module: main?.name ?? "" };
}

// ---- Unreal ------------------------------------------------------------------------------------

export type UnrealSession = { mem: CachedMem; names: Names; objects: ObjectArray; dump: ObjectDump; module: string; namesAddr: bigint; objectsAddr: bigint };

const moduleNamed = (name?: string) => (name && findModule(new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "i"))) || mainModule();

/** The name table at `address`: FNamePool (4.23+), or legacy GNames (≤4.22) when `legacy`. */
function nameTable(mem: Mem, address: bigint, legacy?: boolean): Names {
  return legacy ? new LegacyNames(mem, address) : new NamePool(mem, address);
}

export async function unrealOpen(opts: { module?: string; names?: bigint; legacyNames?: boolean; objects?: bigint; offsets?: Offsets; limit?: number; onProgress?: (done: number, total: number) => void } = {}): Promise<UnrealSession> {
  const m = moduleNamed(opts.module);
  if (!m) throw new Error("attach to the game first");
  const mem = new CachedMem();
  const off = opts.offsets ?? kDefaultOffsets;
  const base = toBig(m.base);
  let names: Names | null = null;
  let objects: ObjectArray | null = null;
  if (opts.legacyNames && opts.names === undefined) throw new Error("legacy GNames cannot be found by shape: pass its address (or use Find with the pattern)");
  const { img, ranges } = opts.names !== undefined && opts.objects !== undefined ? { img: new Uint8Array(), ranges: [] } : await dataRanges(m);
  for (const c of opts.names !== undefined ? [{ address: opts.names }] : findNamePools(img, base, ranges)) {
    const np = nameTable(mem, c.address, opts.legacyNames);
    if (await np.init().catch(() => false)) { names = np; break; }
  }
  if (!names) throw new Error(opts.legacyNames ? `no legacy GNames at that address (entry 0 is not "None")` : `no FNamePool (GNames) found in ${m.name}: pass its address (the static NamePoolData)`);
  for (const c of opts.objects !== undefined ? [{ address: opts.objects }] : findObjectArrays(img, base, ranges)) {
    const oa = new ObjectArray(mem, c.address, off);
    if (!(await oa.init().catch(() => false))) continue;
    // the first objects of a real GUObjectArray are named (CoreUObject package, Object class, …)
    const probe = await dumpObjects(names, oa, undefined, 32).catch(() => null);
    if (probe && probe.objects.length >= 8 && probe.objects.filter((o) => !o.name.startsWith("name#")).length >= probe.objects.length * 0.9) { objects = oa; break; }
  }
  if (!objects) throw new Error(`no FUObjectArray (GObjects) found in ${m.name}: pass its address, or adjust the offsets`);
  const dump = await dumpObjects(names, objects, opts.onProgress, opts.limit);
  return { mem, names, objects, dump, module: m.name, namesAddr: names.address, objectsAddr: objects.address };
}

/**
 * The name table (and optionally GUObjectArray) at known addresses, without dumping anything:
 * for decoding single FNames and paging through objects with listObjects.
 */
export async function unrealTables(opts: { names: bigint; legacyNames?: boolean; objects?: bigint; offsets?: Offsets }): Promise<{ names: Names; objects: ObjectArray | null }> {
  const mem = new CachedMem();
  const names = nameTable(mem, opts.names, opts.legacyNames);
  if (!(await names.init().catch(() => false))) throw new Error(`no ${opts.legacyNames ? "legacy GNames" : "FNamePool"} at ${fmtAddr(opts.names)} (entry 0 is not "None")`);
  if (opts.objects === undefined) return { names, objects: null };
  const objects = new ObjectArray(mem, opts.objects, opts.offsets ?? kDefaultOffsets);
  if (!(await objects.init().catch(() => false))) throw new Error(`no FUObjectArray at ${fmtAddr(opts.objects)}`);
  return { names, objects };
}

/** Scans `module` for one of kUnrealSigs (with a possibly edited pattern) and resolves its operand. */
export async function unrealFindBySig(sig: UnrealSig, pattern: string, module?: string): Promise<bigint | null> {
  const m = moduleNamed(module);
  if (!m) throw new Error("attach to the game first");
  const r = await request<{ results: string[] }>("sig_scan_ida", { pattern, module: m.name, find_all: false }, true);
  const hit = r.results?.[0];
  if (!hit) return null;
  const disp = await readBytes(toBig(hit) + BigInt(sig.disp), 4);
  if (!disp || disp.length < 4) return null;
  const at = ripTarget(toBig(hit), disp, sig.len) - BigInt(sig.adjust);
  return sig.deref ? readU64(at) : at;
}

export async function unrealSdk(s: UnrealSession, opts: { filter?: string; max?: number; offsets?: Offsets; onProgress?: (done: number, total: number) => void } = {}): Promise<{ structs: SdkStruct[]; text: string }> {
  const f = opts.filter?.toLowerCase() ?? "";
  const list = s.dump.objects.filter((o) => (o.className === "Class" || o.className === "ScriptStruct") && (!f || o.name.toLowerCase().includes(f))).slice(0, opts.max ?? 5000);
  const structs: SdkStruct[] = [];
  for (const [i, o] of list.entries()) {
    const st = await readStruct(s.mem, s.names, s.dump, o, opts.offsets).catch(() => null);
    if (st) structs.push(st);
    if (i % 50 === 0) opts.onProgress?.(i, list.length);
  }
  const sizes = new Map(structs.map((x) => [x.cppName, x.size]));
  return { structs, text: sdkText(structs, sizes) };
}

// ---- Unity IL2CPP ------------------------------------------------------------------------------

/** global-metadata.dat from a path, or found in memory (games that decrypt it at load). */
export async function il2cppMetadataBytes(path?: string, onProgress?: (done: number) => void): Promise<{ bytes: Uint8Array; source: string }> {
  if (path) {
    const raw = new Uint8Array(await invoke<number[]>("read_binary_file", { path }));
    if (isMetadata(raw)) return { bytes: raw, source: path };
    throw new Error(`${path} does not start with the IL2CPP sanity value (encrypted?): leave the path empty to search memory`);
  }
  let from = 0x10000n;
  for (let tries = 0; tries < 64; tries++) {
    const at = await searchMemory(from, { bytes: new Uint8Array([0xaf, 0x1b, 0xb1, 0xfa]), mask: [true, true, true, true] }, 1, { maxBytes: 8 * 1024 * 1024 * 1024, onProgress });
    if (at === null) break;
    from = at;
    const hdr = await readBytes(at, 0x110);
    if (!hdr || !isMetadata(hdr)) continue;
    const dv = new DataView(hdr.buffer);
    const v = dv.getInt32(4, true);
    if (v < 24 || v > 31) continue;
    let end = 0;
    for (let o = 8; o + 8 <= 0x108; o += 8) end = Math.max(end, dv.getUint32(o, true) + dv.getUint32(o + 4, true));
    if (end < 0x110 || end > 512 << 20) continue;
    const bytes = new Uint8Array(end);
    for (let o = 0; o < end; o += 0x100000) {
      const b = await readBytes(at + BigInt(o), Math.min(0x100000, end - o));
      if (!b) throw new Error(`metadata at ${fmtAddr(at)} is not fully readable`);
      bytes.set(b, o);
    }
    return { bytes, source: `memory ${fmtAddr(at)}` };
  }
  throw new Error("no global-metadata.dat found in memory; give the file path");
}

export async function il2cppDump(opts: { path?: string; onProgress?: (done: number) => void } = {}): Promise<{ md: Il2CppMetadata; source: string; withRva: string[] }> {
  const ga = findModule(/^gameassembly\.(dll|so)$/i);
  if (!ga) throw new Error("GameAssembly.dll is not loaded: this is not an IL2CPP game (or not attached)");
  const { bytes, source } = await il2cppMetadataBytes(opts.path, opts.onProgress);
  const md = parseMetadata(bytes);
  const { img, ranges } = await dataRanges(ga);
  const withRva = applyMethodPointers(md, img, toBig(ga.base), ranges);
  return { md, source, withRva };
}

// ---- Source ------------------------------------------------------------------------------------

export async function sourceNetvars(module?: string): Promise<NetvarDump & { module: string }> {
  const m = module ? findModule(new RegExp(`^${module.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "i")) : findModule(/^client(64)?\.(dll|so)$/i);
  if (!m) throw new Error("client.dll is not loaded (pass the module that holds the ClientClass list)");
  const img = await loadImage(m);
  const pe = parsePe(img);
  const d = dumpNetvars(img, toBig(m.base), pe.is64, pe.sections.filter((s) => !s.x).map((s) => ({ rva: s.rva, size: Math.max(s.vsize, s.rawSize) })));
  if (!d) throw new Error(`no ClientClass list found in ${m.name}`);
  return { ...d, module: m.name };
}
