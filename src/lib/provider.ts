// The app window serves the `ui_*` verbs: analyses that live in this TypeScript (PE parsing,
// strings, xrefs, crypto, FLIRT, YARA, CFG, …) answered for MCP clients through the relay.
// The relay sends {type:"provider_call", call, verb, args}; we answer {type:"provider_reply", call, verb, result|error}.
import { client, request, type Frame } from "./client";
import { fmtAddr, labelAddr, moduleOf, parseAddress, toBig, type Module } from "./hex";
import { loadImage, readBytes } from "./memory";
import { parsePe } from "./analysis/pe";
import { extractStrings } from "./analysis/strings";
import { scanCrypto } from "./analysis/crypto";
import { findCodeCaves } from "./analysis/caves";
import { scanAntiDebug, scanAntiImports, scanAntiStrings } from "./analysis/antidebug";
import { buildIat } from "./analysis/iat";
import { classifyImports } from "./analysis/risk";
import { makeSignature, toCode, toIda } from "./analysis/sigmaker";
import { parseDotnet } from "./analysis/dotnet";
import { matchFlirt } from "./analysis/flirt";
import { buildRtti, findVftables } from "./analysis/rtti";
import { sectionEntropies, detectPacker } from "./analysis/entropy";
import { diffRange } from "./analysis/snapshot";
import { buildXrefIndex, executableRanges } from "./analysis/xrefindex";
import { xrefsTo } from "./live";
import { useConn } from "@/store/conn";
import { useFlirt } from "@/store/flirt";

export type Args = Record<string, unknown>;
export type Handler = (args: Args) => Promise<unknown>;

const handlers = new Map<string, Handler>();

/** Registers a `ui_*` verb. Later registrations replace earlier ones (hot reload). */
export function provide(verb: string, h: Handler): void {
  handlers.set(verb, h);
}

export function providedVerbs(): string[] {
  return [...handlers.keys()].sort();
}

/** JSON-safe copy: BigInt → 0x hex, Uint8Array → hex, Map → object. */
export function jsonSafe(v: unknown): unknown {
  if (typeof v === "bigint") return fmtAddr(v);
  if (v instanceof Uint8Array) return Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("");
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [String(k), jsonSafe(x)]));
  if (Array.isArray(v)) return v.map(jsonSafe);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, jsonSafe(x)]));
  return v;
}

export function modules(): Module[] {
  return useConn.getState().modules;
}

/** `module` arg (exact or case-insensitive name), default the main executable. */
export function pickModule(args: Args): Module {
  const mods = modules();
  if (!mods.length) throw new Error("no modules: attach to a process first");
  const want = typeof args.module === "string" ? args.module.toLowerCase() : "";
  if (want) {
    const m = mods.find((x) => x.name.toLowerCase() === want) ?? mods.find((x) => x.name.toLowerCase().includes(want));
    if (!m) throw new Error(`module not found: ${args.module}`);
    return m;
  }
  const t = useConn.getState().target;
  return mods.find((m) => m.base === t?.base) ?? [...mods].sort((a, b) => b.size - a.size)[0];
}

export function addrArg(args: Args, key = "address"): bigint {
  const raw = args[key];
  if (typeof raw !== "string" && typeof raw !== "number") throw new Error(`missing '${key}'`);
  const v = parseAddress(String(raw), modules());
  if (v === null) throw new Error(`cannot parse ${key}: ${raw}`);
  return v;
}

export function num(args: Args, key: string, dflt: number, max = Number.MAX_SAFE_INTEGER): number {
  const v = Number(args[key]);
  return Number.isFinite(v) && v > 0 ? Math.min(v, max) : dflt;
}

export async function moduleImage(args: Args): Promise<{ m: Module; img: Uint8Array; base: bigint }> {
  const m = pickModule(args);
  return { m, img: await loadImage(m), base: toBig(m.base) };
}

function limitList<T>(list: T[], args: Args, dflt = 500): { count: number; truncated: boolean; results: T[] } {
  const lim = num(args, "limit", dflt, 20000);
  return { count: list.length, truncated: list.length > lim, results: list.slice(0, lim) };
}

// ------------------------------------------------------------------------------------------------
// Built-in handlers
// ------------------------------------------------------------------------------------------------

provide("ui_pe_info", async (args) => {
  const { m, img } = await moduleImage(args);
  const pe = parsePe(img);
  return {
    module: m.name, base: m.base, ...pe,
    exports: pe.exports.slice(0, num(args, "limit", 2000)), exportCount: pe.exports.length,
    entropy: sectionEntropies(img, pe), packer: detectPacker(img, pe),
  };
});

provide("ui_strings", async (args) => {
  const { m, img, base } = await moduleImage(args);
  const min = num(args, "min_length", 5, 256);
  const filter = typeof args.filter === "string" ? new RegExp(args.filter, "i") : null;
  const list = extractStrings(img, min)
    .filter((s) => !filter || filter.test(s.text))
    .map((s) => ({ address: fmtAddr(base + BigInt(s.rva)), rva: s.rva, wide: s.wide, text: s.text }));
  return { module: m.name, ...limitList(list, args) };
});

provide("ui_xrefs_to", async (args) => {
  const a = addrArg(args);
  const list = await xrefsTo(fmtAddr(a), modules());
  return { target: labelAddr(a, modules()), ...limitList(list.map((x) => ({ address: fmtAddr(x.address), at: labelAddr(x.address, modules()), kind: x.kind })), args) };
});

provide("ui_xref_index", async (args) => {
  const { m, img, base } = await moduleImage(args);
  const idx = buildXrefIndex(img, executableRanges(img));
  const top = [...idx.to.entries()].map(([rva, refs]) => ({ address: fmtAddr(base + BigInt(rva)), refs: refs.length }))
    .sort((a, b) => b.refs - a.refs);
  return { module: m.name, total: idx.all.length, ...limitList(top, args, 100) };
});

provide("ui_crypto_scan", async (args) => {
  const { m, img, base } = await moduleImage(args);
  return { module: m.name, ...limitList(scanCrypto(img, base), args) };
});

provide("ui_code_caves", async (args) => {
  const { m, img, base } = await moduleImage(args);
  return { module: m.name, ...limitList(findCodeCaves(img, base, { minSize: num(args, "min_size", 16) }), args) };
});

provide("ui_antidebug_scan", async (args) => {
  const { m, img, base } = await moduleImage(args);
  const pe = parsePe(img);
  const imports = pe.imports.flatMap((d) => d.funcs.map((f) => ({ name: f.name ?? "" })));
  const hits = [...scanAntiDebug(img, base, pe), ...scanAntiImports(imports, base), ...scanAntiStrings(extractStrings(img, 5), base)];
  return { module: m.name, ...limitList(hits, args) };
});

provide("ui_triage_imports", async (args) => {
  const { m, img, base } = await moduleImage(args);
  const hits = classifyImports(buildIat(img, base)).map((h) => ({ level: h.level, why: h.why, dll: h.entry.dll, name: h.entry.name, slot: h.entry.address }));
  return { module: m.name, ...limitList(hits, args) };
});

provide("ui_make_signature", async (args) => {
  const a = addrArg(args);
  const m = moduleOf(a, modules());
  if (!m) throw new Error("address is outside every module");
  const r = await request<{ results: { address: string; length: number; bytes: string; text: string }[] }>("disassemble", { address: fmtAddr(a), size: 0x200 });
  const count = async (ida: string) => {
    const hits = await request<{ results: string[] }>("sig_scan_ida", { pattern: ida, module: m.name, find_all: true }, true);
    return hits.results?.length ?? 0;
  };
  const sig = await makeSignature(r.results, count);
  if (!sig) throw new Error("no unique signature within 512 bytes");
  return { address: fmtAddr(a), module: m.name, ida: toIda(sig.pattern), ...toCode(sig.pattern), hits: sig.hits };
});

provide("ui_dotnet_types", async (args) => {
  const { m, img } = await moduleImage(args);
  const info = parseDotnet(img);
  if (!info) throw new Error(`${m.name} has no CLR metadata`);
  const f = typeof args.filter === "string" ? args.filter.toLowerCase() : "";
  const types = info.types.filter((t) => !f || t.fullName.toLowerCase().includes(f));
  return { module: m.name, runtimeVersion: info.runtimeVersion, ...limitList(types, args, 200) };
});

provide("ui_flirt_match", async (args) => {
  const sig = useFlirt.getState().signature;
  if (!sig) throw new Error("no FLIRT signature file loaded (Signatures → FLIRT in the app)");
  const { m, img, base } = await moduleImage(args);
  return { module: m.name, file: useFlirt.getState().fileName, ...limitList(matchFlirt(sig, img, base), args) };
});

provide("ui_rtti_classes", async (args) => {
  const { m, img, base } = await moduleImage(args);
  const pe = parsePe(img);
  const inv = buildRtti(img, base, pe);
  const f = typeof args.filter === "string" ? args.filter.toLowerCase() : "";
  const classes = inv.classes.filter((c) => !f || c.name.toLowerCase().includes(f))
    .map((c) => ({ ...c, vftables: c.vftables.length ? c.vftables : findVftables(img, base, c, pe) }));
  return { module: m.name, unnamed: inv.unnamed, ...limitList(classes, args, 300) };
});

provide("ui_snapshot_diff", async (args) => {
  const a = addrArg(args);
  const size = num(args, "size", 4096, 0x100000);
  const wait = num(args, "delay_ms", 1000, 60000);
  const before = await readBytes(a, size);
  await new Promise((r) => setTimeout(r, wait));
  const after = await readBytes(a, size);
  if (!before || !after) throw new Error("range not readable");
  return { address: fmtAddr(a), size, delay_ms: wait, ...limitList(diffRange(before, after, fmtAddr(a)), args, 2000) };
});

// ------------------------------------------------------------------------------------------------
// Wire-up
// ------------------------------------------------------------------------------------------------

let registered = false;

async function onCall(f: Frame): Promise<void> {
  const call = f.call;
  const verb = String(f.verb ?? "");
  const h = handlers.get(verb);
  try {
    if (!h) throw new Error(`unknown app verb: ${verb}`);
    const result = await h((f.args as Args) ?? {});
    client.send({ type: "provider_reply", call, verb, result: jsonSafe(result) });
  } catch (e) {
    client.send({ type: "provider_reply", call, verb, error: e instanceof Error ? e.message : String(e) });
  }
}

/** Announce this window as the provider whenever the relay connection comes up. */
export function startProvider(): void {
  if (registered) return;
  registered = true;
  client.on((f) => {
    if (f.type === "provider_call") void onCall(f);
  });
  const announce = () => void request("provide", { verbs: providedVerbs() }).catch(() => undefined);
  client.onState((up) => up && announce());
  if (client.connected) announce();
}
