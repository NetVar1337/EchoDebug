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
import { pdataFunctions, searchModuleCode, xrefsTo } from "./live";
import { buildCfg, type CfgLine } from "./analysis/cfg";
import { resolveSwitch } from "./analysis/jumptables";
import { assemble } from "./analysis/asm";
import { buildNeedle, formatAs, inspect, type CopyFormat, type NeedleMode } from "./analysis/bytes";
import { floatScanFields, groupMatches, groupSpan, parseGroup } from "./analysis/scancmp";
import { searchMemory } from "./memsearch";
import { readManyChunked } from "./batch";
import { parseYara, scanYara } from "./analysis/yara";
import { toPatEntry, toPatFile } from "./analysis/flirtgen";
import { health } from "./analysis/sigrepair";
import { genInput, moduleFunctions } from "./flirtlive";
import { readRange } from "./memory";
import { useSigs } from "@/store/sigs";
import { useNames } from "@/store/names";
import { imphash, parseDebug, parseRelocs, parseRich, parseTls } from "./analysis/peextra";
import { summarizeResources } from "./analysis/resources";
import { openMetadata } from "./analysis/dotnet";
import { disassembleIl, formatIl, userStringRefs } from "./analysis/cil";
import { findIat } from "./analysis/unpack";
import { diffFunctions } from "./analysis/bindiff";
import { mapPeFile, parseRuntimeFunctions } from "./analysis/pe";
import { loadPdbSymbols, readModuleFileBytes } from "./modfile";
import { batchDecrypt, exportIndex, oepCandidates } from "./unpacklive";
import { functionsFromImage } from "./diffinput";
import { parseSignature, authenticodeHash } from "./analysis/authenticode";
import { invoke } from "@tauri-apps/api/core";
import { guessFields } from "./analysis/structguess";
import { toCpp } from "./analysis/struct";
import { toBinja, toC, toGhidra, toIdaPython, toReclassXml } from "./analysis/typeexport";
import { pointerClassifier } from "./ptrkind";
import { useTypes } from "@/store/types";
import { useConn } from "@/store/conn";
import { useFlirt } from "@/store/flirt";

export type Args = Record<string, unknown>;
export type Handler = (args: Args) => Promise<unknown>;

const handlers = new Map<string, Handler>();

/** Registers a `ui_*` verb. Later registrations replace earlier ones (hot reload). */
export function provide(verb: string, h: Handler): void {
  handlers.set(verb, h);
}

/** Runs a ui_* analysis directly (scripts in the app). */
export async function callProvider(verb: string, args: Args = {}): Promise<unknown> {
  const h = handlers.get(verb);
  if (!h) throw new Error(`unknown app verb: ${verb} (known: ${providedVerbs().join(", ")})`);
  return h(args);
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

provide("ui_cfg", async (args) => {
  const a = addrArg(args);
  const m = moduleOf(a, modules());
  const img = m ? await loadImage(m) : null;
  const base = m ? toBig(m.base) : 0n;
  const decode = async (x: bigint): Promise<CfgLine[]> => (await request<{ results: CfgLine[] }>("disassemble", { address: fmtAddr(x), size: 0x100 }, true).catch(() => null))?.results ?? [];
  const cfg = await buildCfg(a, decode, {
    maxInsns: num(args, "max_insns", 8000, 50000),
    bounds: m ? { lo: base, hi: base + BigInt(m.size) } : undefined,
    switchTargets: img ? (lines, i) => resolveSwitch(lines, i, img, base)?.targets ?? null : undefined,
  });
  return {
    entry: fmtAddr(cfg.entry), truncated: cfg.truncated,
    blocks: cfg.blocks.map((b) => ({ start: fmtAddr(b.start), end: fmtAddr(b.end), terminator: b.terminator, instructions: args.with_text ? b.lines.map((l) => `${l.address}  ${l.text}`) : b.lines.length })),
    edges: cfg.edges.map((e) => ({ from: fmtAddr(e.from), to: fmtAddr(e.to), kind: e.kind, ...(e.label ? { case: e.label } : {}) })),
  };
});

provide("ui_assemble", async (args) => {
  const a = addrArg(args);
  if (typeof args.code !== "string") throw new Error("missing 'code'");
  const bytes = assemble(args.code, a);
  return { address: fmtAddr(a), size: bytes.length, data: Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""), note: "not written; pass data to write_memory to apply" };
});

provide("ui_search_code", async (args) => {
  const m = pickModule(args);
  if (typeof args.pattern !== "string") throw new Error("missing 'pattern' (regex over instruction text)");
  const hits = await searchModuleCode(m, new RegExp(args.pattern, "i"), { limit: num(args, "limit", 200, 5000) });
  return { module: m.name, count: hits.length, results: hits };
});

provide("ui_jump_table", async (args) => {
  const a = addrArg(args);
  const m = moduleOf(a, modules());
  if (!m) throw new Error("address is outside every module");
  const img = await loadImage(m);
  const r = await request<{ results: CfgLine[] }>("disassemble", { address: fmtAddr(a - 0x40n), size: 0x60 }, true);
  const lines = r.results ?? [];
  const i = lines.findIndex((l) => toBig(l.address) === a);
  if (i < 0) throw new Error("no instruction boundary at that address (pass the indirect jmp itself)");
  const t = resolveSwitch(lines, i, img, toBig(m.base));
  if (!t) throw new Error("no recognisable jump table behind this jump");
  return { ...t, targets: t.targets.map((x) => labelAddr(x, modules())) };
});

provide("ui_functions", async (args) => {
  const m = pickModule(args);
  const pdata = await pdataFunctions(m).catch(() => []);
  return { module: m.name, source: ".pdata", ...limitList(pdata, args, 2000) };
});

provide("ui_find_memory", async (args) => {
  const from = addrArg(args, "from");
  const mode = (typeof args.mode === "string" ? args.mode : "hex") as NeedleMode;
  if (typeof args.query !== "string") throw new Error("missing 'query'");
  const needle = buildNeedle(args.query, mode);
  const dir = args.backward ? -1 : 1;
  const hits: string[] = [];
  let cur = from;
  for (let i = 0; i < num(args, "count", 1, 100); i++) {
    const hit = await searchMemory(cur, needle, dir, { maxBytes: num(args, "max_mib", 512, 4096) * 1024 * 1024 });
    if (hit === null) break;
    hits.push(labelAddr(hit, modules()));
    cur = hit;
  }
  return { query: args.query, mode, count: hits.length, results: hits };
});

provide("ui_group_scan", async (args) => {
  if (typeof args.spec !== "string") throw new Error("missing 'spec', e.g. 'i32:100; +4 f32:1.5'");
  const g = parseGroup(args.spec);
  const a = g[0];
  const fields: Record<string, unknown> = { value_type: a.type, compare: "exact", value: a.value, writable_only: args.writable_only !== false, ...(typeof args.module === "string" ? { module: args.module } : {}) };
  if (a.type === "f32" || a.type === "f64") Object.assign(fields, floatScanFields(a.value!, "rounded"));
  const r = await request<{ count: number }>("scan_new", fields);
  if (r.count > 200_000) throw new Error(`${r.count} anchors; make the first member more specific or pass a module`);
  const anchors: string[] = [];
  for (let off = 0; off < r.count; off += 2000) anchors.push(...(await request<{ results: { address: string }[] }>("scan_results", { offset: off, limit: 2000 })).results.map((h) => h.address));
  const bytes = await readManyChunked(anchors.map((x) => ({ address: x, size: groupSpan(g) })));
  const matches = anchors.filter((_, i) => bytes[i] && groupMatches(g, bytes[i]!));
  return { anchors: anchors.length, count: matches.length, results: matches.slice(0, num(args, "limit", 500, 20000)).map((x) => labelAddr(x, modules())) };
});

provide("ui_inspect", async (args) => {
  const a = addrArg(args);
  const b = await readBytes(a, num(args, "size", 64, 4096));
  if (!b) throw new Error("not readable");
  const fmt = (typeof args.format === "string" ? args.format : "spaced") as CopyFormat;
  return { address: labelAddr(a, modules()), little_endian: inspect(b, true), big_endian: inspect(b, false), bytes: formatAs(b, fmt) };
});

provide("ui_yara_scan", async (args) => {
  if (typeof args.rules !== "string") throw new Error("missing 'rules' (YARA source)");
  const rules = parseYara(args.rules);
  const out: unknown[] = [];
  if (typeof args.address === "string") {
    const a = addrArg(args);
    const size = num(args, "size", 0x10000, 256 * 1024 * 1024);
    for (const h of scanYara(rules, await readRange(a, size))) out.push({ ...h, strings: h.strings.slice(0, 50).map((s) => ({ ...s, address: labelAddr(a + BigInt(s.offset), modules()) })) });
  } else {
    const list = args.module === "*" ? modules() : [pickModule(args)];
    for (const m of list) {
      const img = await loadImage(m);
      let entrypoint: number | undefined;
      try { entrypoint = parsePe(img).entryRva; } catch { /* not PE */ }
      for (const h of scanYara(rules, img, { entrypoint })) out.push({ ...h, module: m.name, strings: h.strings.slice(0, 50).map((s) => ({ ...s, address: labelAddr(toBig(m.base) + BigInt(s.offset), modules()) })) });
    }
  }
  return { rules: rules.length, count: out.length, matches: out };
});

provide("ui_sig_health", async () => {
  const mods = modules();
  const main = pickModule({}).name;
  const out = [];
  for (const s of useSigs.getState().sigs) {
    const hits = await request<{ results: string[]; success: boolean }>("sig_scan_ida", { pattern: s.ida, module: s.module || main, find_all: true }, true).catch(() => null);
    const n = hits?.success ? hits.results.length : 0;
    out.push({ name: s.name, module: s.module || main, ida: s.ida, hits: n, health: health(n), first: hits?.results?.[0] ? labelAddr(hits.results[0], mods) : null });
  }
  return { count: out.length, broken: out.filter((x) => x.health !== "ok").length, results: out };
});

provide("ui_flirt_pat", async (args) => {
  const m = pickModule(args);
  const names = useNames.getState();
  const fns = (await moduleFunctions(m)).map((f) => ({ ...f, name: names.nameOf(f.address) }))
    .filter((f) => !args.named_only || f.name)
    .slice(0, num(args, "limit", 2000, 20000))
    .map((f) => ({ ...f, name: f.name || `sub_${(toBig(f.address) - toBig(m.base)).toString(16)}` }));
  const entries = (await genInput(fns)).map(toPatEntry).filter((e) => e !== null);
  return { module: m.name, count: entries.length, pat: toPatFile(entries) };
});

provide("ui_pe_details", async (args) => {
  const { m, img, base } = await moduleImage(args);
  const pe = parsePe(img);
  const out: Record<string, unknown> = { module: m.name, imphash: imphash(pe), rich: parseRich(img), tls: parseTls(img, base, pe), relocations: (() => { const r = parseRelocs(img, pe, 0); return { total: r.total, byType: r.byType }; })(), debug: parseDebug(img, pe) };
  if (args.signature) {
    const f = await readModuleFileBytes(m);
    const sig = parseSignature(f.bytes);
    out.signature = sig ? { ...sig, fileDigest: await authenticodeHash(f.bytes, sig.digestAlgorithm === "sha1" ? "sha1" : "sha256"), path: f.path } : null;
  }
  return out;
});

provide("ui_resources", async (args) => {
  const { m, img } = await moduleImage(args);
  const r = summarizeResources(img);
  return { module: m.name, version: r.version, manifest: r.manifest, strings: r.strings.slice(0, 2000), dialogs: r.dialogs, icons: r.icons.length, resources: r.leaves.length };
});

provide("ui_load_symbols", async (args) => {
  const m = pickModule(args);
  return { module: m.name, ...(await loadPdbSymbols(m, { overwrite: Boolean(args.overwrite) })) };
});

provide("ui_il", async (args) => {
  const { m, img } = await moduleImage(args);
  const md = openMetadata(img);
  if (!md) throw new Error(`${m.name} has no CLR metadata`);
  const want = typeof args.method === "string" ? args.method.toLowerCase() : "";
  const hits = md.methods.filter((x) => `${x.type}::${x.name}`.toLowerCase().includes(want) || x.token === Number(args.token));
  if (!hits.length) throw new Error(`no method matches '${args.method ?? args.token}'`);
  return { module: m.name, methods: hits.slice(0, num(args, "limit", 5, 50)).map((x) => { try { return { method: `${x.type}::${x.name}`, token: x.token, il: formatIl(disassembleIl(img, x.rva, md.tokenName)) }; } catch (e) { return { method: `${x.type}::${x.name}`, token: x.token, error: String(e) }; } }) };
});

provide("ui_user_strings", async (args) => {
  const { m, img } = await moduleImage(args);
  const md = openMetadata(img);
  if (!md) throw new Error(`${m.name} has no CLR metadata`);
  const refs = userStringRefs(img, md.methods);
  const f = typeof args.filter === "string" ? args.filter.toLowerCase() : "";
  const list = md.userStrings.filter((u) => !f || u.text.toLowerCase().includes(f)).map((u) => ({ text: u.text, token: u.token, loadedBy: (refs.get(u.token) ?? []).map((r) => `${r.method}+IL_${r.offset.toString(16).padStart(4, "0")}`) }));
  return { module: m.name, ...limitList(list, args) };
});

provide("ui_find_oep", async (args) => {
  const m = pickModule(args);
  const r = await oepCandidates(m, num(args, "max_insns", 2_000_000, 5_000_000));
  return { module: m.name, instructions: r.instructions, stop: r.stop, candidates: r.candidates.map((c) => ({ ...c, address: labelAddr(c.address, modules()) })) };
});

provide("ui_rebuild_imports", async (args) => {
  const m = pickModule(args);
  const idx = await exportIndex(modules(), m);
  const blocks = findIat(await loadImage(m), idx);
  return { module: m.name, exports_indexed: idx.size, blocks: blocks.map((b) => ({ rva: b.rva, dll: b.dll, imports: b.thunks.map((t) => t.name || `#${t.ordinal}`) })), note: "save the rebuilt PE from the Unpack tab" };
});

provide("ui_batch_decrypt", async (args) => {
  const r = await batchDecrypt(addrArg(args), modules(), { limit: num(args, "limit", 100, 1000) });
  return { count: r.length, decrypted: r.filter((x) => x.result).length, results: r.map((x) => ({ site: labelAddr(x.site, modules()), text: x.result?.text ?? null, encoding: x.result?.encoding, stop: x.stop, error: x.error })) };
});

provide("ui_binary_diff", async (args) => {
  const m = pickModule(args);
  if (typeof args.old_path !== "string") throw new Error("missing 'old_path' (an older build of the module on this machine)");
  if (!/\.(exe|dll|sys)$/i.test(args.old_path)) throw new Error("old_path must be a .exe, .dll or .sys file");
  const raw = new Uint8Array(await invoke<number[]>("read_binary_file", { path: args.old_path }));
  const oldImg = mapPeFile(raw);
  const oldPe = parsePe(oldImg);
  const oldFns = parseRuntimeFunctions(oldImg, oldPe).filter((f) => !f.chained).slice(0, 6000).map((f) => ({ rva: f.begin, size: f.end - f.begin, name: "" }));
  const newImg = await loadImage(m);
  const nb = toBig(m.base);
  const newFns = (await moduleFunctions(m)).slice(0, 6000).map((f) => ({ rva: Number(toBig(f.address) - nb), size: f.size, name: useNames.getState().nameOf(f.address) }));
  const r = diffFunctions(await functionsFromImage(oldImg, oldPe.imageBase, oldFns), await functionsFromImage(newImg, nb, newFns), Number(oldPe.imageBase), Number(nb));
  return { module: m.name, matched: r.pairs.length, changed: r.pairs.filter((p) => p.changed).map((p) => ({ old_rva: p.old.rva, new: labelAddr(nb + BigInt(p.new.rva), modules()), kind: p.kind, similarity: Number(p.similarity.toFixed(3)) })).slice(0, 2000), added: r.onlyNew.map((f) => labelAddr(nb + BigInt(f.rva), modules())).slice(0, 2000), removed: r.onlyOld.map((f) => f.rva).slice(0, 2000) };
});

provide("ui_guess_struct", async (args) => {
  const a = addrArg(args);
  const size = num(args, "size", 0x100, 0x4000);
  const b = await readBytes(a, size);
  if (!b) throw new Error("not readable");
  const fields = guessFields(b, { kindOf: await pointerClassifier(modules()) });
  const name = typeof args.name === "string" ? args.name : `Guess_${a.toString(16)}`;
  if (args.save) useTypes.getState().add(name, fields);
  return { address: labelAddr(a, modules()), size, fields, cpp: toCpp(name, fields), saved: Boolean(args.save) };
});

provide("ui_export_struct", async (args) => {
  const t = typeof args.name === "string" ? useTypes.getState().find(args.name) : undefined;
  if (!t) throw new Error(`no type '${args.name}' in the app's catalog (${useTypes.getState().types.map((x) => x.name).join(", ") || "empty"})`);
  const fmt = String(args.format ?? "cpp");
  const text = fmt === "c" ? toC(t.name, t.fields) : fmt === "ida" ? toIdaPython(t.name, t.fields) : fmt === "ghidra" ? toGhidra(t.name, t.fields) : fmt === "binja" ? toBinja(t.name, t.fields) : fmt === "reclass" ? toReclassXml([t]) : toCpp(t.name, t.fields);
  return { name: t.name, format: fmt, text };
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
