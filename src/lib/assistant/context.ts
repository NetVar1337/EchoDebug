// Gathers what the assistant's one-click actions send: the function under the cursor (its
// instructions, structured pseudocode, the user's names and comments, its callees), the struct on
// screen with a live sample, and a module's imports, strings and triage findings.
import { request } from "../client";
import { fmtAddr, labelAddr, moduleOf, toBig } from "../hex";
import { loadImage } from "../memory";
import { pdataFunctions } from "../live";
import { buildCfg, type CfgLine } from "../analysis/cfg";
import { buildStructure } from "../analysis/structure";
import { pseudocode } from "../analysis/pseudocode";
import { resolveSwitch } from "../analysis/jumptables";
import { fieldValue, kFieldSizes, layout } from "../analysis/struct";
import { parsePe } from "../analysis/pe";
import { extractStrings } from "../analysis/strings";
import { callProvider } from "../provider";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { useStructCtx } from "@/store/structctx";
import { sampleStrings, type FunctionContext, type ModuleContext, type StructContext } from "./prompts";

const norm = (a: string) => toBig(a).toString(16);

export async function functionContext(at: string): Promise<FunctionContext> {
  const { modules, backend } = useConn.getState();
  const names = useNames.getState();
  const a = toBig(at);
  const m = moduleOf(a, modules);
  const img = m ? await loadImage(m).catch(() => null) : null;
  const mbase = m ? toBig(m.base) : 0n;
  let bounds = m ? { lo: mbase, hi: mbase + BigInt(m.size) } : undefined;
  let entry = a;
  if (m) {
    const fn = (await pdataFunctions(m).catch(() => [])).find((f) => toBig(f.address) <= a && a < toBig(f.address) + BigInt(f.size));
    if (fn) {
      entry = toBig(fn.address);
      bounds = { lo: entry, hi: entry + BigInt(fn.size) };
    }
  }
  const decode = async (x: bigint): Promise<CfgLine[]> => (await request<{ results: CfgLine[] }>("disassemble", { address: fmtAddr(x), size: 0x100 }, true).catch(() => null))?.results ?? [];
  const cfg = await buildCfg(entry, decode, {
    maxInsns: 4000,
    bounds,
    switchTargets: img ? (lines, i) => resolveSwitch(lines, i, img, mbase)?.targets ?? null : undefined,
  });
  const lines = cfg.blocks.flatMap((b) => b.lines).sort((x, y) => (toBig(x.address) < toBig(y.address) ? -1 : 1));
  if (!lines.length) throw new Error(`no instructions at ${fmtAddr(entry)}`);
  const nameOf = (x: string) => names.nameOf(x);
  const inFn = new Set(lines.map((l) => norm(l.address)));
  // every address the code mentions: callees, globals, jump targets
  const mentioned = new Set<string>();
  const callees = new Map<string, string>();
  for (const l of lines) {
    for (const h of l.text.match(/0x[0-9a-f]{4,16}/gi) ?? []) mentioned.add(norm(h));
    const c = /^call\s+(?:qword ptr \[)?(0x[0-9a-f]+)/i.exec(l.text);
    if (c) callees.set(fmtAddr(toBig(c[1])), nameOf(c[1]) || labelAddr(c[1], modules));
  }
  const disasm = lines.map((l) => {
    const nm = nameOf(l.address);
    const cm = names.commentOf(l.address);
    return `${l.address}  ${l.text}${nm ? `  ; <${nm}>` : ""}${cm ? `  ; ${cm}` : ""}`;
  });
  let pseudo: string[] | undefined;
  try {
    pseudo = pseudocode(buildStructure(lines), { abi: backend === "local" ? "sysv" : "win64", nameOf }).map((p) => "  ".repeat(p.indent) + p.text);
  } catch {
    pseudo = undefined;
  }
  const all = names.list();
  return {
    address: fmtAddr(entry),
    label: nameOf(fmtAddr(entry)) || labelAddr(entry, modules),
    module: m?.name,
    where: m ? `${m.name}+0x${(entry - mbase).toString(16)}` : undefined,
    disasm,
    pseudocode: pseudo,
    names: all.filter((n) => n.name && (mentioned.has(norm(n.address)) || inFn.has(norm(n.address)))).map((n) => ({ address: fmtAddr(toBig(n.address)), name: n.name })),
    comments: all.filter((n) => n.comment && inFn.has(norm(n.address))).map((n) => ({ address: fmtAddr(toBig(n.address)), text: n.comment })),
    callees: [...callees].map(([address, label]) => ({ address, label })),
    abi: backend === "local" ? "sysv" : "win64",
  };
}

/** The struct the Structs view shows, with the bytes it last read. */
export function structContext(): StructContext {
  const s = useStructCtx.getState();
  if (!s.base) throw new Error("open an address in the Structs view first");
  if (!s.data) throw new Error("the Structs view has not read the struct yet");
  const lay = layout(s.fields);
  const data = s.data;
  const hex: string[] = [];
  for (let off = 0; off < Math.min(data.length, 0x800); off += 16) {
    const row = data.subarray(off, off + 16);
    hex.push(`+0x${off.toString(16).padStart(3, "0")}  ${Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47)}  ${Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("")}`);
  }
  return {
    name: s.name,
    base: s.base,
    rtti: s.rtti || undefined,
    fields: s.fields.map((f, i) => ({ offset: lay[i].offset, size: kFieldSizes[f.type], type: f.type, name: f.name || `field_${lay[i].offset.toString(16)}`, value: lay[i].offset + kFieldSizes[f.type] <= data.length ? fieldValue(data, lay[i].offset, f.type) : "??" })),
    hex,
  };
}

/** Imports, triage findings and a sample of the strings of `name` (default: the main module). */
export async function moduleContext(name?: string): Promise<ModuleContext> {
  const { modules, target } = useConn.getState();
  const m = (name ? modules.find((x) => x.name.toLowerCase() === name.toLowerCase()) : undefined) ?? modules.find((x) => x.base === target?.base) ?? modules[0];
  if (!m) throw new Error("attach to a process first");
  const img = await loadImage(m);
  let imports: ModuleContext["imports"] = [];
  let pe: unknown;
  try {
    const info = parsePe(img);
    imports = info.imports.map((d) => ({ dll: d.dll, names: d.funcs.map((f) => f.name ?? `#${f.ordinal}`) }));
    pe = { machine: info.machine, is64: info.is64, timestamp: info.timestamp, subsystem: info.subsystem, entryRva: info.entryRva, sections: info.sections.map((s) => ({ name: s.name, rva: s.rva, vsize: s.vsize, r: s.r, w: s.w, x: s.x })), exports: info.exports.length, exportSample: info.exports.slice(0, 60).map((e) => e.name) };
    const extra = (await callProvider("ui_pe_info", { module: m.name, limit: 1 }).catch(() => null)) as { entropy?: unknown; packer?: unknown } | null;
    if (extra) pe = { ...(pe as object), entropy: extra.entropy, packer: extra.packer };
  } catch {
    pe = undefined; // not a PE (ELF on Linux): strings and the model's own tool calls still work
  }
  const triage = ((await callProvider("ui_triage_imports", { module: m.name, limit: 200 }).catch(() => null)) as { results?: { level: string; why: string; dll: string; name: string }[] } | null)?.results ?? [];
  const all = extractStrings(img, 6).map((s) => s.text);
  return { name: m.name, base: m.base, size: m.size, pe, imports, triage, strings: sampleStrings(all), stringsTotal: all.length };
}
