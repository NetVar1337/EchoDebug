// Request and prompt builders for the assistant, plus the parsers that turn its
// submit_* tool calls into review lists. Pure, so they are unit-tested.
import { kFieldSizes, layout, type Field, type FieldType } from "../analysis/struct";
import { apiTools } from "./tools";

export type ModelInfo = { id: string; label: string; note: string; fallback: boolean };

/** Default first; the ids are the API's model ids. */
export const kModels: ModelInfo[] = [
  { id: "claude-opus-5-5", label: "Claude Opus 5.5", note: "default", fallback: true },
  { id: "claude-sonnet-5-5", label: "Claude Sonnet 5.5", note: "faster, cheaper", fallback: true },
  { id: "claude-haiku-5-5", label: "Claude Haiku 5.5", note: "fastest, cheapest", fallback: false },
  { id: "claude-fable-5-1", label: "Claude Fable 5.1", note: "most capable, most expensive", fallback: true },
];
export const kDefaultModel = kModels[0].id;
export type Effort = "low" | "medium" | "high" | "xhigh" | "max";
export const kEfforts: Effort[] = ["low", "medium", "high", "xhigh", "max"];

export const kSystemPrompt = `You are the analysis assistant inside EchoDebug, a reverse-engineering workbench attached to a live process the user is authorized to analyze (their own software, or a target they are permitted to test).

You can call EchoDebug's read-only analysis tools: memory reads, disassembly, module and PE information, strings, cross-references, RTTI, signatures scans, the user's names and comments, and similar. You cannot write memory, freeze values, dump, patch, rename, attach or run code; when a change would help, describe it and the user applies it. Every tool call you make is shown to the user.

Addresses are 0x-prefixed hex strings and byte payloads lowercase hex. Refer to code by address (and by the user's names when there are any). Keep answers short and concrete; say when something is a guess.

When asked for names or struct fields, call submit_name_suggestions or submit_struct_fields with your suggestions: the user reviews and accepts each one. Prefer descriptive snake_case or the naming style the user already uses.`;

export type Msg = { role: "user" | "assistant"; content: unknown };

/** Messages API request body (the desktop side adds the key and streams it). */
export function buildRequest(opts: { model: string; effort: Effort; messages: Msg[]; tools?: boolean; maxTokens?: number }): Record<string, unknown> {
  const info = kModels.find((m) => m.id === opts.model);
  return {
    model: opts.model,
    max_tokens: opts.maxTokens ?? 64000,
    system: [{ type: "text", text: kSystemPrompt }],
    // the tools and system prompt are the same every turn: cache them and the history
    cache_control: { type: "ephemeral" },
    thinking: { type: "adaptive", display: "summarized" },
    output_config: { effort: opts.effort },
    ...(info?.fallback ? { fallbacks: "default" } : {}),
    ...(opts.tools === false ? {} : { tools: apiTools() }),
    messages: opts.messages,
  };
}

// ---- context -> prompts ------------------------------------------------------------------------

export type FunctionContext = {
  address: string;
  label: string;
  module?: string;
  /** e.g. game.exe+0x1a2b */
  where?: string;
  /** "addr  text" lines */
  disasm: string[];
  pseudocode?: string[];
  names: { address: string; name: string }[];
  comments: { address: string; text: string }[];
  callees: { address: string; label: string }[];
  abi: "win64" | "sysv";
};

const kMaxDisasm = 1500;
const kMaxPseudo = 600;

/** `lines` capped at `max`, with a note saying how many were left out (never cut silently). */
export function capLines(lines: readonly string[], max: number, what: string): string {
  if (lines.length <= max) return lines.join("\n");
  return `${lines.slice(0, max).join("\n")}\n[${lines.length - max} more ${what} not included; use the tools to read them]`;
}

const tag = (name: string, body: string, attrs = "") => `<${name}${attrs ? " " + attrs : ""}>\n${body}\n</${name}>`;

function functionBlock(c: FunctionContext): string {
  const parts = [
    tag("function", [`address: ${c.address}`, `label: ${c.label}`, c.where ? `location: ${c.where}` : "", c.module ? `module: ${c.module}` : "", `calling convention: ${c.abi === "win64" ? "Windows x64 (rcx, rdx, r8, r9)" : "System V x86-64 (rdi, rsi, rdx, rcx, r8, r9)"}`].filter(Boolean).join("\n")),
    tag("disassembly", capLines(c.disasm, kMaxDisasm, "instructions"), `instructions="${c.disasm.length}"`),
  ];
  if (c.pseudocode?.length) parts.push(tag("pseudocode", capLines(c.pseudocode, kMaxPseudo, "lines"), 'note="experimental structuring of the same instructions; registers are not variables"'));
  if (c.names.length) parts.push(tag("user_names", c.names.map((n) => `${n.address} ${n.name}`).join("\n")));
  if (c.comments.length) parts.push(tag("user_comments", c.comments.map((n) => `${n.address} ${n.text}`).join("\n")));
  if (c.callees.length) parts.push(tag("callees", c.callees.map((n) => `${n.address} ${n.label}`).join("\n")));
  return parts.join("\n\n");
}

export function explainFunctionPrompt(c: FunctionContext): string {
  return `${functionBlock(c)}

Explain what the function ${c.label} does: its purpose, inputs and return value, the important branches, constants, strings and calls. Use the tools if you need more (a callee's code, a string, who calls it).`;
}

export function suggestNamesPrompt(c: FunctionContext): string {
  return `${functionBlock(c)}

Suggest names for ${c.label}, for its callees that still have generated labels (sub_…, module+0x…), for globals it reads or writes, and for its stack locals and arguments. Keep names the user already chose unless the code clearly contradicts them. Use the tools if a callee needs a look. Then call submit_name_suggestions once with all suggestions; for a local or argument use the function's address, kind "local" or "argument" and the register or stack slot as "current".`;
}

export type StructContext = {
  name: string;
  base: string;
  rtti?: string;
  fields: { offset: number; size: number; type: string; name: string; value: string }[];
  /** "+0x000  00 11 22 …  ascii" rows */
  hex: string[];
};

export function suggestStructPrompt(c: StructContext): string {
  const fields = c.fields.map((f) => `+0x${f.offset.toString(16).padStart(3, "0")} ${f.type.padEnd(6)} ${f.name.padEnd(20)} = ${f.value}`);
  return [
    tag("struct", [`name: ${c.name}`, `address: ${c.base}`, c.rtti ? `rtti: ${c.rtti}` : "", `size: 0x${(c.fields.reduce((n, f) => Math.max(n, f.offset + f.size), 0)).toString(16)}`].filter(Boolean).join("\n")),
    tag("current_layout", fields.join("\n")),
    tag("live_sample", c.hex.join("\n"), 'note="read just now from the process"'),
    `Suggest field types and names for this structure from the live sample: pointers (to code, vtables, strings, heap), floats and vectors, counters, flags, padding. Read pointed-to memory or RTTI with the tools when it helps. Then call submit_struct_fields once with the fields you are reasonably confident about (offset, type, name, one-sentence reason).`,
  ].join("\n\n");
}

export type ModuleContext = {
  name: string;
  base: string;
  size: number;
  pe?: unknown;
  imports: { dll: string; names: string[] }[];
  triage: { level: string; why: string; dll: string; name: string }[];
  strings: string[];
  stringsTotal: number;
};

export function summariseModulePrompt(c: ModuleContext): string {
  const imports = c.imports.map((i) => `${i.dll}: ${i.names.slice(0, 80).join(", ")}${i.names.length > 80 ? ` … (+${i.names.length - 80})` : ""}`);
  return [
    tag("module", `name: ${c.name}\nbase: ${c.base}\nsize: 0x${c.size.toString(16)}`),
    c.pe ? tag("pe_info", JSON.stringify(c.pe, null, 1).slice(0, 12000)) : "",
    tag("imports", capLines(imports, 120, "DLLs")),
    tag("triage", c.triage.length ? capLines(c.triage.map((t) => `[${t.level}] ${t.dll}!${t.name}: ${t.why}`), 150, "findings") : "no findings"),
    tag("strings", capLines(c.strings, 400, "strings"), `total="${c.stringsTotal}" note="sample, most distinctive first"`),
    `Summarise ${c.name}: what kind of program or library it is, its main capabilities judging by the imports and strings, anything the triage findings suggest (protection, anti-analysis, injection, networking), and where to start reversing. Use the tools if something needs checking.`,
  ].filter(Boolean).join("\n\n");
}

/** Picks the more informative strings of a module for the summary prompt. */
export function sampleStrings(all: readonly string[], max = 400): string[] {
  const seen = new Set<string>();
  const scored: { s: string; k: number }[] = [];
  for (const s of all) {
    const t = s.trim();
    if (t.length < 6 || seen.has(t)) continue;
    seen.add(t);
    const letters = (t.match(/[a-z]/gi) ?? []).length / t.length;
    if (letters < 0.5) continue;
    let k = Math.min(t.length, 60) * letters;
    if (/https?:\/\/|\\\\|[a-z]:\\|\.(dll|exe|sys|json|ini|cfg|log)\b|%[sd]|error|fail|debug|version|password|token|key/i.test(t)) k += 40;
    scored.push({ s: t.length > 160 ? t.slice(0, 160) + "…" : t, k });
  }
  return scored.sort((a, b) => b.k - a.k).slice(0, max).map((x) => x.s);
}

// ---- review lists ------------------------------------------------------------------------------

export type NameSuggestion = { id: string; address: string; kind: "function" | "callee" | "global" | "local" | "argument"; current: string; name: string; reason: string };
export type FieldSuggestion = { id: string; offset: number; type: FieldType; name: string; reason: string };

const kKinds = ["function", "callee", "global", "local", "argument"] as const;

/** A usable identifier: letters, digits, _ and :: (C++ scopes); at most 80 characters. */
export function cleanIdentifier(s: string): string {
  return s.trim().replace(/\s+/g, "_").replace(/[^A-Za-z0-9_:~]/g, "").replace(/^[0-9]+/, "").slice(0, 80);
}

const normAddr = (a: unknown): string | null => {
  if (typeof a !== "string" && typeof a !== "number") return null;
  const s = String(a).trim().toLowerCase();
  const m = /^(?:0x)?([0-9a-f]{1,16})$/.exec(s);
  return m ? "0x" + m[1].replace(/^0+(?=.)/, "") : null;
};

let seq = 0;
const nid = () => `s${Date.now().toString(36)}${(seq++).toString(36)}`;

/** submit_name_suggestions input → review entries (invalid ones dropped). */
export function parseNameSuggestions(input: unknown): NameSuggestion[] {
  const list = (input as { suggestions?: unknown })?.suggestions;
  if (!Array.isArray(list)) return [];
  const out: NameSuggestion[] = [];
  const seen = new Set<string>();
  for (const x of list.slice(0, 200)) {
    const o = x as Record<string, unknown>;
    const address = normAddr(o.address);
    const name = typeof o.name === "string" ? cleanIdentifier(o.name) : "";
    const kind = kKinds.includes(o.kind as never) ? (o.kind as NameSuggestion["kind"]) : "function";
    if (!address || !name) continue;
    const current = typeof o.current === "string" ? o.current.slice(0, 80) : "";
    const key = `${address}|${kind}|${current}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ id: nid(), address, kind, current, name, reason: typeof o.reason === "string" ? o.reason.slice(0, 300) : "" });
  }
  return out;
}

/** submit_struct_fields input → review entries, sorted by offset, overlaps dropped. */
export function parseStructFields(input: unknown, maxSize = 0x10000): FieldSuggestion[] {
  const list = (input as { fields?: unknown })?.fields;
  if (!Array.isArray(list)) return [];
  const cand: FieldSuggestion[] = [];
  for (const x of list.slice(0, 512)) {
    const o = x as Record<string, unknown>;
    const offset = typeof o.offset === "string" ? Number(o.offset) : Number(o.offset);
    const type = o.type as FieldType;
    const name = typeof o.name === "string" ? cleanIdentifier(o.name) : "";
    if (!Number.isInteger(offset) || offset < 0 || !(type in kFieldSizes) || !name) continue;
    if (offset + kFieldSizes[type] > maxSize) continue;
    cand.push({ id: nid(), offset, type, name, reason: typeof o.reason === "string" ? o.reason.slice(0, 300) : "" });
  }
  cand.sort((a, b) => a.offset - b.offset);
  const out: FieldSuggestion[] = [];
  let end = 0;
  for (const f of cand) {
    if (f.offset < end) continue;
    out.push(f);
    end = f.offset + kFieldSizes[f.type];
  }
  return out;
}

/** hex fields that cover `n` bytes, largest first */
function hexFill(n: number, at: number): Field[] {
  const out: Field[] = [];
  let off = at;
  while (n > 0) {
    const t: FieldType = n >= 8 && off % 8 === 0 ? "hex64" : n >= 4 && off % 4 === 0 ? "hex32" : n >= 2 && off % 2 === 0 ? "hex16" : "hex8";
    out.push({ type: t, name: "" });
    n -= kFieldSizes[t];
    off += kFieldSizes[t];
  }
  return out;
}

/**
 * Puts a field of `type` at byte `offset` of a ReClass-style layout (fields follow each other).
 * The fields it overlaps are replaced; leftover bytes of a split field become hex fields, and a
 * layout shorter than the new field is padded.
 */
export function applyFieldAt(fields: readonly Field[], offset: number, type: FieldType, name: string): Field[] {
  const size = kFieldSizes[type];
  const lay = layout(fields);
  const total = lay.length ? lay[lay.length - 1].offset + lay[lay.length - 1].size : 0;
  const out: Field[] = [];
  let i = 0;
  // fields entirely before
  while (i < fields.length && lay[i].offset + lay[i].size <= offset) out.push(fields[i++]);
  // the part of a field that starts before offset
  const head = i < fields.length ? lay[i].offset : total;
  if (head < offset) out.push(...hexFill(offset - head, head));
  out.push({ type, name });
  // skip every field that overlaps [offset, offset + size)
  while (i < fields.length && lay[i].offset < offset + size) i++;
  const prevEnd = i > 0 ? lay[i - 1].offset + lay[i - 1].size : 0;
  if (prevEnd > offset + size) out.push(...hexFill(prevEnd - offset - size, offset + size));
  while (i < fields.length) out.push(fields[i++]);
  return out;
}
