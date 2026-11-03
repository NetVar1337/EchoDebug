// Slash commands and @-mentions of the assistant composer: parsing and autocomplete. Pure, so
// they are unit-tested; the store runs the commands and resolves the mentions.

export type SlashDef = { name: string; args?: string; help: string };

export const kSlash: SlashDef[] = [
  { name: "explain", args: "[addr]", help: "Explain the function at the cursor (or at addr)" },
  { name: "names", help: "Suggest names for the function at the cursor" },
  { name: "struct", help: "Suggest fields for the struct in the Structs view" },
  { name: "summary", args: "[module]", help: "Summarise a module (default: the focused or main one)" },
  { name: "model", args: "<name>", help: "Switch model (fuzzy match)" },
  { name: "provider", args: "<name>", help: "Switch provider" },
  { name: "new", help: "Start a new conversation" },
  { name: "clear", help: "Clear this conversation" },
  { name: "compact", help: "Summarise the history to shrink the context" },
  { name: "retry", help: "Send the last message again" },
  { name: "export", help: "Save this conversation as Markdown" },
  { name: "tools", help: "List the tools the assistant may call" },
  { name: "context", help: "Show what is attached and a token estimate" },
  { name: "cost", help: "Token usage and cost of this conversation" },
  { name: "system", args: "[prompt | reset]", help: "Show or replace this conversation's system prompt" },
  { name: "help", help: "Commands, mentions and shortcuts" },
];

export type Slash = { name: string; args: string; def?: SlashDef };

/** `/name args…` → the command (def undefined when unknown); null for ordinary text. */
export function parseSlash(text: string): Slash | null {
  const t = text.trim();
  const m = /^\/([a-z][a-z-]*)(?:\s+([\s\S]*))?$/i.exec(t);
  if (!m) return null;
  const name = m[1].toLowerCase();
  return { name, args: (m[2] ?? "").trim(), def: kSlash.find((d) => d.name === name) };
}

/** Commands matching what is typed so far (only while the first word is being typed). */
export function slashCompletions(text: string): SlashDef[] {
  const m = /^\/([a-z-]*)$/i.exec(text.trimStart());
  if (!m) return [];
  const q = m[1].toLowerCase();
  return kSlash.filter((d) => d.name.startsWith(q)).concat(q ? kSlash.filter((d) => !d.name.startsWith(q) && d.name.includes(q)) : []);
}

export function helpText(): string {
  const w = Math.max(...kSlash.map((d) => d.name.length + (d.args ? d.args.length + 1 : 0)));
  return [
    "Commands:",
    ...kSlash.map((d) => `  /${(d.name + (d.args ? " " + d.args : "")).padEnd(w)}  ${d.help}`),
    "",
    "Mentions attach context to your message:",
    "  @function          the function at the disassembly cursor",
    "  @0x140001000       memory and disassembly at an address",
    "  @game.exe+0x1a2b   the same, module-relative",
    "  @struct:Name       a struct type from the Structs catalog",
    "  @module:name.dll   a module's imports, strings and triage",
    "  @selection         the memory selection (or the disassembly cursor)",
    "",
    "Keys: Enter sends · Shift+Enter new line · Esc stops · ↑ in an empty box edits the last message · Ctrl+L focuses the box",
  ].join("\n");
}

// ---- mentions ---------------------------------------------------------------------------------

export type MentionKind = "function" | "address" | "struct" | "module" | "selection";
export type Mention = { kind: MentionKind; ref: string };

/** Characters a mention may contain after the '@'. */
const kTok = /[A-Za-z0-9_.:+~$<>-]/;

export function mentionToken(m: Mention): string {
  switch (m.kind) {
    case "function": return "@function";
    case "selection": return "@selection";
    case "struct": return `@struct:${m.ref}`;
    case "module": return `@module:${m.ref}`;
    case "address": return `@${m.ref}`;
  }
}

/** What one `@token` (without the '@') refers to, or null when it is not a mention. */
export function classifyMention(tok: string): Mention | null {
  const t = tok.replace(/[.,;:!?)]+$/, "");
  if (t === "function" || t === "fn") return { kind: "function", ref: "" };
  if (t === "selection" || t === "sel") return { kind: "selection", ref: "" };
  let m = /^struct:(.+)$/i.exec(t);
  if (m) return { kind: "struct", ref: m[1] };
  m = /^module:(.+)$/i.exec(t);
  if (m) return { kind: "module", ref: m[1] };
  if (/^0x[0-9a-f]{1,16}$/i.test(t)) return { kind: "address", ref: t.toLowerCase() };
  if (/^[A-Za-z0-9_.-]+\+0x[0-9a-f]{1,16}$/i.test(t)) return { kind: "address", ref: t };
  return null;
}

/** Every mention in `text` (an '@' at the start or after whitespace), deduplicated, in order. */
export function parseMentions(text: string): Mention[] {
  const out: Mention[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== "@" || (i > 0 && !/\s|\(/.test(text[i - 1]))) continue;
    let j = i + 1;
    while (j < text.length && kTok.test(text[j])) j++;
    const m = classifyMention(text.slice(i + 1, j));
    if (m) {
      const k = mentionToken(m);
      if (!seen.has(k)) {
        seen.add(k);
        out.push(m);
      }
    }
    i = j - 1;
  }
  return out;
}

/** The `@query` being typed at `caret`, if any: its start offset and the text after '@'. */
export function mentionAt(text: string, caret: number): { start: number; query: string } | null {
  let i = caret - 1;
  while (i >= 0 && kTok.test(text[i])) i--;
  if (i < 0 || text[i] !== "@" || (i > 0 && !/\s|\(/.test(text[i - 1]))) return null;
  return { start: i, query: text.slice(i + 1, caret) };
}

export type MentionItem = { mention: Mention; label: string; detail: string };

export type MentionSources = {
  names: readonly { address: string; name: string }[];
  modules: readonly { name: string; base: string }[];
  structs: readonly { name: string }[];
  cursor: string | null;
  selection: string | null;
};

/** Autocomplete for `@query`: the fixed mentions, then structs, modules and named addresses. */
export function mentionCompletions(query: string, src: MentionSources, max = 12): MentionItem[] {
  const q = query.toLowerCase();
  const out: MentionItem[] = [];
  const add = (it: MentionItem) => out.length < max && out.push(it);
  const matches = (s: string) => !q || s.toLowerCase().includes(q.replace(/^(struct|module):/, ""));
  if ("function".startsWith(q) || "fn".startsWith(q)) add({ mention: { kind: "function", ref: "" }, label: "@function", detail: src.cursor ? `function at ${src.cursor}` : "function at the disassembly cursor" });
  if ("selection".startsWith(q)) add({ mention: { kind: "selection", ref: "" }, label: "@selection", detail: src.selection ?? "memory selection or disassembly cursor" });
  const direct = classifyMention(query);
  if (direct?.kind === "address") add({ mention: direct, label: mentionToken(direct), detail: "memory and disassembly here" });
  if (!q.startsWith("module:")) for (const s of src.structs) if (matches(s.name) || q.startsWith("struct:") && s.name.toLowerCase().startsWith(q.slice(7))) add({ mention: { kind: "struct", ref: s.name }, label: `@struct:${s.name}`, detail: "struct type" });
  if (!q.startsWith("struct:")) for (const m of src.modules) if (matches(m.name)) add({ mention: { kind: "module", ref: m.name }, label: `@module:${m.name}`, detail: `module at ${m.base}` });
  if (q && !q.includes(":")) for (const n of src.names) if (n.name.toLowerCase().includes(q)) add({ mention: { kind: "address", ref: n.address.toLowerCase() }, label: `@${n.address.toLowerCase()}`, detail: n.name });
  return out;
}

/** Replaces the `@query` at [start, caret) with the chosen mention's token. */
export function insertMention(text: string, start: number, caret: number, m: Mention): { text: string; caret: number } {
  const tok = mentionToken(m) + " ";
  return { text: text.slice(0, start) + tok + text.slice(caret).replace(/^\s+/, ""), caret: start + tok.length };
}
