// Turns the @-mentions of a message into context blocks sent with it. The data sources are
// injected (the store passes the live ones), so the resolution is unit-tested.
import { mentionToken, type Mention } from "./commands";
import { capLines, type FunctionContext, type ModuleContext } from "./prompts";

export type MentionDeps = {
  /** the disassembly cursor */
  cursor: () => string | null;
  /** an address expression (0x…, module+0x…) → 0x-prefixed address */
  parse: (expr: string) => string | null;
  functionAt: (addr: string) => Promise<FunctionContext>;
  /** hex of `size` bytes at addr */
  read: (addr: string, size: number) => Promise<string>;
  /** "addr  text" lines */
  disasm: (addr: string, count: number) => Promise<string[]>;
  label: (addr: string) => string;
  struct: (name: string) => { name: string; fields: { offset: number; type: string; name: string }[] } | undefined;
  module: (name: string) => Promise<ModuleContext>;
  /** the memory view's selection, if any */
  memorySelection: () => { from: string; to: string } | null;
};

export type Attachment = { token: string; kind: Mention["kind"]; title: string; text: string; error?: string };

const kMaxRead = 0x400;

function hexRows(addr: string, hex: string): string[] {
  const base = BigInt(addr);
  const rows: string[] = [];
  for (let off = 0; off * 2 < hex.length; off += 16) {
    const bytes = hex.slice(off * 2, off * 2 + 32).match(/../g) ?? [];
    const ascii = bytes.map((b) => { const c = parseInt(b, 16); return c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : "."; }).join("");
    rows.push(`0x${(base + BigInt(off)).toString(16)}  ${bytes.join(" ").padEnd(47)}  ${ascii}`);
  }
  return rows;
}

const tag = (name: string, attrs: string, body: string) => `<${name} ${attrs}>\n${body}\n</${name}>`;

/** One mention → an attachment (errors are attached as such, so the model knows it is missing). */
export async function resolveMention(m: Mention, d: MentionDeps): Promise<Attachment> {
  const token = mentionToken(m);
  const fail = (e: unknown): Attachment => ({ token, kind: m.kind, title: token, text: "", error: e instanceof Error ? e.message : String(e) });
  try {
    switch (m.kind) {
      case "function": {
        const at = d.cursor();
        if (!at) throw new Error("no disassembly cursor");
        const f = await d.functionAt(at);
        const body = [`address: ${f.address}`, `label: ${f.label}`, f.where ? `location: ${f.where}` : "", "", capLines(f.disasm, 800, "instructions"), f.pseudocode?.length ? `\npseudocode:\n${capLines(f.pseudocode, 300, "lines")}` : ""].filter((x) => x !== "").join("\n");
        return { token, kind: m.kind, title: `function ${f.label}`, text: tag("attachment", `ref="${token}" kind="function"`, body) };
      }
      case "address": {
        const a = d.parse(m.ref);
        if (!a) throw new Error(`cannot resolve ${m.ref}`);
        const [hex, lines] = await Promise.all([d.read(a, 0x100).catch(() => ""), d.disasm(a, 24).catch(() => [] as string[])]);
        const body = [`address: ${a} (${d.label(a)})`, hex ? `memory:\n${hexRows(a, hex).join("\n")}` : "memory: unreadable", lines.length ? `disassembly:\n${lines.join("\n")}` : ""].filter(Boolean).join("\n\n");
        return { token, kind: m.kind, title: `${m.ref} → ${d.label(a)}`, text: tag("attachment", `ref="${token}" kind="address"`, body) };
      }
      case "struct": {
        const s = d.struct(m.ref);
        if (!s) throw new Error(`no struct type named ${m.ref}`);
        const body = s.fields.map((f) => `+0x${f.offset.toString(16).padStart(3, "0")} ${f.type.padEnd(6)} ${f.name}`).join("\n");
        return { token, kind: m.kind, title: `struct ${s.name} (${s.fields.length} fields)`, text: tag("attachment", `ref="${token}" kind="struct" name="${s.name}"`, body || "(no fields)") };
      }
      case "module": {
        const c = await d.module(m.ref);
        const imports = c.imports.map((i) => `${i.dll}: ${i.names.slice(0, 40).join(", ")}${i.names.length > 40 ? ` … (+${i.names.length - 40})` : ""}`);
        const body = [`name: ${c.name}`, `base: ${c.base}`, `size: 0x${c.size.toString(16)}`, `imports:\n${capLines(imports, 60, "DLLs")}`, c.triage.length ? `triage:\n${capLines(c.triage.map((t) => `[${t.level}] ${t.dll}!${t.name}: ${t.why}`), 60, "findings")}` : "", `strings (sample of ${c.stringsTotal}):\n${capLines(c.strings, 120, "strings")}`].filter(Boolean).join("\n\n");
        return { token, kind: m.kind, title: `module ${c.name}`, text: tag("attachment", `ref="${token}" kind="module"`, body) };
      }
      case "selection": {
        const sel = d.memorySelection();
        if (sel) {
          const from = BigInt(sel.from);
          const size = Math.min(Number(BigInt(sel.to) - from) + 1, kMaxRead);
          const hex = await d.read(sel.from, size);
          const cut = Number(BigInt(sel.to) - from) + 1 > kMaxRead ? `\n[selection is longer; first 0x${kMaxRead.toString(16)} bytes shown]` : "";
          return { token, kind: m.kind, title: `memory ${sel.from}…${sel.to}`, text: tag("attachment", `ref="${token}" kind="memory_selection"`, `${sel.from} (${d.label(sel.from)}), ${size} bytes\n${hexRows(sel.from, hex).join("\n")}${cut}`) };
        }
        const at = d.cursor();
        if (!at) throw new Error("nothing is selected");
        const lines = await d.disasm(at, 32);
        return { token, kind: m.kind, title: `disassembly at ${at}`, text: tag("attachment", `ref="${token}" kind="disassembly"`, `${at} (${d.label(at)})\n${lines.join("\n")}`) };
      }
    }
  } catch (e) {
    return fail(e);
  }
}

/** The user content to send: attachments first (as context), then what the user typed. */
export function withAttachments(text: string, atts: readonly Attachment[]): string {
  const ok = atts.filter((a) => !a.error);
  const bad = atts.filter((a) => a.error);
  const notes = bad.map((a) => `<attachment ref="${a.token}" error="${a.error!.replace(/"/g, "'")}" />`);
  if (!ok.length && !notes.length) return text;
  return [...ok.map((a) => a.text), ...notes, text].join("\n\n");
}
