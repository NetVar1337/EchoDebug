// Saved conversations: the transcript the panel shows, the messages sent to the model, the
// provider and model they ran on and their usage. Serialised as one JSON document per
// conversation (stored by the desktop app, mode 0600), exported as Markdown on /export.
import type { Block, Usage } from "./stream";
import type { Msg } from "./prompts";
import { fmtCost, fmtUsage, totalCost } from "./cost";

export type Entry =
  | { kind: "user"; id: string; text: string; /** short title for a generated prompt; the full text is expandable */ title?: string; /** what was attached by @-mentions */ attachments?: string[]; /** index in `messages` where this turn starts */ at?: number }
  | { kind: "assistant"; id: string; blocks: Block[]; model: string; provider: string; streaming: boolean; usage?: Usage; cost?: number | null; started?: number; ms?: number }
  | { kind: "tool"; id: string; name: string; input: unknown; result?: string; isError?: boolean; running: boolean }
  | { kind: "note"; id: string; text: string; level: "info" | "warn" | "error"; /** monospace preformatted (help, tool lists) */ pre?: boolean; actions?: string[] };

export type Conversation = {
  v: 1;
  id: string;
  title: string;
  created: number;
  updated: number;
  provider: string;
  model: string;
  /** null: the default system prompt */
  system: string | null;
  entries: Entry[];
  messages: Msg[];
};

const rid = () => `c${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;

export function newConversation(provider: string, model: string, now = Date.now()): Conversation {
  return { v: 1, id: rid(), title: "", created: now, updated: now, provider, model, system: null, entries: [], messages: [] };
}

/** A title from the first thing the user asked. */
export function autoTitle(text: string): string {
  const line = text.replace(/<[^>]+>[\s\S]*?<\/[^>]+>/g, " ").replace(/@\S+/g, (m) => m).split("\n").map((l) => l.trim()).find(Boolean) ?? "";
  const t = line.replace(/\s+/g, " ");
  return t.length > 60 ? t.slice(0, 57).trimEnd() + "…" : t || "New conversation";
}

export function serialize(c: Conversation): string {
  // running state is never saved
  const entries = c.entries.map((e) => (e.kind === "assistant" ? { ...e, streaming: false } : e.kind === "tool" ? { ...e, running: false } : e));
  const totals = totalCost(entries.filter((e) => e.kind === "assistant") as { cost?: number | null; usage?: Usage }[]);
  return JSON.stringify({ ...c, entries, count: entries.filter((e) => e.kind === "user").length, cost: totals.usd });
}

export function deserialize(s: string): Conversation {
  const v = JSON.parse(s) as Partial<Conversation> & { v?: number };
  if (!v || typeof v !== "object" || typeof v.id !== "string") throw new Error("not a saved conversation");
  if (v.v !== 1) throw new Error(`unsupported conversation version ${String(v.v)}`);
  return {
    v: 1,
    id: v.id,
    title: typeof v.title === "string" ? v.title : "",
    created: Number(v.created) || 0,
    updated: Number(v.updated) || 0,
    provider: typeof v.provider === "string" ? v.provider : "anthropic",
    model: typeof v.model === "string" ? v.model : "",
    system: typeof v.system === "string" ? v.system : null,
    entries: Array.isArray(v.entries) ? v.entries : [],
    messages: Array.isArray(v.messages) ? v.messages : [],
  };
}

const fence = (s: string, lang = "") => {
  const n = Math.max(3, ...[...s.matchAll(/`{3,}/g)].map((m) => m[0].length + 1));
  return "`".repeat(n) + lang + "\n" + s + "\n" + "`".repeat(n);
};

/** The conversation as Markdown (thinking and tool results collapsed into details blocks). */
export function exportMarkdown(c: Conversation): string {
  const out = [`# ${c.title || "Assistant conversation"}`, "", `Provider: ${c.provider} · model: ${c.model} · ${new Date(c.updated).toISOString()}`, ""];
  for (const e of c.entries) {
    if (e.kind === "user") {
      out.push("## You", "");
      if (e.title) out.push(`**${e.title}**`, "", "<details><summary>Prompt sent</summary>", "", fence(e.text), "", "</details>", "");
      else out.push(e.text, "");
      if (e.attachments?.length) out.push(`Attached: ${e.attachments.join(", ")}`, "");
    } else if (e.kind === "assistant") {
      out.push(`## Assistant (${e.model})`, "");
      for (const b of e.blocks) {
        if (!b) continue;
        if (b.type === "text") out.push((b as { text: string }).text, "");
        else if (b.type === "thinking" && (b as { thinking: string }).thinking) out.push("<details><summary>Thinking</summary>", "", (b as { thinking: string }).thinking, "", "</details>", "");
      }
      if (e.usage) out.push(`_${fmtUsage(e.usage)} · ${fmtCost(e.cost)}_`, "");
    } else if (e.kind === "tool") {
      out.push(`<details><summary>Tool ${e.name}${e.isError ? " (error)" : ""}</summary>`, "", fence(JSON.stringify(e.input, null, 1), "json"), "", e.result !== undefined ? fence(e.result.length > 4000 ? e.result.slice(0, 4000) + "\n…" : e.result) : "", "", "</details>", "");
    } else if (e.kind === "note") {
      out.push(`> ${e.text.replace(/\n/g, "\n> ")}`, "");
    }
  }
  const t = totalCost(c.entries.filter((e) => e.kind === "assistant") as { cost?: number | null; usage?: Usage }[]);
  out.push("---", "", `Total cost: ${fmtCost(t.usd)}${t.complete ? "" : " (some replies had no known price)"}`);
  return out.join("\n");
}

/** What /compact asks the model for. */
export const kCompactPrompt = `Summarise our conversation so far so it can replace the full history. Keep every fact we established about the target: addresses (exact, 0x-prefixed), names, struct layouts, what each function does, open questions and what I asked for last. Be dense; leave out pleasantries and tool-call mechanics. Reply with the summary only, no tool calls.`;

/** The new history after /compact: the summary as context, acknowledged. */
export function compactedMessages(summary: string): Msg[] {
  return [
    { role: "user", content: `<conversation_summary note="earlier messages were compacted into this summary">\n${summary}\n</conversation_summary>\n\nContinue from this summary.` },
    { role: "assistant", content: [{ type: "text", text: "Understood. I have the summary of our earlier conversation and will continue from it." }] },
  ];
}

/** The messages of the conversation up to (not including) the last user turn, and that turn's text. */
export function lastUserTurn(c: Pick<Conversation, "entries" | "messages">): { before: Msg[]; text: string; title?: string; entryIndex: number } | null {
  for (let i = c.entries.length - 1; i >= 0; i--) {
    const e = c.entries[i];
    if (e.kind === "user" && e.at !== undefined) return { before: c.messages.slice(0, e.at), text: e.text, title: e.title, entryIndex: i };
  }
  return null;
}
