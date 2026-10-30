// AI assistant (AiDA-style): the model drives the same verbs as the UI via src/lib/tools.json
import tools from "./tools.json";
import { request } from "./client";
import type { AiSettings } from "@/store/ui";

export type Tool = { name: string; verb: string; description: string; input_schema: Record<string, unknown> };
export type ChatLine = { role: "user" | "assistant" | "tool"; text: string };

const kTools = tools as Tool[];
const kMaxSteps = 16;
const kMaxResult = 12_000;

export const kSystem =
  "You are EchoDebug's reverse-engineering assistant. You inspect a live Windows x64 process through Echo's " +
  "hypervisor-backed memory API using the provided tools. Addresses are 0x-prefixed hex strings; byte data is " +
  "lowercase hex. Prefer reading and disassembling before concluding; never write memory unless the user asks. " +
  "Be concise and show addresses as module+0xRVA when you know the module.";

async function runTool(name: string, input: unknown): Promise<string> {
  const t = kTools.find((x) => x.name === name);
  if (!t) return JSON.stringify({ error: `unknown tool ${name}` });
  try {
    const r = await request(t.verb, (input ?? {}) as Record<string, unknown>, true);
    const { type: _t, id: _i, ...rest } = r;
    const s = JSON.stringify(rest);
    return s.length > kMaxResult ? s.slice(0, kMaxResult) + `…(truncated ${s.length - kMaxResult} chars)` : s;
  } catch (e) {
    return JSON.stringify({ error: e instanceof Error ? e.message : String(e) });
  }
}

type Emit = (l: ChatLine) => void;

/** Provider-native history lives in `history`; it is mutated in place so follow-up turns keep context. */
export async function chat(s: AiSettings, history: unknown[], userText: string, emit: Emit, signal: AbortSignal): Promise<void> {
  if (!s.apiKey) throw new Error("set an API key in Settings → AI assistant");
  history.push({ role: "user", content: userText });
  for (let step = 0; step < kMaxSteps; step++) {
    const more = s.provider === "anthropic" ? await anthropicStep(s, history, emit, signal) : await openaiStep(s, history, emit, signal);
    if (!more) return;
  }
  emit({ role: "assistant", text: `(stopped after ${kMaxSteps} tool steps)` });
}

async function post(url: string, headers: Record<string, string>, body: unknown, signal: AbortSignal): Promise<any> {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body), signal });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status}: ${text.slice(0, 400)}`);
  return JSON.parse(text);
}

async function anthropicStep(s: AiSettings, history: unknown[], emit: Emit, signal: AbortSignal): Promise<boolean> {
  const r = await post(
    "https://api.anthropic.com/v1/messages",
    { "x-api-key": s.apiKey, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
    { model: s.model, max_tokens: 4096, system: kSystem, messages: history, tools: kTools.map(({ name, description, input_schema }) => ({ name, description, input_schema })) },
    signal,
  );
  history.push({ role: "assistant", content: r.content });
  const results: unknown[] = [];
  for (const b of r.content as any[]) {
    if (b.type === "text" && b.text) emit({ role: "assistant", text: b.text });
    if (b.type === "tool_use") {
      emit({ role: "tool", text: `${b.name} ${JSON.stringify(b.input)}` });
      results.push({ type: "tool_result", tool_use_id: b.id, content: await runTool(b.name, b.input) });
    }
  }
  if (results.length === 0) return false;
  history.push({ role: "user", content: results });
  return true;
}

async function openaiStep(s: AiSettings, history: unknown[], emit: Emit, signal: AbortSignal): Promise<boolean> {
  const r = await post(
    `${s.baseUrl.replace(/\/$/, "")}/chat/completions`,
    { authorization: `Bearer ${s.apiKey}` },
    {
      model: s.model,
      messages: [{ role: "system", content: kSystem }, ...history],
      tools: kTools.map(({ name, description, input_schema }) => ({ type: "function", function: { name, description, parameters: input_schema } })),
    },
    signal,
  );
  const msg = r.choices?.[0]?.message;
  if (!msg) throw new Error("empty response");
  history.push(msg);
  if (msg.content) emit({ role: "assistant", text: msg.content });
  const calls = (msg.tool_calls ?? []) as { id: string; function: { name: string; arguments: string } }[];
  for (const c of calls) {
    let args: unknown = {};
    try { args = JSON.parse(c.function.arguments || "{}"); } catch { /* model sent bad json; pass empty args */ }
    emit({ role: "tool", text: `${c.function.name} ${c.function.arguments}` });
    history.push({ role: "tool", tool_call_id: c.id, content: await runTool(c.function.name, args) });
  }
  return calls.length > 0;
}
