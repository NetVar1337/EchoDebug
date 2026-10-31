// AI assistant (AiDA-style): the model drives the same verbs as the UI via src/lib/tools.json
import tools from "./tools.json";
import { request } from "./client";
import { buildContext, kMutatingTools } from "./ai-providers";
import type { AiSettings } from "@/store/ui";

export type Tool = { name: string; verb: string; description: string; input_schema: Record<string, unknown> };
export type ChatLine = { role: "user" | "assistant" | "tool"; text: string };

export type AiContext = { target?: string; module?: string; selection?: string; address?: string };

const kTools = tools as Tool[];
const kMaxSteps = 24;
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

/** Asks the user before a tool that mutates the target; resolves to "run" or "skip". */
export type ToolApproval = (name: string, args: unknown) => Promise<boolean>;

export type ChatOptions = {
  /** extra system context (target, module, selection) */
  context?: AiContext;
  /** when set, mutating tools need an explicit yes */
  approval?: ToolApproval;
};

/** Provider-native history lives in `history`; it is mutated in place so follow-up turns keep context. */
export async function chat(
  s: AiSettings,
  history: unknown[],
  userText: string,
  emit: Emit,
  signal: AbortSignal,
  opts: ChatOptions = {},
): Promise<void> {
  if (!s.apiKey && !s.baseUrl.startsWith("http://127.0.0.1")) {
    throw new Error("set an API key in Settings → AI assistant");
  }
  const system = kSystem + buildContext(opts.context ?? {});
  history.push({ role: "user", content: userText });
  for (let step = 0; step < kMaxSteps; step++) {
    const more = s.provider === "anthropic" ? await anthropicStep(s, history, emit, signal, system, opts) : await openaiStep(s, history, emit, signal, system, opts);
    if (!more) return;
  }
  emit({ role: "assistant", text: `(stopped after ${kMaxSteps} tool steps)` });
}

type AnthropicBlock =
  | { type: "text"; text: string }
  | { type: "tool_use"; id: string; name: string; input: unknown };
type AnthropicReply = { content: AnthropicBlock[] };
type OpenAiToolCall = { id: string; function: { name: string; arguments: string } };
type OpenAiMessage = { role: string; content: string | null; tool_calls?: OpenAiToolCall[] };
type OpenAiReply = { choices: { message: OpenAiMessage }[] };

async function post<T>(url: string, headers: Record<string, string>, body: unknown, signal: AbortSignal): Promise<T> {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body), signal });
  const text = await res.text();
  if (!res.ok) throw new Error(`${res.status}: ${text.slice(0, 400)}`);
  return JSON.parse(text) as T;
}

/** Runs a tool unless it mutates the target and the user declined. */
async function approveAndRun(name: string, args: unknown, emit: Emit, opts: ChatOptions): Promise<string> {
  if (kMutatingTools[name] && opts.approval) {
    const ok = await opts.approval(name, args);
    if (!ok) {
      emit({ role: "tool", text: `${name} ${JSON.stringify(args)} — declined by the user` });
      return JSON.stringify({ declined: true, tool: name });
    }
  }
  emit({ role: "tool", text: `${name} ${JSON.stringify(args)}` });
  return runTool(name, args);
}

async function anthropicStep(s: AiSettings, history: unknown[], emit: Emit, signal: AbortSignal, system: string, opts: ChatOptions): Promise<boolean> {
  const r = await post<AnthropicReply>(
    "https://api.anthropic.com/v1/messages",
    { "x-api-key": s.apiKey, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
    { model: s.model, max_tokens: 4096, system, messages: history, tools: kTools.map(({ name, description, input_schema }) => ({ name, description, input_schema })) },
    signal,
  );
  history.push({ role: "assistant", content: r.content });
  const results: unknown[] = [];
  for (const b of r.content) {
    if (b.type === "text" && b.text) emit({ role: "assistant", text: b.text });
    if (b.type === "tool_use") {
      results.push({ type: "tool_result", tool_use_id: b.id, content: await approveAndRun(b.name, b.input, emit, opts) });
    }
  }
  if (results.length === 0) return false;
  history.push({ role: "user", content: results });
  return true;
}

async function openaiStep(s: AiSettings, history: unknown[], emit: Emit, signal: AbortSignal, system: string, opts: ChatOptions): Promise<boolean> {
  const r = await post<OpenAiReply>(
    `${s.baseUrl.replace(/\/$/, "")}/chat/completions`,
    { authorization: `Bearer ${s.apiKey}` },
    {
      model: s.model,
      messages: [{ role: "system", content: system }, ...history],
      tools: kTools.map(({ name, description, input_schema }) => ({ type: "function", function: { name, description, parameters: input_schema } })),
    },
    signal,
  );
  const msg = r.choices?.[0]?.message;
  if (!msg) throw new Error("empty response");
  history.push(msg);
  if (msg.content) emit({ role: "assistant", text: msg.content });
  const calls = msg.tool_calls ?? [];
  for (const c of calls) {
    let args: unknown = {};
    try { args = JSON.parse(c.function.arguments || "{}"); } catch { /* model sent bad json; pass empty args */ }
    history.push({ role: "tool", tool_call_id: c.id, content: await approveAndRun(c.function.name, args, emit, opts) });
  }
  return calls.length > 0;
}
