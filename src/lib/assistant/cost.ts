// Token usage and cost: per message from the provider's usage fields × the model's price (or the
// cost the provider reports, as OpenRouter does), summed per conversation; and rough token
// estimates for /context.
import type { Price } from "./providers";
import type { Usage } from "./stream";

/** USD for one reply, or null when the price is unknown. */
export function usageCost(u: Usage | undefined, p: Price | null | undefined): number | null {
  if (!u) return null;
  if (typeof u.cost === "number" && Number.isFinite(u.cost)) return u.cost;
  if (!p) return null;
  const n = (x: number | undefined) => x ?? 0;
  return (n(u.input_tokens) * p.input + n(u.output_tokens) * p.output + n(u.cache_read_input_tokens) * (p.cache_read ?? p.input) + n(u.cache_creation_input_tokens) * (p.cache_write ?? p.input)) / 1e6;
}

export function addUsage(a: Usage, b: Usage | undefined): Usage {
  if (!b) return a;
  const out: Usage = { ...a };
  for (const k of ["input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "reasoning_tokens", "cost"] as const) {
    if (typeof b[k] === "number") out[k] = (out[k] ?? 0) + (b[k] as number);
  }
  return out;
}

/** Total of known costs, and whether every reply's cost was known. */
export function totalCost(items: readonly { cost?: number | null; usage?: Usage }[]): { usd: number; complete: boolean } {
  let usd = 0;
  let complete = true;
  for (const i of items) {
    if (!i.usage) continue;
    if (i.cost == null) complete = false;
    else usd += i.cost;
  }
  return { usd, complete };
}

export function fmtCost(usd: number | null | undefined): string {
  if (usd == null) return "—";
  if (usd === 0) return "$0";
  if (usd < 0.0001) return "<$0.0001";
  if (usd < 1) return `$${usd.toFixed(4)}`;
  return `$${usd.toFixed(2)}`;
}

export function fmtUsage(u: Usage | undefined): string {
  if (!u) return "";
  const parts = [`${u.input_tokens ?? 0} in`];
  if (u.cache_read_input_tokens) parts[0] += ` (+${u.cache_read_input_tokens} cached)`;
  parts.push(`${u.output_tokens ?? 0} out`);
  if (u.reasoning_tokens) parts[1] += ` (${u.reasoning_tokens} reasoning)`;
  return parts.join(" / ");
}

/** A rough token count (≈4 characters per token for English and code). */
export function estimateTokens(s: string): number {
  return Math.ceil(s.length / 4);
}

/** Rough size of a request: system prompt, tool definitions and the conversation. */
export function estimateRequest(system: string, tools: unknown, messages: unknown): { system: number; tools: number; messages: number; total: number } {
  const sys = estimateTokens(system);
  const tl = tools ? estimateTokens(JSON.stringify(tools)) : 0;
  const ms = estimateTokens(JSON.stringify(messages));
  return { system: sys, tools: tl, messages: ms, total: sys + tl + ms };
}
