// Providers and models the assistant can use. Credentials never reach this side: the desktop app
// (src-tauri/relay/src/assistant/) stores them and reports only whether one is there. Model lists
// come live from each provider's list endpoint; the built-in lists below are the offline fallback.

export type ProviderKind = "anthropic" | "openai" | "gemini" | "openrouter" | "openai_compat" | "anthropic_compat";

export type ProviderInfo = {
  id: string;
  kind: ProviderKind;
  name: string;
  base_url: string;
  has_key: boolean;
  /** "sk-…wxyz" */
  key_hint: string | null;
  method: "api_key" | "oauth" | "none" | null;
  /** custom header names (never their values) */
  headers: string[];
  saved: number;
  path: string;
};

export type Price = { input: number; output: number; cache_read?: number | null; cache_write?: number | null };

export type ModelInfo = {
  id: string;
  name: string;
  provider: string;
  context: number | null;
  max_output: number | null;
  tools: boolean | null;
  vision: boolean | null;
  reasoning: boolean | null;
  effort: boolean | null;
  temperature: boolean | null;
  /** USD per million tokens */
  price: Price | null;
  /** from the built-in list, not the provider's API */
  builtin?: boolean;
  created?: number;
};

export const kKindLabels: Record<ProviderKind, string> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  gemini: "Google Gemini",
  openrouter: "OpenRouter",
  openai_compat: "OpenAI-compatible",
  anthropic_compat: "Anthropic-compatible",
};

/** What Settings shows for each built-in provider. */
export const kBuiltins: { id: ProviderKind; keyUrl: string; placeholder: string; blurb: string }[] = [
  { id: "anthropic", keyUrl: "https://console.anthropic.com/settings/keys", placeholder: "sk-ant-…", blurb: "Claude models with an Anthropic API key." },
  { id: "openai", keyUrl: "https://platform.openai.com/api-keys", placeholder: "sk-…", blurb: "GPT and o-series models with an OpenAI API key." },
  { id: "gemini", keyUrl: "https://aistudio.google.com/apikey", placeholder: "AIza…", blurb: "Gemini models with a Google AI Studio API key." },
  { id: "openrouter", keyUrl: "https://openrouter.ai/settings/keys", placeholder: "sk-or-…", blurb: "Hundreds of models on your OpenRouter credits: sign in, or paste a key." },
];

/** Presets for custom endpoints (local servers need no key). */
export const kEndpointPresets: { label: string; kind: ProviderKind; base: string; note: string }[] = [
  { label: "Ollama", kind: "openai_compat", base: "http://127.0.0.1:11434/v1", note: "local, no key" },
  { label: "LM Studio", kind: "openai_compat", base: "http://127.0.0.1:1234/v1", note: "local, no key" },
  { label: "llama.cpp server", kind: "openai_compat", base: "http://127.0.0.1:8080/v1", note: "local, no key" },
  { label: "vLLM", kind: "openai_compat", base: "http://127.0.0.1:8000/v1", note: "optional key" },
  { label: "LiteLLM proxy", kind: "openai_compat", base: "http://127.0.0.1:4000/v1", note: "proxy key" },
  { label: "Azure OpenAI", kind: "openai_compat", base: "https://<resource>.openai.azure.com/openai/v1", note: "add header api-key" },
  { label: "Anthropic-compatible gateway", kind: "anthropic_compat", base: "https://gateway.example.com", note: "x-api-key" },
];

/** Where a provider's requests go, for the data-sent disclosure. */
export function providerHost(p: Pick<ProviderInfo, "base_url">): string {
  const m = /^[a-z]+:\/\/([^/?#]+)/i.exec(p.base_url);
  return m ? m[1] : p.base_url;
}

export function isLocalHost(host: string): boolean {
  return /^(127\.|localhost|\[?::1\]?|0\.0\.0\.0)/i.test(host) || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host);
}

export const usable = (p: ProviderInfo): boolean => p.has_key || p.method === "none";

/** Anthropic per-million prices (the Models API does not report them). */
const kAnthropicPrices: Record<string, Price> = {
  "claude-fable-5-1": { input: 10, output: 50, cache_read: 0.25, cache_write: 12.5 },
  "claude-fable-5": { input: 10, output: 50, cache_read: 1, cache_write: 12.5 },
  "claude-opus-5-5": { input: 4, output: 20, cache_read: 0.2, cache_write: 5 },
  "claude-opus-5": { input: 5, output: 25, cache_read: 0.5, cache_write: 6.25 },
  "claude-opus-4-8": { input: 5, output: 25, cache_read: 0.5, cache_write: 6.25 },
  "claude-opus-4-7": { input: 5, output: 25, cache_read: 0.5, cache_write: 6.25 },
  "claude-opus-4-6": { input: 5, output: 25, cache_read: 0.5, cache_write: 6.25 },
  "claude-sonnet-5-5": { input: 2, output: 10, cache_read: 0.2, cache_write: 2.5 },
  "claude-sonnet-5": { input: 2, output: 10, cache_read: 0.2, cache_write: 2.5 },
  "claude-sonnet-4-6": { input: 3, output: 15, cache_read: 0.3, cache_write: 3.75 },
  "claude-haiku-5-5": { input: 0.1, output: 0.5, cache_read: 0.01, cache_write: 0.125 },
  "claude-haiku-4-5": { input: 1, output: 5, cache_read: 0.1, cache_write: 1.25 },
};

/** Models with server-side refusal fallback (`fallbacks: "default"`). */
export const kFallbackModels = new Set(["claude-fable-5-1", "claude-fable-5", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"]);

/** Price the app knows for a model it did not get one for from the API. */
export function knownPrice(kind: ProviderKind, id: string): Price | null {
  if (kind === "anthropic" || kind === "anthropic_compat") return kAnthropicPrices[id] ?? null;
  return null;
}

const m = (provider: string, id: string, name: string, x: Partial<ModelInfo> = {}): ModelInfo => ({
  id, name, provider, context: null, max_output: null, tools: true, vision: null, reasoning: null, effort: null, temperature: null, price: null, builtin: true, ...x,
});

/** Offline fallback lists (the live list replaces them once fetched). */
export function builtinModels(p: Pick<ProviderInfo, "id" | "kind">): ModelInfo[] {
  switch (p.kind) {
    case "anthropic": {
      const ant = (id: string, name: string, ctx = 1_000_000, out = 128_000) => m(p.id, id, name, { context: ctx, max_output: out, vision: true, reasoning: true, effort: true, temperature: false, price: kAnthropicPrices[id] });
      return [
        ant("claude-opus-5-5", "Claude Opus 5.5"),
        ant("claude-sonnet-5-5", "Claude Sonnet 5.5"),
        ant("claude-haiku-5-5", "Claude Haiku 5.5"),
        ant("claude-fable-5-1", "Claude Fable 5.1"),
        ant("claude-opus-5", "Claude Opus 5"),
        ant("claude-sonnet-5", "Claude Sonnet 5"),
      ];
    }
    case "openai":
      return [
        m(p.id, "gpt-5", "GPT-5", { reasoning: true, effort: true, temperature: false, vision: true }),
        m(p.id, "gpt-5-mini", "GPT-5 mini", { reasoning: true, effort: true, temperature: false, vision: true }),
        m(p.id, "gpt-4.1", "GPT-4.1", { reasoning: false, temperature: true, vision: true }),
      ];
    case "gemini":
      return [
        m(p.id, "gemini-2.5-pro", "Gemini 2.5 Pro", { context: 1_048_576, max_output: 65_536, reasoning: true, effort: true, vision: true, temperature: true }),
        m(p.id, "gemini-2.5-flash", "Gemini 2.5 Flash", { context: 1_048_576, max_output: 65_536, reasoning: true, effort: true, vision: true, temperature: true }),
      ];
    case "openrouter":
      return [
        m(p.id, "anthropic/claude-opus-5-5", "Anthropic: Claude Opus 5.5", { context: 1_000_000, reasoning: true, effort: true, vision: true }),
        m(p.id, "anthropic/claude-sonnet-5-5", "Anthropic: Claude Sonnet 5.5", { context: 1_000_000, reasoning: true, effort: true, vision: true }),
        m(p.id, "openai/gpt-5", "OpenAI: GPT-5", { reasoning: true, effort: true }),
        m(p.id, "google/gemini-2.5-pro", "Google: Gemini 2.5 Pro", { reasoning: true, effort: true }),
      ];
    default:
      return [];
  }
}

/** Adds the prices the app knows to a live list. */
export function withKnownPrices(kind: ProviderKind, list: ModelInfo[]): ModelInfo[] {
  return list.map((x) => (x.price ? x : { ...x, price: knownPrice(kind, x.id) }));
}

export type ModelSettings = {
  /** max output tokens */
  maxTokens?: number;
  effort?: "off" | "low" | "medium" | "high" | "xhigh" | "max";
  temperature?: number | null;
  /** user's price override, USD per million */
  price?: Price | null;
};

export const kEffortLevels = ["low", "medium", "high", "xhigh", "max"] as const;

/** Effort levels a provider understands (others map xhigh/max to high). */
export function effortLevels(kind: ProviderKind): readonly string[] {
  return kind === "anthropic" || kind === "anthropic_compat" ? kEffortLevels : ["low", "medium", "high"];
}

/** The defaults for a model, from what its provider reports. */
export function defaultSettings(kind: ProviderKind, mi: ModelInfo | undefined): Required<Omit<ModelSettings, "price">> {
  const cap = mi?.max_output ?? null;
  const maxTokens = Math.min(cap ?? (kind === "anthropic" ? 64000 : 16000), kind === "anthropic" ? 64000 : 32000);
  // Anthropic's current models think adaptively; others only when the model reasons (and local
  // servers only when the user asks, since many ignore or reject the parameter)
  const effort: ModelSettings["effort"] = kind === "anthropic" ? "medium" : kind === "openai_compat" || kind === "anthropic_compat" ? "off" : mi?.effort || mi?.reasoning ? "medium" : "off";
  return { maxTokens, effort, temperature: null };
}

/** "200K", "1M" */
export function fmtTokens(n: number | null | undefined): string {
  if (n == null) return "?";
  if (n >= 1_000_000) return `${Math.round((n / 1_000_000) * 10) / 10}M`;
  if (n >= 1000) return `${Math.round(n / 1000)}K`;
  return String(n);
}

/** Models whose id or name matches every word of `q`, grouped by provider in list order. */
export function filterModels(all: readonly ModelInfo[], q: string): ModelInfo[] {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return [...all];
  return all.filter((x) => {
    const hay = `${x.id} ${x.name} ${x.provider}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}

/** Fuzzy pick for `/model <name>`: exact id, then id/name containing the query. */
export function findModel(all: readonly ModelInfo[], q: string, provider?: string): ModelInfo | undefined {
  const s = q.trim().toLowerCase();
  if (!s) return undefined;
  const pool = provider ? [...all.filter((x) => x.provider === provider), ...all.filter((x) => x.provider !== provider)] : all;
  return pool.find((x) => x.id.toLowerCase() === s) ?? pool.find((x) => x.name.toLowerCase() === s) ?? pool.find((x) => x.id.toLowerCase().includes(s)) ?? filterModels(pool, s)[0];
}

export const kModelCacheMs = 6 * 3600_000;
