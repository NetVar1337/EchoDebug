// Provider presets and model catalogue for the AI assistant.
// Every preset knows its API shape: "anthropic" uses the Messages API,
// "openai" uses the OpenAI-compatible /chat/completions API.
import type { AiProvider } from "@/store/ui";

export type ProviderPreset = {
  id: string;
  label: string;
  provider: AiProvider;
  baseUrl: string;
  /** true when the endpoint needs no API key (local servers) */
  keyless?: boolean;
  models: string[];
};

export const kProviders: ProviderPreset[] = [
  {
    id: "anthropic",
    label: "Anthropic",
    provider: "anthropic",
    baseUrl: "https://api.anthropic.com/v1",
    models: ["claude-opus-5", "claude-sonnet-5-5", "claude-haiku-4-5"],
  },
  {
    id: "openai",
    label: "OpenAI",
    provider: "openai",
    baseUrl: "https://api.openai.com/v1",
    models: ["gpt-5.2", "gpt-5.2-mini", "gpt-4.1"],
  },
  {
    id: "openrouter",
    label: "OpenRouter",
    provider: "openai",
    baseUrl: "https://openrouter.ai/api/v1",
    models: ["anthropic/claude-sonnet-5-5", "openai/gpt-5.2", "google/gemini-3-pro"],
  },
  {
    id: "groq",
    label: "Groq",
    provider: "openai",
    baseUrl: "https://api.groq.com/openai/v1",
    models: ["llama-4-70b", "qwen3-32b"],
  },
  {
    id: "mistral",
    label: "Mistral",
    provider: "openai",
    baseUrl: "https://api.mistral.ai/v1",
    models: ["mistral-large-latest", "codestral-latest"],
  },
  {
    id: "deepseek",
    label: "DeepSeek",
    provider: "openai",
    baseUrl: "https://api.deepseek.com/v1",
    models: ["deepseek-reasoner", "deepseek-chat"],
  },
  {
    id: "ollama",
    label: "Ollama (local)",
    provider: "openai",
    baseUrl: "http://127.0.0.1:11434/v1",
    keyless: true,
    models: ["qwen3-coder:30b", "llama3.3:70b", "gpt-oss:20b"],
  },
  {
    id: "lmstudio",
    label: "LM Studio (local)",
    provider: "openai",
    baseUrl: "http://127.0.0.1:1234/v1",
    keyless: true,
    models: ["qwen3-coder-30b", "gpt-oss-20b"],
  },
];

export const kProviderById: Record<string, ProviderPreset> = Object.fromEntries(kProviders.map((p) => [p.id, p]));

/** Tools that change the target; the assistant asks before running them. */
export const kMutatingTools: Record<string, true> = {
  write_memory: true,
  freeze_value: true,
  value_scan_clear: true,
  attach: true,
  detach: true,
};

/**
 * Extra system context: the current target, the focused module and the user's
 * selection, so the model does not have to ask for what the UI already knows.
 */
export function buildContext(ctx: { target?: string; module?: string; selection?: string; address?: string }): string {
  const parts: string[] = [];
  if (ctx.target) parts.push(`attached target: ${ctx.target}`);
  if (ctx.module) parts.push(`focused module: ${ctx.module}`);
  if (ctx.selection) parts.push(`user selection: ${ctx.selection}`);
  if (ctx.address) parts.push(`current address: ${ctx.address}`);
  if (!parts.length) return "";
  return "\n\nCurrent session context:\n" + parts.map((p) => `- ${p}`).join("\n");
}
