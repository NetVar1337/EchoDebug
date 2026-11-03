// Runs the assistant's tool calls: only tools allowedTool() knows (read-only EchoDebug tools and
// the two review tools), each input checked against its schema first.
import { request } from "../client";
import { callProvider, jsonSafe } from "../provider";
import { allowedTool, validateInput } from "./tools";

const kMaxResult = 40_000;

export type ToolOutcome = { content: string; isError: boolean };

/** Serialises a tool result for the model, saying so when it had to be shortened. */
export function resultText(v: unknown): string {
  const raw = JSON.stringify(jsonSafe(v)) ?? "null";
  if (raw.length <= kMaxResult) return raw;
  return `${raw.slice(0, kMaxResult)}\n[result truncated: ${raw.length - kMaxResult} more characters; ask for a smaller range or use limit/offset arguments]`;
}

/** Runs an EchoDebug tool for the assistant. `local` handles the submit_* review tools. */
export async function runTool(name: string, input: unknown, invalidJson: string | undefined, local: (name: string, input: unknown) => string): Promise<ToolOutcome> {
  const def = allowedTool(name);
  if (!def) return { content: `'${name}' is not available to the assistant (read-only tools only)`, isError: true };
  if (invalidJson !== undefined) return { content: JSON.stringify({ INVALID_JSON: invalidJson.slice(0, 2000) }), isError: true };
  const problem = validateInput({ type: "object", ...def.input_schema }, input);
  if (problem) return { content: `invalid input: ${problem}`, isError: true };
  if (!def.verb) return { content: local(name, input), isError: false };
  try {
    const args = { ...(input as Record<string, unknown>) };
    const r = def.verb.startsWith("ui_") ? await callProvider(def.verb, args) : await request(def.verb, args);
    if (r && typeof r === "object" && !Array.isArray(r)) {
      const { type: _t, id: _i, ...rest } = r as Record<string, unknown>;
      void _t; void _i;
      return { content: resultText(rest), isError: false };
    }
    return { content: resultText(r), isError: false };
  } catch (e) {
    return { content: String(e instanceof Error ? e.message : e), isError: true };
  }
}
