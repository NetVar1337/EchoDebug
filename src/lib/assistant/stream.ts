// Folds the Messages API's streamed events into the assistant message's content blocks.
// Tool inputs arrive as input_json_delta fragments (eager streaming), so they are parsed strictly
// at the end and checked against the tool's schema before anything runs.

export type Block =
  | { type: "text"; text: string }
  | { type: "thinking"; thinking: string; signature?: string }
  | { type: "redacted_thinking"; data: string }
  | { type: "tool_use"; id: string; name: string; input: unknown; /** raw JSON when it did not parse */ invalid?: string }
  | { type: "fallback"; [k: string]: unknown }
  | { type: string; [k: string]: unknown };

export type Usage = { input_tokens?: number; output_tokens?: number; cache_read_input_tokens?: number; cache_creation_input_tokens?: number };
export type StreamEvent = { type: string; [k: string]: unknown };

export class MessageAccumulator {
  content: Block[] = [];
  model = "";
  stopReason: string | null = null;
  stopDetails: unknown = null;
  usage: Usage = {};
  error: string | null = null;
  private partial = new Map<number, string>();

  apply(ev: StreamEvent): void {
    switch (ev.type) {
      case "message_start": {
        const m = ev.message as { model?: string; usage?: Usage } | undefined;
        this.model = m?.model ?? this.model;
        if (m?.usage) this.usage = { ...this.usage, ...m.usage };
        return;
      }
      case "content_block_start": {
        const i = Number(ev.index);
        const b = { ...(ev.content_block as Block) } as Block & Record<string, unknown>;
        if (b.type === "tool_use") {
          this.partial.set(i, "");
          b.input = {};
        }
        if (b.type === "text" && typeof b.text !== "string") b.text = "";
        if (b.type === "thinking" && typeof b.thinking !== "string") b.thinking = "";
        this.content[i] = b;
        return;
      }
      case "content_block_delta": {
        const i = Number(ev.index);
        const d = ev.delta as Record<string, unknown>;
        const b = this.content[i] as Record<string, unknown> | undefined;
        if (!b || !d) return;
        if (d.type === "text_delta") b.text = String(b.text ?? "") + String(d.text ?? "");
        else if (d.type === "thinking_delta") b.thinking = String(b.thinking ?? "") + String(d.thinking ?? "");
        else if (d.type === "signature_delta") b.signature = String(b.signature ?? "") + String(d.signature ?? "");
        else if (d.type === "input_json_delta") this.partial.set(i, (this.partial.get(i) ?? "") + String(d.partial_json ?? ""));
        else if (d.type === "citations_delta") b.citations = [...((b.citations as unknown[] | undefined) ?? []), d.citation];
        return;
      }
      case "content_block_stop": {
        const i = Number(ev.index);
        const b = this.content[i] as Record<string, unknown> | undefined;
        if (b?.type === "tool_use") this.finishTool(i, b);
        return;
      }
      case "message_delta": {
        const d = ev.delta as { stop_reason?: string; stop_details?: unknown } | undefined;
        if (d?.stop_reason) this.stopReason = d.stop_reason;
        if (d?.stop_details !== undefined) this.stopDetails = d.stop_details;
        const u = ev.usage as Usage | undefined;
        if (u) this.usage = { ...this.usage, ...u };
        return;
      }
      case "error": {
        const e = ev.error as { type?: string; message?: string } | undefined;
        this.error = `${e?.type ?? "error"}: ${e?.message ?? "stream error"}`;
        return;
      }
    }
  }

  private finishTool(i: number, b: Record<string, unknown>): void {
    const raw = this.partial.get(i) ?? "";
    this.partial.delete(i);
    if (!raw.trim()) {
      b.input = {};
      return;
    }
    try {
      const v = JSON.parse(raw);
      if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("not an object");
      b.input = v;
    } catch {
      b.input = {};
      b.invalid = raw;
    }
  }

  /** tool_use blocks of the finished message */
  toolUses(): Extract<Block, { type: "tool_use" }>[] {
    return this.content.filter((b): b is Extract<Block, { type: "tool_use" }> => b?.type === "tool_use");
  }

  text(): string {
    return this.content.filter((b) => b?.type === "text").map((b) => (b as { text: string }).text).join("");
  }
}

/**
 * The assistant content to send back on the next turn. Blocks are echoed unchanged (thinking
 * blocks included, with their signatures) except after a mid-output fallback: thinking,
 * redacted_thinking and tool_use blocks before the last `fallback` block are dropped, and the
 * fallback marker itself is left out. Our own `invalid` annotation is stripped.
 */
export function echoContent(content: readonly Block[]): Block[] {
  const list = content.filter(Boolean);
  const lastFallback = list.map((b) => b.type).lastIndexOf("fallback");
  return list
    .filter((b, i) => {
      if (b.type === "fallback") return false;
      if (i < lastFallback && (b.type === "thinking" || b.type === "redacted_thinking" || b.type === "tool_use")) return false;
      return true;
    })
    .map((b) => {
      if (b.type !== "tool_use") return b;
      const { invalid: _drop, ...rest } = b as Extract<Block, { type: "tool_use" }>;
      void _drop;
      return rest;
    });
}

/** Whether the tools of a finished turn may run: not on a refusal or a cut-off message. */
export function toolsMayRun(stopReason: string | null): boolean {
  return stopReason === "tool_use";
}
