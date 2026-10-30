import { describe, expect, it, vi } from "vitest";

vi.mock("./client", () => ({
  request: vi.fn(async (type: string, fields: Record<string, unknown>) => ({ type: `${type}_result`, id: 1, success: true, echo: fields })),
}));

import { chat, type ChatLine } from "./ai";
import { request } from "./client";

const settings = { provider: "anthropic" as const, apiKey: "k", model: "m", baseUrl: "" };

describe("ai tool loop", () => {
  it("runs a tool call then returns the final answer (anthropic)", async () => {
    const replies = [
      { content: [{ type: "tool_use", id: "t1", name: "read_memory", input: { address: "0x10", size: 4 } }], stop_reason: "tool_use" },
      { content: [{ type: "text", text: "done" }], stop_reason: "end_turn" },
    ];
    const bodies: any[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_u: string, init: RequestInit) => {
      bodies.push(JSON.parse(String(init.body)));
      return new Response(JSON.stringify(replies.shift()), { status: 200 });
    }));
    const lines: ChatLine[] = [];
    const history: unknown[] = [];
    await chat(settings, history, "read it", (l) => lines.push(l), new AbortController().signal);
    expect(request).toHaveBeenCalledWith("read", { address: "0x10", size: 4 }, true);
    expect(lines.map((l) => l.role)).toEqual(["tool", "assistant"]);
    const toolResult = bodies[1].messages.at(-1).content[0];
    expect(toolResult.type).toBe("tool_result");
    expect(JSON.parse(toolResult.content).echo).toEqual({ address: "0x10", size: 4 });
    expect(history).toHaveLength(4);
  });

  it("runs an openai-compatible tool call", async () => {
    const replies = [
      { choices: [{ message: { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "list_modules", arguments: "{}" } }] } }] },
      { choices: [{ message: { role: "assistant", content: "two modules" } }] },
    ];
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(replies.shift()), { status: 200 })));
    const lines: ChatLine[] = [];
    await chat({ ...settings, provider: "openai", baseUrl: "http://x/v1/" }, [], "mods?", (l) => lines.push(l), new AbortController().signal);
    expect(request).toHaveBeenCalledWith("modules", {}, true);
    expect(lines.at(-1)).toEqual({ role: "assistant", text: "two modules" });
  });
});
