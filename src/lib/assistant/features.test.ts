import { describe, expect, it } from "vitest";
import { classifyMention, helpText, insertMention, kSlash, mentionAt, mentionCompletions, mentionToken, parseMentions, parseSlash, slashCompletions } from "./commands";
import { resolveMention, withAttachments, type MentionDeps } from "./mentions";
import { addUsage, estimateRequest, fmtCost, totalCost, usageCost } from "./cost";
import { errorHint } from "./errors";
import { inlineText, parseInline, parseMarkdown } from "./markdown";
import { autoTitle, compactedMessages, deserialize, exportMarkdown, lastUserTurn, newConversation, serialize, type Conversation } from "./conversations";
import { builtinModels, defaultSettings, filterModels, findModel, fmtTokens, isLocalHost, knownPrice, providerHost, usable, withKnownPrices, type ModelInfo } from "./providers";
import { MessageAccumulator } from "./stream";
import { memoryConvs } from "./api";

describe("slash commands", () => {
  it("parses commands and arguments", () => {
    expect(parseSlash("/explain 0x140001000")).toMatchObject({ name: "explain", args: "0x140001000", def: { name: "explain" } });
    expect(parseSlash("  /MODEL  opus 5.5 ")).toMatchObject({ name: "model", args: "opus 5.5" });
    expect(parseSlash("/compact")).toMatchObject({ name: "compact", args: "" });
    expect(parseSlash("/system You are terse.\nAlways cite addresses.")!.args).toBe("You are terse.\nAlways cite addresses.");
    expect(parseSlash("/nope")).toMatchObject({ name: "nope", def: undefined });
    expect(parseSlash("what does /explain do?")).toBeNull();
    expect(parseSlash("// comment")).toBeNull();
    expect(parseSlash("/")).toBeNull();
  });
  it("completes while the first word is typed", () => {
    expect(slashCompletions("/").length).toBe(kSlash.length);
    expect(slashCompletions("/co").map((d) => d.name)).toEqual(["compact", "context", "cost"]);
    expect(slashCompletions("/x").map((d) => d.name)).toEqual(["explain", "export", "context"]);
    expect(slashCompletions("/zz")).toEqual([]);
    expect(slashCompletions("/model opus")).toEqual([]);
    expect(slashCompletions("hello")).toEqual([]);
    // every command the owner asked for exists
    for (const n of ["explain", "names", "struct", "summary", "model", "provider", "clear", "new", "compact", "retry", "export", "tools", "context", "cost", "system", "help"]) expect(kSlash.some((d) => d.name === n), n).toBe(true);
    expect(helpText()).toContain("/compact");
  });
});

describe("mentions", () => {
  it("classifies and parses mentions", () => {
    expect(classifyMention("function")).toEqual({ kind: "function", ref: "" });
    expect(classifyMention("0x140001000,")).toEqual({ kind: "address", ref: "0x140001000" });
    expect(classifyMention("game.exe+0x1a2b")).toEqual({ kind: "address", ref: "game.exe+0x1a2b" });
    expect(classifyMention("struct:CPlayer")).toEqual({ kind: "struct", ref: "CPlayer" });
    expect(classifyMention("module:kernel32.dll")).toEqual({ kind: "module", ref: "kernel32.dll" });
    expect(classifyMention("selection")).toEqual({ kind: "selection", ref: "" });
    expect(classifyMention("someone")).toBeNull();
    const m = parseMentions("compare @function with @0x1400020A0 and @struct:Player, not me@mail.com; again @function");
    expect(m.map(mentionToken)).toEqual(["@function", "@0x1400020a0", "@struct:Player"]);
  });
  it("finds the mention being typed and inserts a pick", () => {
    expect(mentionAt("look at @fun", 12)).toEqual({ start: 8, query: "fun" });
    expect(mentionAt("mail me@x", 9)).toBeNull();
    expect(mentionAt("no mention", 10)).toBeNull();
    const r = insertMention("look at @fun please", 8, 12, { kind: "function", ref: "" });
    expect(r.text).toBe("look at @function please");
    expect(r.caret).toBe("look at @function ".length);
  });
  it("completes from structs, modules and names", () => {
    const src = { names: [{ address: "0x140001000", name: "update_health" }], modules: [{ name: "game.exe", base: "0x140000000" }, { name: "kernel32.dll", base: "0x7ff8" }], structs: [{ name: "Player" }], cursor: "0x140001000", selection: null };
    expect(mentionCompletions("", src).map((x) => x.label).slice(0, 2)).toEqual(["@function", "@selection"]);
    expect(mentionCompletions("play", src).map((x) => x.label)).toEqual(["@struct:Player"]);
    expect(mentionCompletions("kern", src).map((x) => x.label)).toEqual(["@module:kernel32.dll"]);
    expect(mentionCompletions("health", src).map((x) => [x.label, x.detail])).toEqual([["@0x140001000", "update_health"]]);
    expect(mentionCompletions("0x1234", src)[0].label).toBe("@0x1234");
  });
  it("resolves mentions into attachments", async () => {
    const deps: MentionDeps = {
      cursor: () => "0x140001000",
      parse: (e) => (e.startsWith("game.exe+") ? "0x" + (0x140000000 + parseInt(e.split("+")[1], 16)).toString(16) : e.startsWith("0x") ? e : null),
      functionAt: async (a) => ({ address: a, label: "sub_140001000", disasm: [`${a}  ret`], names: [], comments: [], callees: [], abi: "win64" }),
      read: async (_a, size) => "41".repeat(Math.min(size, 32)),
      disasm: async (a) => [`${a}  nop`],
      label: (a) => `lbl_${a}`,
      struct: (n) => (n === "Player" ? { name: "Player", fields: [{ offset: 0, type: "ptr", name: "vtable" }, { offset: 8, type: "f32", name: "health" }] } : undefined),
      module: async () => { throw new Error("not attached"); },
      memorySelection: () => ({ from: "0x2000", to: "0x200f" }),
    };
    const f = await resolveMention({ kind: "function", ref: "" }, deps);
    expect(f.text).toContain('kind="function"');
    expect(f.text).toContain("0x140001000  ret");
    const a = await resolveMention({ kind: "address", ref: "game.exe+0x10" }, deps);
    expect(a.title).toBe("game.exe+0x10 → lbl_0x140000010");
    expect(a.text).toContain("0x140000010  41 41");
    expect(a.text).toContain("AAAA");
    const s = await resolveMention({ kind: "struct", ref: "Player" }, deps);
    expect(s.text).toContain("+0x008 f32    health");
    const missing = await resolveMention({ kind: "struct", ref: "Nope" }, deps);
    expect(missing.error).toMatch(/no struct type/);
    const mod = await resolveMention({ kind: "module", ref: "x.dll" }, deps);
    expect(mod.error).toBe("not attached");
    const sel = await resolveMention({ kind: "selection", ref: "" }, deps);
    expect(sel.title).toBe("memory 0x2000…0x200f");
    expect(sel.text).toContain("16 bytes");
    const text = withAttachments("what is @struct:Player?", [s, missing]);
    expect(text.indexOf("<attachment")).toBe(0);
    expect(text).toContain('error="no struct type named Nope"');
    expect(text.endsWith("what is @struct:Player?")).toBe(true);
    expect(withAttachments("plain", [])).toBe("plain");
  });
});

describe("cost", () => {
  const price = { input: 4, output: 20, cache_read: 0.2, cache_write: 5 };
  it("computes from usage × price, or uses the reported cost", () => {
    expect(usageCost({ input_tokens: 1_000_000, output_tokens: 100_000 }, price)).toBeCloseTo(6);
    expect(usageCost({ input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 1_000_000, cache_creation_input_tokens: 1_000_000 }, price)).toBeCloseTo(5.2);
    expect(usageCost({ input_tokens: 10 }, null)).toBeNull();
    expect(usageCost({ input_tokens: 10, cost: 0.0042 }, null)).toBe(0.0042);
    expect(usageCost(undefined, price)).toBeNull();
    expect(usageCost({ input_tokens: 1_000_000 }, { input: 1, output: 2 })).toBe(1);
  });
  it("sums per conversation and formats", () => {
    expect(addUsage({ input_tokens: 1, output_tokens: 2 }, { input_tokens: 3, cache_read_input_tokens: 4 })).toEqual({ input_tokens: 4, output_tokens: 2, cache_read_input_tokens: 4 });
    expect(totalCost([{ usage: {}, cost: 0.5 }, { usage: {}, cost: 0.25 }])).toEqual({ usd: 0.75, complete: true });
    expect(totalCost([{ usage: {}, cost: 0.5 }, { usage: {}, cost: null }, { cost: null }])).toEqual({ usd: 0.5, complete: false });
    expect(fmtCost(null)).toBe("—");
    expect(fmtCost(0.00001)).toBe("<$0.0001");
    expect(fmtCost(0.01234)).toBe("$0.0123");
    expect(fmtCost(12.345)).toBe("$12.35");
    const e = estimateRequest("abcd", [{ x: 1 }], [{ role: "user", content: "hello" }]);
    expect(e.system).toBe(1);
    expect(e.total).toBe(e.system + e.tools + e.messages);
  });
  it("knows Anthropic prices and keeps API prices", () => {
    expect(knownPrice("anthropic", "claude-opus-5-5")).toMatchObject({ input: 4, output: 20 });
    expect(knownPrice("openai", "gpt-5")).toBeNull();
    const live: ModelInfo[] = [{ id: "claude-opus-5-5", name: "x", provider: "anthropic", context: null, max_output: null, tools: true, vision: null, reasoning: null, effort: null, temperature: null, price: null }];
    expect(withKnownPrices("anthropic", live)[0].price).toMatchObject({ input: 4 });
    expect(withKnownPrices("anthropic", [{ ...live[0], price: { input: 1, output: 1 } }])[0].price).toEqual({ input: 1, output: 1 });
  });
});

describe("providers and models", () => {
  const all = [...builtinModels({ id: "anthropic", kind: "anthropic" }), ...builtinModels({ id: "openrouter", kind: "openrouter" })];
  it("filters and finds models", () => {
    expect(filterModels(all, "sonnet 5.5").map((m) => `${m.provider}/${m.id}`)).toEqual(["anthropic/claude-sonnet-5-5", "openrouter/anthropic/claude-sonnet-5-5"]);
    expect(findModel(all, "claude-haiku-5-5")!.id).toBe("claude-haiku-5-5");
    expect(findModel(all, "sonnet", "openrouter")!.provider).toBe("openrouter");
    expect(findModel(all, "gpt-5")!.id).toBe("openai/gpt-5");
    expect(findModel(all, "zzz")).toBeUndefined();
  });
  it("defaults per provider", () => {
    expect(defaultSettings("anthropic", all[0])).toEqual({ maxTokens: 64000, effort: "medium", temperature: null });
    expect(defaultSettings("openai_compat", undefined).effort).toBe("off");
    expect(defaultSettings("openrouter", { ...all[0], max_output: 8000 }).maxTokens).toBe(8000);
    expect(fmtTokens(1_000_000)).toBe("1M");
    expect(fmtTokens(200_000)).toBe("200K");
    expect(fmtTokens(null)).toBe("?");
  });
  it("hosts and usability", () => {
    expect(providerHost({ base_url: "http://127.0.0.1:11434/v1" })).toBe("127.0.0.1:11434");
    expect(isLocalHost("127.0.0.1:11434")).toBe(true);
    expect(isLocalHost("192.168.1.5:8000")).toBe(true);
    expect(isLocalHost("api.openai.com")).toBe(false);
    const p = { id: "x", kind: "openai_compat" as const, name: "", base_url: "", has_key: false, key_hint: null, method: null, headers: [], saved: 0, path: "" };
    expect(usable(p)).toBe(false);
    expect(usable({ ...p, method: "none" })).toBe(true);
  });
});

describe("errors", () => {
  it("offers the right actions", () => {
    expect(errorHint("HTTP 401 authentication_error: invalid x-api-key (check the Anthropic credential in Settings → Assistant)").actions).toEqual(["settings"]);
    expect(errorHint("HTTP 429: slow down (rate limited; retry after 8s, then /retry)")).toEqual({ actions: ["retry"], retryAfter: 8 });
    expect(errorHint("HTTP 400: prompt is too long (the conversation is too long for this model; run /compact or start a /new conversation)").actions).toContain("compact");
    expect(errorHint("HTTP 404 (unknown model or endpoint; refresh the model list or check the base URL in Settings → Assistant)").actions).toEqual(expect.arrayContaining(["models", "settings"]));
    expect(errorHint("cannot reach api.openai.com: dns").actions).toEqual(["retry"]);
  });
});

describe("markdown", () => {
  it("parses blocks", () => {
    const b = parseMarkdown("# Title\n\nSome **bold** and `code`.\n\n- one\n  - nested\n- two\n\n1. first\n2. second\n\n```asm\nmov rax, 0x140001000\n```\n\n> quoted\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n---");
    expect(b.map((x) => x.t)).toEqual(["h", "p", "list", "list", "code", "quote", "table", "hr"]);
    expect(b[2]).toMatchObject({ t: "list", ordered: false, items: [{ level: 0 }, { level: 1 }, { level: 0 }] });
    expect(b[3]).toMatchObject({ ordered: true, start: 1 });
    expect(b[4]).toEqual({ t: "code", lang: "asm", code: "mov rax, 0x140001000", open: false });
    expect(b[6]).toMatchObject({ t: "table", rows: [[[{ t: "text", v: "1" }], [{ t: "text", v: "2" }]]] });
  });
  it("renders an unterminated fence while streaming as open code", () => {
    const b = parseMarkdown("Here:\n```c\nint x;");
    expect(b[1]).toEqual({ t: "code", lang: "c", code: "int x;", open: true });
  });
  it("parses inline marks and addresses", () => {
    const i = parseInline("call **sub_1400** at 0x140001000 or game.exe+0x1a2b, see [docs](https://x.y) and *note* `0x1234`");
    expect(i.filter((x) => x.t === "addr").map((x) => (x as { v: string }).v)).toEqual(["0x140001000", "game.exe+0x1a2b"]);
    expect(i.some((x) => x.t === "b")).toBe(true);
    expect(i.some((x) => x.t === "i")).toBe(true);
    expect(i.find((x) => x.t === "link")).toMatchObject({ href: "https://x.y" });
    expect(i.find((x) => x.t === "code")).toEqual({ t: "code", v: "0x1234" });
    expect(inlineText(parseInline("snake_case_name stays"))).toBe("snake_case_name stays");
    expect(parseInline("2 * 3 * 4").every((x) => x.t === "text")).toBe(true);
    expect(inlineText(parseInline("\\*literal\\*"))).toBe("*literal*");
  });
});

describe("conversations", () => {
  const conv = (): Conversation => {
    const c = newConversation("anthropic", "claude-opus-5-5", 1000);
    c.title = "Health";
    c.entries = [
      { kind: "user", id: "u1", text: "what does @function do?", at: 0, attachments: ["function sub_1"] },
      { kind: "assistant", id: "a1", blocks: [{ type: "thinking", thinking: "hmm" }, { type: "text", text: "It **heals**." }], model: "claude-opus-5-5", provider: "anthropic", streaming: true, usage: { input_tokens: 10, output_tokens: 5 }, cost: 0.001 },
      { kind: "tool", id: "t1", name: "read_memory", input: { address: "0x10" }, result: "{\"hex\":\"00\"}", running: true },
      { kind: "user", id: "u2", text: "and the caller?", at: 3 },
      { kind: "note", id: "n1", text: "rate limited", level: "error" },
    ];
    c.messages = [{ role: "user", content: "a" }, { role: "assistant", content: [] }, { role: "user", content: [] }, { role: "user", content: "and the caller?" }];
    return c;
  };
  it("round-trips through JSON without running state", () => {
    const c = conv();
    const s = serialize(c);
    const back = deserialize(s);
    expect(back.title).toBe("Health");
    expect(back.entries.length).toBe(5);
    expect((back.entries[1] as { streaming: boolean }).streaming).toBe(false);
    expect((back.entries[2] as { running: boolean }).running).toBe(false);
    expect(JSON.parse(s).count).toBe(2);
    expect(JSON.parse(s).cost).toBe(0.001);
    expect(() => deserialize("{}")).toThrow();
    expect(() => deserialize(JSON.stringify({ id: "x", v: 9 }))).toThrow(/version/);
  });
  it("persists through a backend: list, rename, delete", async () => {
    const b = memoryConvs();
    const c1 = conv();
    const c2 = { ...newConversation("openai", "gpt-5", 5000), title: "Other", updated: 5000 };
    await b.save(c1.id, serialize(c1));
    await b.save(c2.id, serialize(c2));
    expect((await b.list()).map((x) => x.title)).toEqual(["Other", "Health"]);
    const loaded = deserialize(await b.load(c1.id));
    await b.save(c1.id, serialize({ ...loaded, title: "Renamed", updated: 9000 }));
    expect((await b.list())[0].title).toBe("Renamed");
    await b.remove(c2.id);
    expect((await b.list()).length).toBe(1);
    await expect(b.load(c2.id)).rejects.toThrow();
  });
  it("exports Markdown", () => {
    const md = exportMarkdown(conv());
    for (const s of ["# Health", "## You", "what does @function do?", "Attached: function sub_1", "## Assistant (claude-opus-5-5)", "It **heals**.", "<summary>Thinking</summary>", "Tool read_memory", "> rate limited", "Total cost: $0.0010"]) expect(md).toContain(s);
  });
  it("finds the last user turn for retry / edit, and builds compacted history", () => {
    const t = lastUserTurn(conv())!;
    expect(t.text).toBe("and the caller?");
    expect(t.before.length).toBe(3);
    expect(t.entryIndex).toBe(3);
    const m = compactedMessages("We found the health function at 0x140001000.");
    expect(m.length).toBe(2);
    expect(m[0].role).toBe("user");
    expect(String(m[0].content)).toContain("0x140001000");
    expect(autoTitle("<attachment ref=\"@function\">\nlots\n</attachment>\n\nWhy does it crash?")).toBe("Why does it crash?");
    expect(autoTitle("x".repeat(100)).length).toBe(58);
  });
});

describe("normalised stream events", () => {
  it("keep OpenRouter reasoning details and Gemini signatures on their blocks", () => {
    const acc = new MessageAccumulator();
    for (const ev of [
      { type: "message_start", message: { model: "anthropic/claude-opus-5-5", usage: {} } },
      { type: "content_block_start", index: 0, content_block: { type: "thinking", thinking: "", origin: "openrouter" } },
      { type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: "hm" } },
      { type: "content_block_delta", index: 0, delta: { type: "details_delta", details: [{ type: "reasoning.text", signature: "s" }] } },
      { type: "content_block_stop", index: 0 },
      { type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "gem_0", name: "read_memory", input: {}, origin: "gemini", signature: "SIG" } },
      { type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '{"address":"0x10","size":4}' } },
      { type: "content_block_stop", index: 1 },
      { type: "message_delta", delta: { stop_reason: "tool_use" }, usage: { input_tokens: 5, output_tokens: 2, cost: 0.0001 } },
      { type: "message_stop" },
    ]) acc.apply(ev);
    expect(acc.content[0]).toMatchObject({ thinking: "hm", origin: "openrouter", details: [{ signature: "s" }] });
    expect(acc.toolUses()[0]).toMatchObject({ id: "gem_0", signature: "SIG", input: { address: "0x10", size: 4 } });
    expect(acc.usage.cost).toBe(0.0001);
  });
});
