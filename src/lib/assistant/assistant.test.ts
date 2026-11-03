import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import kTools from "../tools.json";
import { allowedTool, apiTools, assistantTools, isReadOnlyVerb, kAssistantDeny, kDestructive, kStateful, validateInput, type ToolDef } from "./tools";
import { MessageAccumulator, echoContent, toolsMayRun } from "./stream";
import {
  applyFieldAt, buildRequest, capLines, cleanIdentifier, explainFunctionPrompt, kDefaultModel, kModels, kSystemPrompt, parseNameSuggestions,
  parseStructFields, sampleStrings, suggestNamesPrompt, suggestStructPrompt, summariseModulePrompt, type FunctionContext,
} from "./prompts";
import type { Field } from "../analysis/struct";

/** a `const NAME: &[&str] = &[ ... ];` list from a Rust source file */
function rustList(file: string, name: string): string[] {
  const src = readFileSync(new URL(file, import.meta.url), "utf8");
  const m = new RegExp(`const ${name}: &\\[&str\\] = &\\[([\\s\\S]*?)\\];`).exec(src);
  if (!m) throw new Error(`${name} not found in ${file}`);
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
}

describe("assistant tool filtering", () => {
  it("mirrors the relay's lists exactly", () => {
    expect(kDestructive).toEqual(rustList("../../../src-tauri/relay/src/mcp.rs", "DESTRUCTIVE"));
    expect(kStateful).toEqual(rustList("../../../src-tauri/relay/src/mcp.rs", "STATEFUL"));
    expect(kAssistantDeny).toEqual(rustList("../../../src-tauri/relay/src/assistant.rs", "ASSISTANT_DENY"));
  });

  it("never offers write, freeze, dump, patch, rename, attach or execution tools", () => {
    const offered = new Set(apiTools().map((t) => t.name));
    for (const name of [
      "write_memory", "freeze_value", "freeze_group", "dump_module", "revert_patch", "set_name", "set_comment", "attach", "detach",
      "value_scan_first", "value_scan_next", "emulate", "emu_start", "emu_step", "emu_run", "emu_set", "lift_trace", "devirt", "watch_add",
      "alert_add", "agent_config", "cancel_job", "ui_find_oep", "ui_batch_decrypt", "ui_rebuild_imports", "ui_load_symbols", "ui_guess_struct",
      "reopen_native_socket", "module_monitor", "page_monitor", "mem_snapshot", "ptr_save",
      // the native debugger's access finder and API monitor, their read-only tools included
      "find_accesses_start", "find_accesses_results", "find_accesses_stop",
      "api_monitor_start", "api_monitor_log", "api_monitor_stop", "api_monitor_signatures",
    ]) {
      expect(offered.has(name), name).toBe(false);
      expect(allowedTool(name), name).toBeUndefined();
    }
    // every offered EchoDebug tool maps to a verb that is not gated, stateful or denied
    for (const t of assistantTools()) {
      expect(kDestructive).not.toContain(t.verb);
      expect(kStateful).not.toContain(t.verb);
      expect(kAssistantDeny).not.toContain(t.verb);
    }
  });

  it("offers the read-only analysis tools and the two review tools", () => {
    const offered = new Set(apiTools().map((t) => t.name));
    for (const name of ["read_memory", "disassemble", "list_modules", "ui_strings", "ui_pe_info", "ui_xrefs_to", "list_names", "list_comments", "ui_cfg", "submit_name_suggestions", "submit_struct_fields"]) {
      expect(offered.has(name), name).toBe(true);
    }
    expect(apiTools().every((t) => t.eager_input_streaming && t.input_schema.type === "object")).toBe(true);
    expect(assistantTools().length).toBeLessThan((kTools as ToolDef[]).length);
    expect(isReadOnlyVerb("dbg_continue")).toBe(false);
  });

  it("validates tool inputs against their schema", () => {
    const schema = allowedTool("read_memory")!.input_schema;
    expect(validateInput(schema, { address: "0x1000", size: 16 })).toBeNull();
    expect(validateInput(schema, { address: "0x1000" })).toMatch(/size is required/);
    expect(validateInput(schema, { address: 4096, size: 16 })).toMatch(/address must be string/);
    expect(validateInput(schema, [])).toMatch(/must be object/);
    const sub = allowedTool("submit_struct_fields")!.input_schema;
    expect(validateInput(sub, { fields: [{ offset: 0, type: "ptr", name: "vtable", reason: "" }] })).toBeNull();
    expect(validateInput(sub, { fields: [{ offset: 0, type: "pointer", name: "vtable", reason: "" }] })).toMatch(/must be one of/);
  });
});

describe("request builder", () => {
  it("defaults to the current default model with adaptive thinking, effort, caching and fallbacks", () => {
    expect(kDefaultModel).toBe("claude-opus-5-5");
    const b = buildRequest({ model: kDefaultModel, effort: "medium", messages: [{ role: "user", content: "hi" }] });
    expect(b.model).toBe("claude-opus-5-5");
    expect(b.thinking).toEqual({ type: "adaptive", display: "summarized" });
    expect(b.output_config).toEqual({ effort: "medium" });
    expect(b.cache_control).toEqual({ type: "ephemeral" });
    expect(b.fallbacks).toBe("default");
    expect(b).not.toHaveProperty("temperature");
    expect((b.tools as unknown[]).length).toBeGreaterThan(10);
    expect((b.system as { text: string }[])[0].text).toBe(kSystemPrompt);
  });
  it("sends no fallbacks for models without server-side fallback, and no tools on request", () => {
    const haiku = kModels.find((m) => m.id === "claude-haiku-5-5")!;
    const b = buildRequest({ model: haiku.id, effort: "low", messages: [], tools: false });
    expect(b).not.toHaveProperty("fallbacks");
    expect(b).not.toHaveProperty("tools");
  });
});

const fn: FunctionContext = {
  address: "0x140001000", label: "sub_140001000", where: "game.exe+0x1000", module: "game.exe", abi: "win64",
  disasm: ["0x140001000  push rbx", "0x140001001  call 0x140002000", "0x140001006  ret"],
  pseudocode: ["sub_140002000(rcx);"],
  names: [{ address: "0x140003000", name: "g_player" }],
  comments: [{ address: "0x140001001", text: "updates health" }],
  callees: [{ address: "0x140002000", label: "sub_140002000" }],
};

describe("prompt builders", () => {
  it("explain function includes code, names, comments and callees", () => {
    const p = explainFunctionPrompt(fn);
    for (const s of ["0x140001000  push rbx", "<pseudocode", "g_player", "updates health", "<callees>", "Windows x64", "Explain what the function sub_140001000 does"]) expect(p).toContain(s);
  });
  it("suggest names asks for submit_name_suggestions", () => {
    const p = suggestNamesPrompt(fn);
    expect(p).toContain("submit_name_suggestions");
    expect(p).toContain("0x140001006  ret");
  });
  it("never truncates silently", () => {
    const lines = Array.from({ length: 10 }, (_, i) => `l${i}`);
    expect(capLines(lines, 20, "x")).toBe(lines.join("\n"));
    expect(capLines(lines, 3, "instructions")).toBe("l0\nl1\nl2\n[7 more instructions not included; use the tools to read them]");
    const big = explainFunctionPrompt({ ...fn, disasm: Array.from({ length: 2000 }, (_, i) => `0x${i.toString(16)} nop`) });
    expect(big).toContain("[500 more instructions not included");
  });
  it("struct prompt carries layout and the live sample", () => {
    const p = suggestStructPrompt({ name: "Player", base: "0x2000", rtti: "class CPlayer", fields: [{ offset: 0, size: 8, type: "ptr", name: "vtable", value: "0x7ff6…" }, { offset: 8, size: 4, type: "f32", name: "field_8", value: "100" }], hex: ["+0x000  00 11 22 33"] });
    for (const s of ["class CPlayer", "+0x000 ptr", "field_8", "<live_sample", "submit_struct_fields", "size: 0xc"]) expect(p).toContain(s);
  });
  it("module summary carries imports, triage and strings", () => {
    const p = summariseModulePrompt({ name: "game.exe", base: "0x140000000", size: 0x10000, imports: [{ dll: "KERNEL32.dll", names: ["VirtualProtect", "CreateThread"] }], triage: [{ level: "high", why: "changes page protection", dll: "KERNEL32.dll", name: "VirtualProtect" }], strings: ["https://example.com/api"], stringsTotal: 1 });
    for (const s of ["KERNEL32.dll: VirtualProtect, CreateThread", "[high] KERNEL32.dll!VirtualProtect", "https://example.com/api", 'total="1"']) expect(p).toContain(s);
  });
  it("samples distinctive strings first", () => {
    const s = sampleStrings(["aaaaaa", "aaaaaa", "@@@@@@@@@", "Failed to open config.ini", "hello world", "x"], 10);
    expect(s[0]).toBe("Failed to open config.ini");
    expect(s).not.toContain("@@@@@@@@@");
    expect(s.filter((x) => x === "aaaaaa").length).toBe(1);
  });
});

describe("review parsers", () => {
  it("parses name suggestions and drops junk", () => {
    const r = parseNameSuggestions({ suggestions: [
      { address: "0x140001000", kind: "function", name: "update player health", reason: "writes +0x100" },
      { address: "140002000", kind: "callee", name: "clamp_health", reason: "" },
      { address: "nope", kind: "callee", name: "x", reason: "" },
      { address: "0x1", kind: "global", name: "!!!", reason: "" },
      { address: "0x140001000", kind: "local", current: "[rbp-0x18]", name: "player", reason: "" },
    ] });
    expect(r.map((x) => [x.address, x.kind, x.name])).toEqual([
      ["0x140001000", "function", "update_player_health"],
      ["0x140002000", "callee", "clamp_health"],
      ["0x140001000", "local", "player"],
    ]);
    expect(parseNameSuggestions({})).toEqual([]);
    expect(cleanIdentifier("9lives::get")).toBe("lives::get");
  });

  it("parses struct fields, sorted and without overlaps", () => {
    const r = parseStructFields({ fields: [
      { offset: 8, type: "f32", name: "health", reason: "" },
      { offset: 0, type: "ptr", name: "vtable", reason: "" },
      { offset: 10, type: "u32", name: "overlaps", reason: "" },
      { offset: 12, type: "bogus", name: "x", reason: "" },
      { offset: "0x10", type: "vec3", name: "position", reason: "" },
    ] });
    expect(r.map((f) => [f.offset, f.type, f.name])).toEqual([[0, "ptr", "vtable"], [8, "f32", "health"], [16, "vec3", "position"]]);
  });

  it("applies a field into a contiguous layout", () => {
    const hex = (n: number): Field[] => Array.from({ length: n }, () => ({ type: "hex64", name: "" }));
    // replace a whole hex64
    expect(applyFieldAt(hex(2), 0, "ptr", "vtable")).toEqual([{ type: "ptr", name: "vtable" }, { type: "hex64", name: "" }]);
    // split a hex64: f32 at +0xc leaves 4 bytes before it
    expect(applyFieldAt(hex(2), 12, "f32", "health")).toEqual([{ type: "hex64", name: "" }, { type: "hex32", name: "" }, { type: "f32", name: "health" }]);
    // a vec3 at +4 spans two hex64s: 4 bytes before, then 0 after (4+12 = 16)
    expect(applyFieldAt(hex(2), 4, "vec3", "pos")).toEqual([{ type: "hex32", name: "" }, { type: "vec3", name: "pos" }]);
    // past the end pads
    expect(applyFieldAt(hex(1), 16, "u32", "id")).toEqual([{ type: "hex64", name: "" }, { type: "hex64", name: "" }, { type: "u32", name: "id" }]);
    // leftover after a small field inside a big one
    expect(applyFieldAt(hex(1), 0, "u16", "flags")).toEqual([{ type: "u16", name: "flags" }, { type: "hex16", name: "" }, { type: "hex32", name: "" }]);
  });
});

describe("stream accumulation", () => {
  const feed = (acc: MessageAccumulator, evs: Record<string, unknown>[]) => evs.forEach((e) => acc.apply(e as never));

  it("builds text, thinking and tool_use blocks", () => {
    const acc = new MessageAccumulator();
    feed(acc, [
      { type: "message_start", message: { model: "claude-opus-5-5", usage: { input_tokens: 10 } } },
      { type: "content_block_start", index: 0, content_block: { type: "thinking", thinking: "" } },
      { type: "content_block_delta", index: 0, delta: { type: "thinking_delta", thinking: "look" } },
      { type: "content_block_delta", index: 0, delta: { type: "signature_delta", signature: "sig" } },
      { type: "content_block_stop", index: 0 },
      { type: "content_block_start", index: 1, content_block: { type: "text", text: "" } },
      { type: "content_block_delta", index: 1, delta: { type: "text_delta", text: "Hel" } },
      { type: "content_block_delta", index: 1, delta: { type: "text_delta", text: "lo" } },
      { type: "content_block_stop", index: 1 },
      { type: "content_block_start", index: 2, content_block: { type: "tool_use", id: "t1", name: "read_memory", input: {} } },
      { type: "content_block_delta", index: 2, delta: { type: "input_json_delta", partial_json: '{"address":"0x10",' } },
      { type: "content_block_delta", index: 2, delta: { type: "input_json_delta", partial_json: '"size":4}' } },
      { type: "content_block_stop", index: 2 },
      { type: "message_delta", delta: { stop_reason: "tool_use" }, usage: { output_tokens: 5 } },
      { type: "message_stop" },
    ]);
    expect(acc.model).toBe("claude-opus-5-5");
    expect(acc.content[0]).toEqual({ type: "thinking", thinking: "look", signature: "sig" });
    expect(acc.text()).toBe("Hello");
    expect(acc.toolUses()).toEqual([{ type: "tool_use", id: "t1", name: "read_memory", input: { address: "0x10", size: 4 } }]);
    expect(acc.stopReason).toBe("tool_use");
    expect(acc.usage).toEqual({ input_tokens: 10, output_tokens: 5 });
    expect(toolsMayRun(acc.stopReason)).toBe(true);
  });

  it("marks invalid tool JSON instead of guessing", () => {
    const acc = new MessageAccumulator();
    feed(acc, [
      { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "t1", name: "read_memory", input: {} } },
      { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: '{"address":"0x10' } },
      { type: "content_block_stop", index: 0 },
      { type: "message_delta", delta: { stop_reason: "max_tokens" } },
    ]);
    const t = acc.toolUses()[0];
    expect(t.invalid).toBe('{"address":"0x10');
    expect(toolsMayRun(acc.stopReason)).toBe(false);
    expect(toolsMayRun("refusal")).toBe(false);
    expect(echoContent(acc.content)[0]).not.toHaveProperty("invalid");
  });

  it("echoes content back, dropping pre-fallback thinking and tool_use", () => {
    const content = [
      { type: "thinking", thinking: "a", signature: "s1" },
      { type: "text", text: "partial " },
      { type: "tool_use", id: "x", name: "read_memory", input: {} },
      { type: "fallback", from: { model: "claude-opus-5-5" }, to: { model: "claude-opus-4-8" } },
      { type: "thinking", thinking: "b", signature: "s2" },
      { type: "text", text: "rest" },
    ];
    expect(echoContent(content).map((b) => b.type)).toEqual(["text", "thinking", "text"]);
    const plain = [{ type: "thinking", thinking: "a", signature: "s" }, { type: "text", text: "t" }];
    expect(echoContent(plain)).toEqual(plain);
  });
});
