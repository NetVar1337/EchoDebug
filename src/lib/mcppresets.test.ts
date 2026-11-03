import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import tools from "@/lib/tools.json";
import { allowedTools, changingTools, kPresets, matchPreset } from "./mcppresets";
import { isGatedVerb, isReadOnlyVerb, kRawWrites } from "./verbclass";
import { explainFailure, maskToken, rpcBody, snippets, testConnection } from "./mcpconnect";
import { argsFromForm, type Tool } from "@/components/panels/mcp/ToolRunner";
import { ago, isLive, type McpSession } from "@/components/panels/mcp/Connections";

const preset = (id: string) => kPresets.find((p) => p.id === id)!;
const verbOf = (name: string) => (tools as { name: string; verb: string }[]).find((t) => t.name === name)!.verb;

describe("MCP tool profiles", () => {
  it("map onto the policy's mode and lists", () => {
    expect(preset("readonly").policy.mode).toBe("readonly");
    expect(preset("re").policy).toEqual({ mode: "ask", allow: [], deny: [] });
    expect(preset("full").policy).toEqual({ mode: "allow", allow: [], deny: [] });
  });

  it("read-only analysis denies every tool that changes something, and keeps reads", () => {
    const ro = preset("readonly").policy;
    for (const n of ["write_memory", "freeze_value", "dump_module", "set_name", "set_comment", "revert_patch", "emu_start", "value_scan_first", "load_symbols", "record_trace"]) {
      if ((tools as { name: string }[]).some((t) => t.name === n)) expect(ro.deny, n).toContain(n);
    }
    const allowed = allowedTools(ro);
    for (const n of ["read_memory", "disassemble", "list_modules", "attach", "detach", "status"]) expect(allowed, n).toContain(n);
    for (const n of allowed) expect(isReadOnlyVerb(verbOf(n)) || ["attach", "detach", "cancel"].includes(verbOf(n)), n).toBe(true);
    expect(allowed.length).toBeLessThan(tools.length);
    expect(changingTools()).toEqual(ro.deny);
  });

  it("reverse engineering asks before target changes and allows the rest", () => {
    const re = preset("re").policy;
    expect(allowedTools(re).length).toBe(tools.length);
    expect(isGatedVerb("write") && isGatedVerb("dump") && isGatedVerb("trace_record")).toBe(true);
    expect(isGatedVerb("attach") || isGatedVerb("ui_set_name")).toBe(false);
  });

  it("recognises a policy as a profile, else custom", () => {
    for (const p of kPresets) expect(matchPreset({ ...p.policy, deny: [...p.policy.deny].reverse() })).toBe(p.id);
    expect(matchPreset({ mode: "allow", allow: [], deny: ["write_memory"] })).toBeNull();
    expect(matchPreset({ mode: "ask", allow: ["read_memory"], deny: [] })).toBeNull();
  });

  it("allowedTools follows allow lists and the read-only gate", () => {
    expect(allowedTools({ mode: "allow", allow: ["read_memory", "write_memory"], deny: ["write_memory"] })).toEqual(["read_memory"]);
    const ro = allowedTools({ mode: "readonly", allow: [], deny: [] });
    expect(ro).not.toContain("write_memory");
    expect(ro).toContain("attach");
  });

  it("the verb classes match the relay's annotation lists", () => {
    const src = readFileSync("src-tauri/relay/src/mcp.rs", "utf8");
    const list = (name: string) => [...(new RegExp(`const ${name}: &\\[&str\\] = &\\[([^\\]]*)\\]`).exec(src)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    expect(new Set(list("DESTRUCTIVE"))).toEqual(kRawWrites);
    for (const v of list("STATEFUL")) expect(isReadOnlyVerb(v), v).toBe(false);
  });
});

describe("MCP connection helpers", () => {
  it("builds 2026-07-28 requests and snippets", () => {
    const b = rpcBody(3, "tools/call", { name: "status" }) as { params: { _meta: Record<string, unknown> } };
    expect(b.params._meta["io.modelcontextprotocol/protocolVersion"]).toBe("2026-07-28");
    expect(b.params._meta["io.modelcontextprotocol/clientCapabilities"]).toEqual({});
    const s = snippets({ port: 47110, token: "tok" }, { command: "C:\\Program Files\\EchoDebug\\EchoDebug.exe", args: ["--mcp-stdio"] });
    const json = JSON.parse(s.find((x) => x.id === "json-http")!.text);
    expect(json.mcpServers.echodebug).toEqual({ type: "http", url: "http://127.0.0.1:47110/mcp", headers: { Authorization: "Bearer tok" } });
    expect(JSON.parse(s.find((x) => x.id === "json-stdio")!.text).mcpServers.echodebug.args).toEqual(["--mcp-stdio"]);
    expect(s.find((x) => x.id === "claude-code-stdio")!.text).toBe('claude mcp add --scope user echodebug -- "C:\\\\Program Files\\\\EchoDebug\\\\EchoDebug.exe" --mcp-stdio');
    expect(s.find((x) => x.id === "claude-code")!.text).toContain('--header "Authorization: Bearer tok"');
    const noTok = snippets({ port: 1, token: "" }, null);
    expect(noTok.find((x) => x.id === "json-stdio")!.text).toContain("echodebug-relay");
    expect(noTok.find((x) => x.id === "json-http")!.text).not.toContain("Authorization");
    expect(maskToken("Bearer 0123456789abcdef0123", "0123456789abcdef0123")).toBe("Bearer 012345…0123");
  });

  it("the connection test reports what failed", async () => {
    const reply = (status: number, body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status }));
    const ok: typeof fetch = (_u, init) => {
      const m = JSON.parse(String(init?.body)).method;
      expect((init?.headers as Record<string, string>)["Mcp-Method"]).toBe(m);
      return m === "server/discover"
        ? reply(200, { result: { supportedVersions: ["2026-07-28"] } })
        : reply(200, { result: { isError: false, structuredContent: { backend: "local", target: { name: "game" } } } });
    };
    const r = await testConnection({ port: 1, token: "t" }, ok);
    expect(r.ok).toBe(true);
    expect(r.message).toContain("game");
    const denied: typeof fetch = () => reply(401, { error: { code: 401, message: "The relay token is wrong" } });
    const r2 = await testConnection({ port: 1, token: "bad" }, denied);
    expect(r2).toMatchObject({ ok: false, step: "server/discover", message: "The relay token is wrong" });
    const down: typeof fetch = () => Promise.reject(new TypeError("Failed to fetch"));
    expect((await testConnection({ port: 1, token: "" }, down)).message).toContain("Cannot reach");
    expect(explainFailure(403, null)).toContain("Origin");
  });

  it("the tool tester turns form fields into typed arguments", () => {
    const t: Tool = { name: "x", verb: "x", description: "", input_schema: { properties: { address: { type: "string" }, size: { type: "integer" }, all: { type: "boolean" }, regs: { type: "object" } }, required: ["address"] } };
    expect(argsFromForm(t, { address: "0x10", size: "0x20", all: "true", regs: '{"rax":"1"}' })).toEqual({ args: { address: "0x10", size: 32, all: true, regs: { rax: "1" } } });
    expect(argsFromForm(t, { size: "4" }).error).toContain("address");
    expect(argsFromForm(t, { address: "a", size: "x" }).error).toContain("number");
  });

  it("connection list ages and liveness", () => {
    const now = 1_000_000_000;
    expect(ago(now - 2000, now)).toBe("just now");
    expect(ago(now - 90_000, now)).toBe("1m ago");
    const s = { streams: 0, last_seen: now - 31 * 60_000 } as McpSession;
    expect(isLive(s, now)).toBe(false);
    expect(isLive({ ...s, streams: 1 }, now)).toBe(true);
  });
});
