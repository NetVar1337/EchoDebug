// Talking to the relay's MCP endpoint like a client would (the MCP panel's connection test), and
// the copyable setup snippets for clients EchoDebug cannot configure in one click.

export const kLatestProtocol = "2026-07-28";

export type McpTarget = { port: number; token: string };

export type TestResult = { ok: boolean; ms: number; step: string; message: string; detail?: unknown };

const endpoint = (t: McpTarget) => `http://127.0.0.1:${t.port}/mcp`;

function headers(t: McpTarget, method: string, name?: string): Record<string, string> {
  const h: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    "MCP-Protocol-Version": kLatestProtocol,
    "Mcp-Method": method,
  };
  if (name) h["Mcp-Name"] = name;
  if (t.token) h.Authorization = `Bearer ${t.token}`;
  return h;
}

/** A 2026-07-28 request body (per-request _meta, no session). */
export function rpcBody(id: number, method: string, params: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    id,
    method,
    params: {
      ...params,
      _meta: {
        "io.modelcontextprotocol/protocolVersion": kLatestProtocol,
        "io.modelcontextprotocol/clientInfo": { name: "EchoDebug connection test", version: "1" },
        "io.modelcontextprotocol/clientCapabilities": {},
      },
    },
  };
}

/** Explains an HTTP failure of /mcp in words a user can act on. */
export function explainFailure(status: number, body: unknown): string {
  const msg = (body as { error?: { message?: string } } | null)?.error?.message;
  if (status === 401) return msg ?? "The relay rejected the token: copy the current one from this panel.";
  if (status === 403) return "The relay refused the request's Origin (only the app and localhost may call it).";
  if (status === 404) return msg ?? "Not found.";
  return msg ? `HTTP ${status}: ${msg}` : `HTTP ${status}`;
}

async function post(t: McpTarget, id: number, method: string, params: Record<string, unknown>, name?: string, fetchFn: typeof fetch = fetch) {
  const res = await fetchFn(endpoint(t), { method: "POST", headers: headers(t, method, name), body: JSON.stringify(rpcBody(id, method, params)) });
  const text = await res.text();
  let body: unknown = null;
  try { body = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body: body as { result?: Record<string, unknown>; error?: { code: number; message: string } } | null };
}

/**
 * The connection test: server/discover, then tools/call `status`, over the real HTTP endpoint with
 * the token, exactly as an MCP client sends them.
 */
export async function testConnection(t: McpTarget, fetchFn: typeof fetch = fetch): Promise<TestResult> {
  const t0 = performance.now();
  const done = (ok: boolean, step: string, message: string, detail?: unknown): TestResult => ({ ok, ms: Math.round(performance.now() - t0), step, message, detail });
  try {
    const d = await post(t, 1, "server/discover", {}, undefined, fetchFn);
    if (d.status !== 200 || !d.body?.result) return done(false, "server/discover", explainFailure(d.status, d.body), d.body);
    const versions = (d.body.result.supportedVersions as string[] | undefined) ?? [];
    const s = await post(t, 2, "tools/call", { name: "status", arguments: {} }, "status", fetchFn);
    if (s.status !== 200 || !s.body?.result) return done(false, "tools/call status", explainFailure(s.status, s.body), s.body);
    const r = s.body.result as { isError?: boolean; structuredContent?: { backend?: string; provider?: boolean; target?: { name?: string } | null } };
    if (r.isError) return done(false, "tools/call status", "the status tool failed", r);
    const sc = r.structuredContent ?? {};
    const target = sc.target?.name ? `, attached to ${sc.target.name}` : ", no target attached";
    return done(true, "tools/call status", `MCP works (protocol ${versions[0] ?? "?"}; backend ${sc.backend ?? "?"}${target}).`, r);
  } catch (e) {
    return done(false, "connect", `Cannot reach ${endpoint(t)}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

export type Snippet = { id: string; label: string; text: string; hint?: string };

/** Setup text for any client: HTTP and stdio JSON, the CLIs' add commands, a curl probe. */
export function snippets(t: McpTarget, stdio: { command: string; args: string[] } | null): Snippet[] {
  const url = endpoint(t);
  const auth = t.token ? { Authorization: `Bearer ${t.token}` } : undefined;
  const header = t.token ? ` --header "Authorization: Bearer ${t.token}"` : "";
  const quote = (s: string) => (/[\s"]/.test(s) ? JSON.stringify(s) : s);
  const cmd = stdio ?? { command: "echodebug-relay", args: ["--stdio"] };
  const cmdLine = [cmd.command, ...cmd.args].map(quote).join(" ");
  const http = { mcpServers: { echodebug: { type: "http", url, ...(auth ? { headers: auth } : {}) } } };
  const std = { mcpServers: { echodebug: { command: cmd.command, args: cmd.args } } };
  return [
    { id: "json-http", label: "Any client: Streamable HTTP (JSON)", text: JSON.stringify(http, null, 2), hint: "The usual mcpServers shape; some clients call the URL key serverUrl or httpUrl." },
    { id: "json-stdio", label: "Any client: stdio (JSON)", text: JSON.stringify(std, null, 2), hint: "stdio needs no token: the server reads it from EchoDebug's config folder." },
    { id: "claude-code", label: "Claude Code (command)", text: `claude mcp add --scope user --transport http echodebug ${url}${header}` },
    { id: "claude-code-stdio", label: "Claude Code, stdio (command)", text: `claude mcp add --scope user echodebug -- ${cmdLine}` },
    { id: "codex", label: "Codex CLI, stdio (command)", text: `codex mcp add echodebug -- ${cmdLine}` },
    { id: "gemini", label: "Gemini CLI (command)", text: `gemini mcp add --scope user --transport http${header} echodebug ${url}` },
    { id: "curl", label: "Probe with curl", text: `curl -s${t.token ? ` -H "Authorization: Bearer ${t.token}"` : ""} ${url}/health` },
  ];
}

/** Hides the token in text shown on screen (previews, diffs). */
export function maskToken(text: string, token: string): string {
  if (!token || token.length < 12) return text;
  return text.split(token).join(`${token.slice(0, 6)}…${token.slice(-4)}`);
}
