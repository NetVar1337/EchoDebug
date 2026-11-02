// MCP Server panel: endpoint + connect hints, the tool catalog with a live call tester,
// the prompt/resource catalogs, and a live log of tools/call requests the relay has seen.
import { useEffect, useMemo, useState } from "react";
import { Check, Copy, Play, RefreshCw } from "lucide-react";
import tools from "@/lib/tools.json";
import { request } from "@/lib/client";
import { isTauri } from "@/lib/tauri";
import { mcpAddCommand, useConn } from "@/store/conn";
import { attempt } from "@/store/output";
import { CopyChip, IconButton, Panel, useCopy } from "../ui";

type Tool = { name: string; verb: string; description: string; input_schema: { required?: string[] } };
type Prompt = { name: string; description: string; arguments?: { name: string; description: string; required?: boolean }[] };
type Resource = { uri: string; name: string; description: string };
type Meta = { serverInfo: { name: string; version: string }; prompts: Prompt[]; resources: Resource[]; tools: number };
type LogEntry = { ts: number; tool: string; verb: string; args: string; ok: boolean; ms: number };

const kTools = tools as unknown as Tool[];

export default function McpPanel() {
  const c = useConn();
  const [copied, copy] = useCopy();
  const [meta, setMeta] = useState<Meta | null>(null);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [filter, setFilter] = useState("");
  const [openTool, setOpenTool] = useState<string | null>(null);
  const [argsText, setArgsText] = useState("{}");
  const [result, setResult] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const endpoint = `http://127.0.0.1:${c.port}/mcp`;
  const addCmd = mcpAddCommand(c.port, c.token);

  const loadMeta = async () => {
    const m = await attempt("mcp_meta", request<Meta>("mcp_meta"));
    if (m) setMeta(m);
  };
  const loadLog = async () => {
    const r = await request<{ entries: LogEntry[] }>("mcp_log", {}, true).catch(() => null);
    if (r?.entries) setLog(r.entries.slice().reverse());
  };
  useEffect(() => {
    if (!c.relay) return;
    void loadMeta();
    void loadLog();
    const t = setInterval(() => void loadLog(), 2000);
    return () => clearInterval(t);
  }, [c.relay]);

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return f ? kTools.filter((t) => t.name.toLowerCase().includes(f) || t.description.toLowerCase().includes(f)) : kTools;
  }, [filter]);

  const runTool = async (t: Tool) => {
    setRunning(true);
    setResult(null);
    try {
      const args = argsText.trim() ? (JSON.parse(argsText) as Record<string, unknown>) : {};
      const r = await request(t.verb, args, true);
      setResult(JSON.stringify(r, null, 2));
    } catch (e) {
      setResult(String(e));
    } finally {
      setRunning(false);
      void loadLog();
    }
  };

  const prefill = (t: Tool) => {
    const req = (t.input_schema.required ?? []).map((k) => `  "${k}": ""`).join(",\n");
    setArgsText(`{\n${req}\n}`);
    setResult(null);
    setOpenTool(openTool === t.name ? null : t.name);
  };

  return (
    <Panel
      title={<>MCP Server <span className="faint">{meta ? `${meta.serverInfo.name} v${meta.serverInfo.version}` : ""}</span></>}
      actions={<IconButton tip="Refresh catalog & log" onClick={() => { void loadMeta(); void loadLog(); }}><RefreshCw size={14} /></IconButton>}
    >
      <div className="panel-section">
        <div className="row"><span className="dot" data-state={c.relay ? "ok" : "bad"} /> Relay {c.relay ? "running" : "offline"}</div>
        <div className="row"><span className="dot" data-state={c.ext ? "ok" : "bad"} /> Agent (ext verbs) {c.ext ? `v${c.extVersion}` : c.os === "linux" ? "not available (Windows-only); local backend serves core verbs" : "not loaded"}</div>
        <div className="row"><span className="dot" data-state={c.agent || c.backend === "local" ? "ok" : "bad"} /> Memory backend {c.agent ? "Echo server" : c.backend === "local" ? "local /proc (Linux)" : "waiting for attach"}</div>
        <div className="row"><span className="dot" data-state={c.target ? "ok" : "warn"} /> Target {c.target ? `${c.target.name ?? "?"} (pid ${c.target.pid})` : "none — attach from Targets"}</div>
        <div className="label" style={{ marginTop: 6 }}>Endpoint</div>
        <CopyChip text={endpoint} copied={copied} onCopy={copy} />
        <div className="label" style={{ marginTop: 6 }}>Connect a client (Claude Code)</div>
        <CopyChip text={addCmd} copied={copied} onCopy={copy} />
        <div className="row" style={{ marginTop: 4 }}>
          <span className="faint grow" style={{ fontSize: 12 }}>
            {c.token ? "Requests without this bearer token get 401." : "No token: start the browser UI with ?token= from the relay's output."}
          </span>
          {isTauri() && <button className="btn" onClick={() => void attempt("token", c.regenerateToken())}>Regenerate token</button>}
        </div>
        <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>
          Any MCP client works — the relay speaks Streamable HTTP JSON-RPC 2.0 on <span className="mono">POST /mcp</span> (batch supported).
          Capabilities: tools ({meta?.tools ?? kTools.length}), prompts, resources.
        </div>
      </div>

      <div className="panel-section">
        <div className="label">Prompts</div>
        {(meta?.prompts ?? []).map((p) => (
          <div key={p.name} className="mcp-row" title={p.arguments?.map((a) => `${a.name}${a.required ? " (required)" : ""}`).join(", ")}>
            <span className="mono">{p.name}</span>
            <span className="faint ellipsis">{p.description}</span>
          </div>
        ))}
        <div className="label" style={{ marginTop: 6 }}>Resources</div>
        {(meta?.resources ?? []).map((r) => (
          <div key={r.uri} className="mcp-row">
            <span className="mono">{r.uri}</span>
            <span className="faint ellipsis">{r.name}</span>
          </div>
        ))}
      </div>

      <div className="panel-section">
        <div className="row">
          <span className="label grow">Tools ({shown.length}/{kTools.length})</span>
          <input className="input" style={{ width: 140 }} placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </div>
        <div className="mcp-tools">
          {shown.map((t) => (
            <div key={t.name}>
              <button className="mcp-row mcp-tool" data-open={openTool === t.name} onClick={() => prefill(t)} title={t.description}>
                <Play size={11} />
                <span className="mono">{t.name}</span>
                <span className="faint ellipsis">{t.description}</span>
              </button>
              {openTool === t.name && (
                <div className="mcp-call">
                  <div className="faint" style={{ fontSize: 11 }}>verb <span className="mono">{t.verb}</span> — arguments as JSON (required: {(t.input_schema.required ?? []).join(", ") || "none"})</div>
                  <textarea className="textarea mono" rows={4} value={argsText} spellCheck={false} onChange={(e) => setArgsText(e.target.value)} />
                  <div className="row">
                    <button className="btn primary" disabled={running} onClick={() => void runTool(t)}>{running ? "Running…" : "Call tool"}</button>
                    {result && <IconButton tip="Copy result" onClick={() => copy(result)}><Copy size={13} /></IconButton>}
                  </div>
                  {result && <pre className="mcp-result">{result.length > 8000 ? result.slice(0, 8000) + "…" : result}</pre>}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="panel-section">
        <div className="label">MCP call log <span className="faint">(last {log.length})</span></div>
        {log.length === 0 && <div className="faint" style={{ fontSize: 12 }}>No tools/call requests yet — call one above or from an MCP client.</div>}
        <div className="mcp-log">
          {log.slice(0, 30).map((e, i) => (
            <div key={i} className="mcp-log-row" data-ok={e.ok}>
              <span className="mono dim">{new Date(e.ts).toLocaleTimeString()}</span>
              <span className="mono">{e.tool}</span>
              <span className="faint ellipsis mono">{e.args}</span>
              <span className="mono dim">{e.ms}ms</span>
              <span>{e.ok ? <Check size={12} /> : "✕"}</span>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}
