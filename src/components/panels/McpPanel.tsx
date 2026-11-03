// MCP Server panel: first-run card, server status and endpoint, connected clients, one-click
// client setup, tool profiles and the call policy, the tool catalog with a tester, prompts and
// resources, and a live log of tools/call requests the relay has seen.
import { useEffect, useMemo, useState } from "react";
import { Check, Download, RefreshCw, X } from "lucide-react";
import tools from "@/lib/tools.json";
import { request } from "@/lib/client";
import { isTauri } from "@/lib/tauri";
import { kPresets, matchPreset, allowedTools } from "@/lib/mcppresets";
import { testConnection, type TestResult } from "@/lib/mcpconnect";
import { useConn } from "@/store/conn";
import { attempt, log as outLog } from "@/store/output";
import { parseList, useMcp, type PolicyMode } from "@/store/mcp";
import { saveText } from "@/lib/save";
import { CopyChip, IconButton, Panel, useCopy } from "../ui";
import ClientSetup from "./mcp/ClientSetup";
import Connections, { type McpSession } from "./mcp/Connections";
import ToolRunner from "./mcp/ToolRunner";

type Prompt = { name: string; description: string; arguments?: { name: string; description: string; required?: boolean }[] };
type Resource = { uri: string; name: string; description: string };
type Meta = { serverInfo: { name: string; version: string }; protocolVersion: string; protocolVersions?: string[]; prompts: Prompt[]; resources: Resource[]; resourceTemplates?: { uriTemplate: string; name: string }[]; tools: number; visibleTools?: number };
type LogEntry = { ts: number; tool: string; verb: string; args: string; ok: boolean; ms: number; outcome?: "ok" | "error" | "denied"; client?: string | null; transport?: string; approved_via?: string | null };

const kUiTools = (tools as { verb: string }[]).filter((t) => t.verb.startsWith("ui_")).length;

export default function McpPanel() {
  const c = useConn();
  const [copied, copy] = useCopy();
  const [meta, setMeta] = useState<Meta | null>(null);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [sessions, setSessions] = useState<McpSession[]>([]);
  const [test, setTest] = useState<TestResult | "running" | null>(null);

  const pol = useMcp();
  const [allowText, setAllowText] = useState(pol.allow.join(", "));
  const [denyText, setDenyText] = useState(pol.deny.join(", "));
  useEffect(() => setDenyText(pol.deny.join(", ")), [pol.deny]);
  useEffect(() => setAllowText(pol.allow.join(", ")), [pol.allow]);
  const policy = { mode: pol.mode, allow: pol.allow, deny: pol.deny };
  const preset = matchPreset(policy);
  const offered = useMemo(() => allowedTools(policy).length, [pol.mode, pol.allow, pol.deny]);

  const exportAudit = async () => {
    const r = await attempt("mcp_audit_export", request<{ jsonl: string; audit_file: string; audit_path: string }>("mcp_audit_export"));
    if (!r) return;
    const text = r.audit_file || r.jsonl;
    if (!text.trim()) return outLog("warn", "mcp", "the call log is empty");
    const path = await saveText("mcp-audit.jsonl", text.endsWith("\n") ? text : text + "\n", { name: "JSON Lines", extensions: ["jsonl"] });
    if (path) outLog("info", "mcp", `audit log saved to ${path}`);
  };
  const endpoint = `http://127.0.0.1:${c.port}/mcp`;
  const authHeader = c.token ? `Authorization: Bearer ${c.token}` : "";

  const loadMeta = async () => {
    const m = await attempt("mcp_meta", request<Meta>("mcp_meta"));
    if (m) setMeta(m);
  };
  const loadLive = async () => {
    const r = await request<{ entries: LogEntry[] }>("mcp_log", {}, true).catch(() => null);
    if (r?.entries) setLog(r.entries.slice().reverse());
    const s = await request<{ sessions: McpSession[] }>("mcp_sessions", {}, true).catch(() => null);
    if (s?.sessions) setSessions(s.sessions);
  };
  useEffect(() => {
    if (!c.relay) return;
    void loadMeta();
    void loadLive();
    const t = setInterval(() => void loadLive(), 2000);
    return () => clearInterval(t);
  }, [c.relay]);

  const runTest = async () => {
    setTest("running");
    const r = await testConnection({ port: c.port, token: c.token });
    setTest(r);
    outLog(r.ok ? "info" : "warn", "mcp", `connection test: ${r.message}`);
    void loadLive();
  };
  const scrollToSetup = () => document.getElementById("mcp-connect")?.scrollIntoView({ behavior: "smooth", block: "start" });

  return (
    <Panel
      title={<>MCP Server <span className="faint">{meta ? `${meta.serverInfo.name} v${meta.serverInfo.version}` : ""}</span></>}
      actions={<IconButton tip="Refresh" onClick={() => { void loadMeta(); void loadLive(); }}><RefreshCw size={14} /></IconButton>}
    >
      {!pol.onboarded && (
        <div className="panel-section mcp-card">
          <div className="row">
            <span className="grow"><b>Use EchoDebug from an AI client</b></span>
            <IconButton tip="Hide this card" onClick={() => pol.setOnboarded(true)}><X size={13} /></IconButton>
          </div>
          <div className="faint" style={{ fontSize: 12 }}>Claude, Cursor, VS Code, Codex and other MCP clients can read memory, disassemble and run EchoDebug's analyses. Three steps:</div>
          <div className="mcp-steps">
            <div className="row"><span className="dot" data-state={c.relay ? "ok" : "bad"} /><span className="grow">1. Server {c.relay ? <>running at <span className="mono">{endpoint}</span></> : <>offline{c.relayError ? `: ${c.relayError}` : ""}</>}</span></div>
            <div className="row"><span className="dot" data-state={sessions.length ? "ok" : "warn"} /><span className="grow">2. {sessions.length ? `${sessions.length} client${sessions.length > 1 ? "s" : ""} connected` : "Connect a client"}</span><button className="btn small primary" onClick={scrollToSetup}>Connect a client</button></div>
            <div className="row">
              <span className="dot" data-state={test && test !== "running" ? (test.ok ? "ok" : "bad") : "warn"} />
              <span className="grow">3. Check it works</span>
              <button className="btn small" disabled={!c.relay || test === "running"} onClick={() => void runTest()}>{test === "running" ? "Testing…" : "Run a test call"}</button>
            </div>
          </div>
          {test && test !== "running" && <div className={test.ok ? "mcp-ok" : "mcp-error"}>{test.ok ? <Check size={12} /> : <X size={12} />} {test.message} <span className="faint">({test.ms} ms, {test.step})</span></div>}
        </div>
      )}

      <div className="panel-section">
        <div className="row"><span className="dot" data-state={c.relay ? "ok" : "bad"} /><span className="grow">Server {c.relay ? "running" : "offline"}{meta ? <span className="faint"> · MCP {meta.protocolVersion}{meta.protocolVersions ? ` (also ${meta.protocolVersions.slice(1).join(", ")})` : ""}</span> : null}</span></div>
        {c.relayError && <div className="mcp-error">{c.relayError}. Another EchoDebug or echodebug-relay may hold the port; close it or set ECHODEBUG_PORT.</div>}
        <div className="row"><span className="dot" data-state={c.provider ? "ok" : "warn"} /><span className="grow">App window tools ({kUiTools} <span className="mono">ui_*</span>) {c.provider ? "served by this window" : "unavailable: clients do not see them until an app window is open"}</span></div>
        <div className="row"><span className="dot" data-state={c.agent || c.backend === "local" ? "ok" : "bad"} /><span className="grow">Memory backend {c.agent ? "Echo server" : c.backend === "local" ? "local /proc (Linux)" : "waiting for attach"}{c.ext ? ` · agent v${c.extVersion}` : ""}</span></div>
        <div className="row"><span className="dot" data-state={c.target ? "ok" : "warn"} /><span className="grow">Target {c.target ? `${c.target.name ?? "?"} (pid ${c.target.pid})` : "none: clients call attach, or attach from Targets"}</span></div>
        <div className="label" style={{ marginTop: 6 }}>Endpoint (Streamable HTTP)</div>
        <CopyChip text={endpoint} copied={copied} onCopy={copy} />
        {c.token ? (
          <>
            <div className="label" style={{ marginTop: 6 }}>Auth header</div>
            <CopyChip text={authHeader} copied={copied} onCopy={copy} />
            <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>HTTP clients must send this token, so other programs on this machine cannot reach the target's memory. stdio clients need none. Keep it private.</div>
            {isTauri() && (
              <div className="row" style={{ marginTop: 4 }}>
                <span className="faint grow" style={{ fontSize: 12 }}>After regenerating, update HTTP clients (Connect a client → Update).</span>
                <button className="btn" onClick={() => void attempt("token", c.regenerateToken())}>Regenerate token</button>
              </div>
            )}
          </>
        ) : (
          <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>Relay authentication is off (<span className="mono">ECHODEBUG_AUTH=0</span>): any local program can use the relay.</div>
        )}
        {pol.onboarded && (
          <div className="row" style={{ marginTop: 4 }}>
            <button className="btn small" disabled={!c.relay || test === "running"} onClick={() => void runTest()}>{test === "running" ? "Testing…" : "Test the connection"}</button>
            {test && test !== "running" && <span className={test.ok ? "mcp-ok" : "mcp-error"} style={{ fontSize: 11.5 }}>{test.message}</span>}
          </div>
        )}
      </div>

      <Connections sessions={sessions} onChange={() => void loadLive()} />

      <ClientSetup />

      <div className="panel-section">
        <div className="label">Tool profile</div>
        <div className="mcp-presets">
          {kPresets.map((p) => (
            <button key={p.id} className="mcp-preset" data-active={preset === p.id} onClick={() => pol.applyPreset(p.id)} title={p.hint}>
              <b>{p.label}</b>
              <span className="faint">{p.hint}</span>
            </button>
          ))}
        </div>
        <div className="faint" style={{ fontSize: 12 }}>{preset ? kPresets.find((p) => p.id === preset)!.label : "Custom policy"}: {offered} of {tools.length} tools offered{c.provider ? "" : " (app window tools appear when a window is open)"}. Clients see only offered tools and are told when the list changes.</div>
        <details className="mcp-policy" open={!preset}>
          <summary className="label">Call policy details</summary>
          <div className="row" style={{ marginTop: 6 }}>
            {(["allow", "ask", "readonly"] as PolicyMode[]).map((m) => (
              <button key={m} className={`btn small${pol.mode === m ? " primary" : ""}`} onClick={() => pol.setPolicy({ mode: m })}>
                {m === "allow" ? "Allow all" : m === "ask" ? "Ask before changes" : "Read-only"}
              </button>
            ))}
          </div>
          <div className="faint" style={{ fontSize: 12 }}>
            {pol.mode === "allow" ? "MCP clients may call every offered tool." : pol.mode === "ask" ? "Calls that change the target (writes, freezes, patch reverts, debugger breakpoints and monitors), dumps and real-thread traces wait for your approval." : "Calls that change the target are refused; reads and analyses still work."}
            {" "}Tool annotations (readOnlyHint/destructiveHint) tell clients the same.
          </div>
          {pol.mode === "ask" && (
            <label className="row" style={{ gap: 6 }}>
              <input type="checkbox" checked={pol.elicit} onChange={(e) => pol.setPolicy({ elicit: e.target.checked })} />
              <span className="grow">Let clients that support elicitation ask you in their own window (otherwise this window asks)</span>
            </label>
          )}
          <div className="label" style={{ marginTop: 6 }}>Allow only (empty: every tool)</div>
          <input className="input mono" placeholder="read_memory, disassemble, …" value={allowText} onChange={(e) => setAllowText(e.target.value)} onBlur={() => pol.setPolicy({ allow: parseList(allowText) })} />
          <div className="label" style={{ marginTop: 6 }}>Never allow</div>
          <textarea className="textarea mono" rows={2} placeholder="write_memory, freeze_value, …" value={denyText} onChange={(e) => setDenyText(e.target.value)} onBlur={() => pol.setPolicy({ deny: parseList(denyText) })} />
          <label className="row" style={{ gap: 6, marginTop: 6 }}><input type="checkbox" checked={pol.audit} onChange={(e) => pol.setPolicy({ audit: e.target.checked })} /><span className="grow">Keep an audit file (<span className="mono">mcp-audit.jsonl</span> in the config folder)</span></label>
          <button className="btn small" style={{ alignSelf: "flex-start" }} onClick={() => void exportAudit()}><Download size={12} /> Export audit (JSONL)</button>
        </details>
      </div>

      <ToolRunner policy={policy} provider={c.provider} />

      <div className="panel-section">
        <details>
          <summary className="label">Prompts ({meta?.prompts.length ?? 0}) and resources ({(meta?.resources.length ?? 0) + (meta?.resourceTemplates?.length ?? 0)})</summary>
          {(meta?.prompts ?? []).map((p) => (
            <div key={p.name} className="mcp-row" title={p.arguments?.map((a) => `${a.name}${a.required ? " (required)" : ""}`).join(", ")}>
              <span className="mono">{p.name}</span>
              <span className="faint ellipsis">{p.description}</span>
            </div>
          ))}
          {(meta?.resources ?? []).map((r) => (
            <div key={r.uri} className="mcp-row">
              <span className="mono">{r.uri}</span>
              <span className="faint ellipsis">{r.name}</span>
            </div>
          ))}
          {(meta?.resourceTemplates ?? []).map((r) => (
            <div key={r.uriTemplate} className="mcp-row">
              <span className="mono">{r.uriTemplate}</span>
              <span className="faint ellipsis">{r.name} (template)</span>
            </div>
          ))}
        </details>
      </div>

      <div className="panel-section">
        <div className="label">MCP call log <span className="faint">(last {log.length})</span></div>
        {log.length === 0 && <div className="faint" style={{ fontSize: 12 }}>No tools/call requests yet: call one above or from an MCP client.</div>}
        <div className="mcp-log">
          {log.slice(0, 30).map((e, i) => (
            <div key={i} className="mcp-log-row" data-ok={e.ok} title={e.outcome === "denied" ? "refused by the call policy" : e.approved_via ? `approved in the ${e.approved_via}` : undefined}>
              <span className="mono dim">{new Date(e.ts).toLocaleTimeString()}</span>
              <span className="mono">{e.tool}</span>
              <span className="faint ellipsis mono grow">{e.args}</span>
              {e.client && <span className="faint ellipsis" style={{ maxWidth: 90 }}>{e.client}</span>}
              <span className="mono dim">{e.ms}ms</span>
              <span>{e.ok ? <Check size={12} /> : e.outcome === "denied" ? "⛔" : "✕"}</span>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}
