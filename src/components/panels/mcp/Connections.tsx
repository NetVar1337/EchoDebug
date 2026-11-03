// Live list of MCP clients: who connected (clientInfo from initialize / per-request _meta), over
// what, their last call, and a Disconnect button per session.
import { Unplug } from "lucide-react";
import { request } from "@/lib/client";
import { attempt, log } from "@/store/output";
import { IconButton } from "../../ui";

export type McpSession = {
  id: string;
  transport: string;
  era: "session" | "stateless";
  protocolVersion: string;
  client: { name?: string; version?: string; title?: string } | null;
  elicitation: boolean;
  created: number;
  last_seen: number;
  calls: number;
  last_call: { tool: string; ts: number; outcome: string } | null;
  streams: number;
  log_level: string | null;
};

export function ago(ts: number, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/** Sessions seen in the last 30 minutes, or still holding a stream open, count as connected. */
export function isLive(s: McpSession, now = Date.now()): boolean {
  return s.streams > 0 || now - s.last_seen < 30 * 60_000;
}

export default function Connections({ sessions, onChange }: { sessions: McpSession[]; onChange: () => void }) {
  const now = Date.now();
  const live = sessions.filter((s) => isLive(s, now));
  const disconnect = async (s: McpSession) => {
    const r = await attempt("mcp_disconnect", request<{ disconnected: boolean }>("mcp_disconnect", { session: s.id }));
    if (r) log("info", "mcp", `disconnected ${s.client?.name ?? "client"} (${s.transport})${s.era === "session" ? ": it must reconnect to use EchoDebug again" : ""}`);
    onChange();
  };
  return (
    <div className="panel-section">
      <div className="label">Connected clients <span className="faint">({live.length})</span></div>
      {live.length === 0 && <div className="faint" style={{ fontSize: 12 }}>No MCP client has connected yet. Add one below, then ask it to call EchoDebug's <span className="mono">status</span> tool.</div>}
      {live.map((s) => (
        <div key={s.id} className="mcp-session">
          <div className="row">
            <span className="dot" data-state={s.streams > 0 || now - s.last_seen < 120_000 ? "ok" : "warn"} />
            <span className="grow ellipsis">
              <b>{s.client?.title ?? s.client?.name ?? "unnamed client"}</b>{s.client?.version ? <span className="faint"> v{s.client.version}</span> : null}
            </span>
            <span className="pill" title={s.era === "session" ? "initialize-based session" : "stateless 2026-07-28 requests"}>{s.transport} · {s.protocolVersion}</span>
            <IconButton tip={s.era === "session" ? "Disconnect (ends the session; the client must reconnect)" : "Disconnect (closes its notification streams)"} onClick={() => void disconnect(s)}><Unplug size={13} /></IconButton>
          </div>
          <div className="faint" style={{ fontSize: 11 }}>
            {s.last_call ? <>last call <span className="mono">{s.last_call.tool}</span> {ago(s.last_call.ts, now)} ({s.last_call.outcome}) · </> : "no tool calls yet · "}
            {s.calls} call{s.calls === 1 ? "" : "s"} · seen {ago(s.last_seen, now)}{s.streams ? ` · ${s.streams} stream${s.streams > 1 ? "s" : ""} open` : ""}{s.elicitation ? " · can ask its user (elicitation)" : ""}
          </div>
        </div>
      ))}
    </div>
  );
}
