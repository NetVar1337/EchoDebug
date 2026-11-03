// "Connect a client": detected MCP clients with one-click add / remove (desktop app), a preview of
// the exact change with a backup, and copyable snippets for every other client.
import { useEffect, useState } from "react";
import { Check, Copy, ExternalLink, RefreshCw } from "lucide-react";
import { isTauri, mcpClientApply, mcpClientPreview, mcpClients, openUrl, type McpClientRow, type McpClients, type McpPlan, type McpTransport } from "@/lib/tauri";
import { maskToken, snippets } from "@/lib/mcpconnect";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { IconButton, useCopy } from "../../ui";

type Pending = { client: McpClientRow; action: "install" | "uninstall"; transport?: McpTransport; plan: McpPlan };

const kTransportLabel: Record<McpTransport, string> = { http: "HTTP", stdio: "stdio" };

/** Diff lines with +/- colouring. */
export function DiffView({ diff, token }: { diff: string; token: string }) {
  return (
    <pre className="mcp-result mcp-diff">
      {maskToken(diff, token).split("\n").map((l, i) => (
        <span key={i} data-kind={l.startsWith("+++") || l.startsWith("---") ? "head" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : l.startsWith("@@") ? "hunk" : ""}>{l}{"\n"}</span>
      ))}
    </pre>
  );
}

export default function ClientSetup() {
  const c = useConn();
  const [data, setData] = useState<McpClients | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [busy, setBusy] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [copied, copy] = useCopy();
  const desktop = isTauri();

  const load = async () => {
    if (!desktop) return;
    const d = await attempt("mcp clients", mcpClients());
    if (d) setData(d);
  };
  useEffect(() => { void load(); }, [desktop, c.port, c.token]);

  const preview = async (client: McpClientRow, action: "install" | "uninstall", transport?: McpTransport) => {
    setBusy(true);
    const plan = await attempt("mcp clients", mcpClientPreview(client.id, action, transport));
    setBusy(false);
    if (plan) setPending({ client, action, transport, plan });
  };
  const apply = async () => {
    if (!pending) return;
    setBusy(true);
    const r = await attempt("mcp clients", mcpClientApply(pending.client.id, pending.action, pending.transport, pending.plan.diff));
    setBusy(false);
    if (r) {
      const what = pending.action === "install" ? `added EchoDebug (${kTransportLabel[pending.transport ?? "http"]}) to ${pending.client.name}` : `removed EchoDebug from ${pending.client.name}`;
      log("info", "mcp", `${what}: ${r.path}${r.backup ? ` (backup: ${r.backup})` : ""}. Restart ${pending.client.name} to pick it up.`);
      setPending(null);
      void load();
    }
  };

  const rows = data?.clients ?? [];
  const shown = showAll ? rows : rows.filter((r) => r.installed || r.configured);
  const other = snippets({ port: c.port, token: c.token }, data?.stdio ?? null);

  return (
    <div className="panel-section" id="mcp-connect">
      <div className="row">
        <span className="label grow">Connect a client</span>
        {desktop && <IconButton tip="Detect clients again" onClick={() => void load()}><RefreshCw size={13} /></IconButton>}
      </div>
      {!desktop && <div className="faint" style={{ fontSize: 12 }}>One-click setup writes client config files, so it needs the EchoDebug desktop app. Copy a snippet below instead.</div>}
      {desktop && (
        <>
          <div className="faint" style={{ fontSize: 12 }}>
            EchoDebug adds one <span className="mono">echodebug</span> entry to the client's own config file and touches nothing else; you see the change first and the old file is kept as a backup.
            <b> HTTP</b> talks to this window (needs the token, kept in that file); <b>stdio</b> lets the client start EchoDebug in the background (no token in the file).
          </div>
          {shown.length === 0 && <div className="faint" style={{ fontSize: 12 }}>No supported client found on this machine.</div>}
          {shown.map((r) => (
            <div key={r.id} className="mcp-client" data-configured={!!r.configured}>
              <div className="row">
                <span className="dot" data-state={r.configured ? "ok" : r.installed ? "warn" : ""} />
                <span className="grow">{r.name} {r.configured && <span className="pill accent">added ({r.configured === "other" ? "custom" : kTransportLabel[r.configured]})</span>} {!r.installed && !r.configured && <span className="pill">not found</span>}</span>
                {r.transports.map((t) => (
                  <button key={t} className="btn small" disabled={busy} onClick={() => void preview(r, "install", t)} title={t === "http" ? "Streamable HTTP to this window, with the token header" : "The client launches EchoDebug in stdio mode (no token)"}>
                    {r.configured === t ? `Update (${kTransportLabel[t]})` : `Add (${kTransportLabel[t]})`}
                  </button>
                ))}
                {r.configured && <button className="btn small" disabled={busy} onClick={() => void preview(r, "uninstall")}>Remove</button>}
                <IconButton tip={`${r.name} MCP docs`} onClick={() => void openUrl(r.docs)}><ExternalLink size={12} /></IconButton>
              </div>
              <div className="faint mono ellipsis" style={{ fontSize: 11 }} title={r.path}>{r.path}</div>
              {r.error && <div className="mcp-error">The file is not valid ({r.error}); EchoDebug will not change it until it is fixed.</div>}
              {pending?.client.id === r.id && (
                <div className="mcp-call">
                  <div style={{ fontSize: 12 }}>
                    {pending.plan.changes
                      ? <>{pending.plan.deletes ? "Delete" : pending.plan.exists ? "Change" : "Create"} <span className="mono">{pending.plan.path}</span>{pending.plan.exists ? " (a backup of the current file is written next to it)" : ""}:</>
                      : <>Nothing to change: <span className="mono">{pending.plan.path}</span> already has this entry.</>}
                  </div>
                  {pending.plan.changes && <DiffView diff={pending.plan.diff} token={c.token} />}
                  <div className="faint" style={{ fontSize: 11.5 }}>{r.note}</div>
                  <div className="row">
                    {pending.plan.changes && <button className="btn primary" disabled={busy} onClick={() => void apply()}>{pending.action === "install" ? "Write config" : "Remove entry"}</button>}
                    <button className="btn" onClick={() => setPending(null)}>Cancel</button>
                    {pending.transport && r.snippets[pending.transport] && (
                      <IconButton tip="Copy just the entry" onClick={() => copy(r.snippets[pending.transport!]!)}>{copied === r.snippets[pending.transport] ? <Check size={12} /> : <Copy size={12} />}</IconButton>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
          {rows.length > shown.length || showAll ? (
            <button className="btn small" style={{ alignSelf: "flex-start" }} onClick={() => setShowAll(!showAll)}>{showAll ? "Only detected clients" : `Show all ${rows.length} clients`}</button>
          ) : null}
        </>
      )}
      <details className="mcp-snippets">
        <summary className="label">Other clients: copy a snippet</summary>
        {other.map((s) => (
          <div key={s.id} className="mcp-snippet">
            <div className="row">
              <span className="grow" style={{ fontSize: 12 }}>{s.label}</span>
              <IconButton tip="Copy" onClick={() => copy(s.text)}>{copied === s.text ? <Check size={12} /> : <Copy size={12} />}</IconButton>
            </div>
            <pre className="mcp-result">{maskToken(s.text, c.token)}</pre>
            {s.hint && <div className="faint" style={{ fontSize: 11 }}>{s.hint}</div>}
          </div>
        ))}
      </details>
    </div>
  );
}
