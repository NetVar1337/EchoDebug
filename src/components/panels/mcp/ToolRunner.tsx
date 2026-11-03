// The tool catalog with "test this tool": a form from the tool's input schema (or raw JSON), run
// through the same MCP path a client uses (policy, approval, result shape), with the result as a
// client sees it.
import { useMemo, useState } from "react";
import { Check, Copy, Play } from "lucide-react";
import tools from "@/lib/tools.json";
import { request } from "@/lib/client";
import { isGatedVerb, isReadOnlyVerb } from "@/lib/verbclass";
import { allowedTools, type PolicyShape } from "@/lib/mcppresets";
import { useCopy } from "../../ui";

type Prop = { type?: string | string[]; description?: string; enum?: unknown[]; items?: unknown };
export type Tool = { name: string; verb: string; description: string; input_schema: { properties?: Record<string, Prop>; required?: string[] } };
type CallResult = { isError: boolean; content: { type: string; text?: string; uri?: string; name?: string; description?: string }[]; structuredContent?: unknown };

const kTools = tools as unknown as Tool[];

const typeOf = (p: Prop): string => (Array.isArray(p.type) ? p.type[0] : p.type) ?? "string";

/** Form values → tool arguments (numbers, booleans and JSON for arrays/objects; empty fields left out). */
export function argsFromForm(tool: Tool, values: Record<string, string>): { args: Record<string, unknown>; error?: string } {
  const args: Record<string, unknown> = {};
  for (const [k, p] of Object.entries(tool.input_schema.properties ?? {})) {
    const v = (values[k] ?? "").trim();
    if (!v) continue;
    const t = typeOf(p);
    if (t === "integer" || t === "number") {
      const n = /^0x[0-9a-f]+$/i.test(v) ? parseInt(v, 16) : Number(v);
      if (!Number.isFinite(n)) return { args, error: `${k} must be a number` };
      args[k] = n;
    } else if (t === "boolean") {
      args[k] = v === "true";
    } else if (t === "array" || t === "object") {
      try { args[k] = JSON.parse(v); } catch { return { args, error: `${k} must be JSON (${t})` }; }
    } else {
      args[k] = v;
    }
  }
  const missing = (tool.input_schema.required ?? []).filter((k) => !(k in args));
  return missing.length ? { args, error: `required: ${missing.join(", ")}` } : { args };
}

function Badge({ verb }: { verb: string }) {
  if (isGatedVerb(verb)) return <span className="pill mcp-badge" data-kind="danger" title="writes target memory or files: the ask policy asks first">changes target</span>;
  if (!isReadOnlyVerb(verb)) return <span className="pill mcp-badge" data-kind="warn" title="changes EchoDebug's state (attach, scans, emulator, names…)">stateful</span>;
  return <span className="pill mcp-badge" title="readOnlyHint">read-only</span>;
}

export default function ToolRunner({ policy, provider }: { policy: PolicyShape; provider: boolean }) {
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [raw, setRaw] = useState<string | null>(null);
  const [result, setResult] = useState<{ r?: CallResult; error?: string; ms?: number } | null>(null);
  const [running, setRunning] = useState(false);
  const [copied, copy] = useCopy();
  const allowed = useMemo(() => new Set(allowedTools(policy)), [policy]);

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return f ? kTools.filter((t) => t.name.toLowerCase().includes(f) || t.description.toLowerCase().includes(f)) : kTools;
  }, [filter]);

  const toggle = (t: Tool) => {
    setResult(null);
    setValues({});
    setRaw(null);
    setOpen(open === t.name ? null : t.name);
  };

  const run = async (t: Tool) => {
    let args: Record<string, unknown>;
    if (raw !== null) {
      try { args = raw.trim() ? JSON.parse(raw) : {}; } catch (e) { return setResult({ error: `arguments are not JSON: ${String(e)}` }); }
    } else {
      const f = argsFromForm(t, values);
      if (f.error) return setResult({ error: f.error });
      args = f.args;
    }
    setRunning(true);
    setResult(null);
    try {
      const r = await request<{ result: CallResult; ms: number }>("mcp_test_call", { name: t.name, arguments: args });
      setResult({ r: r.result, ms: r.ms });
    } catch (e) {
      setResult({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      setRunning(false);
    }
  };

  const rpc = (t: Tool) => {
    const args = raw !== null ? (() => { try { return JSON.parse(raw || "{}"); } catch { return {}; } })() : argsFromForm(t, values).args;
    return JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: t.name, arguments: args } }, null, 2);
  };

  return (
    <div className="panel-section">
      <div className="row">
        <span className="label grow">Tools ({allowed.size} offered / {kTools.length})</span>
        <input className="input" style={{ width: 140 }} placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      <div className="mcp-tools">
        {shown.map((t) => {
          const offered = allowed.has(t.name) && (provider || !t.verb.startsWith("ui_"));
          const props = Object.entries(t.input_schema.properties ?? {});
          const req = new Set(t.input_schema.required ?? []);
          return (
            <div key={t.name}>
              <button className="mcp-row mcp-tool" data-open={open === t.name} data-off={!offered} onClick={() => toggle(t)} title={offered ? t.description : `${t.description}\n\nNot offered to clients right now (${!allowed.has(t.name) ? "the call policy" : "the app window serves it"}).`}>
                <Play size={11} />
                <span className="mono">{t.name}</span>
                <span className="faint ellipsis grow">{t.description}</span>
              </button>
              {open === t.name && (
                <div className="mcp-call">
                  <div className="row" style={{ fontSize: 11 }}>
                    <Badge verb={t.verb} />
                    <span className="faint grow">verb <span className="mono">{t.verb}</span>{!allowed.has(t.name) ? " · refused by the current policy" : ""}</span>
                    <button className="btn small" onClick={() => setRaw(raw === null ? JSON.stringify(argsFromForm(t, values).args, null, 2) : null)}>{raw === null ? "Raw JSON" : "Form"}</button>
                  </div>
                  <div className="faint" style={{ fontSize: 11.5 }}>{t.description}</div>
                  {raw !== null ? (
                    <textarea className="textarea mono" rows={5} value={raw} spellCheck={false} onChange={(e) => setRaw(e.target.value)} />
                  ) : props.length === 0 ? (
                    <div className="faint" style={{ fontSize: 11.5 }}>No arguments.</div>
                  ) : (
                    <div className="mcp-form">
                      {props.map(([k, p]) => {
                        const ty = typeOf(p);
                        return (
                          <label key={k} className="mcp-field" title={p.description}>
                            <span className="mono">{k}{req.has(k) ? " *" : ""}</span>
                            {ty === "boolean" ? (
                              <select className="select" value={values[k] ?? ""} onChange={(e) => setValues({ ...values, [k]: e.target.value })}>
                                <option value="">(default)</option><option value="true">true</option><option value="false">false</option>
                              </select>
                            ) : p.enum ? (
                              <select className="select" value={values[k] ?? ""} onChange={(e) => setValues({ ...values, [k]: e.target.value })}>
                                <option value="">(default)</option>
                                {p.enum.map((x) => <option key={String(x)} value={String(x)}>{String(x)}</option>)}
                              </select>
                            ) : (
                              <input className="input mono" placeholder={`${ty}${p.description ? ` · ${p.description}` : ""}`} value={values[k] ?? ""} onChange={(e) => setValues({ ...values, [k]: e.target.value })} onKeyDown={(e) => e.key === "Enter" && void run(t)} />
                            )}
                          </label>
                        );
                      })}
                    </div>
                  )}
                  <div className="row">
                    <button className="btn primary" disabled={running} onClick={() => void run(t)}>{running ? "Running…" : "Call tool"}</button>
                    <button className="btn small" onClick={() => copy(rpc(t))}>{copied === rpc(t) ? <Check size={11} /> : <Copy size={11} />} Copy as JSON-RPC</button>
                    {result?.ms !== undefined && <span className="faint" style={{ fontSize: 11 }}>{result.ms} ms</span>}
                  </div>
                  {result?.error && <div className="mcp-error">{result.error}</div>}
                  {result?.r && <CallView r={result.r} copy={copy} />}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function CallView({ r, copy }: { r: CallResult; copy: (t: string) => void }) {
  const text = r.structuredContent !== undefined ? JSON.stringify(r.structuredContent, null, 2) : r.content.filter((c) => c.type === "text").map((c) => c.text).join("\n");
  const links = r.content.filter((c) => c.type === "resource_link");
  const denied = r.isError && /deny list|allow list|read-only|denied|declined|approval/.test(text);
  return (
    <>
      <div className="row" style={{ fontSize: 11.5 }}>
        <span className="pill mcp-badge" data-kind={r.isError ? "danger" : "ok"}>{denied ? "refused by policy" : r.isError ? "isError" : "ok"}</span>
        <span className="grow faint">what the client receives{r.structuredContent !== undefined ? " (structuredContent)" : ""}</span>
        <button className="btn small" onClick={() => copy(JSON.stringify(r, null, 2))}><Copy size={11} /> Copy result</button>
      </div>
      <pre className="mcp-result">{text.length > 8000 ? text.slice(0, 8000) + "…" : text}</pre>
      {links.length > 0 && (
        <div className="faint" style={{ fontSize: 11 }}>
          resource links: {links.map((l) => <span key={l.uri} className="mono" title={l.description}> {l.uri}</span>)}
        </div>
      )}
    </>
  );
}
