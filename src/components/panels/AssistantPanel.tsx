// Assistant panel: chat with Claude about the target, with one-click actions that send the
// function at the cursor, the struct on screen or a module summary. The assistant may call
// EchoDebug's read-only tools; every call is listed in the transcript.
import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { Check, Eraser, Send, Square, Wrench, X } from "lucide-react";
import { useAssistant, type Entry } from "@/store/assistant";
import { useConn } from "@/store/conn";
import { useUi } from "@/store/ui";
import { available } from "@/lib/assistant/api";
import { kEfforts, kModels, type Effort } from "@/lib/assistant/prompts";
import { IconButton, Panel } from "../ui";

/** Plain text with addresses turned into links and `code` in mono. */
function Rich({ text }: { text: string }) {
  const ui = useUi();
  const parts: ReactNode[] = [];
  const re = /(`[^`\n]+`)|(\b0x[0-9a-fA-F]{6,16}\b)/g;
  let last = 0;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    if (m[1]) parts.push(<code key={m.index} className="mono">{m[1].slice(1, -1)}</code>);
    else { const a = m[2]; parts.push(<span key={m.index} className="link mono" onClick={() => ui.goDisasm(a)}>{a}</span>); }
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return <div className="as-text">{parts}</div>;
}

function short(v: unknown, n = 120): string {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function EntryView({ e }: { e: Entry }) {
  if (e.kind === "user") {
    return (
      <div className="as-msg as-user">
        {e.title ? <details><summary><b>{e.title}</b> <span className="faint">({Math.round(e.text.length / 1024 * 10) / 10} KiB sent)</span></summary><pre className="as-pre">{e.text}</pre></details> : <div className="as-text">{e.text}</div>}
      </div>
    );
  }
  if (e.kind === "note") return <div className={`as-note ${e.level === "error" ? "danger" : e.level === "warn" ? "warn" : "faint"}`}>{e.text}</div>;
  if (e.kind === "tool") {
    return (
      <details className="as-tool">
        <summary><Wrench size={11} /> <span className="mono">{e.name}</span> <span className="faint mono">{short(e.input)}</span>{e.running ? <span className="faint"> · running…</span> : e.isError ? <span className="danger"> · error</span> : null}</summary>
        {e.result !== undefined && <pre className="as-pre">{e.result.length > 6000 ? e.result.slice(0, 6000) + `\n… (${e.result.length - 6000} more characters sent to the model)` : e.result}</pre>}
      </details>
    );
  }
  const model = kModels.find((m) => m.id === e.model)?.label ?? e.model;
  return (
    <div className="as-msg as-bot">
      {e.blocks.map((b, i) => {
        if (!b) return null;
        if (b.type === "thinking") {
          const t = (b as { thinking: string }).thinking;
          return t ? <details key={i} className="as-think"><summary className="faint">Thinking</summary><div className="as-text faint">{t}</div></details> : null;
        }
        if (b.type === "text") return <Rich key={i} text={(b as { text: string }).text} />;
        if (b.type === "fallback") return <div key={i} className="as-note faint">Continued on {String((b as { to?: { model?: string } }).to?.model ?? "a fallback model")}</div>;
        return null;
      })}
      <div className="as-meta faint">{model}{e.streaming ? " · …" : e.usage ? ` · ${e.usage.input_tokens ?? 0}${e.usage.cache_read_input_tokens ? ` (+${e.usage.cache_read_input_tokens} cached)` : ""} in / ${e.usage.output_tokens ?? 0} out` : ""}</div>
    </div>
  );
}

export default function AssistantPanel() {
  const a = useAssistant();
  const ui = useUi();
  const attached = useConn((s) => !!s.target);
  const [text, setText] = useState("");
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { void a.refreshKey(); }, [ui.settingsOpen]);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [a.entries]);

  const send = () => {
    const t = text;
    setText("");
    void a.send(t);
  };

  const header = (
    <>
      <select className="select" value={a.model} title="Model" onChange={(e) => a.set({ model: e.target.value })}>
        {kModels.map((m) => <option key={m.id} value={m.id}>{m.label}{m.note ? ` (${m.note})` : ""}</option>)}
      </select>
      <select className="select" value={a.effort} title="Effort: how much the model thinks (and spends) per answer" onChange={(e) => a.set({ effort: e.target.value as Effort })}>
        {kEfforts.map((x) => <option key={x}>{x}</option>)}
      </select>
      <IconButton tip="Clear conversation" onClick={() => a.clear()}><Eraser size={13} /></IconButton>
    </>
  );

  if (!available()) {
    return <Panel title="Assistant"><div className="panel-section faint">The assistant runs in the EchoDebug desktop app, which keeps your API key out of the web view.</div></Panel>;
  }
  const noKey = a.keyInfo !== null && !a.keyInfo.present;

  return (
    <Panel title="Assistant" actions={header} className="assistant">
      <div className="panel-section as-disclosure">
        What you send here (the code, memory, names and tool results the assistant reads) goes to Anthropic&apos;s API at api.anthropic.com to generate the answer. The assistant can only use read-only tools; nothing is renamed or changed until you accept it.
      </div>
      {noKey ? (
        <div className="panel-section">
          <div className="label">No API key yet</div>
          <div className="faint" style={{ fontSize: 12.5 }}>
            The assistant uses your own Anthropic API key. Create one at console.anthropic.com (API keys), then add it in <span className="link" onClick={() => ui.set({ settingsOpen: true })}>Settings → Assistant</span>. The key stays in the desktop app and is only sent to api.anthropic.com.
          </div>
        </div>
      ) : (
        <div className="panel-section">
          <div className="row" style={{ flexWrap: "wrap", gap: 4 }}>
            <button className="btn small" disabled={a.busy || !attached} title="Sends the disassembly and pseudocode of the function at the disassembly cursor, with your names and comments" onClick={() => void a.explainFunction()}>Explain function</button>
            <button className="btn small" disabled={a.busy || !attached} title="Names for the function, its callees, globals and locals: a list you accept one by one" onClick={() => void a.suggestNames()}>Suggest names</button>
            <button className="btn small" disabled={a.busy || !attached} title="Field types and names from the Structs view's live sample: a list you accept one by one" onClick={() => void a.suggestFields()}>Suggest struct fields</button>
            <button className="btn small" disabled={a.busy || !attached} title="Imports, strings and triage findings of the focused (or main) module" onClick={() => void a.summariseModule()}>Summarise module</button>
          </div>
        </div>
      )}
      {(a.names.length > 0 || a.fields.length > 0) && (
        <div className="panel-section as-review">
          {a.names.length > 0 && (
            <>
              <div className="row"><span className="label grow">Suggested names ({a.names.length})</span><button className="btn small" onClick={() => a.names.forEach((n) => a.rejectName(n.id))}>Dismiss all</button></div>
              {a.names.map((n) => (
                <div key={n.id} className="as-sugg">
                  <div className="row">
                    <span className="link mono" onClick={() => ui.goDisasm(n.address)}>{n.current || n.address}</span>
                    <span className="faint">→</span>
                    <b className="mono grow ellipsis">{n.name}</b>
                    <span className="pill">{n.kind}</span>
                    <IconButton tip={n.kind === "local" || n.kind === "argument" ? "Accept (adds a comment at the function)" : "Accept (rename)"} onClick={() => a.acceptName(n.id)}><Check size={12} /></IconButton>
                    <IconButton tip="Reject" onClick={() => a.rejectName(n.id)}><X size={12} /></IconButton>
                  </div>
                  {n.reason && <div className="faint as-reason">{n.reason}</div>}
                </div>
              ))}
            </>
          )}
          {a.fields.length > 0 && (
            <>
              <div className="row"><span className="label grow">Suggested fields for {a.fieldsFor} ({a.fields.length})</span><button className="btn small" onClick={() => a.fields.forEach((f) => a.rejectField(f.id))}>Dismiss all</button></div>
              {a.fields.map((f) => (
                <div key={f.id} className="as-sugg">
                  <div className="row">
                    <span className="mono faint">+0x{f.offset.toString(16)}</span>
                    <span className="mono">{f.type}</span>
                    <b className="mono grow ellipsis">{f.name}</b>
                    <IconButton tip="Accept (sets the field in the Structs view)" onClick={() => a.acceptField(f.id)}><Check size={12} /></IconButton>
                    <IconButton tip="Reject" onClick={() => a.rejectField(f.id)}><X size={12} /></IconButton>
                  </div>
                  {f.reason && <div className="faint as-reason">{f.reason}</div>}
                </div>
              ))}
            </>
          )}
        </div>
      )}
      <div className="panel-body as-transcript">
        {a.entries.length === 0 && <div className="panel-section faint">Ask about the target, or use an action above. The assistant can read memory, disassemble, list strings, xrefs, imports and your names; every tool call appears here.</div>}
        {a.entries.map((e) => <Fragment key={e.id}><EntryView e={e} /></Fragment>)}
        <div ref={end} />
      </div>
      <div className="panel-section as-input">
        <textarea
          className="input"
          rows={3}
          placeholder={noKey ? "Add an API key in Settings first" : "Ask about the target… (Enter sends, Shift+Enter for a new line)"}
          value={text}
          disabled={noKey}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); if (!a.busy) send(); } }}
        />
        {a.busy
          ? <button className="btn small" onClick={() => a.stop()}><Square size={11} /> Stop</button>
          : <button className="btn small primary" disabled={noKey || !text.trim()} onClick={send}><Send size={11} /> Send</button>}
      </div>
    </Panel>
  );
}
