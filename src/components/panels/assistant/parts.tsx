// Pieces of the assistant panel: the model picker, the conversation list, per-model settings,
// transcript entries and the Claude Code card.
import { useEffect, useMemo, useRef, useState } from "react";
import { Brain, Check, ChevronRight, Copy, Eye, Pencil, RefreshCw, RotateCcw, Trash2, Wrench } from "lucide-react";
import { useAssistant, type Entry } from "@/store/assistant";
import { mcpAddCommand, useConn } from "@/store/conn";
import { useUi } from "@/store/ui";
import { effortLevels, filterModels, fmtTokens, kKindLabels, usable, type ModelInfo, type ProviderKind } from "@/lib/assistant/providers";
import { fmtCost, fmtUsage } from "@/lib/assistant/cost";
import { CopyChip, IconButton, useCopy } from "../../ui";
import { Markdown, PlainLinked } from "./Markdown";

const priceText = (m: ModelInfo) => (m.price ? (m.price.input === 0 && m.price.output === 0 ? "free" : `$${m.price.input}/$${m.price.output}`) : "");

function useOutside(onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // the anchor (the pop and the button that opens it) counts as inside: the button toggles
    const h = (e: MouseEvent) => { const box = ref.current?.parentElement ?? ref.current; if (box && !box.contains(e.target as Node)) onClose(); };
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    setTimeout(() => document.addEventListener("mousedown", h));
    document.addEventListener("keydown", k);
    return () => { document.removeEventListener("mousedown", h); document.removeEventListener("keydown", k); };
  }, [onClose]);
  return ref;
}

/** Searchable model list of every usable provider, grouped by provider. */
export function ModelPicker() {
  const a = useAssistant();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const close = () => a.set({ pickerOpen: false });
  const ref = useOutside(close);
  const providers = (a.providers ?? []).filter(usable);
  const all = a.allModels();
  const list = useMemo(() => filterModels(all, q), [all, q]);
  useEffect(() => { setSel(0); }, [q]);
  const pick = (m: ModelInfo) => a.select(m.provider, m.id);
  return (
    <div className="as-pop as-picker" ref={ref}>
      <input
        className="input"
        autoFocus
        placeholder="Search models…"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, list.length - 1)); }
          if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
          if (e.key === "Enter" && list[sel]) pick(list[sel]);
        }}
      />
      <div className="as-picker-list">
        {providers.map((p) => {
          const ms = list.filter((m) => m.provider === p.id);
          const cache = a.modelCache[p.id];
          if (!ms.length && q) return null;
          return (
            <div key={p.id}>
              <div className="as-picker-group">
                <span className="grow">{p.name}</span>
                <span className="faint" title={cache?.error ?? ""}>{cache?.error ? "offline list" : cache ? `${cache.models.length} live` : "built-in"}</span>
                <IconButton tip={`Refresh ${p.name} models`} onClick={() => void a.refreshModels(p.id, true)}><RefreshCw size={11} /></IconButton>
              </div>
              {ms.map((m) => {
                const i = list.indexOf(m);
                const active = m.provider === a.provider && m.id === a.model;
                return (
                  <div key={m.id} className="as-picker-item" data-active={i === sel} data-current={active} onClick={() => pick(m)} onMouseEnter={() => setSel(i)}>
                    <div className="row">
                      <span className="ellipsis grow">{m.name}</span>
                      {active && <Check size={11} />}
                    </div>
                    <div className="row faint as-picker-meta">
                      <span className="mono ellipsis grow">{m.id}</span>
                      {m.context ? <span title="Context window">{fmtTokens(m.context)}</span> : null}
                      {m.tools === false && <span className="warn" title="No tool calling: the assistant cannot read the target itself">no tools</span>}
                      {m.tools && <span title="Tool calling"><Wrench size={10} /></span>}
                      {m.vision && <span title="Image input"><Eye size={10} /></span>}
                      {m.reasoning && <span title="Reasoning / thinking"><Brain size={10} /></span>}
                      {priceText(m) && <span title="USD per million input / output tokens">{priceText(m)}</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          );
        })}
        {!providers.length && <div className="faint as-pad">Set up a provider in Settings → Assistant first.</div>}
      </div>
    </div>
  );
}

/** Max output tokens, effort and temperature where the model supports them, and a price override. */
export function ModelSettingsPop({ onClose }: { onClose: () => void }) {
  const a = useAssistant();
  const ref = useOutside(onClose);
  const p = a.activeProvider();
  const mi = a.activeModel();
  const s = a.modelSettings();
  const kind = (p?.kind ?? "anthropic") as ProviderKind;
  const efforts = effortLevels(kind);
  const showTemp = kind !== "anthropic" && mi?.temperature !== false;
  const showEffort = kind === "anthropic" || mi?.reasoning !== false;
  const price = s.price ?? mi?.price ?? null;
  return (
    <div className="as-pop as-settings" ref={ref}>
      <div className="label">{mi?.name ?? a.model}</div>
      <div className="faint as-small">{p?.name} · context {fmtTokens(mi?.context)} · max output {fmtTokens(mi?.max_output)}</div>
      <label className="as-field">Max output tokens
        <input className="input mono" type="number" min={256} max={mi?.max_output ?? 256000} step={1024} value={s.maxTokens} onChange={(e) => a.setModelSettings({ maxTokens: Math.max(1, Number(e.target.value) || 1) })} />
      </label>
      {showEffort && (
        <label className="as-field">{kind === "anthropic" ? "Effort" : "Reasoning effort"}
          <select className="select" value={s.effort} onChange={(e) => a.setModelSettings({ effort: e.target.value as never })}>
            {kind !== "anthropic" && <option value="off">off (provider default)</option>}
            {efforts.map((x) => <option key={x} value={x}>{x}</option>)}
          </select>
        </label>
      )}
      {kind === "anthropic" && <div className="faint as-small">Current Claude models think adaptively; effort sets how much (and how much it costs).</div>}
      {showTemp && (
        <label className="as-field">Temperature
          <span className="row">
            <input type="range" min={0} max={2} step={0.05} value={s.temperature ?? 1} disabled={s.temperature == null} onChange={(e) => a.setModelSettings({ temperature: Number(e.target.value) })} />
            <span className="mono">{s.temperature == null ? "default" : s.temperature.toFixed(2)}</span>
            <input type="checkbox" title="Set a temperature" checked={s.temperature != null} onChange={(e) => a.setModelSettings({ temperature: e.target.checked ? 0.7 : null })} />
          </span>
        </label>
      )}
      <label className="as-field">Price, USD per million tokens (in / out)
        <span className="row">
          <input className="input mono" style={{ width: 70 }} type="number" min={0} step={0.01} placeholder="?" value={price?.input ?? ""} onChange={(e) => a.setModelSettings({ price: { input: Number(e.target.value) || 0, output: price?.output ?? 0 } })} />
          <input className="input mono" style={{ width: 70 }} type="number" min={0} step={0.01} placeholder="?" value={price?.output ?? ""} onChange={(e) => a.setModelSettings({ price: { input: price?.input ?? 0, output: Number(e.target.value) || 0 } })} />
          {s.price && <button className="btn small" onClick={() => a.setModelSettings({ price: undefined })}>reset</button>}
        </span>
      </label>
      <div className="faint as-small">{mi?.price && !s.price ? "Price from the provider / built-in list." : s.price ? "Your price override." : "No known price: costs show as —."}</div>
    </div>
  );
}

/** Saved conversations: open, rename, delete. */
export function ConversationList({ onClose }: { onClose: () => void }) {
  const a = useAssistant();
  const ref = useOutside(onClose);
  const [editing, setEditing] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  useEffect(() => { void a.listConversations(); }, []);
  const list = a.convs.some((c) => c.id === a.conv.id) || !a.conv.entries.length ? a.convs : [{ id: a.conv.id, title: a.conv.title || "Current conversation", updated: a.conv.updated, provider: a.conv.provider, model: a.conv.model, count: 0 }, ...a.convs];
  return (
    <div className="as-pop as-convs" ref={ref}>
      <div className="row"><span className="label grow">Conversations</span><button className="btn small" onClick={() => { a.newConversation(); onClose(); }}>New</button></div>
      {!a.saveHistory && <div className="faint as-small">Saving is off (Settings → Assistant).</div>}
      <div className="as-convs-list">
        {list.map((c) => (
          <div key={c.id} className="as-conv" data-current={c.id === a.conv.id}>
            {editing === c.id ? (
              <input className="input" autoFocus value={title} onChange={(e) => setTitle(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { void a.renameConversation(c.id, title); setEditing(null); } if (e.key === "Escape") setEditing(null); }} onBlur={() => setEditing(null)} />
            ) : (
              <span className="grow ellipsis as-conv-title" onClick={() => { void a.openConversation(c.id); onClose(); }} title={`${c.provider ?? ""} ${c.model ?? ""}`}>{c.title || "Untitled"}</span>
            )}
            <span className="faint as-small">{new Date(c.updated).toLocaleDateString()}</span>
            <IconButton tip="Rename" onClick={() => { setEditing(c.id); setTitle(c.title); }}><Pencil size={11} /></IconButton>
            <IconButton tip="Delete" onClick={() => { if (window.confirm(`Delete "${c.title || "Untitled"}"?`)) void a.deleteConversation(c.id); }}><Trash2 size={11} /></IconButton>
          </div>
        ))}
        {!list.length && <div className="faint as-pad">No saved conversations yet.</div>}
      </div>
    </div>
  );
}

function short(v: unknown, n = 120): string {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function pretty(v: unknown): string {
  try { return JSON.stringify(v, null, 2); } catch { return String(v); }
}

/** Result text pretty-printed when it is JSON. */
function prettyResult(s: string): string {
  if (s.length > 200_000) return s;
  try { return JSON.stringify(JSON.parse(s), null, 1); } catch { return s; }
}

const kActionLabels: Record<string, string> = { settings: "Open Settings", retry: "Retry", compact: "Compact", models: "Refresh models" };

export function EntryView({ e, last, models }: { e: Entry; last: boolean; models: Map<string, string> }) {
  const a = useAssistant();
  const ui = useUi();
  const [copied, copy] = useCopy();
  if (e.kind === "user") {
    return (
      <div className="as-msg as-user">
        {e.title ? <details><summary><b>{e.title}</b> <span className="faint">({Math.round((e.text.length / 1024) * 10) / 10} KiB sent)</span></summary><pre className="as-pre">{e.text}</pre></details> : <div className="as-text">{e.text}</div>}
        {e.attachments?.length ? <div className="as-chips">{e.attachments.map((t) => <span key={t} className="as-chip faint">{t}</span>)}</div> : null}
        {last && !a.busy && !e.title && <div className="as-user-tools"><IconButton tip="Edit and resend (↑)" onClick={() => a.editLast()}><Pencil size={11} /></IconButton><IconButton tip="Retry" onClick={() => void a.retry()}><RotateCcw size={11} /></IconButton></div>}
      </div>
    );
  }
  if (e.kind === "note") {
    return (
      <div className={`as-note ${e.level === "error" ? "danger" : e.level === "warn" ? "warn" : "faint"}`}>
        {e.pre ? <pre className="as-pre as-note-pre">{e.text}</pre> : <span>{e.text}</span>}
        {e.actions?.map((x) => (
          <button key={x} className="btn small" onClick={() => {
            if (x === "settings") ui.set({ settingsOpen: true });
            else if (x === "retry") void a.retry();
            else if (x === "compact") void a.compact();
            else if (x === "models") void a.refreshModels(a.provider, true);
          }}>{kActionLabels[x] ?? x}</button>
        ))}
      </div>
    );
  }
  if (e.kind === "tool") {
    return (
      <details className="as-tool" data-error={!!e.isError}>
        <summary><ChevronRight size={11} className="as-caret" /><Wrench size={11} /> <span className="mono">{e.name}</span> <span className="faint mono ellipsis">{short(e.input)}</span>{e.running ? <span className="faint"> · running…</span> : e.isError ? <span className="danger"> · error</span> : null}</summary>
        <div className="as-tool-body">
          <div className="faint as-small">input</div>
          <pre className="as-pre">{pretty(e.input)}</pre>
          {e.result !== undefined && (
            <>
              <div className="faint as-small">result{e.result.length > 8000 ? ` (first 8000 of ${e.result.length} characters shown; all were sent)` : ""}</div>
              <pre className="as-pre">{prettyResult(e.result.length > 8000 ? e.result.slice(0, 8000) : e.result)}</pre>
            </>
          )}
        </div>
      </details>
    );
  }
  const name = models.get(`${e.provider}/${e.model}`) ?? e.model;
  const text = e.blocks.filter((b) => b?.type === "text").map((b) => (b as { text: string }).text).join("");
  const lastIdx = e.blocks.length - 1;
  return (
    <div className="as-msg as-bot">
      {e.blocks.map((b, i) => {
        if (!b) return null;
        if (b.type === "thinking") {
          const t = (b as { thinking: string }).thinking;
          if (!t) return e.streaming && i === lastIdx ? <div key={i} className="faint as-small">Thinking…</div> : null;
          return <details key={i} className="as-think" open={e.streaming && i === lastIdx}><summary className="faint"><Brain size={11} /> Thinking{e.streaming && i === lastIdx ? "…" : ""}</summary><PlainLinked text={t} /></details>;
        }
        if (b.type === "redacted_thinking") return null;
        if (b.type === "text") return <Markdown key={i} text={(b as { text: string }).text} />;
        if (b.type === "fallback") return <div key={i} className="as-note faint">Continued on {String((b as { to?: { model?: string } }).to?.model ?? "a fallback model")}</div>;
        return null;
      })}
      {e.streaming && !e.blocks.length && <div className="faint as-small">Waiting for {name}…</div>}
      <div className="as-meta faint">
        <span className="grow">{name}{e.streaming ? " · …" : ""}{e.ms ? ` · ${(e.ms / 1000).toFixed(1)}s` : ""}{e.usage ? ` · ${fmtUsage(e.usage)} · ${fmtCost(e.cost)}` : ""}</span>
        {!e.streaming && text && <button className="as-code-copy" title="Copy reply" aria-label="Copy reply" onClick={() => copy(text)}>{copied === text ? <Check size={11} /> : <Copy size={11} />}</button>}
      </div>
    </div>
  );
}

/**
 * Claude subscription users: run Claude Code itself (signed in with their own account) and connect
 * it to EchoDebug's MCP server. The app never signs in to claude.ai or runs Claude Code for them.
 */
export function ClaudeCodeCard() {
  const conn = useConn();
  const ui = useUi();
  const [copied, copy] = useCopy();
  const cmd = mcpAddCommand(conn.port, conn.token);
  return (
    <div className="as-card">
      <div className="label">Use your Claude subscription with Claude Code</div>
      <div className="faint as-small">
        Claude Pro/Max users: run Claude Code (signed in with your own account) and connect it to EchoDebug&apos;s MCP server; it gets the same tools, under the MCP policy you set.
        <br />Why not here: Anthropic doesn&apos;t allow third-party apps to offer claude.ai login, including through the Agent SDK.
      </div>
      <CopyChip text={cmd} copied={copied} onCopy={copy} />
      <span className="link as-small" onClick={() => ui.setRail("mcp")}>Open the MCP Server panel</span>
    </div>
  );
}

export function ProviderBadge({ kind }: { kind: ProviderKind }) {
  return <span className="pill">{kKindLabels[kind]}</span>;
}

