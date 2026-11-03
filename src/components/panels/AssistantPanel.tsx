// Assistant panel: chat with a model of your choice (Anthropic, OpenAI, Gemini, OpenRouter, or a
// local / self-hosted OpenAI- or Anthropic-compatible endpoint) about the target, with one-click
// actions, slash commands and @-mentions that attach the function at the cursor, an address, a
// struct, a module or the selection. The assistant may call EchoDebug's read-only tools; every
// call is listed in the transcript.
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronDown, Download, History, Plus, SlidersHorizontal, X } from "lucide-react";
import { useAssistant } from "@/store/assistant";
import { useConn } from "@/store/conn";
import { useUi } from "@/store/ui";
import { available } from "@/lib/assistant/api";
import { isLocalHost, providerHost, usable } from "@/lib/assistant/providers";
import { kSystemPrompt } from "@/lib/assistant/prompts";
import { fmtCost, totalCost } from "@/lib/assistant/cost";
import { IconButton, Panel } from "../ui";
import { Composer } from "./assistant/Composer";
import { ClaudeCodeCard, ConversationList, EntryView, ModelPicker, ModelSettingsPop } from "./assistant/parts";

function SystemEditor() {
  const a = useAssistant();
  const [text, setText] = useState(a.conv.system ?? kSystemPrompt);
  return (
    <div className="panel-section as-system">
      <div className="row"><span className="label grow">System prompt (this conversation)</span><IconButton tip="Close" onClick={() => a.set({ systemEditing: false })}><X size={12} /></IconButton></div>
      <textarea className="input mono" rows={8} value={text} onChange={(e) => setText(e.target.value)} />
      <div className="row">
        <button className="btn small primary" onClick={() => a.setSystem(text.trim() === kSystemPrompt.trim() ? null : text)}><Check size={11} /> Save</button>
        <button className="btn small" onClick={() => { a.setSystem(null); }}>Reset to default</button>
        <span className="faint as-small">The default tells the model it may only read and how to hand back names and fields.</span>
      </div>
    </div>
  );
}

export default function AssistantPanel() {
  const a = useAssistant();
  const ui = useUi();
  const attached = useConn((s) => !!s.target);
  const [pop, setPop] = useState<null | "convs" | "settings">(null);
  const end = useRef<HTMLDivElement>(null);
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => { void a.refreshProviders(); }, [ui.settingsOpen]);
  useEffect(() => { void a.listConversations(); }, []);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [a.conv.entries]);
  // Ctrl+L focuses the message box; Esc stops a running reply from anywhere in the panel
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "l") {
        e.preventDefault();
        useAssistant.setState((s) => ({ focusTick: s.focusTick + 1 }));
      } else if (e.key === "Escape" && useAssistant.getState().busy && root.current?.contains(document.activeElement)) {
        useAssistant.getState().stop();
      }
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);

  const p = a.activeProvider();
  const mi = a.activeModel();
  const ready = !!p && usable(p);
  const models = useMemo(() => new Map(a.allModels().map((m) => [`${m.provider}/${m.id}`, m.name])), [a.providers, a.modelCache]);
  const cost = totalCost(a.conv.entries.filter((e) => e.kind === "assistant") as never);
  const lastUser = a.conv.entries.map((e) => e.kind).lastIndexOf("user");

  if (!available()) {
    return <Panel title="Assistant"><div className="panel-section faint">The assistant runs in the EchoDebug desktop app, which keeps your API keys out of the web view.</div></Panel>;
  }

  const header = (
    <>
      <div className="as-anchor">
        <button className="btn small as-model-btn" title="Model (/model)" disabled={!a.providers?.some(usable)} onClick={() => a.set({ pickerOpen: !a.pickerOpen })}>
          <span className="ellipsis">{mi?.name ?? a.model}</span><ChevronDown size={11} />
        </button>
        {a.pickerOpen && <ModelPicker />}
      </div>
      <div className="as-anchor">
        <IconButton tip="Model settings: max output, effort, temperature, price" disabled={!ready} onClick={() => setPop(pop === "settings" ? null : "settings")}><SlidersHorizontal size={13} /></IconButton>
        {pop === "settings" && <ModelSettingsPop onClose={() => setPop(null)} />}
      </div>
      <div className="as-anchor">
        <IconButton tip="Conversations" onClick={() => setPop(pop === "convs" ? null : "convs")}><History size={13} /></IconButton>
        {pop === "convs" && <ConversationList onClose={() => setPop(null)} />}
      </div>
      <IconButton tip="Export as Markdown (/export)" disabled={!a.conv.entries.length} onClick={() => void a.exportConversation()}><Download size={13} /></IconButton>
      <IconButton tip="New conversation (/new)" onClick={() => a.newConversation()}><Plus size={13} /></IconButton>
    </>
  );

  const host = p ? providerHost(p) : "";
  const local = p ? isLocalHost(host) : false;

  return (
    <div ref={root} className="as-root">
      <Panel title="Assistant" actions={header} className="assistant">
        <div className="panel-section as-disclosure">
          {ready ? (
            <>What you send here (code, memory, names and the tool results the assistant reads) goes to <b>{p.name}</b> ({local ? `${host}, on your network` : host}) to generate the answer. The assistant can only use read-only tools; nothing is renamed or changed until you accept it.</>
          ) : (
            <>The assistant sends what you ask about (code, memory, names, tool results) to the provider you choose. It can only use read-only tools.</>
          )}
        </div>
        {!ready ? (
          <div className="panel-section as-setup">
            <div className="label">Choose a provider</div>
            <div className="faint as-small">
              Add an Anthropic, OpenAI or Gemini API key, sign in with OpenRouter, or point it at a local model (Ollama, LM Studio, vLLM, llama.cpp) in <span className="link" onClick={() => ui.set({ settingsOpen: true })}>Settings → Assistant</span>. Keys stay in the desktop app and only go to their provider.
            </div>
            <ClaudeCodeCard />
          </div>
        ) : (
          <div className="panel-section">
            <div className="row" style={{ flexWrap: "wrap", gap: 4 }}>
              <button className="btn small" disabled={a.busy || !attached} title="/explain: the disassembly and pseudocode of the function at the disassembly cursor, with your names and comments" onClick={() => void a.explainFunction()}>Explain function</button>
              <button className="btn small" disabled={a.busy || !attached} title="/names: names for the function, its callees, globals and locals: a list you accept one by one" onClick={() => void a.suggestNames()}>Suggest names</button>
              <button className="btn small" disabled={a.busy || !attached} title="/struct: field types and names from the Structs view's live sample: a list you accept one by one" onClick={() => void a.suggestFields()}>Suggest struct fields</button>
              <button className="btn small" disabled={a.busy || !attached} title="/summary: imports, strings and triage findings of the focused (or main) module" onClick={() => void a.summariseModule()}>Summarise module</button>
            </div>
          </div>
        )}
        {a.systemEditing && <SystemEditor />}
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
          {a.conv.entries.length === 0 && (
            <div className="panel-section faint as-empty">
              Ask about the target, use an action above, or type <span className="mono">/</span> for commands and <span className="mono">@</span> to attach context (<span className="mono">@function</span>, <span className="mono">@0x…</span>, <span className="mono">@struct:Name</span>, <span className="mono">@module:name</span>, <span className="mono">@selection</span>). The assistant can read memory, disassemble, list strings, xrefs, imports and your names; every tool call appears here.
            </div>
          )}
          {a.conv.entries.map((e, i) => <Fragment key={e.id}><EntryView e={e} last={i === lastUser} models={models} /></Fragment>)}
          <div ref={end} />
        </div>
        {a.conv.entries.some((e) => e.kind === "assistant" && e.usage) && (
          <div className="as-convmeta faint">
            <span className="ellipsis grow">{a.conv.title}</span>
            <span title="This conversation's cost (from usage × price, or as the provider reports it)">{fmtCost(cost.usd)}{cost.complete ? "" : "+?"}</span>
          </div>
        )}
        <Composer disabled={!ready} placeholder={ready ? `Message ${mi?.name ?? a.model}… (/ for commands, @ to attach, Enter sends)` : "Set up a provider in Settings → Assistant first"} />
      </Panel>
    </div>
  );
}
