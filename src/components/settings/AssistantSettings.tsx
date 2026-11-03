// Settings → Assistant: a credential per provider (API key, or OpenRouter's sign-in), custom
// OpenAI- / Anthropic-compatible endpoints, connection tests and whether conversations are saved.
// Keys are sent to the desktop app once and never shown again.
import { useEffect, useState } from "react";
import { CheckCircle2, LogIn, Plug, Trash2 } from "lucide-react";
import * as api from "@/lib/assistant/api";
import { kBuiltins, kEndpointPresets, kKindLabels, providerHost, isLocalHost, usable, type ProviderInfo, type ProviderKind } from "@/lib/assistant/providers";
import { isTauri, openUrl } from "@/lib/tauri";
import { useAssistant } from "@/store/assistant";
import { attempt, log } from "@/store/output";
import { ClaudeCodeCard } from "../panels/assistant/parts";
import { Row, Section } from "./layout";

type TestState = Record<string, { ok: boolean; text: string } | "running">;

function TestButton({ id, tests, setTests }: { id: string; tests: TestState; setTests: (f: (t: TestState) => TestState) => void }) {
  const t = tests[id];
  const run = async () => {
    setTests((x) => ({ ...x, [id]: "running" }));
    try {
      const r = await api.testProvider(id);
      setTests((x) => ({ ...x, [id]: { ok: true, text: `OK: ${r.models} models from ${r.host} in ${r.ms} ms` } }));
      void useAssistant.getState().refreshModels(id, true);
    } catch (e) {
      setTests((x) => ({ ...x, [id]: { ok: false, text: e instanceof Error ? e.message : String(e) } }));
    }
  };
  return <button className="btn" disabled={t === "running"} onClick={() => void run()}><Plug size={12} /> {t === "running" ? "Testing…" : "Test"}</button>;
}

function TestResult({ t }: { t: TestState[string] | undefined }) {
  if (!t || t === "running") return null;
  return <div className={`settings-note ${t.ok ? "" : "danger"}`} style={{ paddingTop: 0 }}>{t.text}</div>;
}

function statusText(p: ProviderInfo | undefined): string {
  if (!p || !usable(p)) return "Not set up.";
  if (p.method === "oauth") return `Signed in with OpenRouter (key ${p.key_hint ?? "stored"}).`;
  if (p.method === "none") return "No key (local endpoint).";
  return `Key ${p.key_hint ?? "stored"}.`;
}

function headersFromText(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of s.split("\n")) {
    const i = line.indexOf(":");
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 32) || "endpoint";

function EndpointForm({ existing, onDone }: { existing?: ProviderInfo; onDone: () => void }) {
  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState<ProviderKind>(existing?.kind ?? "openai_compat");
  const [base, setBase] = useState(existing?.base_url ?? "");
  const [key, setKey] = useState("");
  const [headers, setHeaders] = useState(existing ? existing.headers.map((h) => `${h}: `).join("\n") : "");
  const save = async () => {
    const id = existing?.id ?? `custom-${slug(name || base.replace(/^https?:\/\//, ""))}`;
    const hs = headersFromText(headers);
    // editing: header lines left without a value keep the stored value
    const keepHeaders = existing && Object.values(hs).every((v) => !v) && Object.keys(hs).join() === existing.headers.join();
    const r = await attempt("assistant", api.saveProvider({ id, kind, name: name || base, base_url: base, api_key: key, ...(keepHeaders ? {} : { headers: hs }) }));
    if (r) { log("info", "assistant", `saved endpoint ${r.name}`); onDone(); }
  };
  return (
    <div className="as-endpoint-form">
      <div className="row" style={{ flexWrap: "wrap", gap: 4 }}>
        {!existing && kEndpointPresets.map((p) => (
          <button key={p.label} className="btn small" title={p.note} onClick={() => { setName(p.label); setKind(p.kind); setBase(p.base); if (p.label === "Azure OpenAI") setHeaders("api-key: "); }}>{p.label}</button>
        ))}
      </div>
      <div className="row">
        <input className="input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} style={{ width: 140 }} />
        <select className="select" value={kind} onChange={(e) => setKind(e.target.value as ProviderKind)} disabled={!!existing}>
          <option value="openai_compat">OpenAI-compatible</option>
          <option value="anthropic_compat">Anthropic-compatible</option>
        </select>
      </div>
      <input className="input mono" placeholder={kind === "openai_compat" ? "http://127.0.0.1:11434/v1" : "https://gateway.example.com"} value={base} onChange={(e) => setBase(e.target.value)} />
      <input className="input mono" type="password" autoComplete="off" spellCheck={false} placeholder={existing?.has_key ? "key stored (leave empty to keep)" : "API key (optional for local servers)"} value={key} onChange={(e) => setKey(e.target.value)} />
      <textarea className="input mono" rows={2} placeholder={"Extra headers, one per line\nX-Team: research"} value={headers} onChange={(e) => setHeaders(e.target.value)} />
      <div className="row">
        <button className="btn primary" disabled={!base.trim()} onClick={() => void save()}>{existing ? "Save" : "Add endpoint"}</button>
        <button className="btn" onClick={onDone}>Cancel</button>
        {base && /^http:\/\//i.test(base) && !isLocalHost(providerHost({ base_url: base })) && key && <span className="warn as-small">This key would be sent over plain http.</span>}
      </div>
    </div>
  );
}

export function AssistantSettings() {
  const a = useAssistant();
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [tests, setTests] = useState<TestState>({});
  const [signin, setSignin] = useState<number | null>(null);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  useEffect(() => { void a.refreshProviders(); }, []);
  if (!isTauri()) {
    return <Section title="Assistant"><div className="settings-note">The assistant and its credentials live in the desktop app.</div></Section>;
  }
  const byId = new Map((a.providers ?? []).map((p) => [p.id, p]));
  const refresh = () => void a.refreshProviders();
  const saveKey = async (id: string) => {
    const r = await attempt("assistant", api.saveProvider({ id, api_key: keys[id] ?? "" }));
    setKeys((k) => ({ ...k, [id]: "" }));
    if (r) { log("info", "assistant", `${r.name}: key saved`); refresh(); }
  };
  const remove = async (id: string) => {
    const r = await attempt("assistant", api.removeProvider(id));
    if (r) { log("info", "assistant", `${r.name}: ${r.kind === "openrouter" ? "signed out" : "removed"}`); refresh(); }
  };
  const signIn = async () => {
    const s = api.signInOpenRouter();
    setSignin(s.id);
    const r = await attempt("assistant", s.done);
    setSignin(null);
    if (r) { log("info", "assistant", "signed in to OpenRouter"); refresh(); }
  };
  const customs = (a.providers ?? []).filter((p) => p.kind === "openai_compat" || p.kind === "anthropic_compat");

  return (
    <Section title="Assistant">
      {kBuiltins.map((b) => {
        const p = byId.get(b.id);
        const ok = !!p && usable(p);
        return (
          <div key={b.id}>
            <Row label={<>{kKindLabels[b.id]} {ok && <CheckCircle2 size={12} className="ok" />}</>} hint={<>{b.blurb} {statusText(p)} <span className="link" onClick={() => void openUrl(b.keyUrl)}>Get a key</span></>}>
              <div className="row" style={{ flexWrap: "wrap", justifyContent: "flex-end" }}>
                {b.id === "openrouter" && (signin === null
                  ? <button className="btn primary" title="OpenRouter's OAuth PKCE sign-in: opens your browser, then stores the key it returns" onClick={() => void signIn()}><LogIn size={12} /> Sign in with OpenRouter</button>
                  : <button className="btn" onClick={() => void api.cancelSignIn(signin)}>Waiting for the browser… Cancel</button>)}
                <input className="input mono" type="password" autoComplete="off" spellCheck={false} placeholder={ok ? "replace key" : b.placeholder} value={keys[b.id] ?? ""} onChange={(e) => setKeys((k) => ({ ...k, [b.id]: e.target.value }))} onKeyDown={(e) => e.key === "Enter" && keys[b.id]?.trim() && void saveKey(b.id)} style={{ width: 150 }} />
                <button className="btn" disabled={!keys[b.id]?.trim()} onClick={() => void saveKey(b.id)}>Save</button>
                {ok && <TestButton id={b.id} tests={tests} setTests={setTests} />}
                {ok && <button className="btn" onClick={() => void remove(b.id)}>{p!.method === "oauth" ? "Sign out" : "Remove"}</button>}
              </div>
            </Row>
            <TestResult t={tests[b.id]} />
          </div>
        );
      })}
      <div className="settings-note">
        Subscription sign-in (Claude Pro/Max, ChatGPT Plus) isn&apos;t offered because those providers don&apos;t allow third-party apps to use it; use an API key, OpenRouter sign-in, or a compatible endpoint.
      </div>
      <div className="settings-note"><ClaudeCodeCard /></div>
      <Row label="Custom endpoints" hint="OpenAI-compatible (Ollama, LM Studio, vLLM, llama.cpp, LiteLLM, Azure OpenAI) or Anthropic-compatible servers. Local servers need no key.">
        {!adding && <button className="btn" onClick={() => { setAdding(true); setEditing(null); }}>Add endpoint</button>}
      </Row>
      {adding && <div className="settings-note"><EndpointForm onDone={() => { setAdding(false); refresh(); }} /></div>}
      {customs.map((p) => (
        <div key={p.id}>
          <Row label={<>{p.name} <span className="pill">{kKindLabels[p.kind]}</span></>} hint={<><span className="mono">{p.base_url}</span> · {statusText(p)}{p.headers.length ? ` · headers: ${p.headers.join(", ")}` : ""}</>}>
            <div className="row">
              <TestButton id={p.id} tests={tests} setTests={setTests} />
              <button className="btn" onClick={() => { setEditing(editing === p.id ? null : p.id); setAdding(false); }}>Edit</button>
              <button className="btn" title="Forget this endpoint" onClick={() => void remove(p.id)}><Trash2 size={12} /></button>
            </div>
          </Row>
          <TestResult t={tests[p.id]} />
          {editing === p.id && <div className="settings-note"><EndpointForm existing={p} onDone={() => { setEditing(null); refresh(); }} /></div>}
        </div>
      ))}
      <Row label="Save conversations" hint={<>Keep assistant conversations (they contain code and data read from the target) in <span className="mono">{a.storage?.conversations ?? "the config directory"}</span>, readable only by your user.</>}>
        <label className="switch">
          <input type="checkbox" checked={a.saveHistory} onChange={(e) => a.set({ saveHistory: e.target.checked })} />
          <span />
        </label>
      </Row>
      {a.storage && <div className="settings-note">Credentials: {a.storage.note} Each provider&apos;s key is only sent to that provider; a custom endpoint&apos;s key only to the base URL saved with it. What you send from the Assistant panel goes to the provider you choose there.</div>}
    </Section>
  );
}
