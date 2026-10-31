import { X } from "lucide-react";
import { useConn } from "@/store/conn";
import { kProviders } from "@/lib/ai-providers";
import { kMotionPrefs, useMotion } from "@/store/motion";
import { attempt, log } from "@/store/output";
import { kDefaultAi, useUi, type AiProvider, type Theme } from "@/store/ui";
import { useUpdate } from "@/store/update";
import { installAgent, isTauri, openScriptsFolder } from "@/lib/tauri";
import { IconButton } from "./ui";

const kAccents = ["", "#2eb8a6", "#88c0d0", "#f26b38", "#a78bfa", "#f472b6", "#facc15"];

export default function SettingsModal() {
  const ui = useUi();
  const conn = useConn();
  const upd = useUpdate();
  const motion = useMotion((s) => s.pref);
  const setMotion = useMotion((s) => s.setPref);
  const ai = ui.ai;
  const setAi = (p: Partial<typeof ai>) => ui.set({ ai: { ...ai, ...p } });
  const close = () => ui.set({ settingsOpen: false });
  const reinstall = async () => {
    const r = await attempt("agent", installAgent());
    if (r) log("info", "agent", `installed ${r.path}${r.changed ? " (updated)" : " (unchanged)"}`);
    else if (!isTauri()) log("warn", "agent", "agent install is only available in the desktop app");
  };
  return (
    <div className="modal-scrim" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div className="modal" role="dialog" aria-label="Settings">
        <div className="panel-head">
          <div className="panel-title">Settings</div>
          <div className="grow" />
          <IconButton tip="Close" onClick={close}><X size={14} /></IconButton>
        </div>
        <div className="modal-body">
          <div className="settings-group">
            <div className="label">Appearance</div>
            <div className="settings-row">
              <span>Theme</span>
              <select className="select" value={ui.theme} onChange={(e) => ui.set({ theme: e.target.value as Theme })}>
                <option value="obsidian">Obsidian</option>
                <option value="nord">Nord</option>
                <option value="blood-orange">Blood Orange</option>
              </select>
            </div>
            <div className="settings-row">
              <span>Accent</span>
              <div className="row">
                {kAccents.map((c) => (
                  <button key={c || "default"} className="swatch" data-active={ui.accent === c} title={c || "theme default"} aria-label={c || "theme default"}
                    style={{ background: c || "var(--bg-2)" }} onClick={() => ui.set({ accent: c })} />
                ))}
              </div>
            </div>
            <div className="settings-row">
              <span>Motion</span>
              <select className="select" value={motion} onChange={(e) => setMotion(e.target.value as typeof motion)}>
                {kMotionPrefs.map((m) => <option key={m.id} value={m.id}>{m.label} — {m.hint}</option>)}
              </select>
            </div>
          </div>

          <div className="settings-group">
            <div className="label">Echo connection</div>
            <div className="settings-row"><span>Relay</span><span className="mono">ws://127.0.0.1:{conn.port} {conn.relay ? "· up" : "· down"}</span></div>
            <div className="settings-row"><span>MCP endpoint</span><span className="mono selectable">http://127.0.0.1:{conn.port}/mcp</span></div>
            <div className="settings-row">
              <span>Agent script</span>
              <div className="row">
                <button className="btn" onClick={() => void reinstall()}>Reinstall agent</button>
                <button className="btn" onClick={() => void attempt("agent", openScriptsFolder())} disabled={!isTauri()}>Open scripts folder</button>
              </div>
            </div>
            <div className="faint" style={{ fontSize: 12 }}>
              Load <span className="mono">echo_debug.as</span> in Echo; the app installs it to <span className="mono">%APPDATA%\scripts</span>. Reopen the Echo menu to refresh the script list.
            </div>
          </div>

          <div className="settings-group">
            <div className="label">AI assistant</div>
            <div className="settings-row">
              <span>Provider</span>
              <select className="select" value={ai.provider} onChange={(e) => {
                const provider = e.target.value as AiProvider;
                setAi({ provider, model: provider === "anthropic" ? kDefaultAi.model : "gpt-4o" });
              }}>
                <option value="anthropic">Anthropic</option>
                <option value="openai">OpenAI-compatible</option>
              </select>
            </div>
            <div className="settings-row">
              <span>Endpoint</span>
              <select className="select" value={ai.baseUrl} onChange={(e) => {
                const p = kProviders.find((x) => x.baseUrl === e.target.value);
                setAi(p ? { baseUrl: p.baseUrl, provider: p.provider, model: p.models[0] } : { baseUrl: e.target.value });
              }}>
                {kProviders.map((p) => <option key={p.id} value={p.baseUrl}>{p.label}</option>)}
                {ai.baseUrl && !kProviders.some((p) => p.baseUrl === ai.baseUrl) && <option value={ai.baseUrl}>{ai.baseUrl}</option>}
              </select>
            </div>
            {ai.provider === "openai" && (
              <div className="settings-row"><span>Base URL</span><input className="input mono" value={ai.baseUrl} onChange={(e) => setAi({ baseUrl: e.target.value })} /></div>
            )}
            <div className="settings-row">
              <span>Model</span>
              <input className="input mono" list="echodebug-models" value={ai.model} onChange={(e) => setAi({ model: e.target.value })} />
              <datalist id="echodebug-models">
                {kProviders.flatMap((p) => p.models).map((m) => <option key={m} value={m} />)}
              </datalist>
            </div>
            <div className="settings-row"><span>API key</span><input className="input mono" type="password" autoComplete="off" value={ai.apiKey} onChange={(e) => setAi({ apiKey: e.target.value })} /></div>
            <div className="faint" style={{ fontSize: 12 }}>The key is stored locally on this machine (app storage) and sent only to the provider above. Local servers (Ollama, LM Studio) need no key.</div>
          </div>

          <div className="settings-group">
            <div className="label">Updates</div>
            <div className="settings-row">
              <span>Auto-update</span>
              <label className="row"><input type="checkbox" checked={ui.autoUpdate} onChange={(e) => ui.set({ autoUpdate: e.target.checked })} /> download updates in the background (checks at startup and every 30 min)</label>
            </div>
            <div className="settings-row">
              <span>Version</span>
              <div className="row">
                <span className="mono">v{conn.appVersion}</span>
                {upd.phase === "ready" ? (
                  <button className="btn primary" onClick={() => void upd.restart()}>Restart to update to v{upd.version}</button>
                ) : upd.phase === "available" ? (
                  <button className="btn primary" onClick={() => void upd.download()}>Download v{upd.version}</button>
                ) : (
                  <button className="btn" disabled={upd.phase === "checking" || upd.phase === "downloading" || upd.phase === "installing"} onClick={() => void upd.check({ manual: true })}>Check for updates</button>
                )}
              </div>
            </div>
            <div className="settings-row"><span>Status</span><span className="faint">{updateSummary(upd)}</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}

function updateSummary(u: ReturnType<typeof useUpdate.getState>): string {
  const when = u.lastChecked ? `last checked ${new Date(u.lastChecked).toLocaleTimeString()}` : "not checked yet";
  switch (u.phase) {
    case "checking": return "checking…";
    case "available": return `v${u.version} available · ${when}`;
    case "downloading": return `downloading v${u.version}${u.progress !== null ? ` ${Math.round(u.progress * 100)}%` : "…"}`;
    case "ready": return `v${u.version} ready, it installs on restart (or automatically at next launch)`;
    case "installing": return "installing…";
    case "uptodate": return `up to date · ${when}`;
    case "error": return `error: ${u.error}`;
    default: return u.error ? `error: ${u.error}` : `up to date · ${when}`;
  }
}
