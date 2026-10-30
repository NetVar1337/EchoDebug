import { X } from "lucide-react";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { kDefaultAi, useUi, type AiProvider, type Theme } from "@/store/ui";
import { useUpdate } from "@/store/update";
import { installAgent, isTauri, openScriptsFolder } from "@/lib/tauri";
import { IconButton } from "./ui";

const kAccents = ["", "#2eb8a6", "#88c0d0", "#f26b38", "#a78bfa", "#f472b6", "#facc15"];

export default function SettingsModal() {
  const ui = useUi();
  const conn = useConn();
  const check = useUpdate((s) => s.check);
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
            {ai.provider === "openai" && (
              <div className="settings-row"><span>Base URL</span><input className="input mono" value={ai.baseUrl} onChange={(e) => setAi({ baseUrl: e.target.value })} /></div>
            )}
            <div className="settings-row"><span>Model</span><input className="input mono" value={ai.model} onChange={(e) => setAi({ model: e.target.value })} /></div>
            <div className="settings-row"><span>API key</span><input className="input mono" type="password" autoComplete="off" value={ai.apiKey} onChange={(e) => setAi({ apiKey: e.target.value })} /></div>
            <div className="faint" style={{ fontSize: 12 }}>The key is stored locally on this machine (app storage) and sent only to the provider above.</div>
          </div>

          <div className="settings-group">
            <div className="label">Updates</div>
            <div className="settings-row">
              <span>Auto-update</span>
              <label className="row"><input type="checkbox" checked={ui.autoUpdate} onChange={(e) => ui.set({ autoUpdate: e.target.checked })} /> install updates on startup</label>
            </div>
            <div className="settings-row"><span>Version</span><div className="row"><span className="mono">v{conn.appVersion}</span><button className="btn" onClick={() => void check(true)}>Check now</button></div></div>
          </div>
        </div>
      </div>
    </div>
  );
}
