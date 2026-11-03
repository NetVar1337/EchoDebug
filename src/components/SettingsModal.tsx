import { useProjects } from "@/lib/projects";
import { useEffect, useState, type ReactNode } from "react";
import { Check, X } from "lucide-react";
import { mcpAddCommand, useConn } from "@/store/conn";
import { kMotionPrefs, useMotion } from "@/store/motion";
import { attempt, log } from "@/store/output";
import { useUi, type Theme } from "@/store/ui";
import { useUpdate } from "@/store/update";
import { installAgent, isTauri, openScriptsFolder } from "@/lib/tauri";
import { isWindowsOs } from "@/lib/tauri";
import { CopyChip, IconButton, useCopy } from "./ui";
import * as assistantApi from "@/lib/assistant/api";
import { useAssistant } from "@/store/assistant";

const kAccents = ["", "#2eb8a6", "#88c0d0", "#f26b38", "#a78bfa", "#f472b6", "#facc15"];
const kThemes: { id: Theme; label: string }[] = [
  { id: "obsidian", label: "Obsidian" },
  { id: "nord", label: "Nord" },
  { id: "blood-orange", label: "Blood Orange" },
];

export default function SettingsModal() {
  const projects = useProjects();
  const ui = useUi();
  const conn = useConn();
  const upd = useUpdate();
  const motion = useMotion((s) => s.pref);
  const setMotion = useMotion((s) => s.setPref);
  const [copied, copy] = useCopy();
  const close = () => ui.set({ settingsOpen: false });
  const reinstall = async () => {
    const r = await attempt("agent", installAgent());
    if (r) log("info", "agent", `installed ${r.path}${r.changed ? " (updated)" : " (unchanged)"}`);
    else if (!isTauri()) log("warn", "agent", "agent install is only available in the desktop app");
  };
  const windowsOnly = isWindowsOs(conn.os);
  const endpoint = `http://127.0.0.1:${conn.port}/mcp`;
  const busy = upd.phase === "checking" || upd.phase === "downloading" || upd.phase === "installing";
  return (
    <div className="modal-scrim" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div className="modal" role="dialog" aria-label="Settings">
        <div className="panel-head">
          <div className="panel-title">Settings</div>
          <div className="grow" />
          <IconButton tip="Close" onClick={close}><X size={14} /></IconButton>
        </div>
        <div className="modal-body">
          <Section title="Appearance">
            <Row label="Theme">
              <Segmented value={ui.theme} options={kThemes} onChange={(theme) => ui.set({ theme })} />
            </Row>
            <Row label="Accent">
              <div className="row">
                {kAccents.map((c) => (
                  <button key={c || "default"} className="swatch" data-active={ui.accent === c} title={c || "theme default"} aria-label={c || "theme default"}
                    style={c ? { background: c } : { background: "var(--bg-2)", color: "var(--text)" }} onClick={() => ui.set({ accent: c })}>
                    {ui.accent === c && <Check size={11} strokeWidth={3} />}
                  </button>
                ))}
              </div>
            </Row>
            <Row label="Motion" hint={kMotionPrefs.find((m) => m.id === motion)?.hint}>
              <Segmented value={motion} options={kMotionPrefs} onChange={setMotion} />
            </Row>
          </Section>

          <Section title="Connection">
            <Row label="Relay">
              <span className="status-pill mono"><span className="dot" data-state={conn.relay ? "ok" : "bad"} />ws://127.0.0.1:{conn.port}<span className="faint">{conn.relay ? "up" : "down"}</span></span>
            </Row>
            <Row label="MCP endpoint" hint="Tool catalog and live call log live in the MCP Server panel.">
              <CopyChip text={endpoint} copied={copied} onCopy={copy} />
            </Row>
            <Row label="Add to Claude Code" hint="Includes this install's bearer token; /mcp rejects requests without it.">
              <CopyChip text={mcpAddCommand(conn.port, conn.token)} copied={copied} onCopy={copy} />
            </Row>
            {isTauri() && conn.token && (
              <Row label="MCP token" hint="Regenerating locks out MCP clients until they are re-added with the new command.">
                <button className="btn" onClick={() => void attempt("token", conn.regenerateToken())}>Regenerate token</button>
              </Row>
            )}
            {windowsOnly ? (
              <Row label="Agent script" hint={<>Load <span className="mono">echo_debug.as</span> in Echo, installed to <span className="mono">%APPDATA%\scripts</span>.</>}>
                <div className="row">
                  <button className="btn" onClick={() => void reinstall()}>Reinstall</button>
                  <button className="btn" onClick={() => void attempt("agent", openScriptsFolder())} disabled={!isTauri()}>Open folder</button>
                </div>
              </Row>
            ) : (
              <div className="settings-note">
                The Echo agent is Windows-only. On <span className="mono">{conn.os}</span> the relay serves a local <span className="mono">/proc</span> backend — attach from the Targets panel.
              </div>
            )}
          </Section>

          <AssistantSection />

          <Section title="Workspace">
            <Row label="Reattach on start" hint={ui.lastTarget ? `Attach to ${ui.lastTarget} again when the app starts, if it is running.` : "Attach to the last target again when the app starts."}>
              <label className="switch">
                <input type="checkbox" role="switch" checked={ui.reattach} onChange={(e) => ui.set({ reattach: e.target.checked })} />
                <span />
              </label>
            </Row>
            <Row label="Module projects" hint="Save names, comments and bookmarks per module build (by RVA) and restore them on the next attach.">
              <label className="switch">
                <input type="checkbox" role="switch" checked={projects.enabled} onChange={(e) => projects.setEnabled(e.target.checked)} />
                <span />
              </label>
            </Row>
            <Row label="Panel sizes" hint="Splitter positions are remembered between runs.">
              <button className="btn" onClick={() => { ui.set({ layout: {} }); for (const v of ["--left-w", "--scan-w", "--bottom-h", "--right-w"]) document.querySelector<HTMLElement>(".app")?.style.removeProperty(v); }}>Reset layout</button>
            </Row>
          </Section>

          <Section title="Updates">
            <Row label="Auto-update" hint="Checks at startup and every 30 min.">
              <label className="switch">
                <input type="checkbox" role="switch" checked={ui.autoUpdate} onChange={(e) => ui.set({ autoUpdate: e.target.checked })} />
                <span />
              </label>
            </Row>
            <Row label={<>Version <span className="pill mono">v{conn.appVersion}</span></>} hint={updateSummary(upd)}>
              {upd.phase === "ready" ? (
                <button className="btn primary" onClick={() => void upd.restart()}>Restart to update</button>
              ) : upd.phase === "available" ? (
                <button className="btn primary" onClick={() => void upd.download()}>Download v{upd.version}</button>
              ) : (
                <button className="btn" disabled={busy} onClick={() => void upd.check({ manual: true })}>Check for updates</button>
              )}
            </Row>
          </Section>
        </div>
      </div>
    </div>
  );
}

/** The assistant's Anthropic API key: set, replace or remove it. The key is never shown again. */
function AssistantSection() {
  const [info, setInfo] = useState<assistantApi.KeyInfo | null>(null);
  const [key, setKey] = useState("");
  const refresh = useAssistant((s) => s.refreshKey);
  useEffect(() => { void assistantApi.keyStatus().then(setInfo).catch(() => setInfo(null)); }, []);
  const save = async () => {
    const r = await attempt("assistant", assistantApi.setKey(key));
    setKey("");
    if (r) { setInfo(r); log("info", "assistant", "API key saved"); void refresh(); }
  };
  const remove = async () => {
    const r = await attempt("assistant", assistantApi.clearKey());
    if (r) { setInfo(r); log("info", "assistant", "API key removed"); void refresh(); }
  };
  if (!isTauri()) {
    return <Section title="Assistant"><div className="settings-note">The assistant and its API key live in the desktop app.</div></Section>;
  }
  return (
    <Section title="Assistant">
      <Row label="Anthropic API key" hint={info?.present ? <>A key is stored. {info.note}</> : <>Needed for the Assistant panel. Create one at console.anthropic.com. It is only ever sent to api.anthropic.com and is never shown again or logged.</>}>
        <div className="row">
          <input className="input mono" type="password" autoComplete="off" spellCheck={false} placeholder={info?.present ? "replace with a new key" : "sk-ant-..."} value={key} onChange={(e) => setKey(e.target.value)} onKeyDown={(e) => e.key === "Enter" && key.trim() && void save()} style={{ width: 200 }} />
          <button className="btn" disabled={!key.trim()} onClick={() => void save()}>Save</button>
          {info?.present && <button className="btn" onClick={() => void remove()}>Remove</button>}
        </div>
      </Row>
      {info && <div className="settings-note">Stored at <span className="mono">{info.path}</span>. {info.storage === "file" ? "No OS keychain is used here: the file is readable only by your user account." : ""} What you send from the Assistant panel (code, memory, names, tool results) goes to Anthropic.</div>}
    </Section>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="settings-group">
      <div className="label">{title}</div>
      <div className="settings-card">{children}</div>
    </section>
  );
}

function Row({ label, hint, children }: { label: ReactNode; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="settings-row">
      <div className="settings-label">
        <span>{label}</span>
        {hint && <span className="settings-hint">{hint}</span>}
      </div>
      <div className="settings-control">{children}</div>
    </div>
  );
}

function Segmented<T extends string>({ value, options, onChange }: { value: T; options: readonly { id: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div className="segmented" role="radiogroup">
      {options.map((o) => (
        <button key={o.id} role="radio" aria-checked={value === o.id} data-active={value === o.id} onClick={() => onChange(o.id)}>{o.label}</button>
      ))}
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
