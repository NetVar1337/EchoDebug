import { useProjects } from "@/lib/projects";
import type { ReactNode } from "react";
import { Check, X } from "lucide-react";
import { mcpAddCommand, useConn } from "@/store/conn";
import { kMotionPrefs, useMotion } from "@/store/motion";
import { attempt, log } from "@/store/output";
import { useUi, type Theme } from "@/store/ui";
import { useUpdate } from "@/store/update";
import { kDefaultServer, useSymbols } from "@/store/symbols";
import { installAgent, isTauri, openScriptsFolder } from "@/lib/tauri";
import { isWindowsOs } from "@/lib/tauri";
import { CopyChip, IconButton, useCopy } from "./ui";
import PluginsSettings from "./PluginsSettings";

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
  const sym = useSymbols();
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

          <Section title="Symbols">
            <Row label="Symbol path" hint={<>Folders and stores searched for PDBs, <span className="mono">_NT_SYMBOL_PATH</span> syntax: <span className="mono">C:\pdbs;srv*C:\symbols*https://…;cache*D:\sym</span>. The image's folder and the app cache are always searched.</>}>
              <input className="input mono" style={{ width: 260 }} placeholder="C:\pdbs;srv*C:\symbols*https://…" value={sym.symbolPath} onChange={(e) => sym.setSettings({ symbolPath: e.target.value })} />
            </Row>
            <Row label="Symbol servers" hint="One URL per line, asked in order when a PDB is downloaded.">
              <textarea className="textarea" rows={2} style={{ width: 260 }} value={sym.servers.join("\n")} onChange={(e) => sym.setSettings({ servers: e.target.value.split("\n").map((x) => x.trim()) })} onBlur={() => sym.setSettings({ servers: sym.servers.filter(Boolean).length ? sym.servers.filter(Boolean) : [kDefaultServer] })} />
            </Row>
            <Row label="Use _NT_SYMBOL_PATH" hint="Also read the environment variables of the relay process.">
              <label className="switch">
                <input type="checkbox" role="switch" checked={sym.useEnv} onChange={(e) => sym.setSettings({ useEnv: e.target.checked })} />
                <span />
              </label>
            </Row>
            <Row label="Auto-download" hint="Network access: download missing PDBs from the servers whenever symbols are loaded, without a click. Off: only the Download button (or an MCP client's ui_load_symbols) goes online.">
              <label className="switch">
                <input type="checkbox" role="switch" checked={sym.autoDownload} onChange={(e) => sym.setSettings({ autoDownload: e.target.checked })} />
                <span />
              </label>
            </Row>
            <Row label="Load on attach" hint="Load the PDBs already on this machine (symbol path, cache) for every module after attaching; with auto-download, fetch the rest too.">
              <label className="switch">
                <input type="checkbox" role="switch" checked={sym.autoLoad} onChange={(e) => sym.setSettings({ autoLoad: e.target.checked })} />
                <span />
              </label>
            </Row>
          </Section>

          <Section title="Plugins">
            <PluginsSettings />
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
