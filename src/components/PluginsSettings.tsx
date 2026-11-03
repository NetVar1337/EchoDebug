// Settings → Plugins: installed plugins, enable / disable (with the permissions shown first),
// reload, open the folder.
import { useEffect, useState } from "react";
import { FolderOpen, RefreshCw, ShieldAlert } from "lucide-react";
import { describePermissions } from "@/lib/plugins/manifest";
import { pluginsDir } from "@/lib/plugins/loader";
import { isTauri } from "@/lib/tauri";
import { attempt } from "@/store/output";
import { usePlugins } from "@/store/plugins";

export default function PluginsSettings() {
  const p = usePlugins();
  const [asking, setAsking] = useState<string | null>(null);
  useEffect(() => {
    if (isTauri() && !p.scanned) void attempt("plugins", p.scan());
  }, []);
  const openFolder = async () => {
    const dir = await pluginsDir();
    if (!dir) return;
    const { openPath } = await import("@tauri-apps/plugin-opener");
    await openPath(dir);
  };
  if (!isTauri()) {
    return <div className="settings-note">Plugins load from the app's config folder, so they are available in the desktop app only.</div>;
  }
  return (
    <>
      <div className="settings-row">
        <div className="settings-label">
          <span>Plugin folder</span>
          <span className="settings-hint">One folder per plugin with a <span className="mono">manifest.json</span> and an ES module. Plugins run as JavaScript inside EchoDebug: enable only plugins you trust. They are never exposed over MCP.</span>
        </div>
        <div className="settings-control row">
          <button className="btn" onClick={() => void attempt("plugins", openFolder())}><FolderOpen size={12} /> Open</button>
          <button className="btn" onClick={() => void attempt("plugins", p.reload())}><RefreshCw size={12} /> Reload</button>
        </div>
      </div>
      {p.found.length === 0 && <div className="settings-note">No plugins installed. Copy <span className="mono">examples/plugins/module-overview</span> into the plugin folder and press Reload.</div>}
      {p.found.map((d) => {
        const m = d.manifest;
        const id = m?.id ?? d.dir;
        const on = !!m && p.enabled.includes(m.id);
        const st = m ? p.status[m.id] : undefined;
        return (
          <div key={d.dir} className="settings-row" style={{ flexWrap: "wrap" }}>
            <div className="settings-label">
              <span>{m ? <>{m.name} <span className="pill mono">v{m.version}</span></> : <span className="mono">{d.dir}</span>}</span>
              <span className="settings-hint">
                {m?.description && <>{m.description} · </>}
                <span className="mono">{id}</span>
                {m && <> · {m.permissions.length ? m.permissions.join(", ") : "read-only"}</>}
                {d.errors.length > 0 && <span className="danger"> · {d.errors.join("; ")}</span>}
                {st?.state === "error" && <span className="danger"> · {st.message}</span>}
                {d.warnings.length > 0 && <span className="warn"> · {d.warnings.join("; ")}</span>}
              </span>
            </div>
            <div className="settings-control">
              <label className="switch" title={on ? "Disable" : "Enable"}>
                <input type="checkbox" role="switch" disabled={!m || d.errors.length > 0} checked={on}
                  onChange={(e) => (e.target.checked ? setAsking(id) : void attempt("plugins", p.disable(id)))} />
                <span />
              </label>
            </div>
            {asking === id && m && (
              <div className="plugin-consent">
                <div className="row"><ShieldAlert size={14} className="warn" /> <b>Enable {m.name}?</b> It will be able to:</div>
                <ul>{describePermissions(m.permissions).map((t) => <li key={t}>{t}</li>)}</ul>
                <div className="row">
                  <button className="btn primary" onClick={() => { setAsking(null); void attempt("plugins", p.enable(id)); }}>Enable</button>
                  <button className="btn" onClick={() => setAsking(null)}>Cancel</button>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </>
  );
}
