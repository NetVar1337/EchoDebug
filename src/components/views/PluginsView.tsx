// Plugins view: the views plugins registered (each renders into its own container) and the
// table analyses they offer.
import { useEffect, useMemo, useRef, useState } from "react";
import { Play, Puzzle } from "lucide-react";
import { checkResult, usePluginRegistry, type AnalysisResult, type Registered } from "@/lib/plugins/registry";
import { usePlugins } from "@/store/plugins";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { saveText } from "@/lib/save";
import { Empty } from "../ui";

function PluginViewHost({ view }: { view: Registered<"view"> }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    let cleanup: (() => void) | void;
    let live = true;
    Promise.resolve()
      .then(() => view.render(el))
      .then((c) => {
        if (live) cleanup = c;
        else if (typeof c === "function") c();
      })
      .catch((e) => {
        log("error", `plugin:${view.plugin}`, `${view.title}: ${e instanceof Error ? e.message : e}`);
        el.textContent = `This plugin view failed: ${e instanceof Error ? e.message : e}`;
      });
    return () => {
      live = false;
      try {
        if (typeof cleanup === "function") cleanup();
      } catch { /* the plugin's own cleanup */ }
      el.replaceChildren();
    };
  }, [view.key]);
  return <div ref={ref} className="plugin-view" data-plugin={view.plugin} />;
}

const isAddr = (c: unknown) => typeof c === "string" && /^0x[0-9a-f]{4,16}$/i.test(c);

function AnalysisRunner({ a }: { a: Registered<"analysis"> }) {
  const ui = useUi();
  const [args, setArgs] = useState<Record<string, string>>(() => Object.fromEntries((a.params ?? []).map((p) => [p.name, p.default ?? ""])));
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState("");
  const run = async () => {
    setBusy(true);
    setError("");
    try {
      setResult(checkResult(await a.run({ ...args })));
    } catch (e) {
      setResult(null);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const csv = () => {
    if (!result) return;
    const q = (c: unknown) => `"${String(c ?? "").replace(/"/g, '""')}"`;
    void saveText(`${a.key.replace(/\W+/g, "_")}.csv`, [result.columns.map(q).join(","), ...result.rows.map((r) => r.map(q).join(","))].join("\n"));
  };
  return (
    <div className="plugin-analysis">
      <div className="toolbar">
        <span className="panel-title">{a.title}</span>
        <span className="faint ellipsis grow">{a.description ?? ""}</span>
        {(a.params ?? []).map((p) => (
          <input key={p.name} className="input mono" style={{ width: 160 }} placeholder={p.label ?? p.name} title={p.label ?? p.name} value={args[p.name] ?? ""} onChange={(e) => setArgs({ ...args, [p.name]: e.target.value })} onKeyDown={(e) => e.key === "Enter" && void run()} />
        ))}
        <button className="btn small primary" disabled={busy} onClick={() => void run()}><Play size={12} /> {busy ? "Running…" : "Run"}</button>
        {result && <button className="btn small" onClick={csv}>CSV</button>}
      </div>
      {error && <div className="panel-section danger" style={{ fontSize: 12 }}>{error}</div>}
      {result && (
        <div style={{ maxHeight: 360, overflow: "auto" }}>
          <div className="faint" style={{ fontSize: 11, padding: "2px 8px" }}>{result.rows.length} rows</div>
          <table className="table mono">
            <thead><tr>{result.columns.map((c, i) => <th key={i}>{c}</th>)}</tr></thead>
            <tbody>
              {result.rows.slice(0, 5000).map((r, i) => (
                <tr key={i}>{r.map((c, j) => <td key={j} className={isAddr(c) ? "link" : undefined} onClick={isAddr(c) ? () => ui.goDisasm(String(c)) : undefined} title={String(c ?? "")}>{String(c ?? "")}</td>)}</tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function PluginsView() {
  const reg = usePluginRegistry();
  const plugins = usePlugins();
  const ui = useUi();
  const tabs = useMemo(() => [...reg.views.map((v) => ({ id: v.key, label: v.title, by: v.pluginName })), ...(reg.analyses.length ? [{ id: "analyses", label: "Analyses", by: "" }] : [])], [reg.views, reg.analyses]);
  const [sel, setSel] = useState<string>("");
  const active = tabs.find((t) => t.id === sel) ?? tabs[0];
  if (!tabs.length) {
    const n = plugins.found.filter((f) => f.manifest).length;
    return (
      <Empty icon={<Puzzle size={26} strokeWidth={1.5} />} title="No plugin views or analyses."
        hint={<>Plugins are JavaScript modules in the <span className="mono">plugins</span> folder of the EchoDebug config directory. {n ? `${n} installed; enable them` : "Install one (see examples/plugins) and enable it"} in <span className="link" onClick={() => ui.set({ settingsOpen: true })}>Settings → Plugins</span>.</>} />
    );
  }
  const view = reg.views.find((v) => v.key === active.id);
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div className="toolbar">
        {tabs.map((t) => (
          <button key={t.id} className={`btn small${t.id === active.id ? " primary" : ""}`} title={t.by ? `from ${t.by}` : undefined} onClick={() => setSel(t.id)}>{t.label}</button>
        ))}
      </div>
      <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        {view ? <PluginViewHost key={view.key} view={view} /> : reg.analyses.map((a) => <AnalysisRunner key={a.key} a={a} />)}
      </div>
    </div>
  );
}
