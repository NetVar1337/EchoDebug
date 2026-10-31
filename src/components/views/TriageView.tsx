// Triage: the imports of a module that deserve a second look, with the
// callsites of each one so the finding can be inspected straight away.
import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { labelAddr } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { buildIat, type IatEntry } from "@/lib/analysis/iat";
import { classifyImports, type RiskHit } from "@/lib/analysis/risk";
import { xrefsTo, type LiveXref } from "@/lib/live";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

export default function TriageView() {
  const m = useFocusedModule();
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [hits, setHits] = useState<RiskHit[]>([]);
  const [progress, setProgress] = useState(1);
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<IatEntry | null>(null);
  const [refs, setRefs] = useState<LiveXref[] | null>(null);

  useEffect(() => {
    if (!m) return;
    let live = true;
    setHits([]);
    setProgress(0);
    void attempt("triage", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      const found = classifyImports(buildIat(img, BigInt(m.base)));
      setHits(found);
      const high = found.filter((h) => h.level === "high").length;
      log("info", "triage", `${found.length} notable imports in ${m.name} (${high} high risk)`);
    });
    return () => { live = false; };
  }, [m?.name, m?.base]);

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return hits.filter((h) => !f || h.entry.name.toLowerCase().includes(f) || h.why.includes(f) || h.entry.dll.toLowerCase().includes(f));
  }, [hits, filter]);

  const showRefs = async (e: IatEntry) => {
    setSel(e);
    setRefs(null);
    const list = await attempt("xrefs", xrefsTo(e.address, modules));
    if (list) setRefs(list);
  };

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "420px" }}>
        <div className="list-col">
          <div className="toolbar">
            <ModulePicker />
            <label className="search grow"><Search size={13} /><input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
          </div>
          {progress < 1 && <Progress value={progress} />}
          <div className="vlist">
            {shown.length === 0 && progress >= 1 && (
              <div className="empty">
                <div className="empty-title">Nothing notable.</div>
                <div className="empty-hint">This module does not import the APIs the triage table watches for (memory tampering, injection, anti-analysis).</div>
              </div>
            )}
            {shown.map((h) => (
              <div key={h.entry.address} className="fn-row" data-selected={sel?.address === h.entry.address} onClick={() => void showRefs(h.entry)}>
                <span className="risk-dot" data-level={h.level} />
                <span className="grow ellipsis">{h.entry.name}</span>
                <span className="faint ellipsis" style={{ maxWidth: 110 }}>{h.entry.dll}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="list-col vlist" style={{ borderRight: "none" }}>
          {!sel ? (
            <div className="empty">
              <div className="empty-title">Pick an import.</div>
              <div className="empty-hint">The right pane lists every place in the module that references the import slot.</div>
            </div>
          ) : (
            <>
              <div className="panel-section">
                <div className="label">{sel.dll}!{sel.name}</div>
                <div className="kv">
                  <span>slot</span><span className="link" onClick={() => ui.goMemory(sel.address)}>{sel.address}</span>
                  <span>risk</span><span className={hits.find((h) => h.entry.address === sel.address)?.level === "high" ? "danger" : "warn"}>
                    {hits.find((h) => h.entry.address === sel.address)?.level}
                  </span>
                  <span>why</span><span>{hits.find((h) => h.entry.address === sel.address)?.why}</span>
                </div>
              </div>
              <table className="table mono">
                <thead><tr><th>Callsite</th><th>Kind</th></tr></thead>
                <tbody>
                  {(refs ?? []).map((x) => (
                    <tr key={x.rva} onClick={() => ui.goDisasm("0x" + x.address.toString(16))}>
                      <td className="link">{labelAddr("0x" + x.address.toString(16), modules)}</td>
                      <td className="faint">{x.kind}</td>
                    </tr>
                  ))}
                  {refs && refs.length === 0 && <tr><td className="faint">No references found.</td></tr>}
                  {!refs && <tr><td className="faint">Searching…</td></tr>}
                </tbody>
              </table>
            </>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
