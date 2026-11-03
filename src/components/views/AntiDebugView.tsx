// Anti-debug / anti-tamper: the places in a module that try to find out
// whether it is being analysed, and the APIs it asks the operating system
// with. Every hit is a place worth looking at, not proof of a check.
import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { labelAddr } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { scanAntiDebug, scanAntiImports, scanAntiStrings, type AntiHit } from "@/lib/analysis/antidebug";
import { buildIat } from "@/lib/analysis/iat";
import { extractStrings } from "@/lib/analysis/strings";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

export default function AntiDebugView() {
  const m = useFocusedModule();
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [hits, setHits] = useState<AntiHit[]>([]);
  const [progress, setProgress] = useState(1);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    if (!m) return;
    let live = true;
    setHits([]);
    setProgress(0);
    void attempt("antidebug", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      const base = BigInt(m.base);
      const code = scanAntiDebug(img, base);
      const iat = buildIat(img, base);
      const apis = scanAntiImports(iat.entries, base);
      const strings = extractStrings(img, 4).map((s) => ({ rva: s.rva, text: s.text }));
      const windows = scanAntiStrings(strings, base);
      const all = [...code, ...apis, ...windows].sort((a, b) => b.confidence - a.confidence || a.rva - b.rva);
      setHits(all);
      log("info", "antidebug", `${all.length} anti-analysis indicators in ${m.name}`);
    });
    return () => { live = false; };
  }, [m?.name, m?.base]);

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    if (!f) return hits;
    return hits.filter((h) => h.kind.includes(f) || h.detail.toLowerCase().includes(f));
  }, [hits, filter]);

  const grouped = useMemo(() => {
    const map = new Map<string, AntiHit[]>();
    for (const h of shown) {
      const list = map.get(h.kind);
      if (list) list.push(h);
      else map.set(h.kind, [h]);
    }
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [shown]);

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <ModulePicker />
          <label className="search grow"><Search size={13} /><input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
          <span className="faint mono">{hits.length} hits</span>
        </div>
        {progress < 1 && <Progress value={progress} />}
        <div className="vlist">
          {shown.length === 0 && progress >= 1 && (
            <div className="empty">
              <div className="empty-title">Nothing found.</div>
              <div className="empty-hint">No debugger-detection instruction, API or window name in the executable sections of this module.</div>
            </div>
          )}
          {grouped.map(([kind, list]) => (
            <div key={kind}>
              <div className="toolbar" style={{ borderTop: "1px solid var(--border)" }}>
                <span className="panel-title">{kind}</span>
                <span className="grow" />
                <span className="faint mono">{list.length}</span>
              </div>
              {list.map((h, i) => (
                <div key={`${h.kind}-${h.rva}-${i}`} className="fn-row" onClick={() => { if (h.rva >= 0) ui.goDisasm(h.address); }}>
                  <span className="mono ellipsis" style={{ maxWidth: 150 }}>{h.bytes || "—"}</span>
                  <span className="grow ellipsis">{h.detail}</span>
                  {h.rva >= 0 && <span className="faint mono ellipsis" style={{ maxWidth: 160 }}>{labelAddr(h.address, modules)}</span>}
                  <span className="faint mono">{Math.round(h.confidence * 100)}%</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    </NeedsAgent>
  );
}
