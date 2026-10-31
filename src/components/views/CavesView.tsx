// Code caves: padding regions inside executable sections that can hold
// injected code. Click a cave to inspect it, then copy a stub into it.
import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { labelAddr, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { findCodeCaves, type CodeCave } from "@/lib/analysis/code-caves";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

const kMinSizes = [8, 16, 32, 64, 128];

export default function CavesView() {
  const m = useFocusedModule();
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [caves, setCaves] = useState<CodeCave[]>([]);
  const [progress, setProgress] = useState(1);
  const [minSize, setMinSize] = useState(16);
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<CodeCave | null>(null);

  useEffect(() => {
    if (!m) return;
    let live = true;
    setCaves([]);
    setProgress(0);
    void attempt("caves", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      const found = findCodeCaves(img, toBig(m.base), { minSize });
      setCaves(found);
      log("info", "caves", `${found.length} caves (>= ${minSize} bytes) in ${m.name}`);
    });
    return () => { live = false; };
  }, [m?.name, m?.base, minSize]);

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return caves.filter((c) => !f || c.section.toLowerCase().includes(f) || c.address.includes(f));
  }, [caves, filter]);

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "380px" }}>
        <div className="list-col">
          <div className="toolbar">
            <ModulePicker />
            <label className="search grow"><Search size={13} /><input placeholder="Filter section…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
            <select className="select" value={minSize} onChange={(e) => setMinSize(Number(e.target.value))}>
              {kMinSizes.map((s) => <option key={s} value={s}>≥ {s}</option>)}
            </select>
          </div>
          {progress < 1 && <Progress value={progress} />}
          <div className="vlist">
            {shown.length === 0 && progress >= 1 && (
              <div className="empty">
                <div className="empty-title">No code caves.</div>
                <div className="empty-hint">Lower the minimum size or pick another module. Caves are runs of 0xCC, 0x90 or 0x00 inside executable sections.</div>
              </div>
            )}
            {shown.map((c) => (
              <div key={c.rva} className="fn-row" data-selected={sel?.rva === c.rva} onClick={() => setSel(c)} onDoubleClick={() => ui.goMemory(c.address)}>
                <span className="grow ellipsis mono">{labelAddr(c.address, modules)}</span>
                <span className="faint">{c.size}</span>
                <span className="faint">{c.fill.toString(16).padStart(2, "0")}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="list-col" style={{ borderRight: "none" }}>
          {!sel ? (
            <div className="empty">
              <div className="empty-title">Pick a cave.</div>
              <div className="empty-hint">A cave is padding inside an executable section: room for a hook or a stub without moving any code.</div>
            </div>
          ) : (
            <div className="vlist">
              <div className="panel-section">
                <div className="label">Cave</div>
                <div className="kv">
                  <span>address</span><span className="link" onClick={() => ui.goMemory(sel.address)}>{sel.address}</span>
                  <span>rva</span><span>0x{sel.rva.toString(16)}</span>
                  <span>size</span><span>{sel.size} bytes</span>
                  <span>filler</span><span>0x{sel.fill.toString(16).padStart(2, "0")}</span>
                  <span>section</span><span>{sel.section}</span>
                </div>
                <div className="row">
                  <button className="btn small" onClick={() => ui.goMemory(sel.address)}>View in memory</button>
                  <button className="btn small" onClick={() => ui.goDisasm(sel.address)}>Disassemble</button>
                  <span className="grow" />
                  <span className="faint" style={{ fontSize: 12 }}>up to {sel.size} bytes of payload</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
