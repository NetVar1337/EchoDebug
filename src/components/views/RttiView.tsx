// RTTI class inventory: every class the module declares, with its base class
// and the vftables that belong to it.
import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { labelAddr } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { buildRtti, findVftables, type RttiClass, type RttiInventory } from "@/lib/analysis/rtti";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

export default function RttiView() {
  const m = useFocusedModule();
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [inv, setInv] = useState<RttiInventory | null>(null);
  const [progress, setProgress] = useState(1);
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<RttiClass | null>(null);
  const [vfts, setVfts] = useState<RttiClass["vftables"]>([]);

  useEffect(() => {
    if (!m) return;
    let live = true;
    setInv(null);
    setProgress(0);
    void attempt("rtti", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      const found = buildRtti(img, BigInt(m.base));
      setInv(found);
      log("info", "rtti", `${found.classes.length} RTTI classes in ${m.name}`);
    });
    return () => { live = false; };
  }, [m?.name, m?.base]);

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    if (!inv) return [];
    return inv.classes.filter((c) => !f || c.name.toLowerCase().includes(f) || c.base.toLowerCase().includes(f));
  }, [inv, filter]);

  const select = async (c: RttiClass) => {
    setSel(c);
    setVfts([]);
    if (!m) return;
    const img = await attempt("rtti", loadImage(m));
    if (!img) return;
    setVfts(findVftables(img, BigInt(m.base), c));
  };

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "380px" }}>
        <div className="list-col">
          <div className="toolbar">
            <ModulePicker />
            <label className="search grow"><Search size={13} /><input placeholder="Filter classes…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
          </div>
          {progress < 1 && <Progress value={progress} />}
          <div className="vlist">
            {shown.length === 0 && progress >= 1 && (
              <div className="empty">
                <div className="empty-title">No RTTI classes.</div>
                <div className="empty-hint">This module has no MSVC type descriptors, so it was probably built without RTTI or it is not a C++ binary.</div>
              </div>
            )}
            {shown.map((c) => (
              <div key={c.rva} className="fn-row" data-selected={sel?.rva === c.rva} onClick={() => void select(c)}>
                <span className="grow ellipsis">{c.name}</span>
                {c.base && <span className="faint ellipsis" style={{ maxWidth: 120 }}>: {c.base}</span>}
              </div>
            ))}
          </div>
        </div>
        <div className="list-col vlist" style={{ borderRight: "none" }}>
          {!sel ? (
            <div className="empty">
              <div className="empty-title">Pick a class.</div>
              <div className="empty-hint">Every class the module declares is listed here, with the vftables that belong to it.</div>
            </div>
          ) : (
            <>
              <div className="panel-section">
                <div className="label">{sel.name}</div>
                <div className="kv">
                  <span>mangled</span><span className="mono selectable">{sel.mangled}</span>
                  <span>descriptor</span><span className="mono link" onClick={() => ui.goMemory(sel.address)}>{sel.address}</span>
                  <span>base</span><span>{sel.base || "—"}</span>
                </div>
              </div>
              <div className="panel-section">
                <div className="label">Vftables</div>
                {vfts.length === 0 ? (
                  <div className="faint">No vftable found for this class (it may have none, or it is not a polymorphic type).</div>
                ) : (
                  <table className="table mono">
                    <thead><tr><th>Address</th><th>Slots</th></tr></thead>
                    <tbody>
                      {vfts.map((v) => (
                        <tr key={v.rva} onClick={() => ui.goMemory(v.address)}>
                          <td className="link">{labelAddr(v.address, modules)}</td>
                          <td className="dim">{v.slots}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
