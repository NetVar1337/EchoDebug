// Xref Explorer: the whole reference graph of a module in one pass.
//
// Every other view asks "what points here?" one address at a time, which means
// rescanning the image per question. This builds the index once and then
// answers both directions instantly: who calls this, what does this call, and
// which addresses are the busiest hubs in the module.
import { useEffect, useMemo, useState } from "react";
import { ArrowDownToLine, ArrowUpFromLine, Crosshair, Search } from "lucide-react";
import { fmtAddr, labelAddr, parseAddress, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { buildXrefIndex, executableRanges, type Xref, type XrefIndex } from "@/lib/analysis/xrefindex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

type Direction = "to" | "from";

export default function XrefView() {
  const m = useFocusedModule();
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [idx, setIdx] = useState<XrefIndex | null>(null);
  const [progress, setProgress] = useState(1);
  const [addr, setAddr] = useState("");
  const [dir, setDir] = useState<Direction>("to");
  const [filter, setFilter] = useState("");
  const [hubs, setHubs] = useState<{ rva: number; count: number }[]>([]);

  useEffect(() => {
    if (!m) return;
    let live = true;
    setIdx(null);
    setProgress(0);
    void attempt("xrefs", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      const ranges = executableRanges(img);
      const index = buildXrefIndex(img, ranges);
      setIdx(index);
      // The addresses that are referenced the most are the interesting hubs.
      const ranked = [...index.to.entries()]
        .map(([rva, list]) => ({ rva, count: list.length }))
        .filter((x) => x.count > 1)
        .sort((a, b) => b.count - a.count)
        .slice(0, 50);
      setHubs(ranked);
      log("info", "xrefs", `${index.all.length} references indexed in ${m.name}`);
    });
    return () => { live = false; };
  }, [m?.name, m?.base]);

  const base = m ? toBig(m.base) : 0n;
  const target = useMemo(() => {
    if (!addr.trim()) return null;
    try {
      const a = parseAddress(addr.trim());
      if (a === null) return null;
      return a >= base ? Number(a - base) : null;
    } catch {
      return null;
    }
  }, [addr, base]);

  const refs = useMemo(() => {
    if (!idx || target === null) return [] as Xref[];
    const list = dir === "to" ? idx.to.get(target) : idx.from.get(target);
    return (list ?? []).slice().sort((a, b) => a.fromRva - b.fromRva);
  }, [idx, target, dir]);

  const shownHubs = useMemo(() => {
    const f = filter.toLowerCase();
    if (!f) return hubs;
    return hubs.filter((h) => labelAddr("0x" + (base + BigInt(h.rva)).toString(16), modules).toLowerCase().includes(f));
  }, [hubs, filter, base, modules]);

  const goto = (rva: number) => {
    ui.goDisasm("0x" + (base + BigInt(rva)).toString(16));
  };

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "420px" }}>
        <div className="list-col">
          <div className="toolbar">
            <ModulePicker />
            <label className="search grow"><Search size={13} /><input placeholder="Address or module+offset…" value={addr} onChange={(e) => setAddr(e.target.value)} /></label>
          </div>
          {progress < 1 && <Progress value={progress} />}
          <div className="toolbar">
            <button className="btn" data-active={dir === "to"} onClick={() => setDir("to")}><ArrowDownToLine size={13} /> References to</button>
            <button className="btn" data-active={dir === "from"} onClick={() => setDir("from")}><ArrowUpFromLine size={13} /> References from</button>
          </div>
          <div className="vlist">
            {target === null ? (
              <div className="empty">
                <div className="empty-title">Pick an address.</div>
                <div className="empty-hint">Type an address, or use the crosshair on the right to jump into a reference.</div>
              </div>
            ) : refs.length === 0 ? (
              <div className="empty">
                <div className="empty-title">No references.</div>
                <div className="empty-hint">Nothing in the executable sections of this module refers to that address.</div>
              </div>
            ) : (
              refs.map((x, i) => (
                <div key={`${x.fromRva}-${i}`} className="fn-row" onClick={() => goto(x.fromRva)}>
                  <span className="tag">{x.kind}</span>
                  <span className="mono grow ellipsis">{fmtAddr(base + BigInt(x.fromRva))}</span>
                  <span className="faint mono ellipsis" style={{ maxWidth: 150 }}>{labelAddr("0x" + (base + BigInt(x.toRva)).toString(16), modules)}</span>
                </div>
              ))
            )}
          </div>
        </div>
        <div className="list-col vlist" style={{ borderRight: "none" }}>
          <div className="toolbar">
            <span className="panel-title">Most referenced</span>
            <span className="grow" />
            <label className="search"><Search size={13} /><input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
          </div>
          {shownHubs.length === 0 ? (
            <div className="empty">
              <div className="empty-hint">The reference index of this module is empty or still loading.</div>
            </div>
          ) : (
            <table className="table mono">
              <thead><tr><th>Address</th><th>Symbol</th><th className="right">Refs</th><th /></tr></thead>
              <tbody>
                {shownHubs.map((h) => {
                  const a = "0x" + (base + BigInt(h.rva)).toString(16);
                  return (
                    <tr key={h.rva}>
                      <td className="link" onClick={() => goto(h.rva)}>{fmtAddr(base + BigInt(h.rva))}</td>
                      <td className="ellipsis" style={{ maxWidth: 220 }}>{labelAddr(a, modules)}</td>
                      <td className="right dim">{h.count}</td>
                      <td>
                        <button className="row-action" title="Use as the xref target" onClick={() => { setAddr(a); setDir("to"); }}><Crosshair size={12} /></button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
