import { useEffect, useMemo, useState } from "react";
import { Download, Search } from "lucide-react";
import { fmtAddr, labelAddr, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { xrefsTo, type LiveXref } from "@/lib/live";
import { extractStrings, type FoundString } from "@/lib/analysis/strings";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";
import VList from "../VList";

const kCats: Record<string, RegExp> = {
  all: /./,
  urls: /https?:\/\/|wss?:\/\//i,
  paths: /[a-z]:\\|\\\\|\/[a-z0-9_]+\/[a-z0-9_]/i,
  rtti: /^\.\?A[VU]|class |struct /,
  formats: /%[-+ #0]*\d*(?:\.\d+)?[sdifuxXpc]/,
};

export default function StringsView() {
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const m = useFocusedModule();
  const [strings, setStrings] = useState<FoundString[]>([]);
  const [progress, setProgress] = useState(1);
  const [filter, setFilter] = useState("");
  const [cat, setCat] = useState("all");
  const [minLen, setMinLen] = useState(5);
  const [refs, setRefs] = useState<{ s: string; list: LiveXref[] } | null>(null);

  useEffect(() => {
    if (!m) return;
    let live = true;
    setStrings([]);
    setProgress(0);
    void attempt("strings", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      const s = extractStrings(img, minLen);
      setStrings(s);
      log("info", "strings", `${s.length} strings in ${m.name}`);
    });
    return () => { live = false; };
  }, [m?.name, m?.base, minLen]);

  const shown = useMemo(() => {
    let re: RegExp | null = null;
    try { re = filter ? new RegExp(filter, "i") : null; } catch { re = null; }
    const f = filter.toLowerCase();
    return strings.filter((s) => kCats[cat].test(s.text) && (!filter || (re ? re.test(s.text) : s.text.toLowerCase().includes(f))));
  }, [strings, filter, cat]);

  const exportCsv = () => {
    if (!m) return;
    const rows = shown.map((s) => `${fmtAddr(toBig(m.base) + BigInt(s.rva))},${s.wide ? "utf16" : "ascii"},"${s.text.replace(/"/g, '""')}"`);
    const url = URL.createObjectURL(new Blob(["address,kind,text\n" + rows.join("\n")], { type: "text/csv" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: `${m.name}_strings.csv` });
    a.click();
    URL.revokeObjectURL(url);
  };

  const showRefs = async (s: FoundString) => {
    if (!m) return;
    const list = await attempt("xrefs", xrefsTo(fmtAddr(toBig(m.base) + BigInt(s.rva)), modules));
    if (list) setRefs({ s: s.text, list });
  };

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <ModulePicker />
          <label className="search grow"><Search size={13} /><input placeholder="Filter (regex ok)…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
          <select className="select" value={cat} onChange={(e) => setCat(e.target.value)}>{Object.keys(kCats).map((c) => <option key={c}>{c}</option>)}</select>
          <select className="select" value={minLen} onChange={(e) => setMinLen(Number(e.target.value))}>{[4, 5, 6, 8, 12].map((n) => <option key={n} value={n}>min {n}</option>)}</select>
          <span className="faint" style={{ fontSize: 12 }}>{shown.length.toLocaleString()} / {strings.length.toLocaleString()}</span>
          <IconButton tip="Export CSV" onClick={exportCsv}><Download size={14} /></IconButton>
        </div>
        {progress < 1 && <Progress value={progress} />}
        <VList count={shown.length} row={(i) => {
          const s = shown[i];
          const a = m ? fmtAddr(toBig(m.base) + BigInt(s.rva)) : "";
          return (
            <div className="fn-row" data-selected={ui.selected === a} onClick={() => ui.select(a)} onDoubleClick={() => ui.goMemory(a)}>
              <span style={{ width: 150, flexShrink: 0 }}>{m ? labelAddr(a, modules).replace(/^.*\+/, "+") : ""}</span>
              <span className="faint" style={{ width: 40, flexShrink: 0 }}>{s.wide ? "u16" : "a"}</span>
              <span className="grow ellipsis" style={{ color: "var(--text)" }} title={s.text}>{s.text}</span>
              <button className="row-action" onClick={(e) => { e.stopPropagation(); void showRefs(s); }}>xrefs</button>
            </div>
          );
        }} />
        {refs && (
          <div style={{ maxHeight: 180, overflow: "auto", borderTop: "1px solid var(--border-soft)" }}>
            <div className="toolbar"><span className="panel-title ellipsis">Xrefs to "{refs.s.slice(0, 60)}"</span><span className="grow" /><span className="faint">{refs.list.length}</span><button className="row-action" onClick={() => setRefs(null)}>close</button></div>
            <table className="table"><tbody>
              {refs.list.map((x) => <tr key={x.rva} onClick={() => ui.goDisasm(fmtAddr(x.address))}><td className="mono link">{labelAddr(x.address, modules)}</td><td className="faint">{x.kind}</td></tr>)}
            </tbody></table>
          </div>
        )}
      </div>
    </NeedsAgent>
  );
}
