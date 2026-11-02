import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { fmtAddr, labelAddr, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { parsePe, type PeInfo } from "@/lib/analysis/pe";
import { detectPacker, sectionEntropies, type PackerVerdict, type SectionEntropy } from "@/lib/analysis/entropy";
import { buildIat, type IatMap, type IatEntry } from "@/lib/analysis/iat";
import { xrefsTo, type LiveXref } from "@/lib/live";
import { useConn } from "@/store/conn";
import { attempt } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress, Tabs } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";
import ElfView from "./ElfView";
import { isElf } from "@/lib/analysis/elf";

type Sub = "headers" | "sections" | "exports" | "imports" | "analysis" | "iat";
const kLimit = 3000;
const hx = (n: number | bigint) => "0x" + n.toString(16).toUpperCase();

export default function PeView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const m = useFocusedModule();
  const [pe, setPe] = useState<PeInfo | null>(null);
  const [err, setErr] = useState("");
  const [progress, setProgress] = useState(1);
  const [sub, setSub] = useState<Sub>("headers");
  const [filter, setFilter] = useState("");
  const [entropy, setEntropy] = useState<SectionEntropy[]>([]);
  const [packer, setPacker] = useState<PackerVerdict | null>(null);
  const [iat, setIat] = useState<IatMap | null>(null);
  const [importRefs, setImportRefs] = useState<Record<string, LiveXref[]>>({});
  const [importRefsSel, setImportRefsSel] = useState<IatEntry | null>(null);
  const [elf, setElf] = useState(false);

  useEffect(() => {
    if (!m) return;
    let live = true;
    setPe(null);
    setErr("");
    setElf(false);
    setProgress(0);
    void attempt("pe", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      if (isElf(img)) return setElf(true);
      try {
        const parsed = parsePe(img);
        setPe(parsed);
        setEntropy(sectionEntropies(img, parsed));
        setPacker(detectPacker(img, parsed));
        setIat(buildIat(img, toBig(m.base), parsed));
      } catch (e) { setErr(String(e)); }
    });
    return () => { live = false; };
  }, [m?.name, m?.base]);

  const base = m ? toBig(m.base) : 0n;
  const abs = (rva: number) => fmtAddr(base + BigInt(rva));
  const f = filter.toLowerCase();
  const exports = useMemo(() => (pe?.exports ?? []).filter((e) => !f || e.name.toLowerCase().includes(f)), [pe, f]);
  const imports = useMemo(() => (pe?.imports ?? []).map((d) => ({ ...d, funcs: d.funcs.filter((x) => !f || d.dll.toLowerCase().includes(f) || (x.name ?? "").toLowerCase().includes(f)) })).filter((d) => d.funcs.length), [pe, f]);

  /** Finds every place in the module that references an import slot. */
  const showImportRefs = async (e: IatEntry) => {
    setImportRefsSel(e);
    if (importRefs[e.address]) return;
    const list = await attempt("xrefs", xrefsTo(e.address, modules));
    if (list) setImportRefs((r) => ({ ...r, [e.address]: list }));
  };

  const body = () => {
    if (!pe) return <div className="empty"><div className="empty-title">{err ? "Not a readable PE image." : "Reading image…"}</div>{err && <div className="empty-hint">{err}</div>}</div>;
    if (sub === "headers")
      return (
        <div className="kv">
          <span>machine</span><span>{hx(pe.machine)} {pe.is64 ? "(PE32+)" : "(PE32)"}</span>
          <span>timestamp</span><span>{hx(pe.timestamp)} · {new Date(pe.timestamp * 1000).toISOString().slice(0, 19)}</span>
          <span>entry</span><span className="link" onClick={() => ui.goDisasm(abs(pe.entryRva))}>{abs(pe.entryRva)} (rva {hx(pe.entryRva)})</span>
          <span>image base</span><span>{hx(pe.imageBase)} (loaded at {m?.base})</span>
          <span>size of image</span><span>{hx(pe.sizeOfImage)}</span>
          <span>subsystem</span><span>{pe.subsystem}</span>
          <span>characteristics</span><span>{hx(pe.characteristics)}</span>
          <span>dll chars</span><span>{hx(pe.dllCharacteristics)}{pe.dllCharacteristics & 0x40 ? " ASLR" : ""}{pe.dllCharacteristics & 0x100 ? " NX" : ""}{pe.dllCharacteristics & 0x4000 ? " CFG" : ""}</span>
          {pe.dirs.filter((d) => d.rva).flatMap((d) => [<span key={d.name + "k"}>{d.name}</span>, <span key={d.name}>rva {hx(d.rva)} size {hx(d.size)}</span>])}
        </div>
      );
    if (sub === "sections")
      return (
        <table className="table mono">
          <thead><tr><th>Name</th><th>RVA</th><th>VSize</th><th>Raw</th><th>Flags</th></tr></thead>
          <tbody>{pe.sections.map((s) => (
            <tr key={s.name + s.rva} onClick={() => ui.select(abs(s.rva))} onDoubleClick={() => (s.x ? ui.goDisasm(abs(s.rva)) : ui.goMemory(abs(s.rva)))}>
              <td>{s.name}</td><td>{hx(s.rva)}</td><td>{hx(s.vsize)}</td><td>{hx(s.rawSize)}</td><td>{s.r ? "R" : "-"}{s.w ? "W" : "-"}{s.x ? "X" : "-"}</td>
            </tr>))}
          </tbody>
        </table>
      );
    if (sub === "exports")
      return (
        <table className="table mono">
          <colgroup><col style={{ width: 70 }} /><col /><col style={{ width: 110 }} /></colgroup>
          <thead><tr><th>Ord</th><th>Name</th><th>RVA</th></tr></thead>
          <tbody>{exports.slice(0, kLimit).map((e) => (
            <tr key={e.ordinal} onClick={() => ui.select(abs(e.rva))} onDoubleClick={() => !e.forwarder && ui.goDisasm(abs(e.rva))}>
              <td className="faint">{e.ordinal}</td><td title={e.forwarder}>{e.name || <span className="faint">(ordinal)</span>}{e.forwarder && <span className="faint"> → {e.forwarder}</span>}</td><td className="dim">{hx(e.rva)}</td>
            </tr>))}
            {exports.length > kLimit && <tr><td colSpan={3} className="faint">{exports.length - kLimit} more, refine the filter</td></tr>}
          </tbody>
        </table>
      );
    if (sub === "imports")
      return (
        <div className="tree mono">
          {imports.map((d) => (
            <details key={d.dll} open={!!f}>
              <summary>{d.dll} <span className="faint">({d.funcs.length})</span></summary>
              {d.funcs.slice(0, kLimit).map((x) => (
                <div key={x.iatRva} className="fn-row" onClick={() => ui.select(abs(x.iatRva))} onDoubleClick={() => ui.goMemory(abs(x.iatRva))} style={{ paddingLeft: 28 }}>
                  <span className="grow">{x.name ?? `#${x.ordinal}`}</span><span className="faint">IAT {hx(x.iatRva)}</span>
                </div>
              ))}
            </details>
          ))}
        </div>
      );
    if (sub === "iat")
      return (
        <>
          <table className="table mono">
            <colgroup><col style={{ width: 160 }} /><col /><col style={{ width: 120 }} /><col style={{ width: 70 }} /></colgroup>
            <thead><tr><th>DLL</th><th>Function</th><th>Slot</th><th>Refs</th></tr></thead>
            <tbody>
              {(iat?.entries ?? []).slice(0, kLimit).map((e) => (
                <tr key={e.address} onClick={() => ui.select(e.address)} onDoubleClick={() => void showImportRefs(e)}>
                  <td className="faint ellipsis">{e.dll}</td>
                  <td className="link">{e.name}</td>
                  <td className="dim">{hx(e.rva)}</td>
                  <td className="dim">{importRefs[e.address]?.length ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {importRefsSel && (
            <div style={{ borderTop: "1px solid var(--border-soft)" }}>
              <div className="toolbar">
                <span className="panel-title">Callsites of {importRefsSel.name}</span>
                <span className="grow" />
                <button className="row-action" onClick={() => setImportRefsSel(null)}>close</button>
              </div>
              <table className="table mono">
                <tbody>
                  {(importRefs[importRefsSel.address] ?? []).map((x) => (
                    <tr key={x.address} onClick={() => ui.goDisasm("0x" + x.address.toString(16))}>
                      <td className="link">{labelAddr("0x" + x.address.toString(16), modules)}</td>
                      <td className="faint">{x.kind}</td>
                    </tr>
                  ))}
                  {(importRefs[importRefsSel.address] ?? []).length === 0 && (
                    <tr><td className="faint">No references found in the module image.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </>
      );
    return (
      <div className="panel-section">
        <div className="label">Packer / protection</div>
        {packer ? (
          <>
            <div className={packer.packed ? "danger" : "ok"}>
              {packer.packed ? "likely packed or protected" : "no packing indicators"} · confidence {Math.round(packer.confidence * 100)}%
            </div>
            {packer.reasons.length > 0 && (
              <ul className="faint" style={{ fontSize: 12, margin: 0, paddingLeft: 18 }}>
                {packer.reasons.map((r, i) => <li key={i}>{r}</li>)}
              </ul>
            )}
          </>
        ) : (
          <div className="faint">No verdict.</div>
        )}
        <div className="label">Section entropy</div>
        <table className="table mono">
          <thead><tr><th>Section</th><th>Size</th><th>Entropy</th></tr></thead>
          <tbody>
            {entropy.map((e) => (
              <tr key={e.name + e.rva}>
                <td>{e.name}</td>
                <td className="faint">{(e.size / 1024).toFixed(0)}K</td>
                <td>
                  <span className={e.entropy > 7.2 ? "danger" : e.entropy > 6.5 ? "warn" : "ok"}>{e.entropy.toFixed(2)}</span>
                  <span className="entropy-bar"><span style={{ width: `${(e.entropy / 8) * 100}%` }} data-hot={e.entropy > 7.2} /></span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  if (elf && m) return <NeedsAgent><ElfView m={m} /></NeedsAgent>;

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <ModulePicker />
          {(sub === "exports" || sub === "imports") && <label className="search grow"><Search size={13} /><input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>}
          <span className="grow" />
          {pe && <span className="faint" style={{ fontSize: 12 }}>{pe.sections.length} sections · {pe.exports.length} exports · {pe.imports.reduce((n, d) => n + d.funcs.length, 0)} imports</span>}
        </div>
        {progress < 1 && <Progress value={progress} />}
        <Tabs tabs={[{ id: "headers", label: "Headers" }, { id: "sections", label: "Sections" }, { id: "exports", label: "Exports" }, { id: "imports", label: "Imports" }, { id: "iat", label: "IAT" }, { id: "analysis", label: "Analysis" }]} active={sub} onSelect={setSub} />
        <div className="vlist">{body()}</div>
      </div>
    </NeedsAgent>
  );
}
