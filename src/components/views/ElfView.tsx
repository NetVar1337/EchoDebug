// ELF module browser (Linux local backend): header, segments, sections, symbols, dynamic
// section, relocations. Reads the module *file* because section headers are not mapped.
import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { fmtAddr, toBig, type Module } from "@/lib/hex";
import { loadModuleFile } from "@/lib/modfile";
import { elfBias, parseElf, relocTypeName, type ElfInfo } from "@/lib/analysis/elf";
import { attempt } from "@/store/output";
import { useUi } from "@/store/ui";
import { Progress, Tabs } from "../ui";
import ModulePicker from "../ModulePicker";

type Sub = "header" | "segments" | "sections" | "symbols" | "dynamic" | "relocs";
const kLimit = 3000;
const hx = (n: number | bigint) => "0x" + n.toString(16).toUpperCase();

export default function ElfView({ m }: { m: Module }) {
  const ui = useUi();
  const [info, setInfo] = useState<ElfInfo | null>(null);
  const [path, setPath] = useState("");
  const [err, setErr] = useState("");
  const [progress, setProgress] = useState(0);
  const [sub, setSub] = useState<Sub>("header");
  const [filter, setFilter] = useState("");

  useEffect(() => {
    let live = true;
    setInfo(null);
    setErr("");
    setProgress(0);
    void attempt("elf", loadModuleFile(m, (d, t) => live && setProgress(d / t))).then((f) => {
      if (!live) return;
      setProgress(1);
      if (!f) return setErr("the module file could not be read");
      setPath(f.path);
      try { setInfo(parseElf(f.bytes)); } catch (e) { setErr(String(e)); }
    });
    return () => { live = false; };
  }, [m.name, m.base]);

  const bias = info ? elfBias(info, toBig(m.base)) : 0n;
  const abs = (v: bigint) => fmtAddr(v + bias);
  const f = filter.toLowerCase();
  const symbols = useMemo(() => (info?.symbols ?? []).filter((s) => s.name && (!f || s.name.toLowerCase().includes(f))).sort((a, b) => (a.value < b.value ? -1 : 1)), [info, f]);
  const relocs = useMemo(() => (info?.relocs ?? []).filter((r) => !f || r.symbol.toLowerCase().includes(f) || r.section.includes(f)), [info, f]);

  const body = () => {
    if (!info) return <div className="empty"><div className="empty-title">{err ? "Not a readable ELF file." : "Reading module file…"}</div>{err && <div className="empty-hint">{err}</div>}</div>;
    if (sub === "header")
      return (
        <div className="kv">
          <span>file</span><span>{path}</span>
          <span>type</span><span>{info.header.typeName} ({info.header.class}-bit)</span>
          <span>machine</span><span>{info.header.machineName}</span>
          <span>entry</span><span className="link" onClick={() => ui.goDisasm(info.header.typeName === "DYN" ? abs(info.header.entry) : fmtAddr(info.header.entry))}>{hx(info.header.entry)}</span>
          <span>loaded at</span><span>{m.base} (bias {hx(bias)})</span>
          <span>interpreter</span><span>{info.interp || "—"}</span>
          <span>soname</span><span>{info.soname || "—"}</span>
          <span>needed</span><span>{info.needed.join(", ") || "—"}</span>
          <span>build-id</span><span>{info.buildId || "—"}</span>
          <span>counts</span><span>{info.segments.length} segments · {info.sections.length} sections · {info.symbols.length} symbols · {info.relocs.length} relocations</span>
        </div>
      );
    if (sub === "segments")
      return (
        <table className="table mono">
          <thead><tr><th>Type</th><th>Flags</th><th>Offset</th><th>VAddr</th><th>FileSz</th><th>MemSz</th></tr></thead>
          <tbody>{info.segments.map((s, i) => (
            <tr key={i} onDoubleClick={() => s.type === 1 && (s.flags.includes("X") ? ui.goDisasm(abs(s.vaddr)) : ui.goMemory(abs(s.vaddr)))}>
              <td>{s.typeName}</td><td>{s.flags}</td><td>{hx(s.offset)}</td><td>{hx(s.vaddr)}</td><td>{hx(s.filesz)}</td><td>{hx(s.memsz)}</td>
            </tr>))}
          </tbody>
        </table>
      );
    if (sub === "sections")
      return (
        <table className="table mono">
          <thead><tr><th>#</th><th>Name</th><th>Type</th><th>Flags</th><th>Addr</th><th>Size</th></tr></thead>
          <tbody>{info.sections.map((s) => (
            <tr key={s.index} onDoubleClick={() => s.addr && (s.flags.includes("X") ? ui.goDisasm(abs(s.addr)) : ui.goMemory(abs(s.addr)))}>
              <td className="faint">{s.index}</td><td>{s.name}</td><td>{s.typeName}</td><td>{s.flags}</td><td>{hx(s.addr)}</td><td>{hx(s.size)}</td>
            </tr>))}
          </tbody>
        </table>
      );
    if (sub === "symbols")
      return (
        <table className="table mono">
          <colgroup><col /><col style={{ width: 70 }} /><col style={{ width: 70 }} /><col style={{ width: 150 }} /><col style={{ width: 60 }} /></colgroup>
          <thead><tr><th>Name</th><th>Type</th><th>Bind</th><th>Address</th><th>Size</th></tr></thead>
          <tbody>{symbols.slice(0, kLimit).map((s, i) => (
            <tr key={i} onClick={() => s.value && ui.select(abs(s.value))} onDoubleClick={() => s.value && (s.type === "FUNC" ? ui.goDisasm(abs(s.value)) : ui.goMemory(abs(s.value)))}>
              <td className="ellipsis" title={s.name}>{s.name}{s.dynamic && <span className="faint"> (dyn)</span>}</td><td>{s.type}</td><td className="faint">{s.bind}</td><td className="dim">{s.value ? abs(s.value) : "—"}</td><td className="faint">{s.size}</td>
            </tr>))}
            {symbols.length > kLimit && <tr><td colSpan={5} className="faint">{symbols.length - kLimit} more, refine the filter</td></tr>}
          </tbody>
        </table>
      );
    if (sub === "dynamic")
      return (
        <table className="table mono">
          <thead><tr><th>Tag</th><th>Value</th></tr></thead>
          <tbody>{info.dynamic.map((d, i) => <tr key={i}><td>{d.tagName}</td><td>{d.text ?? hx(d.value)}</td></tr>)}</tbody>
        </table>
      );
    return (
      <table className="table mono">
        <thead><tr><th>Section</th><th>Offset</th><th>Type</th><th>Symbol</th><th>Addend</th></tr></thead>
        <tbody>{relocs.slice(0, kLimit).map((r, i) => (
          <tr key={i} onDoubleClick={() => ui.goMemory(abs(r.offset))}>
            <td className="faint">{r.section}</td><td>{abs(r.offset)}</td><td>{relocTypeName(info.header.machine, r.type)}</td><td>{r.symbol || "—"}</td><td className="faint">{hx(r.addend)}</td>
          </tr>))}
          {relocs.length > kLimit && <tr><td colSpan={5} className="faint">{relocs.length - kLimit} more, refine the filter</td></tr>}
        </tbody>
      </table>
    );
  };

  return (
    <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
      <div className="toolbar">
        <ModulePicker />
        {(sub === "symbols" || sub === "relocs") && <label className="search grow"><Search size={13} /><input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>}
        <span className="grow" />
        <span className="faint" style={{ fontSize: 12 }}>ELF browser</span>
      </div>
      {progress < 1 && <Progress value={progress} />}
      <Tabs tabs={[{ id: "header", label: "Header" }, { id: "segments", label: "Segments" }, { id: "sections", label: "Sections" }, { id: "symbols", label: "Symbols" }, { id: "dynamic", label: "Dynamic" }, { id: "relocs", label: "Relocations" }]} active={sub} onSelect={setSub} />
      <div className="vlist">{body()}</div>
    </div>
  );
}
