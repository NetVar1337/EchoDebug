import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, ArrowLeft, Code2, Plus, Trash2, Wand2 } from "lucide-react";
import { pointerClassifier } from "@/lib/ptrkind";
import { saveBinary, saveText } from "@/lib/save";
import { changedFields, guessFields } from "@/lib/analysis/structguess";
import { toBinja, toC, toGhidra, toIdaPython, toReclassProject } from "@/lib/analysis/typeexport";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress, toBig } from "@/lib/hex";
import { readBytes } from "@/lib/memory";
import { fieldValue, kFieldSizes, layout, toCpp, type Field, type FieldType } from "@/lib/analysis/struct";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { useTypes, type TypeDef } from "@/store/types";
import { useUi } from "@/store/ui";
import { CommitInput, IconButton, NeedsAgent, copy } from "../ui";

const kTypes = Object.keys(kFieldSizes) as FieldType[];
const hexRows = (n: number): Field[] => Array.from({ length: n }, () => ({ type: "hex64", name: "" }));

export default function StructsView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const catalog = useTypes();
  const [activeId, setActiveId] = useState<string | null>(null);
  const [cls, setCls] = useState<TypeDef>({ id: "", name: "Class", fields: hexRows(16) });
  const [data, setData] = useState<Uint8Array | null>(null);
  const [rtti, setRtti] = useState<Record<string, string>>({});
  const [history, setHistory] = useState<string[]>([]);
  const [cpp, setCpp] = useState<string | null>(null);
  const [showCatalog, setShowCatalog] = useState(true);
  const [exportFmt, setExportFmt] = useState<"cpp" | "c" | "ida" | "ghidra" | "binja">("cpp");
  const [track, setTrack] = useState(false);
  const [changes, setChanges] = useState<number[]>([]);
  const prevData = useRef<Uint8Array | null>(null);
  const lay = useMemo(() => layout(cls.fields), [cls.fields]);
  const size = lay.length ? lay[lay.length - 1].offset + lay[lay.length - 1].size : 0;
  const base = ui.structAt;

  // Keep the edited class in the catalog so it survives a reload.
  useEffect(() => {
    if (!activeId) return;
    catalog.update(activeId, { name: cls.name, fields: cls.fields });
  }, [cls.name, cls.fields, activeId]);

  useEffect(() => { setChanges([]); prevData.current = null; }, [base, cls.fields, track]);
  useEffect(() => {
    if (!base || !size) return;
    let live = true;
    const load = async () => {
      const b = await readBytes(toBig(base), size).catch(() => null);
      if (!live) return;
      if (track && b && prevData.current) {
        const ch = changedFields(prevData.current, b, layout(cls.fields));
        setChanges((c) => ch.map((x, i) => (c[i] ?? 0) + (x ? 1 : 0)));
      }
      prevData.current = b;
      setData(b);
    };
    void load();
    const t = setInterval(() => void load(), 500);
    return () => { live = false; clearInterval(t); };
  }, [base, size, track, cls.fields]);

  // RTTI for the class itself and every pointer field, resolved once per distinct pointer value
  const ptrs = useMemo(() => {
    const out = base ? [base] : [];
    if (data) cls.fields.forEach((f, i) => f.type === "ptr" && out.push("0x" + fieldValue(data, lay[i].offset, "hex64").replace(/^0+(?=.)/, "").toLowerCase()));
    return out.filter((p) => !(p in rtti));
  }, [data, cls.fields, lay, base, rtti]);

  useEffect(() => {
    if (ptrs.length === 0) return;
    void request<{ results: { success: boolean; name: string }[] }>("rtti_resolve_batch", { addresses: ptrs }, true)
      .then((r) => setRtti((m) => ({ ...m, ...Object.fromEntries(ptrs.map((p, i) => [p, r.results?.[i]?.success ? r.results[i].name : ""])) })))
      .catch(() => setRtti((m) => ({ ...m, ...Object.fromEntries(ptrs.map((p) => [p, ""])) })));
  }, [ptrs]);

  const go = (a: string, push = true) => {
    const v = parseAddress(a, modules);
    if (v === null) return log("warn", "struct", `cannot parse ${a}`);
    if (push && base) setHistory((h) => [...h, base]);
    ui.goStruct(fmtAddr(v));
  };

  /** Retypes the rows from what the live bytes look like. */
  const guess = async () => {
    if (!base || !data) return log("warn", "struct", "enter an object address first");
    const kindOf = await pointerClassifier(modules);
    const fields = guessFields(data, { kindOf });
    setCls((c) => ({ ...c, fields }));
    log("info", "struct", `guessed ${fields.filter((f) => !f.type.startsWith("hex")).length} typed fields over 0x${data.length.toString(16)} bytes`);
  };
  const exportText = () => {
    switch (exportFmt) {
      case "c": return toC(cls.name, cls.fields);
      case "ida": return toIdaPython(cls.name, cls.fields);
      case "ghidra": return toGhidra(cls.name, cls.fields);
      case "binja": return toBinja(cls.name, cls.fields);
      default: return toCpp(cls.name, cls.fields);
    }
  };
  const saveReclass = async () => {
    const all = catalog.types.length ? catalog.types.map((t) => (t.id === activeId ? { ...t, name: cls.name, fields: cls.fields } : t)) : [cls];
    await saveBinary(`${cls.name || "echodebug"}.rcnet`, toReclassProject(all.map((t) => ({ name: t.name, fields: t.fields }))));
  };
  const maxChange = Math.max(1, ...changes);

  const setField = (i: number, p: Partial<Field>) => setCls((c) => ({ ...c, fields: c.fields.map((f, j) => (j === i ? { ...f, ...p } : f)) }));

  const select = (t: TypeDef) => {
    setActiveId(t.id);
    setCls(t);
    setCpp(null);
  };

  const create = () => {
    const id = catalog.add("Class");
    const t = catalog.types.find((x) => x.id === id)!;
    select(t);
  };

  /** Applies the RTTI class name of the object as the type's name. */
  const adoptRtti = () => {
    if (!base) return;
    const name = rtti[base];
    if (!name) return log("warn", "struct", "no RTTI name for this object");
    const clean = name.replace(/^(class|struct)\s+/, "");
    setCls((c) => ({ ...c, name: clean }));
    if (activeId) catalog.update(activeId, { name: clean });
  };

  return (
    <NeedsAgent>
      <div className="split-h" style={{ gridTemplateColumns: showCatalog ? "220px minmax(0, 1fr)" : "minmax(0, 1fr)" }}>
        {showCatalog && <div className="list-col">
          <div className="toolbar">
            <span className="panel-title grow">Types</span>
            <IconButton tip="New type" onClick={create}><Plus size={14} /></IconButton>
          </div>
          <div className="vlist">
            {catalog.types.length === 0 && <div className="panel-section faint">No types yet. Create one to reuse a layout.</div>}
            {catalog.types.map((t) => (
              <div key={t.id} className="fn-row" data-selected={activeId === t.id} onClick={() => select(t)}>
                <span className="grow ellipsis">{t.name || "(unnamed)"}</span>
                <button className="row-action" onClick={(e) => { e.stopPropagation(); catalog.remove(t.id); if (activeId === t.id) setActiveId(null); }}>del</button>
              </div>
            ))}
          </div>
        </div>}
        <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
          <div className="toolbar">
            <IconButton tip="Back" onClick={() => { const p = history.at(-1); if (p) { setHistory(history.slice(0, -1)); go(p, false); } }} disabled={!history.length}><ArrowLeft size={14} /></IconButton>
            <IconButton tip="Type catalog" onClick={() => setShowCatalog(!showCatalog)}><Code2 size={14} /></IconButton>
            <CommitInput value={base ?? ""} placeholder="object address" onCommit={(v) => go(v)} width={200} />
            <CommitInput className="input" value={cls.name} onCommit={(name) => setCls({ ...cls, name })} width={140} />
            {base && rtti[base] && <button className="btn small" onClick={adoptRtti} title="use the RTTI class name">RTTI</button>}
            <span className="grow mono faint">size 0x{size.toString(16)}</span>
            <button className="btn small" onClick={() => setCls({ ...cls, fields: [...cls.fields, ...hexRows(1)] })}><Plus size={12} />8</button>
            <button className="btn small" onClick={() => setCls({ ...cls, fields: [...cls.fields, ...hexRows(8)] })}><Plus size={12} />64</button>
            <IconButton tip="Guess the fields from the live bytes" onClick={() => void guess()} disabled={!data}><Wand2 size={14} /></IconButton>
            <IconButton tip={track ? "Stop tracking changes" : "Track which fields change"} onClick={() => setTrack(!track)}><Activity size={14} className={track ? "accent" : undefined} /></IconButton>
            <select className="select" value={exportFmt} onChange={(e) => { setExportFmt(e.target.value as typeof exportFmt); setCpp(null); }} title="export format">
              <option value="cpp">C++</option><option value="c">C</option><option value="ida">IDAPython</option><option value="ghidra">Ghidra</option><option value="binja">Binary Ninja</option>
            </select>
            <IconButton tip="Show export" onClick={() => setCpp(cpp === null ? exportText() : null)}><Code2 size={14} /></IconButton>
            <button className="btn small" onClick={() => void saveReclass()} title="ReClass.NET project with every type in the catalog (best effort)">.rcnet</button>
            <IconButton tip="Reset layout" onClick={() => setCls({ ...cls, fields: hexRows(16) })}><Trash2 size={14} /></IconButton>
          </div>
          {cpp !== null && (
            <div style={{ borderBottom: "1px solid var(--border-soft)" }}>
              <div className="toolbar"><span className="panel-title">{({ cpp: "C++", c: "C", ida: "IDAPython", ghidra: "Ghidra script", binja: "Binary Ninja" } as const)[exportFmt]}</span><span className="grow" /><button className="btn small" onClick={() => void copy(cpp)}>Copy</button><button className="btn small" onClick={() => void saveText(`${cls.name || "Class"}.${exportFmt === "cpp" || exportFmt === "c" ? "h" : "py"}`, cpp)}>Save</button></div>
              <pre className="code-block" style={{ maxHeight: 220 }}>{cpp}</pre>
            </div>
          )}
          {!base ? (
            <div className="empty"><div className="empty-title">Enter an object address.</div><div className="empty-hint">Fields are read live every 500 ms. Retype a row to reinterpret it; pointers can be followed.</div></div>
          ) : (
            <div className="vlist">
              <table className="table mono">
                <colgroup><col style={{ width: 64 }} /><col style={{ width: 150 }} /><col style={{ width: 80 }} /><col style={{ width: 140 }} /><col /></colgroup>
                <thead><tr><th>Offset</th><th>Address</th><th>Type</th><th>Name</th><th>Value</th></tr></thead>
                <tbody>
                  {cls.fields.map((f, i) => {
                    const { offset } = lay[i];
                    const addr = fmtAddr(toBig(base) + BigInt(offset));
                    const val = data ? fieldValue(data, offset, f.type) : "??";
                    const ptr = f.type === "ptr" || f.type === "hex64" ? "0x" + (data ? fieldValue(data, offset, "hex64") : "0").replace(/^0+(?=.)/, "").toLowerCase() : null;
                    return (
                      <tr key={i} data-selected={ui.selected === addr} onClick={() => ui.select(addr)}
                        style={track && changes[i] ? { background: `color-mix(in srgb, var(--warning) ${Math.round(10 + 40 * (changes[i] / maxChange))}%, transparent)` } : undefined}
                        title={track ? `${changes[i] ?? 0} changes while tracking` : undefined}>
                        <td className="faint">{offset.toString(16).toUpperCase().padStart(4, "0")}</td>
                        <td className="dim">{addr.slice(2).toUpperCase()}</td>
                        <td><select className="select" value={f.type} onChange={(e) => setField(i, { type: e.target.value as FieldType })}>{kTypes.map((t) => <option key={t}>{t}</option>)}</select></td>
                        <td><CommitInput className="input" value={f.name} placeholder="—" onCommit={(name) => setField(i, { name })} /></td>
                        <td>
                          {val}
                          {f.type === "ptr" && ptr && ptr !== "0x0" && (
                            <>
                              {" "}<span className="faint">{labelAddr(ptr, modules) !== ptr ? labelAddr(ptr, modules) : ""}</span>
                              {rtti[ptr] && <span className="pill accent" style={{ marginLeft: 6 }}>{rtti[ptr]}</span>}
                              <button className="row-action" onClick={(e) => { e.stopPropagation(); go(ptr); }}>follow →</button>
                            </>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
