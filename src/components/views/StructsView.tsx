import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, Code2, Columns3, Plus, Trash2, Wand2 } from "lucide-react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress, toBig } from "@/lib/hex";
import { readBytes } from "@/lib/memory";
import { kPresets } from "@/lib/analysis/presets";
import { fieldValue, kFieldSizes, layout, toCpp, type Field, type FieldType } from "@/lib/analysis/struct";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { useTypes, type TypeDef } from "@/store/types";
import { useUi } from "@/store/ui";
import { CommitInput, IconButton, NeedsAgent, copy } from "../ui";
import AutoDetect from "./structs/AutoDetect";
import StructDiff from "./structs/StructDiff";
import UnrealReader from "./structs/UnrealReader";

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
  const [tool, setTool] = useState<"none" | "detect" | "diff" | "unreal">("none");
  const [presetNote, setPresetNote] = useState("");
  const lay = useMemo(() => layout(cls.fields), [cls.fields]);
  const size = lay.length ? lay[lay.length - 1].offset + lay[lay.length - 1].size : 0;
  const base = ui.structAt;

  // Keep the edited class in the catalog so it survives a reload.
  useEffect(() => {
    if (!activeId) return;
    catalog.update(activeId, { name: cls.name, fields: cls.fields });
  }, [cls.name, cls.fields, activeId]);

  useEffect(() => {
    if (!base || !size) return;
    let live = true;
    const load = async () => {
      const b = await readBytes(toBig(base), size).catch(() => null);
      if (live) setData(b);
    };
    void load();
    const t = setInterval(() => void load(), 500);
    return () => { live = false; clearInterval(t); };
  }, [base, size]);

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

  /** Copies an engine preset into the catalog as a new, editable type. */
  const applyPreset = (id: string) => {
    const p = kPresets.find((x) => x.id === id);
    if (!p) return;
    const tid = catalog.add(p.name, p.fields);
    select({ id: tid, name: p.name, fields: p.fields });
    setPresetNote(`${p.engine} · ${p.name}: ${p.description}`);
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
      <div className="split-h" style={{ ["--fn-w" as string]: showCatalog ? "220px" : "0px" }}>
        <div className="list-col" style={{ display: showCatalog ? "flex" : "none" }}>
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
        </div>
        <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
          <div className="toolbar">
            <IconButton tip="Back" onClick={() => { const p = history.at(-1); if (p) { setHistory(history.slice(0, -1)); go(p, false); } }} disabled={!history.length}><ArrowLeft size={14} /></IconButton>
            <IconButton tip="Type catalog" onClick={() => setShowCatalog(!showCatalog)}><Code2 size={14} /></IconButton>
            <CommitInput value={base ?? ""} placeholder="object address" onCommit={(v) => go(v)} width={200} />
            <CommitInput className="input" value={cls.name} onCommit={(name) => setCls({ ...cls, name })} width={140} />
            {base && rtti[base] && <button className="btn small" onClick={adoptRtti} title="use the RTTI class name">RTTI</button>}
            <select className="select" value="" onChange={(e) => applyPreset(e.target.value)} title="engine presets" style={{ width: 90 }}>
              <option value="">Presets…</option>
              {[...new Set(kPresets.map((p) => p.engine))].map((eng) => (
                <optgroup key={eng} label={eng}>{kPresets.filter((p) => p.engine === eng).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</optgroup>
              ))}
            </select>
            <IconButton tip="Auto-detect field types" onClick={() => setTool(tool === "detect" ? "none" : "detect")} disabled={!base}><Wand2 size={14} /></IconButton>
            <IconButton tip="Compare instances" onClick={() => setTool(tool === "diff" ? "none" : "diff")}><Columns3 size={14} /></IconButton>
            <button className="btn small" onClick={() => setTool(tool === "unreal" ? "none" : "unreal")} title="Unreal GNames / GObjects reader">UE</button>
            <span className="grow mono faint">size 0x{size.toString(16)}</span>
            <button className="btn small" onClick={() => setCls({ ...cls, fields: [...cls.fields, ...hexRows(1)] })}><Plus size={12} />8</button>
            <button className="btn small" onClick={() => setCls({ ...cls, fields: [...cls.fields, ...hexRows(8)] })}><Plus size={12} />64</button>
            <IconButton tip="Export C++" onClick={() => setCpp(cpp === null ? toCpp(cls.name, cls.fields) : null)}><Code2 size={14} /></IconButton>
            <IconButton tip="Reset layout" onClick={() => setCls({ ...cls, fields: hexRows(16) })}><Trash2 size={14} /></IconButton>
          </div>
          {cpp !== null && (
            <div style={{ borderBottom: "1px solid var(--border-soft)" }}>
              <div className="toolbar"><span className="panel-title">C++</span><span className="grow" /><button className="btn small" onClick={() => void copy(cpp)}>Copy</button></div>
              <pre className="code-block" style={{ maxHeight: 220 }}>{cpp}</pre>
            </div>
          )}
          {presetNote && (
            <div className="toolbar"><span className="faint grow ellipsis" title={presetNote}>{presetNote}</span><button className="row-action" onClick={() => setPresetNote("")}>×</button></div>
          )}
          {tool === "detect" && base && <AutoDetect base={base} modules={modules} fields={cls.fields} onApply={(fields) => setCls({ ...cls, fields })} onClose={() => setTool("none")} />}
          {tool === "diff" ? (
            <StructDiff base={base} modules={modules} fields={cls.fields} onClose={() => setTool("none")} />
          ) : tool === "unreal" ? (
            <UnrealReader modules={modules} onClose={() => setTool("none")} />
          ) : !base ? (
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
                      <tr key={i} data-selected={ui.selected === addr} onClick={() => ui.select(addr)}>
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
