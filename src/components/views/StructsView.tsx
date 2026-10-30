import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, Code2, Plus, Trash2 } from "lucide-react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress, toBig } from "@/lib/hex";
import { readBytes } from "@/lib/memory";
import { fieldValue, kFieldSizes, layout, toCpp, type Field, type FieldType } from "@/lib/analysis/struct";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, IconButton, NeedsAgent, copy } from "../ui";

const kTypes = Object.keys(kFieldSizes) as FieldType[];
const kKey = "echodebug.struct";
const hexRows = (n: number): Field[] => Array.from({ length: n }, () => ({ type: "hex64", name: "" }));

function loadSaved(): { name: string; fields: Field[] } {
  try {
    const v = JSON.parse(localStorage.getItem(kKey) ?? "");
    if (Array.isArray(v.fields)) return v;
  } catch { /* first run */ }
  return { name: "Class", fields: hexRows(16) };
}

export default function StructsView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const [cls, setCls] = useState(loadSaved);
  const [data, setData] = useState<Uint8Array | null>(null);
  const [rtti, setRtti] = useState<Record<string, string>>({});
  const [history, setHistory] = useState<string[]>([]);
  const [cpp, setCpp] = useState<string | null>(null);
  const lay = useMemo(() => layout(cls.fields), [cls.fields]);
  const size = lay.length ? lay[lay.length - 1].offset + lay[lay.length - 1].size : 0;
  const base = ui.structAt;

  useEffect(() => { localStorage.setItem(kKey, JSON.stringify(cls)); }, [cls]);
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

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <IconButton tip="Back" onClick={() => { const p = history.at(-1); if (p) { setHistory(history.slice(0, -1)); go(p, false); } }} disabled={!history.length}><ArrowLeft size={14} /></IconButton>
          <CommitInput value={base ?? ""} placeholder="object address" onCommit={(v) => go(v)} width={220} />
          <CommitInput className="input" value={cls.name} onCommit={(name) => setCls({ ...cls, name })} width={120} />
          {base && rtti[base] && <span className="pill accent">{rtti[base]}</span>}
          <span className="grow mono faint">size 0x{size.toString(16)}</span>
          <button className="btn small" onClick={() => setCls({ ...cls, fields: [...cls.fields, ...hexRows(1)] })}><Plus size={12} />8</button>
          <button className="btn small" onClick={() => setCls({ ...cls, fields: [...cls.fields, ...hexRows(8)] })}><Plus size={12} />64</button>
          <IconButton tip="Export C++" onClick={() => setCpp(cpp === null ? toCpp(cls.name, cls.fields) : null)}><Code2 size={14} /></IconButton>
          <IconButton tip="Reset layout" onClick={() => setCls({ name: cls.name, fields: hexRows(16) })}><Trash2 size={14} /></IconButton>
        </div>
        {cpp !== null && (
          <div style={{ borderBottom: "1px solid var(--border-soft)" }}>
            <div className="toolbar"><span className="panel-title">C++</span><span className="grow" /><button className="btn small" onClick={() => void copy(cpp)}>Copy</button></div>
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
    </NeedsAgent>
  );
}
