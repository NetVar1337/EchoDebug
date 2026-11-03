// The current layout read at several instances side by side: differing fields are highlighted,
// fields equal everywhere are marked constant (IDs, health and flags are the ones that differ).
import { useEffect, useMemo, useState } from "react";
import { X } from "lucide-react";
import { readMany } from "@/lib/batch";
import { fmtAddr, parseAddress, type Module } from "@/lib/hex";
import { fieldValue, layout, type Field } from "@/lib/analysis/struct";
import { log } from "@/store/output";
import { CommitInput, IconButton } from "../../ui";

const kMaxInstances = 16;

export default function StructDiff({ base, modules, fields, onClose }: { base: string | null; modules: Module[]; fields: Field[]; onClose: () => void }) {
  const [addrs, setAddrs] = useState<string[]>(base ? [base] : []);
  const [arr, setArr] = useState({ at: "", count: "8", stride: "8" });
  const [data, setData] = useState<(Uint8Array | null)[]>([]);
  const lay = useMemo(() => layout(fields), [fields]);
  const size = lay.length ? lay[lay.length - 1].offset + lay[lay.length - 1].size : 0;

  useEffect(() => {
    if (!addrs.length || !size) return;
    let live = true;
    const load = () => void readMany(addrs.map((address) => ({ address, size }))).then((d) => live && setData(d)).catch(() => {});
    load();
    const t = setInterval(load, 500);
    return () => { live = false; clearInterval(t); };
  }, [addrs, size]);

  const add = (text: string) => {
    const out: string[] = [];
    for (const part of text.split(/[\s,;]+/).filter(Boolean)) {
      const v = parseAddress(part, modules);
      if (v === null) return log("warn", "struct", `cannot parse ${part}`);
      out.push(fmtAddr(v));
    }
    setAddrs((a) => [...new Set([...a, ...out])].slice(0, kMaxInstances));
  };

  /** Entries of a pointer array (entity list): *(at + i*stride) for i < count, nulls skipped. */
  const fromArray = async () => {
    const at = parseAddress(arr.at, modules), count = Number(arr.count), stride = Number(arr.stride);
    if (at === null || !(count > 0) || !(stride >= 8)) return log("warn", "struct", "array needs an address, count > 0 and stride >= 8");
    const r = await readMany(Array.from({ length: Math.min(count, 256) }, (_, i) => ({ address: fmtAddr(at + BigInt(i * stride)), size: 8 }))).catch(() => []);
    const ptrs = r.flatMap((b) => (b && b.length === 8 ? [new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, true)] : [])).filter((p) => p > 0xffffn);
    if (!ptrs.length) return log("warn", "struct", "no non-null pointers in that array");
    setAddrs([...new Set(ptrs.map(fmtAddr))].slice(0, kMaxInstances));
  };

  return (
    <div className="list-col" style={{ flex: 1, minHeight: 0, borderRight: "none" }}>
      <div className="toolbar">
        <span className="panel-title">Compare instances</span>
        <CommitInput value="" placeholder="add addresses (space separated)" onCommit={add} width={220} />
        {base && <button className="btn small" onClick={() => add(base)}>+ current</button>}
        <span className="faint">from pointer array</span>
        <CommitInput value={arr.at} placeholder="array address" onCommit={(at) => setArr({ ...arr, at })} width={150} />
        <CommitInput value={arr.count} onCommit={(count) => setArr({ ...arr, count })} width={44} />
        <CommitInput value={arr.stride} onCommit={(stride) => setArr({ ...arr, stride })} width={44} />
        <button className="btn small" onClick={() => void fromArray()} title="count, stride: entry i = *(array + i*stride)">Load</button>
        <span className="grow" />
        <IconButton tip="Close" onClick={onClose}><X size={14} /></IconButton>
      </div>
      {addrs.length < 2 ? (
        <div className="empty"><div className="empty-title">Add two or more instances.</div><div className="empty-hint">Every instance is read with the current layout; fields that differ are highlighted, fields equal everywhere are marked const.</div></div>
      ) : (
        <div className="vlist">
          <table className="table mono">
            <thead>
              <tr>
                <th style={{ width: 64 }}>Offset</th><th style={{ width: 70 }}>Type</th><th style={{ width: 120 }}>Name</th><th style={{ width: 50 }} />
                {addrs.map((a) => (
                  <th key={a} title={a}>{a.slice(2).toUpperCase()} <button className="row-action" onClick={() => setAddrs(addrs.filter((x) => x !== a))}>×</button></th>
                ))}
              </tr>
            </thead>
            <tbody>
              {fields.map((f, i) => {
                const vals = addrs.map((_, k) => (data[k] ? fieldValue(data[k]!, lay[i].offset, f.type) : "??"));
                const same = vals.every((v) => v === vals[0]);
                return (
                  <tr key={i}>
                    <td className="faint">{lay[i].offset.toString(16).toUpperCase().padStart(4, "0")}</td>
                    <td className="dim">{f.type}</td>
                    <td className="ellipsis">{f.name || <span className="faint">—</span>}</td>
                    <td>{same ? <span className="pill">const</span> : <span className="pill accent">diff</span>}</td>
                    {vals.map((v, k) => <td key={k} className="ellipsis" style={same ? { color: "var(--text-dim)" } : { color: "var(--warning)" }}>{v}</td>)}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
