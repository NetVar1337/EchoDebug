// Names & comments panel: the user's own symbol names and annotations,
// with IDA / Ghidra script export.
import { useMemo, useState } from "react";
import { Download, Search, Trash2 } from "lucide-react";
import { labelAddr } from "@/lib/hex";
import { toGhidra, toIdc, useNames } from "@/store/names";
import { useConn } from "@/store/conn";
import { useUi } from "@/store/ui";
import { copy, IconButton, Panel } from "../ui";

export default function NamesPanel() {
  const names = useNames();
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [filter, setFilter] = useState("");

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return names.names
      .filter((n) => !f || n.name.toLowerCase().includes(f) || n.comment.toLowerCase().includes(f) || n.address.includes(f))
      .sort((a, b) => a.address.localeCompare(b.address));
  }, [names.names, filter]);

  const download = (text: string, filename: string) => {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: filename });
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Panel title={<>Names & Comments <span className="faint">{names.names.length}</span></>}>
      <div className="panel-section">
        <label className="search"><Search size={13} /><input placeholder="Filter names…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
        <div className="row wrap">
          <button className="btn small" disabled={!names.names.length} onClick={() => download(toIdc(names.names), "echodebug-names.idc")}>
            <Download size={12} /> IDA
          </button>
          <button className="btn small" disabled={!names.names.length} onClick={() => download(toGhidra(names.names), "EchoDebugNames.java")}>
            <Download size={12} /> Ghidra
          </button>
          <button className="btn small" disabled={!names.names.length} onClick={() => void copy(JSON.stringify(names.names, null, 2))}>Copy JSON</button>
        </div>
        <div className="faint" style={{ fontSize: 12 }}>
          Press <span className="mono">N</span> in the disassembly to rename the current function, <span className="mono">;</span> to comment it.
        </div>
      </div>
      <div className="panel-body">
        {shown.length === 0 ? (
          <div className="panel-section faint">No names yet. Rename a function in the disassembly view to start.</div>
        ) : (
          <table className="table">
            <colgroup><col style={{ width: 130 }} /><col /><col style={{ width: 60 }} /></colgroup>
            <thead><tr><th>Address</th><th>Name / comment</th><th /></tr></thead>
            <tbody>
              {shown.map((n) => (
                <tr key={n.address} data-selected={ui.selected === n.address} onClick={() => ui.select(n.address)} onDoubleClick={() => ui.goDisasm("0x" + n.address)}>
                  <td className="mono dim">{labelAddr("0x" + n.address, modules)}</td>
                  <td>
                    {n.name && <span className="accent mono">{n.name}</span>}
                    {n.comment && <span className="faint" style={{ marginLeft: 6 }}>{n.comment}</span>}
                  </td>
                  <td><IconButton tip="Remove" onClick={() => names.remove(n.address)}><Trash2 size={12} /></IconButton></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
}
