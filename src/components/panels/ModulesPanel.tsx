import { useMemo, useState } from "react";
import { RefreshCw, Search } from "lucide-react";
import { request } from "@/lib/client";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent, Panel } from "../ui";
import { ModuleArchBadge } from "../ArchBadge";

export default function ModulesPanel() {
  const { modules, refreshModules } = useConn();
  const ui = useUi();
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const shown = useMemo(() => modules.filter((m) => m.name.toLowerCase().includes(filter.toLowerCase())), [modules, filter]);
  const dump = async (name: string) => {
    const r = await attempt("dump", request<{ path: string }>("dump", { module: name, filename: name.replace(/\.[^.]+$/, "") + "_dump.bin" }));
    if (r) log("info", "dump", `dumped ${name} → ${r.path}`);
  };
  return (
    <Panel title={<>Modules <span className="faint">{modules.length}</span></>} actions={<IconButton tip="Refresh" onClick={() => void refreshModules()}><RefreshCw size={14} /></IconButton>}>
      <NeedsAgent>
        <div className="panel-section">
          <label className="search"><Search size={13} /><input placeholder="Filter modules…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
          {sel && (
            <div className="row wrap">
              <button className="btn small" onClick={() => ui.goModule(sel, "pe")}>PE</button>
              <button className="btn small" onClick={() => ui.goModule(sel, "strings")}>Strings</button>
              <button className="btn small" onClick={() => { ui.set({ module: sel }); const m = modules.find((x) => x.name === sel); if (m) ui.goDisasm(m.base); }}>Functions</button>
              <button className="btn small" onClick={() => { const m = modules.find((x) => x.name === sel); if (m) ui.goMemory(m.base); }}>Memory</button>
              <button className="btn small" onClick={() => { ui.set({ module: sel }); ui.setTab("crypto"); }}>Crypto</button>
              <button className="btn small" onClick={() => { ui.set({ module: sel }); ui.setTab("caves"); }}>Caves</button>
              <button className="btn small" onClick={() => { ui.set({ module: sel }); ui.setTab("dotnet"); }}>.NET</button>
              <button className="btn small" onClick={() => void dump(sel)}>Dump</button>
            </div>
          )}
        </div>
        <div className="panel-body">
          <table className="table">
            <colgroup><col /><col style={{ width: 120 }} /><col style={{ width: 70 }} /></colgroup>
            <thead><tr><th>Name</th><th>Base</th><th>Size</th></tr></thead>
            <tbody>
              {shown.map((m) => (
                <tr key={m.base} data-selected={sel === m.name || ui.module === m.name} onClick={() => { setSel(m.name); ui.select(m.base); }} onDoubleClick={() => ui.goModule(m.name, "pe")}>
                  <td title={m.name}>{m.name}<ModuleArchBadge module={m} />{ui.module === m.name && <span className="pill accent" style={{ marginLeft: 6 }}>focused</span>}</td>
                  <td className="mono dim">{m.base.replace(/^0x/, "").toUpperCase()}</td>
                  <td className="mono faint">{(m.size / 1024).toFixed(0)}K</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </NeedsAgent>
    </Panel>
  );
}
