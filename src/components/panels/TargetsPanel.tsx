import { useEffect, useMemo, useState } from "react";
import { RefreshCw, Search, Unplug } from "lucide-react";
import { request } from "@/lib/client";
import { useConn } from "@/store/conn";
import { attempt } from "@/store/output";
import { IconButton, Panel } from "../ui";

type Proc = { pid: number; name: string; path: string; memory: number };

export default function TargetsPanel() {
  const c = useConn();
  const [procs, setProcs] = useState<Proc[]>([]);
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState<number | null>(null);

  const load = async () => {
    const r = await attempt("processes", request<{ processes: Proc[] }>("processes"));
    if (r) setProcs(r.processes);
  };
  useEffect(() => {
    if (c.relay) void load();
  }, [c.relay]);

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return f ? procs.filter((p) => p.name.toLowerCase().includes(f) || String(p.pid).includes(f)) : procs;
  }, [procs, filter]);

  const attach = async (p: Proc) => {
    setBusy(p.pid);
    await attempt("attach", c.attach({ pid: p.pid, name: p.name }));
    setBusy(null);
  };

  return (
    <Panel
      title={<>Targets <span className="faint">{procs.length} processes</span></>}
      actions={
        <>
          {c.target && <IconButton tip="Detach" onClick={() => void attempt("detach", c.detach())}><Unplug size={14} /></IconButton>}
          <IconButton tip="Refresh" onClick={() => void load()}><RefreshCw size={14} /></IconButton>
        </>
      }
    >
      <div className="panel-section">
        <div className="row"><span className="dot" data-state={c.relay ? "ok" : "bad"} /> Relay {c.relay ? "running" : "offline"}{c.relayError && <span className="danger"> · {c.relayError}</span>}</div>
        <div className="row"><span className="dot" data-state={c.ext ? "ok" : "bad"} /> Agent {c.ext ? `v${c.extVersion}` : "not loaded"}</div>
        <div className="row"><span className="dot" data-state={c.agent ? "ok" : "bad"} /> Memory server {c.agent ? "connected" : "waiting for attach"}</div>
        {!c.ext && <div className="faint" style={{ fontSize: 12 }}>Load <span className="mono">echo_debug.as</span> in Echo; the app installs it to <span className="mono">%APPDATA%\scripts</span>.</div>}
        <label className="search"><Search size={13} /><input placeholder="Filter processes…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
      </div>
      <div className="panel-body">
        <table className="table">
          <colgroup><col style={{ width: 62 }} /><col /><col style={{ width: 64 }} /></colgroup>
          <thead><tr><th>PID</th><th>Name</th><th /></tr></thead>
          <tbody>
            {shown.map((p) => (
              <tr key={p.pid} data-selected={c.target?.pid === p.pid} onDoubleClick={() => void attach(p)} title={p.path}>
                <td className="mono dim">{p.pid}</td>
                <td>{p.name}</td>
                <td><button className="row-action" disabled={!c.ext || busy !== null} onClick={() => void attach(p)}>{busy === p.pid ? "…" : "Attach"}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
