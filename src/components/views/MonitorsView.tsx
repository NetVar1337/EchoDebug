// Module load/unload timeline and page-change monitors (relay-side; any backend).
import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { fmtAddr, labelAddr, parseAddress, toBig } from "@/lib/hex";
import { request } from "@/lib/client";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useMonitors } from "@/store/monitors";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent } from "../ui";

const time = (ts: number) => new Date(ts).toLocaleTimeString();

type DiffRange = { address: string; size: number; old: string; new: string };

/** Backend-side snapshots: copy a range (or a module) once, then list only what changed. */
function SnapshotDiff() {
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [where, setWhere] = useState("");
  const [size, setSize] = useState("0x10000");
  const [taken, setTaken] = useState<string | null>(null);
  const [diff, setDiff] = useState<{ changed_bytes: number; ranges: DiffRange[]; truncated: boolean } | null>(null);
  const take = async () => {
    const m = modules.find((x) => x.name.toLowerCase() === where.trim().toLowerCase());
    const a = m ? null : parseAddress(where, modules);
    if (!m && a === null) return log("warn", "snapshot", "a module name or an address");
    const r = await attempt("mem_snapshot", request<{ address: string; size: number }>("mem_snapshot", m ? { name: "ui", module: m.name } : { name: "ui", address: fmtAddr(a!), size: Number(size) }));
    if (r) { setTaken(`${r.address} (${(r.size / 1024).toFixed(0)} KiB)`); setDiff(null); }
  };
  const compare = async (update: boolean) => {
    const r = await attempt("mem_diff", request<{ changed_bytes: number; ranges: DiffRange[]; truncated: boolean }>("mem_diff", { name: "ui", update, max_ranges: 500 }));
    if (r) setDiff(r);
  };
  return (
    <div className="panel-section">
      <div className="label">Snapshot diff <span className="faint">(kept in the backend; only changes travel)</span></div>
      <div className="row">
        <input className="input mono grow" placeholder="module name or address" value={where} onChange={(e) => setWhere(e.target.value)} />
        <input className="input mono" style={{ width: 90 }} value={size} onChange={(e) => setSize(e.target.value)} title="size (ignored for a module)" />
        <button className="btn small primary" onClick={() => void take()}>Snapshot</button>
      </div>
      {taken && (
        <div className="row">
          <span className="faint grow" style={{ fontSize: 12 }}>baseline {taken}</span>
          <button className="btn small" onClick={() => void compare(false)}>What changed?</button>
          <button className="btn small" onClick={() => void compare(true)} title="show changes and make the current contents the new baseline">Diff &amp; rebase</button>
        </div>
      )}
      {diff && (
        <table className="table mono"><tbody>
          <tr><td colSpan={3} className="faint">{diff.changed_bytes} bytes changed in {diff.ranges.length}{diff.truncated ? "+" : ""} ranges</td></tr>
          {diff.ranges.map((d) => <tr key={d.address}><td className="link" style={{ width: 170 }} onClick={() => ui.goMemory(d.address)}>{labelAddr(d.address, modules)}</td><td className="faint">{d.size}b</td><td className="ellipsis"><span className="faint">{d.old}</span> → <span className="warn">{d.new}</span></td></tr>)}
        </tbody></table>
      )}
    </div>
  );
}

/** The running job, per-verb stats and the write journal of the backend (agent or local). */
function Backend() {
  const [stats, setStats] = useState<{ verbs: { verb: string; calls: number; ms: number }[]; job?: string; job_ms?: number; queued_events?: number } | null>(null);
  const [journal, setJournal] = useState<{ t: number | string; kind: string; address: string; old: string; new: string }[] | null>(null);
  const loadStats = async () => setStats((await attempt("stats", request<NonNullable<typeof stats>>("stats"))) ?? null);
  const loadJournal = async () => setJournal((await attempt("journal", request<{ entries: NonNullable<typeof journal> }>("journal", { limit: 100 })))?.entries ?? null);
  return (
    <div className="panel-section">
      <div className="row">
        <span className="label grow">Backend</span>
        <button className="btn small" onClick={() => void attempt("cancel", request("cancel")).then(() => log("info", "backend", "cancel requested"))}>Cancel running job</button>
        <button className="btn small" onClick={() => void loadStats()}>Stats</button>
        <button className="btn small" onClick={() => void loadJournal()}>Write journal</button>
      </div>
      {stats && (
        <table className="table mono"><tbody>
          {stats.job ? <tr><td colSpan={3} className="warn">running {stats.job} for {Math.round((stats.job_ms ?? 0) / 1000)} s</td></tr> : null}
          {[...stats.verbs].sort((a, b) => b.ms - a.ms).slice(0, 15).map((v) => <tr key={v.verb}><td>{v.verb}</td><td className="faint">{v.calls}×</td><td className="faint">{v.ms} ms</td></tr>)}
        </tbody></table>
      )}
      {journal && (
        <table className="table mono"><tbody>
          {journal.length === 0 && <tr><td className="faint">no writes or freezes recorded</td></tr>}
          {journal.slice().reverse().map((j, i) => <tr key={i}><td className="faint" style={{ width: 60 }}>{j.kind}</td><td>{j.address}</td><td className="ellipsis"><span className="faint">{j.old}</span> → {j.new}</td></tr>)}
        </tbody></table>
      )}
    </div>
  );
}

export default function MonitorsView() {
  const mon = useMonitors();
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [addr, setAddr] = useState("");
  const [size, setSize] = useState("0x1000");
  const [label, setLabel] = useState("");
  useEffect(() => void mon.refresh(), []);

  const add = async () => {
    const a = parseAddress(addr, modules);
    const n = Number(size);
    if (a === null || !Number.isFinite(n) || n <= 0) return log("warn", "monitor", "address and size required");
    await attempt("page_monitor", mon.watchPages(fmtAddr(a), n, label));
  };
  const watchCode = async () => {
    const m = modules.find((x) => x.base === useConn.getState().target?.base) ?? modules[0];
    if (!m) return;
    await attempt("page_monitor", mon.watchPages(m.base, Math.min(m.size, 64 << 20), `${m.name} image`));
  };

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "460px" }}>
        <div className="list-col vlist">
          <div className="panel-section">
            <div className="row">
              <span className="label grow">Module load / unload</span>
              <label className="row"><input type="checkbox" checked={mon.moduleOn} onChange={(e) => void attempt("module_monitor", mon.setModuleMonitor(e.target.checked))} />monitor</label>
              <button className="btn small" onClick={() => mon.clear()}>Clear</button>
            </div>
            <div className="faint" style={{ fontSize: 12 }}>Polls the module list every second; loads and unloads become events (also MCP notifications) and refresh the module list.</div>
          </div>
          <table className="table mono"><tbody>
            {mon.timeline.length === 0 && <tr><td className="faint">no module events yet</td></tr>}
            {mon.timeline.map((e, i) => (
              <tr key={i}><td className="faint" style={{ width: 80 }}>{time(e.ts)}</td><td className={e.event === "module_loaded" ? "ok" : "warn"} style={{ width: 24 }}>{e.event === "module_loaded" ? "+" : "−"}</td><td className="link" onClick={() => ui.goMemory(e.base)}>{e.name}</td><td className="faint">{e.base}</td></tr>
            ))}
          </tbody></table>
          <SnapshotDiff />
          <Backend />
        </div>
        <div className="list-col vlist" style={{ borderRight: "none" }}>
          <div className="panel-section">
            <div className="label">Page-change monitor <span className="faint">(4 KiB page hashes each second, 64 MiB total)</span></div>
            <div className="row">
              <input className="input mono grow" placeholder="address · module+0x…" value={addr} onChange={(e) => setAddr(e.target.value)} />
              <input className="input mono" style={{ width: 90 }} placeholder="size" value={size} onChange={(e) => setSize(e.target.value)} />
            </div>
            <div className="row">
              <input className="input grow" placeholder="label (optional)" value={label} onChange={(e) => setLabel(e.target.value)} />
              <button className="btn small primary" onClick={() => void add()}>Watch</button>
              <button className="btn small" title="Watch the main module's whole image (unpacking, self-modifying code)" onClick={() => void watchCode()}>Watch main image</button>
            </div>
            {mon.pages.map((p) => (
              <div key={p.address} className="row mono">
                <span className="link grow" onClick={() => ui.goMemory(p.address)}>{p.label || labelAddr(p.address, modules)} <span className="faint">{(p.size / 1024).toFixed(0)} KiB</span></span>
                <span className={p.changes ? "warn" : "faint"}>{p.changes} changes</span>
                <IconButton tip="Stop watching" onClick={() => void attempt("page_monitor", mon.unwatchPages(p.address))}><X size={12} /></IconButton>
              </div>
            ))}
          </div>
          <table className="table mono"><tbody>
            {mon.pageEvents.length === 0 && <tr><td className="faint">no page changes yet</td></tr>}
            {mon.pageEvents.map((e, i) => (
              <tr key={i}>
                <td className="faint" style={{ width: 80 }}>{time(e.ts)}</td>
                <td>{e.label || e.address}</td>
                <td>{e.count} page{e.count === 1 ? "" : "s"}</td>
                <td className="ellipsis">{e.pages.slice(0, 6).map((p) => <span key={p} className="link" style={{ marginRight: 6 }} onClick={() => ui.goMemory(p)}>{labelAddr(toBig(p), modules)}</span>)}</td>
              </tr>
            ))}
          </tbody></table>
        </div>
      </div>
    </NeedsAgent>
  );
}
