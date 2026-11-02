// Module load/unload timeline and page-change monitors (relay-side; any backend).
import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { fmtAddr, labelAddr, parseAddress, toBig } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useMonitors } from "@/store/monitors";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent } from "../ui";

const time = (ts: number) => new Date(ts).toLocaleTimeString();

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
