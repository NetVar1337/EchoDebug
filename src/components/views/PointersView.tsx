import { useEffect, useState } from "react";
import { Pause, Play, Plus, X } from "lucide-react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { IconButton, NeedsAgent, Progress } from "../ui";

type Hop = { address: string; value: string };
type PathResult = { module: string; module_offset: number; offsets: number[] };
const hex = (n: number) => (n < 0 ? "-0x" + (-n).toString(16) : "0x" + n.toString(16));
const parseOff = (s: string) => {
  const t = s.trim();
  const neg = t.startsWith("-");
  const v = parseInt(t.replace(/^-/, "").replace(/^0x/i, ""), 16);
  return Number.isFinite(v) ? (neg ? -v : v) : 0;
};

function Chain() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const addWatch = useWatch((s) => s.addWatch);
  const [base, setBase] = useState(ui.chainAt?.base ?? "");
  const [offsets, setOffsets] = useState<string[]>(ui.chainAt?.offsets.map(hex) ?? ["0x0"]);
  const [hops, setHops] = useState<Hop[]>([]);
  const [final, setFinal] = useState<string | null>(null);
  const [live, setLive] = useState(true);

  useEffect(() => {
    if (ui.chainAt) {
      setBase(ui.chainAt.base);
      setOffsets(ui.chainAt.offsets.map(hex));
    }
  }, [ui.chainAt]);

  useEffect(() => {
    const b = parseAddress(base, modules);
    if (b === null) return;
    let alive = true;
    const walk = async () => {
      const r = await request<{ hops: Hop[]; final: string; ok: boolean }>("chain", { base: fmtAddr(b), offsets: offsets.map(parseOff) }).catch(() => null);
      if (!alive || !r) return;
      setHops(r.hops);
      setFinal(r.ok ? r.final : null);
    };
    void walk();
    const t = live ? setInterval(() => void walk(), 500) : undefined;
    return () => { alive = false; clearInterval(t); };
  }, [base, offsets, live, modules]);

  return (
    <div className="panel-section">
      <div className="label">Pointer chain · addr = *addr + offset</div>
      <div className="row">
        <input className="input mono grow" placeholder="game.exe+0x1A2B3C" value={base} onChange={(e) => setBase(e.target.value)} />
        <IconButton tip={live ? "Pause" : "Live"} onClick={() => setLive(!live)}>{live ? <Pause size={14} /> : <Play size={14} />}</IconButton>
      </div>
      {offsets.map((o, i) => (
        <div key={i} className="row">
          <span className="faint mono" style={{ width: 24 }}>{i + 1}</span>
          <input className="input mono" style={{ width: 120 }} value={o} onChange={(e) => setOffsets(offsets.map((x, j) => (j === i ? e.target.value : x)))} />
          <span className="mono dim ellipsis grow">{hops[i + 1] ? `→ ${hops[i + 1].address}` : ""}</span>
          <IconButton tip="Remove" onClick={() => setOffsets(offsets.filter((_, j) => j !== i))}><X size={12} /></IconButton>
        </div>
      ))}
      <div className="row">
        <button className="btn small" onClick={() => setOffsets([...offsets, "0x0"])}><Plus size={12} />offset</button>
        <span className="grow" />
        {final ? (
          <>
            <span className="mono accent link" onClick={() => ui.goMemory(final)}>{labelAddr(final, modules)}</span>
            <button className="btn small" onClick={() => addWatch(final, "i32", `${base} ${offsets.join(" ")}`)}>watch</button>
          </>
        ) : <span className="danger">broken chain</span>}
      </div>
      {hops.length > 0 && (
        <table className="table mono">
          <thead><tr><th>Hop</th><th>Address</th><th>*value</th></tr></thead>
          <tbody>{hops.map((h, i) => <tr key={i}><td className="faint">{i}</td><td>{labelAddr(h.address, modules)}</td><td className="dim">{h.value}</td></tr>)}</tbody>
        </table>
      )}
    </div>
  );
}

function Scan() {
  const ui = useUi();
  const progress = useConn((s) => s.progress);
  const [target, setTarget] = useState(ui.selected ?? "");
  const [depth, setDepth] = useState(3);
  const [maxOff, setMaxOff] = useState("0x400");
  const [results, setResults] = useState<PathResult[]>([]);
  const [busy, setBusy] = useState(false);
  const modules = useConn((s) => s.modules);
  const run = async () => {
    const t = parseAddress(target, modules);
    if (t === null) return log("warn", "ptrscan", `cannot parse ${target}`);
    setBusy(true);
    const r = await attempt("ptrscan", request<{ results: PathResult[]; truncated: boolean }>("pointer_scan", { target: fmtAddr(t), max_depth: depth, max_offset: parseOff(maxOff), max_results: 500 }));
    setBusy(false);
    if (r) {
      setResults(r.results);
      log("info", "ptrscan", `${r.results.length} paths${r.truncated ? " (truncated)" : ""}`);
    }
  };
  return (
    <div className="panel-section">
      <div className="label">Pointer scan</div>
      <div className="row">
        <input className="input mono grow" placeholder="target address" value={target} onChange={(e) => setTarget(e.target.value)} />
        <select className="select" value={depth} onChange={(e) => setDepth(Number(e.target.value))}>{[1, 2, 3, 4, 5].map((d) => <option key={d} value={d}>depth {d}</option>)}</select>
        <input className="input mono" style={{ width: 80 }} value={maxOff} onChange={(e) => setMaxOff(e.target.value)} title="max offset per level" />
        <button className="btn primary" disabled={busy} onClick={() => void run()}>{busy ? "Scanning…" : "Scan"}</button>
      </div>
      {busy && progress && <Progress value={progress.done / Math.max(1, progress.total)} />}
      {results.length > 0 && (
        <table className="table mono">
          <thead><tr><th>Base</th><th>Offsets</th></tr></thead>
          <tbody>
            {results.map((r, i) => (
              <tr key={i} onClick={() => ui.set({ chainAt: { base: `${r.module}+${hex(r.module_offset)}`, offsets: r.offsets } })} title="load into chain resolver">
                <td className="link">{r.module}+{hex(r.module_offset)}</td>
                <td className="dim">{r.offsets.map(hex).join(" → ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function PointersView() {
  return (
    <NeedsAgent ext>
      <div className="vlist" style={{ height: "100%" }}>
        <Chain />
        <Scan />
      </div>
    </NeedsAgent>
  );
}
