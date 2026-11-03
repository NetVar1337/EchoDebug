// "Find what writes / accesses this address" (Cheat Engine style): a hardware watchpoint on one
// debug register of every thread; each instruction that hits it is listed with its hit count and
// the registers of its last hit. Served by the native debugger (ptrace / Win32), started from the
// Memory view or Watchlist context menu or from here.
import { useCallback, useEffect, useMemo, useState } from "react";
import { Eye, RefreshCw, Square } from "lucide-react";
import { request } from "@/lib/client";
import { sortHits, type Trace, type TraceHit, type TraceKind } from "@/lib/debugger";
import { fmtAddr, labelAddr, parseAddress, showAddr } from "@/lib/hex";
import { onAgentEvent, useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, Empty, IconButton } from "../ui";
import { findAccesses } from "../accessMenu";
import { DebuggerGate } from "../DebuggerGate";

const kRegs = ["rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags"];

export default function AccessFinderView() {
  const { modules } = useConn();
  const ui = useUi();
  const [traces, setTraces] = useState<Trace[]>([]);
  const [addr, setAddr] = useState("");
  const [size, setSize] = useState(4);
  const [kind, setKind] = useState<TraceKind>("write");
  const [sel, setSel] = useState<{ slot: number; address: string } | null>(null);

  const refresh = useCallback(async () => {
    const r = await request<{ traces: Trace[] }>("dbg_trace_results", {}, true).catch(() => null);
    if (r) setTraces(r.traces);
  }, []);
  const active = traces.some((t) => t.active);
  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => void refresh(), 500);
    return () => clearInterval(t);
  }, [active, refresh]);
  useEffect(() => onAgentEvent((f) => {
    if (f.event === "dbg_access" || f.event === "dbg_exit") void refresh();
  }), [refresh]);

  const start = async () => {
    const a = parseAddress(addr || ui.selected || "", modules);
    if (a === null) return log("warn", "access finder", `cannot parse ${addr || "(empty)"}`);
    await findAccesses(fmtAddr(a), size, kind);
    await refresh();
  };
  const stop = async (slot?: number) => {
    const r = await attempt("access finder", request<{ traces: Trace[]; detached?: boolean }>("dbg_trace_stop", slot === undefined ? {} : { slot }));
    if (r) {
      setTraces(r.traces ?? []);
      if (r.detached) log("info", "access finder", "stopped; the debugger detached");
    }
  };

  const selected = useMemo(() => {
    const t = traces.find((x) => x.slot === sel?.slot);
    return t?.hits.find((h) => h.address === sel?.address) ?? null;
  }, [traces, sel]);

  return (
    <DebuggerGate>
      <div className="split-h" style={{ gridTemplateColumns: "minmax(0, 1fr) 230px" }}>
        <div className="list-col">
          <div className="toolbar">
            <CommitInput value={addr} placeholder={ui.selected ? `address (selection ${ui.selected})` : "address · module+0x…"} onCommit={setAddr} width={220} />
            <select className="select" value={size} onChange={(e) => setSize(Number(e.target.value))} title="bytes watched">{[1, 2, 4, 8].map((s) => <option key={s} value={s}>{s} B</option>)}</select>
            <select className="select" value={kind} onChange={(e) => setKind(e.target.value as TraceKind)}>
              <option value="write">writes</option>
              <option value="access">accesses (read + write)</option>
            </select>
            <button className="btn small primary" onClick={() => void start()}><Eye size={13} /> Find what {kind === "write" ? "writes" : "accesses"}</button>
            <span className="grow" />
            <IconButton tip="Refresh" onClick={() => void refresh()}><RefreshCw size={14} /></IconButton>
            <IconButton tip="Stop all traces" onClick={() => void stop()} disabled={!active}><Square size={14} /></IconButton>
          </div>
          <div className="vlist">
            {traces.length === 0 && (
              <Empty icon={<Eye size={26} strokeWidth={1.5} />} title="No access traces."
                hint="Right-click a byte in the Memory view or a Watchlist entry and pick “Find what writes this address”, or enter an address above. A debug register watches it on every thread while the process keeps running; each instruction that touches it is listed here." />
            )}
            {traces.map((t) => (
              <div key={t.slot}>
                <div className="toolbar">
                  <span className={`pill${t.active ? " accent" : ""}`}>DR{t.slot} · {t.active ? "running" : "stopped"}</span>
                  <span className="mono">{t.kind === "write" ? "writes to" : "accesses of"} <span className="link" onClick={() => ui.goMemory(t.address)}>{labelAddr(t.address, modules)}</span> ({t.size} B{t.watch.len !== t.size || t.watch.address !== t.address ? `, watching ${t.watch.len} B at ${t.watch.address}` : ""})</span>
                  <span className="grow" />
                  <span className="faint" style={{ fontSize: 12 }}>{t.total} hit{t.total === 1 ? "" : "s"} · {t.hits.length} instruction{t.hits.length === 1 ? "" : "s"}</span>
                  {t.active && <button className="btn small" onClick={() => void stop(t.slot)}><Square size={12} /> Stop</button>}
                </div>
                <table className="table mono access-hits">
                  <colgroup><col style={{ width: 52 }} /><col style={{ width: 150 }} /><col /><col style={{ width: 60 }} /></colgroup>
                  <thead><tr><th>Count</th><th>Address</th><th>Instruction</th><th>Thread</th></tr></thead>
                  <tbody>
                    {sortHits(t.hits).map((h: TraceHit) => (
                      <tr key={h.address} data-selected={sel?.slot === t.slot && sel.address === h.address} onClick={() => setSel({ slot: t.slot, address: h.address })} onDoubleClick={() => ui.goDisasm(h.address)} title="double-click: disassembly">
                        <td className="accent">{h.count}</td>
                        <td><span className="link" onClick={(e) => { e.stopPropagation(); ui.goDisasm(h.address); }}>{labelAddr(h.address, modules) || showAddr(h.address)}</span></td>
                        <td className="ellipsis">{h.text}</td>
                        <td className="faint">{h.tid}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {t.hits.length === 0 && <div className="panel-section faint">{t.active ? "Waiting for the first access…" : "Nothing touched it."}</div>}
              </div>
            ))}
          </div>
        </div>
        <div className="list-col" style={{ borderRight: "none", overflow: "auto" }}>
          <div className="toolbar"><span className="panel-title">Last hit</span></div>
          {!selected ? (
            <div className="faint" style={{ padding: 8, fontSize: 12 }}>Select an instruction to see the registers of its last hit.</div>
          ) : (
            <>
              <div className="panel-section">
                <span className="link mono" onClick={() => ui.goDisasm(selected.address)}>{labelAddr(selected.address, modules)}</span>
                <span className="mono">{selected.text}</span>
                <span className="faint">{selected.count} hits · thread {selected.tid} · last {new Date(selected.last).toLocaleTimeString()}</span>
              </div>
              <table className="table mono"><tbody>
                {kRegs.filter((k) => selected.regs[k]).map((k) => (
                  <tr key={k}>
                    <td className="faint" style={{ width: 60 }}>{k}</td>
                    <td>{k === "rip" || k === "eflags" ? selected.regs[k] : <span className="link" onClick={() => ui.goMemory(selected.regs[k])}>{selected.regs[k]}</span>}</td>
                  </tr>
                ))}
              </tbody></table>
            </>
          )}
        </div>
      </div>
    </DebuggerGate>
  );
}
