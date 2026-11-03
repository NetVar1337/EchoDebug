// Time-travel trace: record an emulator session or a ptrace'd thread instruction by instruction,
// then scrub through it — registers and memory reconstructed at any position, "when did this
// byte last change?", every write / read / execution, a register over time, and where a value
// came from (dataflow walked back through movs and arithmetic). Backed by the relay's trace_*
// verbs; recordings are saved in <config>/EchoDebug/traces and export as .edt files.
import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, Circle, Download, History, SkipBack, SkipForward, Square, Trash2, Upload, X } from "lucide-react";
import { EchoError, request, type Frame } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress } from "@/lib/hex";
import { saveBinary } from "@/lib/save";
import {
  b64ToBytes, bytesToB64, hexRows, kTraceRegs, locText, nearestStep, sparkline, taintTree, traceQuery, writtenBy,
  type StepDetail, type StepLine, type TaintHop, type TraceSummary, type WriteHit,
} from "@/lib/trace";
import { onAgentEvent, useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent, Progress } from "../ui";

type Hits = { title: string; rows: { step: number; label: string; detail?: string }[]; total: number };
const kMemSize = 128;
const kWindow = 200;

export default function TraceView() {
  const ui = useUi();
  const { backend, modules } = useConn();
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [cur, setCur] = useState<TraceSummary | null>(null);
  const [pos, setPos] = useState(0);
  // recording
  const [source, setSource] = useState<"emu" | "ptrace">("emu");
  const [start, setStart] = useState("");
  const [maxSteps, setMaxSteps] = useState(10000);
  const [until, setUntil] = useState("");
  const [name, setName] = useState("");
  const [recording, setRecording] = useState<number | null>(null);
  // the view at pos
  const [regs, setRegs] = useState<Record<string, string>>({});
  const [last, setLast] = useState<StepDetail | null>(null);
  const [next, setNext] = useState<StepDetail | null>(null);
  const [lines, setLines] = useState<{ from: number; steps: StepLine[] }>({ from: 0, steps: [] });
  const [memAt, setMemAt] = useState("");
  const [mem, setMem] = useState<{ base: bigint; data: string } | null>(null);
  // queries
  const [qAddr, setQAddr] = useState("");
  const [qSize, setQSize] = useState(8);
  const [bps, setBps] = useState<string[]>([]);
  const [bpText, setBpText] = useState("");
  const [hits, setHits] = useState<Hits | null>(null);
  const [taint, setTaint] = useState<{ what: string; hops: TaintHop[] } | null>(null);
  const [series, setSeries] = useState<{ reg: string; points: [number, string][] } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const seq = useRef(0);
  const tid = cur?.trace_id ?? null;
  const steps = cur?.steps ?? 0;

  const addr = (s: string) => {
    const a = parseAddress(s.trim(), modules);
    if (a === null) log("warn", "trace", `not an address: ${s}`);
    return a === null ? null : fmtAddr(a);
  };
  const label = (a: string) => labelAddr(a, modules);

  const refreshList = async () => {
    const r = await request<{ traces: TraceSummary[]; current: string | null }>("trace_list").catch(() => null);
    if (r) setTraces(r.traces);
    return r;
  };
  const open = async (id: string | null, at?: number) => {
    const r = await attempt("trace_info", request<TraceSummary & Frame>("trace_info", id ? { trace: id } : {}));
    if (!r || !r.trace_id) return;
    setCur(r);
    setPos(Math.min(at ?? 0, r.steps));
    setHits(null);
    setTaint(null);
    setSeries(null);
    const first = r.initial_regs?.rsp;
    if (first && !memAt) setMemAt(first);
  };

  useEffect(() => {
    void refreshList().then((r) => { if (r?.current) void open(r.current); });
    return onAgentEvent((f: Frame) => {
      if (f.event === "trace_progress") setRecording(Number(f.steps));
      else if (f.event === "trace_done") {
        setRecording(null);
        void refreshList();
        if (typeof f.trace_id === "string") void open(f.trace_id);
      }
    });
  }, []);

  // everything shown at the current position
  useEffect(() => {
    if (!tid) return;
    const my = ++seq.current;
    const stale = () => my !== seq.current;
    const t = setTimeout(async () => {
      const [r, l, n] = await Promise.all([
        traceQuery<{ regs: Record<string, string> }>(tid, "reg_at", { pos }).catch(() => null),
        pos > 0 ? traceQuery<StepDetail>(tid, "step", { pos: pos - 1 }).catch(() => null) : Promise.resolve(null),
        pos < steps ? traceQuery<StepDetail>(tid, "step", { pos }).catch(() => null) : Promise.resolve(null),
      ]);
      if (stale()) return;
      if (r) setRegs(r.regs);
      setLast(l);
      setNext(n);
      if (pos < lines.from || pos >= lines.from + lines.steps.length - 10 || !lines.steps.length) {
        const from = Math.max(0, pos - 40);
        const s = await traceQuery<{ steps: StepLine[] }>(tid, "steps", { from, count: kWindow }).catch(() => null);
        if (!stale() && s) setLines({ from, steps: s.steps });
      }
      const m = memAt ? addr(memAt) : null;
      if (m) {
        const d = await traceQuery<{ data: string }>(tid, "mem_at", { pos, address: m, size: kMemSize }).catch(() => null);
        if (!stale() && d) setMem({ base: BigInt(m), data: d.data });
      }
    }, 40);
    return () => clearTimeout(t);
  }, [tid, pos, memAt]);

  const go = (p: number) => setPos(Math.max(0, Math.min(steps, p)));

  const record = async () => {
    const args: Record<string, unknown> = { source, max_steps: maxSteps, name: name || undefined };
    if (until.trim()) { const u = addr(until); if (!u) return; args.until = u; }
    if (source === "emu" && start.trim()) { const s = addr(start); if (!s) return; args.start = s; }
    if (source === "ptrace") {
      const st = await request<{ active: boolean }>("dbg_status", {}, true).catch(() => null);
      if (!st?.active && !(await attempt("dbg_attach", request("dbg_attach")))) return;
    }
    setRecording(0);
    try {
      const r = await request<{ trace: TraceSummary }>("trace_record", args);
      log("info", "trace", `recorded ${r.trace.steps} steps (${r.trace.stop_reason})`);
      await refreshList();
      await open(r.trace.trace_id);
    } catch (e) {
      if (e instanceof EchoError && e.code === 2003) log("info", "trace", "still recording; the trace opens when it finishes");
      else log("error", "trace_record", (e as Error).message);
    } finally {
      setRecording(null);
    }
  };

  const doExport = async (t: TraceSummary) => {
    const r = await attempt("trace_export", request<{ data: string; name: string }>("trace_export", { trace: t.trace_id }));
    if (r) await saveBinary(`${(r.name || t.trace_id).replace(/[^\w.-]+/g, "_")}.edt`, b64ToBytes(r.data));
  };
  const doImport = async (f: File) => {
    const data = bytesToB64(new Uint8Array(await f.arrayBuffer()));
    const r = await attempt("trace_import", request<TraceSummary & Frame>("trace_import", { data, name: f.name.replace(/\.edt$/, "") }));
    if (r) { await refreshList(); await open(r.trace_id); }
  };
  const doDelete = async (t: TraceSummary) => {
    if (!window.confirm(`Delete trace ${t.name || t.trace_id}?`)) return;
    await attempt("trace_delete", request("trace_delete", { trace: t.trace_id }));
    if (t.trace_id === tid) setCur(null);
    await refreshList();
  };

  // ---- queries --------------------------------------------------------------------------------
  const range = () => { const a = addr(qAddr); return a ? { address: a, size: qSize } : null; };
  const lastChange = async (a: string, size: number) => {
    const r = await attempt("trace_query", traceQuery<{ write: WriteHit | null }>(tid, "last_write", { address: a, size, pos }));
    if (!r) return;
    if (!r.write) return log("info", "trace", `${a} did not change before step ${pos}${pos < steps ? " (try later in the trace)" : ""}`);
    log("info", "trace", `${a} last changed at step ${r.write.step}: ${r.write.text ?? ""} (${r.write.old} → ${r.write.new})`);
    go(r.write.step + 1);
  };
  const listWrites = async () => {
    const q = range(); if (!q) return;
    const r = await attempt("trace_query", traceQuery<{ writes: WriteHit[]; total: number }>(tid, "writes_to", { ...q, limit: 1000 }));
    if (r) setHits({ title: `writes to ${q.address}..+${q.size}`, total: r.total, rows: r.writes.map((w) => ({ step: w.step, label: `${label(w.pc)}  [${w.address}]`, detail: `${w.old} → ${w.new}` })) });
  };
  const listReads = async () => {
    const q = range(); if (!q) return;
    const r = await attempt("trace_query", traceQuery<{ reads: { step: number; pc: string; address: string; data: string }[]; total: number }>(tid, "reads_of", { ...q, limit: 1000 }));
    if (r) setHits({ title: `reads of ${q.address}..+${q.size}`, total: r.total, rows: r.reads.map((w) => ({ step: w.step, label: `${label(w.pc)}  [${w.address}]`, detail: w.data })) });
  };
  const listExecs = async (a: string | null) => {
    if (!a) return;
    const r = await attempt("trace_query", traceQuery<{ steps: number[]; total: number }>(tid, "executions_of", { address: a, limit: 2000 }));
    if (r) setHits({ title: `executions of ${label(a)}`, total: r.total, rows: r.steps.map((s) => ({ step: s, label: `step ${s}` })) });
  };
  const whereFrom = async (what: { reg: string } | { address: string; size: number }) => {
    const r = await attempt("trace_query", traceQuery<{ hops: TaintHop[] }>(tid, "taint", { ...what, pos, max_hops: 48 }));
    if (r) setTaint({ what: "reg" in what ? what.reg : `[${what.address}]`, hops: r.hops });
  };
  const graph = async (reg: string) => {
    const r = await attempt("trace_query", traceQuery<{ points: [number, string][] }>(tid, "reg_series", { reg, max: 600 }));
    if (r) setSeries({ reg, points: r.points });
  };
  const runTo = async (forward: boolean) => {
    if (!bps.length) return log("info", "trace", "add a breakpoint address first");
    const r = await Promise.all(bps.map((b) => traceQuery<{ step: number | null }>(tid, "seek", { address: b, pos, direction: forward ? "forward" : "back" }).catch(() => null)));
    const s = nearestStep(r.map((x) => x?.step), forward);
    if (s === null) log("info", "trace", `no breakpoint ${forward ? "after" : "before"} step ${pos}`);
    else go(s);
  };

  const written = useMemo(() => (mem ? writtenBy(last, mem.base, kMemSize) : new Set<number>()), [mem, last]);
  const spark = useMemo(() => (series ? sparkline(series.points, 300, 40) : null), [series]);

  const keys = (e: React.KeyboardEvent) => {
    if ((e.target as HTMLElement).tagName === "INPUT") return;
    if (e.key === "ArrowRight") { e.preventDefault(); go(pos + (e.shiftKey ? 100 : 1)); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); go(pos - (e.shiftKey ? 100 : 1)); }
  };

  return (
    <NeedsAgent ext>
      <div className="split-h" style={{ ["--fn-w" as string]: "380px" }} onKeyDown={keys} tabIndex={-1}>
        <div className="list-col vlist">
          <div className="panel-section">
            <div className="label">Record a trace</div>
            <div className="row">
              <select className="select grow" value={source} onChange={(e) => setSource(e.target.value as "emu" | "ptrace")}>
                <option value="emu">Emu Debugger session (Unicorn)</option>
                <option value="ptrace" disabled={backend !== "local"}>Debugger thread (ptrace, Linux)</option>
              </select>
            </div>
            {source === "emu" && <div className="row"><span style={{ width: 64 }}>start</span><input className="input mono grow" value={start} onChange={(e) => setStart(e.target.value)} placeholder="empty: the current session" /></div>}
            <div className="row"><span style={{ width: 64 }}>until</span><input className="input mono grow" value={until} onChange={(e) => setUntil(e.target.value)} placeholder="optional stop address" /></div>
            <div className="row">
              <span style={{ width: 64 }}>max steps</span>
              <input className="input mono" style={{ width: 100 }} type="number" min={1} value={maxSteps} onChange={(e) => setMaxSteps(Math.max(1, Number(e.target.value)))} />
              <input className="input grow" value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
            </div>
            <div className="row">
              {recording === null
                ? <button className="btn primary" onClick={() => void record()}><Circle size={12} /> Record</button>
                : <button className="btn" onClick={() => void request("trace_cancel")}><Square size={12} /> Stop</button>}
              <span className="grow" />
              <IconButton tip="Import a .edt trace file" onClick={() => fileRef.current?.click()}><Upload size={14} /></IconButton>
              <input ref={fileRef} type="file" accept=".edt" style={{ display: "none" }} onChange={(e) => { const f = e.target.files?.[0]; if (f) void doImport(f); e.target.value = ""; }} />
            </div>
            {recording !== null && <><Progress value={recording / maxSteps} /><div className="faint" style={{ fontSize: 12 }}>{recording.toLocaleString()} / {maxSteps.toLocaleString()} steps</div></>}
            <div className="faint" style={{ fontSize: 12 }}>
              {source === "emu" ? "Every instruction, register change, read and write of the emulator; the process is never touched." : "Single-steps the focused thread of the debugged process (it really runs). Kernel writes during system calls are not seen."}
            </div>
          </div>
          <div className="panel-section">
            <div className="label">Traces</div>
            {!traces.length && <div className="faint" style={{ fontSize: 12 }}>None recorded yet.</div>}
            {traces.map((t) => (
              <div key={t.trace_id} className="row" data-active={t.trace_id === tid}>
                <span className={`link grow ellipsis${t.trace_id === tid ? " accent" : ""}`} onClick={() => void open(t.trace_id)} title={new Date(t.created_ms).toLocaleString()}>
                  {t.name || t.trace_id} <span className="faint">· {t.source} · {t.steps?.toLocaleString()} steps</span>
                </span>
                <IconButton tip="Export as .edt" onClick={() => void doExport(t)}><Download size={12} /></IconButton>
                <IconButton tip="Delete" onClick={() => void doDelete(t)}><Trash2 size={12} /></IconButton>
              </div>
            ))}
          </div>
          {cur && (
            <>
              <div className="panel-section">
                <div className="label">Registers at {pos} <span className="faint">(changed by the last step highlighted; click: where from?)</span></div>
                <div className="kv mono">
                  {kTraceRegs.filter((r) => regs[r]).flatMap((r) => [
                    <span key={r + "k"} className="link" title="Plot over time" onClick={() => void graph(r)}>{r}</span>,
                    <span key={r} className={`link${last?.changes[r] ? " warn" : ""}`} title="Where did this value come from?" onClick={() => void whereFrom({ reg: r })}>{regs[r]}</span>,
                  ])}
                </div>
                {series && spark && (
                  <div className="panel-section">
                    <div className="row"><span className="grow">{series.reg} over the trace</span><span className="faint mono">{fmtAddr(spark.min)} … {fmtAddr(spark.max)}</span><IconButton tip="Close" onClick={() => setSeries(null)}><X size={12} /></IconButton></div>
                    <svg viewBox="0 0 300 40" preserveAspectRatio="none" style={{ width: "100%", height: 48, cursor: "pointer" }}
                      onClick={(e) => { const b = (e.currentTarget as SVGSVGElement).getBoundingClientRect(); go(Math.round(((e.clientX - b.left) / b.width) * steps)); }}>
                      <path d={spark.path} fill="none" stroke="var(--accent)" strokeWidth={1.2} vectorEffect="non-scaling-stroke" />
                      <line x1={(pos / Math.max(1, steps)) * 300} x2={(pos / Math.max(1, steps)) * 300} y1={0} y2={40} stroke="var(--text-faint)" strokeDasharray="2 2" vectorEffect="non-scaling-stroke" />
                    </svg>
                  </div>
                )}
              </div>
              <div className="panel-section">
                <div className="label">Query a range</div>
                <div className="row">
                  <input className="input mono grow" value={qAddr} onChange={(e) => setQAddr(e.target.value)} placeholder="address" onKeyDown={(e) => { if (e.key === "Enter") { const q = range(); if (q) void lastChange(q.address, q.size); } }} />
                  <input className="input mono" style={{ width: 56 }} type="number" min={1} value={qSize} onChange={(e) => setQSize(Math.max(1, Number(e.target.value)))} title="size in bytes" />
                </div>
                <div className="row wrap">
                  <button className="btn small" onClick={() => { const q = range(); if (q) void lastChange(q.address, q.size); }} title="Jump to the step that last changed it">Last change</button>
                  <button className="btn small" onClick={() => void listWrites()}>Writes</button>
                  <button className="btn small" onClick={() => void listReads()}>Reads</button>
                  <button className="btn small" onClick={() => { const q = range(); if (q) void whereFrom(q); }} title="Where did this value come from?">Where from?</button>
                  <button className="btn small" onClick={() => void listExecs(addr(qAddr))} title="Steps that executed this address">Executions</button>
                </div>
                <div className="label" style={{ marginTop: 8 }}>Breakpoints (run back / forward)</div>
                <div className="row">
                  <input className="input mono grow" value={bpText} placeholder="address" onChange={(e) => setBpText(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { const a = addr(bpText); if (a && !bps.includes(a)) setBps([...bps, a]); setBpText(""); } }} />
                </div>
                {bps.map((b) => (
                  <div key={b} className="row mono">
                    <span className="link grow" onClick={() => void listExecs(b)}>{label(b)}</span>
                    <IconButton tip="Remove" onClick={() => setBps(bps.filter((x) => x !== b))}><X size={12} /></IconButton>
                  </div>
                ))}
              </div>
              {hits && (
                <div className="panel-section">
                  <div className="row"><span className="grow">{hits.title} <span className="faint">· {hits.total}{hits.rows.length < hits.total ? ` (first ${hits.rows.length})` : ""}</span></span><IconButton tip="Close" onClick={() => setHits(null)}><X size={12} /></IconButton></div>
                  <div className="mono" style={{ fontSize: 12, maxHeight: 240, overflow: "auto" }}>
                    {hits.rows.map((h, i) => (
                      <div key={i} className={`row link${h.step === pos - 1 ? " accent" : ""}`} onClick={() => go(h.step + 1)}>
                        <span className="faint" style={{ width: 56 }}>#{h.step}</span><span className="grow ellipsis">{h.label}</span>{h.detail && <span className="faint ellipsis">{h.detail}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {taint && (
                <div className="panel-section">
                  <div className="row"><span className="grow">Where did {taint.what} come from?</span><IconButton tip="Close" onClick={() => setTaint(null)}><X size={12} /></IconButton></div>
                  <div className="mono" style={{ fontSize: 12, maxHeight: 300, overflow: "auto" }}>
                    {taintTree(taint.hops).map(({ hop, depth }) => (
                      <div key={hop.id} className="row" style={{ paddingLeft: depth * 12 }}>
                        <span className={hop.kind === "unmodeled" ? "warn" : hop.kind === "const" || hop.kind === "initial" ? "accent" : "faint"} style={{ width: 64 }}>{hop.kind}</span>
                        <span>{locText(hop.loc)} = {hop.value}</span>
                        {hop.step !== null && <span className="link ellipsis" onClick={() => go((hop.step ?? 0) + 1)}>#{hop.step} {hop.text}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
        <div className="list-col vlist" style={{ borderRight: "none" }}>
          {!cur ? (
            <div className="empty">
              <div className="empty-title"><History size={18} /> No trace open.</div>
              <div className="empty-hint">Record one from an Emu Debugger session (start it there, or give a start address here) or from the debugger's stopped thread. Then scrub back and forth: every register and every byte the run touched is reconstructed at any step.</div>
            </div>
          ) : (
            <>
              <div className="panel-section">
                <div className="row">
                  <IconButton tip="Run back to a breakpoint" onClick={() => void runTo(false)}><SkipBack size={14} /></IconButton>
                  <IconButton tip="Step back (←)" onClick={() => go(pos - 1)}><ChevronLeft size={14} /></IconButton>
                  <input type="range" className="grow" min={0} max={steps} value={pos} onChange={(e) => go(Number(e.target.value))} />
                  <IconButton tip="Step forward (→)" onClick={() => go(pos + 1)}><ChevronRight size={14} /></IconButton>
                  <IconButton tip="Run forward to a breakpoint" onClick={() => void runTo(true)}><SkipForward size={14} /></IconButton>
                  <input className="input mono" style={{ width: 90 }} type="number" min={0} max={steps} value={pos} title="position" onChange={(e) => go(Number(e.target.value))} />
                  <span className="faint">/ {steps.toLocaleString()}</span>
                </div>
                <div className="faint" style={{ fontSize: 12 }}>
                  {cur.name || cur.trace_id} · {cur.source} · stopped: {cur.stop_reason}{cur.truncated ? " (size limit)" : ""} · {cur.unique_pcs} addresses · {cur.writes} writes · position {pos} = before step {pos}
                </div>
              </div>
              <table className="table mono">
                <thead><tr><th style={{ width: 64 }}>step</th><th>address</th><th>instruction</th><th>effect</th></tr></thead>
                <tbody>
                  {lines.steps.map((l) => (
                    <tr key={l.step} className={l.step === pos ? "selected" : undefined} onClick={() => go(l.step)} style={{ cursor: "pointer" }}>
                      <td className={l.step === pos - 1 ? "accent" : "faint"}>{l.step === pos ? "▶ " : ""}{l.step}</td>
                      <td><span className="link" onClick={(e) => { e.stopPropagation(); ui.goDisasm(l.pc); }}>{label(l.pc)}</span></td>
                      <td>{l.text}</td>
                      <td className="faint ellipsis">{Object.entries(l.changes).slice(0, 3).map(([k, v]) => `${k}=${v}`).join(" ")}{l.writes ? ` ✎${l.writes}` : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {(last || next) && (
                <div className="panel-section">
                  {last && (
                    <div className="mono" style={{ fontSize: 12 }}>
                      <span className="faint">last step #{last.step}:</span> {last.text}
                      {last.accesses.map((a, i) => (
                        <div key={i} className="row" style={{ paddingLeft: 12 }}>
                          <span className={a.kind === "write" ? "warn" : "faint"} style={{ width: 40 }}>{a.kind}</span>
                          <span className="link" onClick={() => { setMemAt(a.address); setQAddr(a.address); setQSize(a.size); }}>[{a.address}]:{a.size}</span>
                          <span className="ellipsis">{a.kind === "write" ? `${a.old} → ${a.new}` : a.data}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {next && <div className="mono" style={{ fontSize: 12 }}><span className="faint">next #{next.step}:</span> {next.text}</div>}
                </div>
              )}
              <div className="panel-section">
                <div className="label">Memory at position {pos} <span className="faint">(?? = not touched by the trace; written by the last step highlighted; click a byte: when did it last change?)</span></div>
                <div className="row"><input className="input mono grow" value={memAt} onChange={(e) => setMemAt(e.target.value)} placeholder="address the trace touched" /></div>
                {mem && (
                  <div className="mono" style={{ fontSize: 12 }}>
                    {hexRows(mem.base, mem.data, 8).map((r) => (
                      <div key={String(r.address)} className="row" style={{ gap: 0 }}>
                        <span className="faint" style={{ display: "inline-block", width: 130 }}>{fmtAddr(r.address)}</span>
                        {r.bytes.map((b, i) => {
                          const off = Number(r.address - mem.base) + i;
                          return (
                            <span key={i} style={{ display: "inline-block", width: 22, textAlign: "center", cursor: b === null ? undefined : "pointer" }}
                              className={b === null ? "faint" : written.has(off) ? "warn" : undefined}
                              onClick={() => b !== null && void lastChange(fmtAddr(mem.base + BigInt(off)), 1)}>
                              {b === null ? "??" : b.toString(16).padStart(2, "0")}
                            </span>
                          );
                        })}
                        <span className="faint" style={{ marginLeft: 8 }}>{r.bytes.map((b) => (b !== null && b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("")}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
