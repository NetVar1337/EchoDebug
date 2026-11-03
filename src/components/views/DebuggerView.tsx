// Native debugger: the relay's ptrace debugger (Linux local backend) or its Win32 debugger
// (Windows, any x64 process on this machine; picked here, separate from Echo). Same verbs and
// events on both: attach, breakpoints (int3 + DR0-DR3), step, continue, pause, threads, registers,
// exceptions. x64dbg's workflow on top: step over (F8), execute till return (Ctrl+F9), run to the
// selected line (F4), set rip to it (Ctrl+*), conditional / logging / single-shot breakpoints with
// x64dbg's expression syntax, an annotated stack pane and a command bar that evaluates expressions.
import { useEffect, useMemo, useRef, useState } from "react";
import { Bug, CornerDownRight, CornerRightUp, Pause, Play, RefreshCw, StepForward, Unplug } from "lucide-react";
import { request, type Frame } from "@/lib/client";
import { fmtAddr, parseAddress, showAddr } from "@/lib/hex";
import { symAddr } from "@/lib/pdb";
import { onAgentEvent, useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { bpFields, bpSummary, debuggerKey, stackOffset, type BpInfo, type DbgAction, type StackEntry } from "@/lib/debugger";
import { CommitInput, IconButton } from "../ui";
import { DebuggerGate } from "../DebuggerGate";
import { useModuleArch } from "../ArchBadge";

type Regs = Record<string, string>;
type Status = {
  active: boolean;
  backend?: string;
  state?: "running" | "stopped";
  pid?: number;
  focus?: number;
  auto?: boolean;
  api_hooks?: number;
  threads?: { tid: number; state: string; rip?: string }[];
  breakpoints?: string[];
  breakpoint_info?: BpInfo[];
  hardware?: { slot: number; address: string | null; kind?: string; len?: number; trace?: boolean }[];
};
type Line = { address: string; text: string; bytes: string };
type Proc = { pid: number; name: string; path: string };

const kRegOrder = ["rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags", "fs_base", "gs_base"];

/** One line for the events list / Output. */
export function describeStop(f: Frame, modules: Parameters<typeof symAddr>[1]): string {
  if (f.event === "dbg_exception") return `${f.description ?? "exception"} ${f.code ?? ""} (first chance, passed on) in thread ${f.tid}`;
  if (f.event === "dbg_output") return `debug output (thread ${f.tid}): ${f.text}`;
  if (f.event === "dbg_log") return `log ${symAddr(String(f.address), modules)} (thread ${f.tid}): ${f.text}`;
  const what = f.reason === "exception"
    ? `${f.first_chance === false ? "second-chance " : ""}exception ${f.code ?? ""} ${f.description ?? ""}`.replace(/\s+/g, " ").trim()
    : `${String(f.reason).replace(/_/g, " ")}${f.signal ? ` ${f.signal}` : ""}${f.watch ? ` (DR${f.slot} ${f.watch})` : ""}${f.hits ? ` (hit ${f.hits})` : ""}`;
  const err = f.condition_error ? ` — condition failed: ${f.condition_error}` : "";
  return `${what} in thread ${f.tid} at ${symAddr(String(f.address), modules)}${err}`;
}

type Draft = { address: string; condition: string; log: string; log_condition: string; once: boolean };

/** x64dbg's Edit breakpoint dialog, inline. */
function BreakpointEditor({ draft, tid, onClose, onSaved }: { draft: Draft; tid?: number; onClose: () => void; onSaved: () => void }) {
  const [d, setD] = useState(draft);
  const [preview, setPreview] = useState("");
  useEffect(() => { setD(draft); setPreview(""); }, [draft.address]);
  const save = async (extra: Record<string, unknown> = {}) => {
    const r = await attempt("breakpoint", request("dbg_break", { ...bpFields(d.address, d), ...extra }));
    if (r) onSaved();
  };
  const tryLog = async () => {
    const r = await request<{ text?: string }>("dbg_format", { text: d.log, tid }, true).catch((e: Error) => ({ text: `error: ${e.message}` }));
    setPreview(r.text ?? String((r as Frame).detail ?? "error"));
  };
  const field = (k: "condition" | "log" | "log_condition", label: string, placeholder: string) => (
    <label className="col" style={{ gap: 2 }}>
      <span className="faint" style={{ fontSize: 11 }}>{label}</span>
      <input className="input mono" value={d[k]} placeholder={placeholder} spellCheck={false} onChange={(e) => setD({ ...d, [k]: e.target.value })} onKeyDown={(e) => e.key === "Enter" && void save()} />
    </label>
  );
  return (
    <div className="panel-section" style={{ gap: 6 }}>
      <div className="label">Edit breakpoint {d.address}</div>
      {field("condition", "Break condition (empty: always)", "e.g. rcx == 0 && $hits > .10")}
      {field("log", "Log text", "e.g. CreateFileW({s:arg(0)}) hit {d:$hits}")}
      {field("log_condition", "Log condition (empty: every hit)", "e.g. strstr(utf16(rcx), \"cfg\")")}
      <label className="row" style={{ fontSize: 12 }}><input type="checkbox" checked={d.once} onChange={(e) => setD({ ...d, once: e.target.checked })} />Single-shot (remove after it breaks)</label>
      {preview && <div className="mono faint" style={{ fontSize: 12 }}>{preview}</div>}
      <div className="row">
        <button className="btn small primary" onClick={() => void save()}>Save</button>
        <button className="btn small" disabled={!d.log || !tid} onClick={() => void tryLog()} title="render the log text against the current registers">Preview log</button>
        <button className="btn small" onClick={() => void save({ reset_hits: true })}>Reset hits</button>
        <span className="grow" />
        <button className="btn small" onClick={onClose}>Close</button>
      </div>
      <div className="faint" style={{ fontSize: 11 }}>
        x64dbg syntax: numbers are hex (<span className="mono">.10</span> is decimal), <span className="mono">[rsp+8]</span> / <span className="mono">dword:[rcx]</span> read memory,
        {" "}<span className="mono">arg(0)</span>, <span className="mono">$hits</span>, <span className="mono">utf16(rcx)</span>, <span className="mono">strstr(a, b)</span>. Log fields:
        {" "}<span className="mono">{"{rax}"}</span> hex, <span className="mono">{"{d:…}"}</span> decimal, <span className="mono">{"{s:…}"}</span> string, <span className="mono">{"{a:…}"}</span> module+offset, <span className="mono">{"{i:…}"}</span> instruction.
      </div>
    </div>
  );
}

function AttachPanel({ onAttached }: { onAttached: () => void }) {
  const { debugger: dbg, target, modules } = useConn();
  // the Echo target's image: an ARM64 process is refused by the (x86-64 only) debugger
  const image = useMemo(() => (target?.base ? modules.find((m) => m.base === target.base) : undefined), [target?.base, modules]);
  const imageArch = useModuleArch(image);
  const [procs, setProcs] = useState<Proc[]>([]);
  const [filter, setFilter] = useState("");
  const [pid, setPid] = useState<number | null>(target?.pid ?? null);
  const load = async () => {
    const r = await attempt("processes", request<{ processes: Proc[] }>("processes"));
    if (r) setProcs(r.processes);
  };
  useEffect(() => { if (dbg === "windows") void load(); }, [dbg]);
  useEffect(() => { if (target?.pid && pid === null) setPid(target.pid); }, [target?.pid]);
  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return procs.filter((p) => !f || p.name.toLowerCase().includes(f) || String(p.pid).includes(f)).slice(0, 400);
  }, [procs, filter]);
  const attach = async () => {
    const r = await attempt("debugger", request<Frame>("dbg_attach", dbg === "windows" && pid ? { pid } : {}));
    if (!r) return;
    const n = (r.threads as number[] | undefined)?.length ?? 0;
    log("info", "debugger", dbg === "windows" ? `Win32 debugger attached to pid ${r.pid}, ${n} threads stopped` : `ptrace attached, ${n} threads stopped`);
    onAttached();
  };
  if (dbg !== "windows")
    return (
      <div className="toolbar">
        <button className="btn small primary" onClick={() => void attach()}><Bug size={13} /> Attach debugger</button>
        <span className="faint" style={{ fontSize: 12 }}>ptrace, to the attached process</span>
      </div>
    );
  return (
    <div className="panel-section">
      <div className="label">Native Windows debugger</div>
      <div className="faint">
        Debugs an x64 process on this machine with the Win32 debug API, separately from Echo. Unlike Echo’s memory access it is visible to the
        process (IsDebuggerPresent, the debug port); detaching restores every breakpoint byte and debug register and leaves the process running.
      </div>
      <div className="row">
        <label className="search grow"><input placeholder="filter processes…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
        <IconButton tip="Reload processes" onClick={() => void load()}><RefreshCw size={13} /></IconButton>
      </div>
      <select className="select" size={8} value={pid ?? ""} onChange={(e) => setPid(Number(e.target.value))} style={{ height: "auto" }}>
        {target?.pid && !shown.some((p) => p.pid === target.pid) && <option value={target.pid}>{target.name ?? "Echo target"} ({target.pid})</option>}
        {shown.map((p) => <option key={p.pid} value={p.pid}>{p.name} ({p.pid}){p.pid === target?.pid ? " · Echo target" : ""}</option>)}
      </select>
      {pid === target?.pid && imageArch === "arm64" && <div className="warn">{target?.name ?? "This process"} is an ARM64 process; the native debugger is x86-64 only and will refuse it.</div>}
      <div className="row">
        <button className="btn small primary" disabled={!pid} onClick={() => void attach()}><Bug size={13} /> Attach to {pid ?? "…"}</button>
      </div>
    </div>
  );
}

export default function DebuggerView() {
  const { modules, debugger: dbg } = useConn();
  const ui = useUi();
  const [status, setStatus] = useState<Status>({ active: false });
  const [regs, setRegs] = useState<Regs>({});
  const [prevRegs, setPrevRegs] = useState<Regs>({});
  const [lines, setLines] = useState<Line[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [stack, setStack] = useState<StackEntry[]>([]);
  const [events, setEvents] = useState<string[]>([]);
  const [hwSlot, setHwSlot] = useState(0);
  const [hwKind, setHwKind] = useState("write");
  const [hwLen, setHwLen] = useState(4);
  const [editing, setEditing] = useState<Draft | null>(null);
  const [cmd, setCmd] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const histAt = useRef(-1);
  const pushEvent = (e: string) => setEvents((x) => [e, ...x].slice(0, 300));

  const refresh = async () => {
    const s = await request<Status>("dbg_status", {}, true).catch(() => null);
    if (s) setStatus(s);
    return s;
  };
  const loadStack = async (tid?: number) => {
    const st = await request<{ entries: StackEntry[] }>("dbg_stack", { count: 48, ...(tid ? { tid } : {}) }, true).catch(() => null);
    setStack(st?.entries ?? []);
  };
  const showRegs = async (r: Regs | undefined, tid?: number) => {
    if (!r) return;
    setPrevRegs(regs);
    setRegs(r);
    if (r.rip) {
      setSelected(r.rip);
      // dbg_disasm reads through the debugger: planted int3s show their original bytes
      const d = await request<{ results: Line[] }>("dbg_disasm", { address: r.rip, size: 160 }, true).catch(() => null);
      if (d?.results) setLines(d.results);
    }
    void loadStack(tid);
  };

  useEffect(() => {
    if (!dbg) return;
    void refresh();
    // what logging breakpoints printed while this view was closed
    void request<{ entries: Frame[] }>("dbg_bp_log", { limit: 10000 }, true)
      .then((r) => setEvents((x) => [...x, ...(r.entries ?? []).slice(-100).reverse().map((f) => describeStop(f, useConn.getState().modules))]))
      .catch(() => {});
    return onAgentEvent((f: Frame) => {
      if (f.event === "dbg_stop") {
        const what = describeStop(f, useConn.getState().modules);
        pushEvent(what);
        log(f.reason === "exception" || f.condition_error ? "warn" : "info", "debugger", what);
        void showRegs(f.regs as Regs, f.tid as number);
        void refresh();
      } else if (f.event === "dbg_log") {
        const what = describeStop(f, useConn.getState().modules);
        pushEvent(what);
        log("info", "debugger", what);
      } else if (f.event === "dbg_exception" || f.event === "dbg_output") {
        pushEvent(describeStop(f, useConn.getState().modules));
      } else if (f.event === "dbg_exit") {
        pushEvent(`process exited (${f.code ?? f.signal})`);
        setStatus({ active: false });
      }
    });
  }, [dbg]);

  const call = async (verb: string, fields: Record<string, unknown> = {}) => {
    const r = await attempt(verb, request<Frame & { regs?: Regs; tid?: number }>(verb, fields));
    if (r?.regs) await showRegs(r.regs, r.tid);
    await refresh();
    return r;
  };
  const addBp = async (text: string) => {
    const a = parseAddress(text, modules);
    if (a === null) return log("warn", "debugger", `cannot parse ${text}`);
    await call("dbg_break", { address: fmtAddr(a), enabled: true });
  };
  const setHw = async (text: string) => {
    const a = parseAddress(text, modules);
    if (a === null) return log("warn", "debugger", `cannot parse ${text}`);
    await call("dbg_hwbreak", { slot: hwSlot, address: fmtAddr(a), kind: hwKind, len: hwLen, enabled: true });
  };
  const editReg = async (name: string) => {
    const next = window.prompt(`New value for ${name}`, regs[name] ?? "0x0");
    if (next === null) return;
    await call("dbg_set_regs", { tid: status.focus, regs: { [name]: next.trim() } });
  };
  const focusThread = async (tid: number) => {
    const r = await attempt("dbg_regs", request<{ regs: Regs; tid: number }>("dbg_regs", { tid }));
    if (r) {
      setStatus((s) => ({ ...s, focus: r.tid }));
      await showRegs(r.regs, r.tid);
    }
  };
  const infoOf = (a: string) => status.breakpoint_info?.find((b) => b.address === a);
  const edit = (a: string) => {
    const b = infoOf(a);
    setEditing({ address: a, condition: b?.condition ?? "", log: b?.log ?? "", log_condition: b?.log_condition ?? "", once: b?.once ?? false });
  };
  const evaluate = async (expr: string) => {
    if (!expr.trim()) return;
    setHistory((h) => [expr, ...h.filter((x) => x !== expr)].slice(0, 50));
    histAt.current = -1;
    const r = await request<{ value?: string; unsigned?: string; signed?: string; symbol?: string; string?: string }>("dbg_eval", { expr, tid: status.focus }, true)
      .catch((e: Error) => ({ error: e.message }) as Record<string, string>);
    const out = "error" in r ? `error: ${r.error}` : r.string !== undefined ? JSON.stringify(r.string)
      : `${r.value} (${r.unsigned}${r.signed !== r.unsigned ? ` / ${r.signed}` : ""})${r.symbol && r.symbol !== r.value ? ` ${r.symbol}` : ""}`;
    pushEvent(`› ${expr} = ${out}`);
    setCmd("");
  };

  const stopped = status.active && status.state === "stopped";
  const act = (a: DbgAction) => {
    const tid = status.focus;
    switch (a) {
      case "run": return stopped && void call("dbg_continue");
      case "pause": return !stopped && status.active && void call("dbg_pause");
      case "stepInto": return stopped && void call("dbg_step", { tid });
      case "stepOver": return stopped && void call("dbg_step_over", { tid });
      case "stepOut": return stopped && void call("dbg_step_out", { tid });
      case "runToCursor": return stopped && selected && void call("dbg_run_to", { tid, address: selected });
      case "toggleBreakpoint": return status.active && selected && void call("dbg_break", { address: selected, enabled: !status.breakpoints?.includes(selected) });
      case "setOrigin": return stopped && selected && void call("dbg_set_regs", { tid, regs: { rip: selected } });
    }
  };
  // x64dbg's keys while this view is open (not while typing)
  const actRef = useRef(act);
  actRef.current = act;
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement) return;
      const a = debuggerKey(e);
      if (!a) return;
      e.preventDefault();
      actRef.current(a);
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);

  return (
    <DebuggerGate>
      <div className="split-h" style={{ ["--fn-w" as string]: "340px" }}>
        <div className="list-col" style={{ overflow: "auto" }}>
          {!status.active ? (
            <AttachPanel onAttached={() => void call("dbg_regs")} />
          ) : (
            <div className="toolbar">
              <IconButton tip="Run (F9)" onClick={() => act("run")} disabled={!stopped}><Play size={14} /></IconButton>
              <IconButton tip="Pause (F12)" onClick={() => act("pause")} disabled={stopped}><Pause size={14} /></IconButton>
              <IconButton tip="Step into (F7)" onClick={() => act("stepInto")} disabled={!stopped}><StepForward size={14} /></IconButton>
              <IconButton tip="Step over (F8)" onClick={() => act("stepOver")} disabled={!stopped}><CornerDownRight size={14} /></IconButton>
              <IconButton tip="Execute till return (Ctrl+F9)" onClick={() => act("stepOut")} disabled={!stopped}><CornerRightUp size={14} /></IconButton>
              <IconButton tip="Detach debugger" onClick={() => void call("dbg_detach")}><Unplug size={14} /></IconButton>
              <span className="grow" />
              <span className="faint" style={{ fontSize: 12 }}>{status.backend === "windows" ? "Win32" : "ptrace"} · {status.state} · pid {status.pid}{status.auto ? " · started by a monitor" : ""}</span>
            </div>
          )}
          {status.active && (
            <div className="panel-section">
              <div className="label">Threads ({status.threads?.length ?? 0})</div>
              <table className="table mono"><tbody>
                {(status.threads ?? []).slice(0, 64).map((t) => (
                  <tr key={t.tid} data-selected={t.tid === status.focus} onClick={() => stopped && void focusThread(t.tid)} title={stopped ? "click: show this thread" : undefined}>
                    <td style={{ width: 70 }}>{t.tid}</td>
                    <td className="faint">{t.state}</td>
                    <td className="ellipsis">{t.rip ? symAddr(t.rip, modules) : ""}</td>
                  </tr>
                ))}
              </tbody></table>
            </div>
          )}
          <div className="panel-section">
            <div className="label">Registers {status.focus ? `(thread ${status.focus})` : ""}</div>
            <table className="table mono"><tbody>
              {kRegOrder.filter((k) => regs[k]).map((k) => (
                <tr key={k} onDoubleClick={() => stopped && void editReg(k)} title="double-click to edit">
                  <td className="faint" style={{ width: 70 }}>{k}</td>
                  <td className={prevRegs[k] && prevRegs[k] !== regs[k] ? "accent" : undefined}>{regs[k]}</td>
                  <td>{k === "rip" || k === "rsp" ? <span className="link" onClick={() => (k === "rip" ? ui.goDisasm(regs[k]) : ui.goMemory(regs[k]))}>go</span> : null}</td>
                </tr>
              ))}
            </tbody></table>
          </div>
          <div className="panel-section">
            <div className="label">Software breakpoints</div>
            <CommitInput value="" placeholder="add: address · module+0x…" onCommit={(v) => v && void addBp(v)} />
            {(status.breakpoints ?? []).map((b) => (
              <div key={b} className="col" style={{ gap: 0 }}>
                <div className="row">
                  <span className="mono link grow" onClick={() => ui.goDisasm(b)}>{symAddr(b, modules)}</span>
                  <button className="row-action" onClick={() => edit(b)}>edit</button>
                  <button className="row-action" onClick={() => void call("dbg_break", { address: b, enabled: false })}>remove</button>
                </div>
                {bpSummary(infoOf(b)) && <div className="mono faint ellipsis" style={{ fontSize: 11, paddingLeft: 8 }}>{bpSummary(infoOf(b))}</div>}
              </div>
            ))}
          </div>
          {editing && status.active && (
            <BreakpointEditor draft={editing} tid={stopped ? status.focus : undefined} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); void refresh(); }} />
          )}
          <div className="panel-section">
            <div className="label">Hardware breakpoints (DR0-DR3)</div>
            <div className="row">
              <select className="select" value={hwSlot} onChange={(e) => setHwSlot(Number(e.target.value))}>{[0, 1, 2, 3].map((s) => <option key={s} value={s}>DR{s}</option>)}</select>
              <select className="select" value={hwKind} onChange={(e) => setHwKind(e.target.value)}>{["exec", "write", "rw"].map((k) => <option key={k}>{k}</option>)}</select>
              <select className="select" value={hwLen} onChange={(e) => setHwLen(Number(e.target.value))} disabled={hwKind === "exec"}>{[1, 2, 4, 8].map((l) => <option key={l} value={l}>{l} B</option>)}</select>
            </div>
            <CommitInput value="" placeholder="address for the slot" onCommit={(v) => v && void setHw(v)} />
            {(status.hardware ?? []).filter((h) => h.address).map((h) => (
              <div key={h.slot} className="row">
                <span className="faint">DR{h.slot}</span>
                <span className="mono grow">{symAddr(h.address!, modules)} {h.kind} {h.kind !== "exec" ? `${h.len}B` : ""}</span>
                {h.trace
                  ? <span className="link" onClick={() => ui.setTab("accesses")}>access finder</span>
                  : <button className="row-action" onClick={() => void call("dbg_hwbreak", { slot: h.slot, enabled: false })}>clear</button>}
              </div>
            ))}
          </div>
          {status.api_hooks ? (
            <div className="panel-section">
              <span>API monitor: {status.api_hooks} functions hooked · <span className="link" onClick={() => ui.setTab("apimon")}>open log</span></span>
            </div>
          ) : null}
        </div>
        <div className="list-col" style={{ borderRight: "none" }}>
          <div className="toolbar">
            <span className="panel-title grow ellipsis" style={{ minWidth: 0 }}>At {regs.rip ? symAddr(regs.rip, modules) : "—"}</span>
            <button className="btn small" disabled={!stopped || !selected} onClick={() => act("runToCursor")} title="Run to the selected line (F4)">Run to here</button>
            <button className="btn small" disabled={!stopped || !selected || selected === regs.rip} onClick={() => act("setOrigin")} title="Set rip to the selected line (Ctrl+*)">Set RIP here</button>
            <button className="btn small" disabled={!status.active || !selected} onClick={() => act("toggleBreakpoint")} title="Toggle a breakpoint on the selected line (F2)">Breakpoint</button>
          </div>
          <div className="vlist listing dbg-listing" style={{ flex: "1 1 45%" }}>
            {lines.map((l) => {
              const bp = status.breakpoints?.includes(l.address);
              const cond = bp && bpSummary(infoOf(l.address));
              return (
                <div
                  key={l.address}
                  className="insn-row"
                  data-selected={l.address === selected}
                  onClick={() => setSelected(l.address)}
                  onDoubleClick={() => void call("dbg_break", { address: l.address, enabled: !bp })}
                  title={cond ? `${cond}\n(double-click to remove)` : "click: select · double-click: toggle a breakpoint"}
                >
                  <span className="insn-va"><span className="dbg-mark">{l.address === regs.rip ? "➜" : ""}{bp ? (cond ? "◆" : "●") : ""}</span>{showAddr(l.address)}</span>
                  <span className="insn-bytes">{l.bytes.replace(/(..)/g, "$1 ").trim()}</span>
                  <span className="insn-text">{l.text}</span>
                </div>
              );
            })}
          </div>
          <div className="toolbar">
            <span className="panel-title grow">Stack</span>
            <span className="faint" style={{ fontSize: 12 }}>{regs.rsp ? `rsp ${regs.rsp}` : ""}</span>
            <IconButton tip="Reload the stack" onClick={() => void loadStack(status.focus)} disabled={!status.active}><RefreshCw size={13} /></IconButton>
          </div>
          <div className="vlist mono" style={{ flex: "1 1 25%", fontSize: 12 }}>
            {stack.length === 0 && <div className="faint" style={{ padding: 8 }}>The stack of the stopped thread: return addresses, code and stack pointers, strings.</div>}
            {stack.map((e) => (
              <div key={e.address} className="row" style={{ padding: "1px 8px", gap: 10, whiteSpace: "nowrap", background: e.rsp ? "var(--selection)" : undefined }}>
                <span className="faint link" style={{ width: 58, flex: "none" }} onClick={() => ui.goMemory(e.address)} title={`${e.address}${e.rbp ? " (rbp)" : ""}: open the slot in Memory`}>{e.rbp && !e.rsp ? "rbp" : stackOffset(e.offset)}</span>
                <span
                  style={{ flex: "none" }}
                  className={e.kind === "return" || e.kind === "code" ? "link" : undefined}
                  onClick={() => (e.kind === "return" || e.kind === "code" ? ui.goDisasm(e.value) : e.kind === "stack" || e.kind === "string" ? ui.goMemory(e.value) : undefined)}
                >{showAddr(e.value)}</span>
                <span className={e.kind === "return" ? "accent ellipsis" : "faint ellipsis"}>{e.kind === "return" || e.kind === "code" ? e.text?.replace(/[\w.]+\+0x[0-9a-f]+|0x[0-9a-f]+/g, (m) => /^0x/.test(m) ? symAddr(m, modules) : m) : e.text ?? ""}</span>
              </div>
            ))}
          </div>
          <div className="toolbar">
            <label className="search grow" title="x64dbg expressions: rax+8, [rsp+28], dword:[rcx], arg(1), utf16(rdx), game.exe+1000, .10 is decimal">
              <span className="faint mono">?</span>
              <input
                className="mono"
                placeholder={status.active ? "evaluate: [rsp+8] · arg(0) · utf16(rcx) · rax == .10" : "attach to evaluate expressions"}
                disabled={!status.active}
                value={cmd}
                spellCheck={false}
                onChange={(e) => setCmd(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void evaluate(cmd);
                  if (e.key === "ArrowUp" || e.key === "ArrowDown") {
                    e.preventDefault();
                    const i = Math.max(-1, Math.min(history.length - 1, histAt.current + (e.key === "ArrowUp" ? 1 : -1)));
                    histAt.current = i;
                    setCmd(i < 0 ? "" : history[i]);
                  }
                }}
              />
            </label>
          </div>
          <div className="vlist mono" style={{ flex: "1 1 30%", fontSize: 12 }}>
            {events.length === 0 && <div className="faint" style={{ padding: 8 }}>Breakpoint hits, log lines, steps, signals, exceptions, exits and evaluated expressions show here.</div>}
            {events.map((e, i) => <div key={i} style={{ padding: "2px 8px" }}>{e}</div>)}
          </div>
        </div>
      </div>
    </DebuggerGate>
  );
}
