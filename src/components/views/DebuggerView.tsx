// Native debugger: the relay's ptrace debugger (Linux local backend) or its Win32 debugger
// (Windows, any x64 process on this machine; picked here, separate from Echo). Same verbs and
// events on both: attach, breakpoints (int3 + DR0-DR3), step, continue, pause, threads, registers,
// exceptions.
import { useEffect, useMemo, useState } from "react";
import { Bug, Pause, Play, RefreshCw, StepForward, Unplug } from "lucide-react";
import { request, type Frame } from "@/lib/client";
import { fmtAddr, parseAddress, showAddr } from "@/lib/hex";
import { symAddr } from "@/lib/pdb";
import { onAgentEvent, useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
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
  hardware?: { slot: number; address: string | null; kind?: string; len?: number; trace?: boolean }[];
};
type Line = { address: string; text: string; bytes: string };
type Proc = { pid: number; name: string; path: string };

const kRegOrder = ["rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags", "fs_base", "gs_base"];

/** One line for the events list / Output. */
export function describeStop(f: Frame, modules: Parameters<typeof symAddr>[1]): string {
  if (f.event === "dbg_exception") return `${f.description ?? "exception"} ${f.code ?? ""} (first chance, passed on) in thread ${f.tid}`;
  if (f.event === "dbg_output") return `debug output (thread ${f.tid}): ${f.text}`;
  const what = f.reason === "exception"
    ? `${f.first_chance === false ? "second-chance " : ""}exception ${f.code ?? ""} ${f.description ?? ""}`.replace(/\s+/g, " ").trim()
    : `${f.reason}${f.signal ? ` ${f.signal}` : ""}${f.watch ? ` (DR${f.slot} ${f.watch})` : ""}`;
  return `${what} in thread ${f.tid} at ${symAddr(String(f.address), modules)}`;
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
  const [events, setEvents] = useState<string[]>([]);
  const [hwSlot, setHwSlot] = useState(0);
  const [hwKind, setHwKind] = useState("write");
  const [hwLen, setHwLen] = useState(4);

  const refresh = async () => {
    const s = await request<Status>("dbg_status", {}, true).catch(() => null);
    if (s) setStatus(s);
    return s;
  };
  const showRegs = async (r: Regs | undefined) => {
    if (!r) return;
    setPrevRegs(regs);
    setRegs(r);
    if (r.rip) {
      // dbg_disasm reads through the debugger: planted int3s show their original bytes
      const d = await request<{ results: Line[] }>("dbg_disasm", { address: r.rip, size: 96 }, true).catch(() => null);
      if (d?.results) setLines(d.results);
    }
  };

  useEffect(() => {
    if (!dbg) return;
    void refresh();
    return onAgentEvent((f: Frame) => {
      if (f.event === "dbg_stop") {
        const what = describeStop(f, useConn.getState().modules);
        setEvents((e) => [what, ...e].slice(0, 200));
        log(f.reason === "exception" ? "warn" : "info", "debugger", what);
        void showRegs(f.regs as Regs);
        void refresh();
      } else if (f.event === "dbg_exception" || f.event === "dbg_output") {
        setEvents((e) => [describeStop(f, useConn.getState().modules), ...e].slice(0, 200));
      } else if (f.event === "dbg_exit") {
        setEvents((e) => [`process exited (${f.code ?? f.signal})`, ...e]);
        setStatus({ active: false });
      }
    });
  }, [dbg]);

  const call = async (verb: string, fields: Record<string, unknown> = {}) => {
    const r = await attempt(verb, request<Frame & { regs?: Regs }>(verb, fields));
    if (r?.regs) await showRegs(r.regs);
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
      await showRegs(r.regs);
    }
  };

  const stopped = status.active && status.state === "stopped";
  return (
    <DebuggerGate>
      <div className="split-h" style={{ ["--fn-w" as string]: "320px" }}>
        <div className="list-col" style={{ overflow: "auto" }}>
          {!status.active ? (
            <AttachPanel onAttached={() => void call("dbg_regs")} />
          ) : (
            <div className="toolbar">
              <IconButton tip="Continue" onClick={() => void call("dbg_continue")} disabled={!stopped}><Play size={14} /></IconButton>
              <IconButton tip="Pause" onClick={() => void call("dbg_pause")} disabled={stopped}><Pause size={14} /></IconButton>
              <IconButton tip="Step into" onClick={() => void call("dbg_step", { tid: status.focus })} disabled={!stopped}><StepForward size={14} /></IconButton>
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
              <div key={b} className="row">
                <span className="mono link grow" onClick={() => ui.goDisasm(b)}>{symAddr(b, modules)}</span>
                <button className="row-action" onClick={() => void call("dbg_break", { address: b, enabled: false })}>remove</button>
              </div>
            ))}
          </div>
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
          <div className="toolbar"><span className="panel-title">At {regs.rip ? symAddr(regs.rip, modules) : "—"}</span></div>
          <div className="vlist listing" style={{ flex: "1 1 60%" }}>
            {lines.map((l, i) => {
              const bp = status.breakpoints?.includes(l.address);
              return (
                <div key={l.address} className="insn-row" data-selected={i === 0} onDoubleClick={() => void call("dbg_break", { address: l.address, enabled: !bp })} title="double-click to toggle a breakpoint">
                  <span className="insn-va">{bp ? "● " : ""}{showAddr(l.address)}</span>
                  <span className="insn-bytes">{l.bytes.replace(/(..)/g, "$1 ").trim()}</span>
                  <span className="insn-text">{l.text}</span>
                </div>
              );
            })}
          </div>
          <div className="toolbar"><span className="panel-title">Events</span></div>
          <div className="vlist mono" style={{ flex: "1 1 40%", fontSize: 12 }}>
            {events.length === 0 && <div className="faint" style={{ padding: 8 }}>Breakpoint hits, steps, signals, exceptions and exits show here.</div>}
            {events.map((e, i) => <div key={i} style={{ padding: "2px 8px" }}>{e}</div>)}
          </div>
        </div>
      </div>
    </DebuggerGate>
  );
}
