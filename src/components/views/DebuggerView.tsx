// ptrace debugger (Linux local backend): attach, breakpoints (int3 + DR0-DR3), step, continue,
// registers. Echo exposes no debugger API, so on Windows this view only explains why.
import { useEffect, useState } from "react";
import { Bug, Pause, Play, StepForward, Unplug } from "lucide-react";
import { request, type Frame } from "@/lib/client";
import { fmtAddr, parseAddress, showAddr } from "@/lib/hex";
import { symAddr } from "@/lib/pdb";
import { onAgentEvent, useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, Empty, IconButton, NeedsAgent } from "../ui";

type Regs = Record<string, string>;
type Status = {
  active: boolean;
  state?: "running" | "stopped";
  pid?: number;
  focus?: number;
  threads?: { tid: number; state: string }[];
  breakpoints?: string[];
  hardware?: { slot: number; address: string | null; kind?: string; len?: number }[];
};
type Line = { address: string; text: string; bytes: string };

const kRegOrder = ["rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags", "fs_base", "gs_base"];

export default function DebuggerView() {
  const { backend, os, modules } = useConn();
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
      const d = await request<{ results: Line[] }>("disassemble", { address: r.rip, size: 96 }, true).catch(() => null);
      if (d?.results) setLines(d.results);
    }
  };

  useEffect(() => {
    if (backend !== "local") return;
    void refresh();
    return onAgentEvent((f: Frame) => {
      if (f.event === "dbg_stop") {
        const what = `${f.reason}${f.signal ? ` ${f.signal}` : ""}${f.watch ? ` (DR${f.slot} ${f.watch})` : ""} in thread ${f.tid} at ${symAddr(String(f.address), useConn.getState().modules)}`;
        setEvents((e) => [what, ...e].slice(0, 200));
        log("info", "debugger", what);
        void showRegs(f.regs as Regs);
        void refresh();
      } else if (f.event === "dbg_exit") {
        setEvents((e) => [`process exited (${f.code ?? f.signal})`, ...e]);
        setStatus({ active: false });
      }
    });
  }, [backend]);

  if (backend !== "local")
    return (
      <Empty icon={<Bug size={26} strokeWidth={1.5} />} title="Debugger needs the local Linux backend."
        hint={os === "windows" || os === "browser"
          ? "Echo's Universal API has no breakpoint, single-step or thread-context API, and EchoDebug ships no driver to add one. On Linux the relay debugs the attached process with ptrace."
          : "Attach to a process from the Targets panel first."} />
    );

  const call = async (verb: string, fields: Record<string, unknown> = {}) => {
    const r = await attempt(verb, request<Frame & { regs?: Regs }>(verb, fields));
    if (r?.regs) await showRegs(r.regs);
    await refresh();
    return r;
  };
  const attach = async () => {
    const r = await call("dbg_attach");
    if (r) {
      log("info", "debugger", `ptrace attached, ${(r.threads as number[] | undefined)?.length ?? 0} threads stopped`);
      await call("dbg_regs");
    }
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
    await call("dbg_set_regs", { regs: { [name]: next.trim() } });
  };

  const stopped = status.active && status.state === "stopped";
  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "320px" }}>
        <div className="list-col" style={{ overflow: "auto" }}>
          <div className="toolbar">
            {!status.active ? (
              <button className="btn small primary" onClick={() => void attach()}><Bug size={13} /> Attach debugger</button>
            ) : (
              <>
                <IconButton tip="Continue" onClick={() => void call("dbg_continue")} disabled={!stopped}><Play size={14} /></IconButton>
                <IconButton tip="Pause" onClick={() => void call("dbg_pause")} disabled={stopped}><Pause size={14} /></IconButton>
                <IconButton tip="Step into" onClick={() => void call("dbg_step")} disabled={!stopped}><StepForward size={14} /></IconButton>
                <IconButton tip="Detach debugger" onClick={() => void call("dbg_detach")}><Unplug size={14} /></IconButton>
              </>
            )}
            <span className="grow" />
            <span className="faint" style={{ fontSize: 12 }}>{status.active ? `${status.state} · pid ${status.pid} · ${status.threads?.length ?? 0} threads` : "not debugging"}</span>
          </div>
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
                <button className="row-action" onClick={() => void call("dbg_hwbreak", { slot: h.slot, enabled: false })}>clear</button>
              </div>
            ))}
          </div>
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
            {events.length === 0 && <div className="faint" style={{ padding: 8 }}>Breakpoint hits, steps, signals and exits show here.</div>}
            {events.map((e, i) => <div key={i} style={{ padding: "2px 8px" }}>{e}</div>)}
          </div>
        </div>
      </div>
    </NeedsAgent>
  );
}
