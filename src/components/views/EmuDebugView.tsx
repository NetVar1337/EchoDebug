// Emulated debugger: a persistent Unicorn session you step, run to an address or breakpoint, and
// edit (registers, memory) — the target process is never touched. Backed by the emu_* verbs
// (Windows: the Echo agent; Linux: the relay's local backend).
import { useState } from "react";
import { Play, StepForward, Square, SkipForward, X } from "lucide-react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useNames } from "@/store/names";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent } from "../ui";

export type EmuState = {
  regs: Record<string, string>;
  rip: string;
  instructions: number;
  stop: { reason: string; address?: string; error_name?: string; fault_address?: string; fault_rip?: string; ran?: number; detail?: string };
  next: { address: string; bytes: string; text: string }[];
  stack: { address: string; value: string }[];
  breakpoints: string[];
  dirty_pages: string[];
  conditions?: Record<string, string>;
  api_calls?: { api: string; result: string; note?: string }[];
  layers?: { entry: string; page: string }[];
  xmm?: Record<string, string>;
};

const kRegs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"];

/** One line describing why the session stopped. */
export function stopText(s: EmuState["stop"]): string {
  switch (s.reason) {
    case "start": return "session started";
    case "step": return "stepped 1 instruction";
    case "count": return `ran ${s.ran ?? "?"} instructions`;
    case "breakpoint": return `breakpoint at ${s.address}`;
    case "until": return `reached ${s.address}`;
    case "returned": return "the function returned";
    case "watchpoint": { const h = (s as { hit?: { access: string; address: string; rip: string } }).hit; return `watchpoint: ${h?.access} of ${h?.address} by ${h?.rip}`; }
    case "restored": return "snapshot restored";
    case "cancelled": return "cancelled";
    case "fault": return `fault ${s.error_name ?? ""}${s.fault_address ? ` at ${s.fault_address}` : ""} (rip ${s.fault_rip ?? "?"}) — fix registers/memory and continue`;
    case "timeout": return `stopped by the time or instruction limit after ${s.ran ?? "?"} instructions`;
    default: return s.reason;
  }
}

export default function EmuDebugView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const nameOf = useNames((s) => s.nameOf);
  const [start, setStart] = useState(ui.selected ?? "");
  const [code, setCode] = useState("");
  const [st, setSt] = useState<EmuState | null>(null);
  const [prev, setPrev] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [bp, setBp] = useState("");
  const [until, setUntil] = useState("");
  const [count, setCount] = useState(10);
  const [memAddr, setMemAddr] = useState("");
  const [mem, setMem] = useState<{ address: string; data: string } | null>(null);
  const [patch, setPatch] = useState("");
  const [stubs, setStubs] = useState(true);
  const [layers, setLayers] = useState(false);
  const [wpAddr, setWpAddr] = useState("");
  const [wpAccess, setWpAccess] = useState("rw");
  const [wps, setWps] = useState<{ address: string; size: number; access: string }[]>([]);
  const [snaps, setSnaps] = useState<string[]>([]);

  const call = async (verb: string, args: Record<string, unknown> = {}) => {
    setBusy(true);
    const r = await attempt(verb, request<EmuState>(verb, args));
    setBusy(false);
    if (r) {
      setPrev(st?.regs ?? {});
      setSt(r);
    }
    return r;
  };
  const addr = (s: string) => {
    const a = parseAddress(s, modules);
    if (a === null) log("warn", "emu", `not an address: ${s}`);
    return a === null ? null : fmtAddr(a);
  };
  const begin = async () => {
    const a = addr(start);
    if (!a) return;
    const clean = code.replace(/[^0-9a-f]/gi, "");
    await call("emu_start", { start: a, ...(clean ? { code: clean } : {}), breakpoints: st?.breakpoints ?? [], stubs, layers });
    setWps([]);
    setSnaps([]);
    setMem(null);
  };
  const editReg = async (r: string) => {
    const v = window.prompt(`New value for ${r}`, st?.regs[r] ?? "");
    if (v === null) return;
    const a = addr(v);
    if (a) await call("emu_set", { regs: { [r]: a } });
  };
  const readMem = async (where = memAddr) => {
    const a = addr(where);
    if (!a) return;
    const r = await attempt("emu_read", request<{ address: string; data: string }>("emu_read", { address: a, size: 128 }));
    if (r) setMem(r);
  };
  const writeMem = async () => {
    if (!mem) return;
    const data = patch.replace(/[^0-9a-f]/gi, "");
    if (!data || data.length % 2) return log("warn", "emu", "patch bytes must be hex");
    await call("emu_set", { write: [{ address: mem.address, data }] });
    void readMem(mem.address);
  };
  const toggleBp = async (a: string | null, on: boolean, condition = "") => {
    if (!a) return;
    await call("emu_break", { address: a, enabled: on, ...(condition ? { condition } : {}) });
  };
  /** "game.exe+0x10 rax==0x5" → breakpoint with a condition */
  const addBp = () => {
    const [where, ...rest] = bp.trim().split(/\s+/);
    void toggleBp(addr(where ?? ""), true, rest.join(""));
    setBp("");
  };
  const addWatch = async () => {
    const a = addr(wpAddr);
    if (!a) return;
    const r = await attempt("emu_watch", request<{ watchpoints: typeof wps }>("emu_watch", { address: a, size: 8, access: wpAccess }));
    if (r) setWps(r.watchpoints);
    setWpAddr("");
  };
  const dropWatch = async (a: string) => {
    const r = await attempt("emu_watch", request<{ watchpoints: typeof wps }>("emu_watch", { address: a, enabled: false }));
    if (r) setWps(r.watchpoints);
  };
  const snapshot = async () => {
    const name = `t${snaps.length + 1}`;
    const r = await attempt("emu_snapshot", request<{ snapshots: string[]; instructions: number }>("emu_snapshot", { name }));
    if (r) { setSnaps(r.snapshots); log("info", "emu", `snapshot ${name} at ${r.instructions} instructions`); }
  };
  const label = (a: string) => {
    const n = nameOf(a.replace(/^0x/, "").padStart(16, "0"));
    return n ? `${labelAddr(a, modules)} <${n}>` : labelAddr(a, modules);
  };

  return (
    <NeedsAgent ext>
      <div className="split-h" style={{ ["--fn-w" as string]: "380px" }}>
        <div className="list-col vlist">
          <div className="panel-section">
            <div className="label">Emulated debugger · Unicorn x86-64 · the target is never modified</div>
            <div className="row"><span style={{ width: 50 }}>start</span><input className="input mono grow" value={start} onChange={(e) => setStart(e.target.value)} placeholder="function address · game.exe+0x1234" /></div>
            <textarea className="textarea" rows={2} value={code} onChange={(e) => setCode(e.target.value)} placeholder="optional: code bytes (hex) for a blank emulator" />
            <div className="row">
              <button className="btn primary" disabled={busy} onClick={() => void begin()}>{st ? "Restart" : "Start session"}</button>
              {st && <IconButton tip="Close the session" onClick={() => void request("emu_close").then(() => setSt(null))}><X size={14} /></IconButton>}
              <label className="row" title="Simulate common API calls and return to the caller"><input type="checkbox" checked={stubs} onChange={(e) => setStubs(e.target.checked)} />API stand-ins</label>
              <label className="row" title="Report written-then-executed pages (unpacking layers)"><input type="checkbox" checked={layers} onChange={(e) => setLayers(e.target.checked)} />layers</label>
            </div>
          </div>
          {st && (
            <>
              <div className="panel-section">
                <div className="row">
                  <IconButton tip="Step one instruction" disabled={busy} onClick={() => void call("emu_step")}><StepForward size={14} /></IconButton>
                  <IconButton tip={`Step ${count} instructions`} disabled={busy} onClick={() => void call("emu_step", { count })}><SkipForward size={14} /></IconButton>
                  <input className="input mono" style={{ width: 64 }} type="number" min={1} value={count} onChange={(e) => setCount(Math.max(1, Number(e.target.value)))} />
                  <IconButton tip="Run to a breakpoint, a return or a fault" disabled={busy} onClick={() => void call("emu_run")}><Play size={14} /></IconButton>
                  <span className="grow" />
                  <span className="faint">{st.instructions} insns</span>
                </div>
                <div className="row">
                  <input className="input mono grow" placeholder="run until… (address)" value={until} onChange={(e) => setUntil(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") { const a = addr(until); if (a) void call("emu_run", { until: a }); } }} />
                  <button className="btn small" disabled={busy || !until} onClick={() => { const a = addr(until); if (a) void call("emu_run", { until: a }); }}>Run to</button>
                </div>
                <div className={st.stop.reason === "fault" ? "warn" : "faint"} style={{ fontSize: 12 }}>{stopText(st.stop)}</div>
              </div>
              <div className="panel-section">
                <div className="label">Registers <span className="faint">(click to edit; changed values are highlighted)</span></div>
                <div className="kv mono">
                  {kRegs.flatMap((r) => [
                    <span key={r + "k"}>{r}</span>,
                    <span key={r} className={`link${prev[r] && prev[r] !== st.regs[r] ? " warn" : ""}`} onClick={() => void editReg(r)}>{st.regs[r]}</span>,
                  ])}
                </div>
              </div>
              <div className="panel-section">
                <div className="label">Breakpoints</div>
                <div className="row">
                  <input className="input mono grow" placeholder="address [condition, e.g. rax==0x5]" value={bp} onChange={(e) => setBp(e.target.value)} onKeyDown={(e) => e.key === "Enter" && addBp()} />
                  <button className="btn small" onClick={addBp}>Add</button>
                </div>
                {st.breakpoints.map((b) => (
                  <div key={b} className="row mono">
                    <Square size={10} className="danger" />
                    <span className="link grow" onClick={() => ui.goDisasm(b)}>{label(b)}{st.conditions?.[b] ? <span className="faint"> if {st.conditions[b]}</span> : null}</span>
                    <IconButton tip="Remove" onClick={() => void toggleBp(b, false)}><X size={12} /></IconButton>
                  </div>
                ))}
                <div className="label" style={{ marginTop: 8 }}>Watchpoints</div>
                <div className="row">
                  <input className="input mono grow" placeholder="address (8 bytes)" value={wpAddr} onChange={(e) => setWpAddr(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void addWatch()} />
                  <select className="select" value={wpAccess} onChange={(e) => setWpAccess(e.target.value)}><option value="rw">r/w</option><option value="r">read</option><option value="w">write</option></select>
                  <button className="btn small" onClick={() => void addWatch()}>Watch</button>
                </div>
                {wps.map((w) => (
                  <div key={w.address} className="row mono">
                    <span className="grow">{label(w.address)} <span className="faint">{w.access}</span></span>
                    <IconButton tip="Remove" onClick={() => void dropWatch(w.address)}><X size={12} /></IconButton>
                  </div>
                ))}
                <div className="label" style={{ marginTop: 8 }}>Snapshots</div>
                <div className="row wrap">
                  <button className="btn small" onClick={() => void snapshot()}>Take snapshot</button>
                  {snaps.map((n) => <button key={n} className="pill" title="Restore this snapshot" onClick={() => void call("emu_restore", { name: n })}>↺ {n}</button>)}
                </div>
              </div>
            </>
          )}
        </div>
        <div className="list-col vlist" style={{ borderRight: "none" }}>
          {!st ? (
            <div className="empty"><div className="empty-title">No session.</div><div className="empty-hint">Pick a function address and start a session: step through it, set breakpoints, change registers or memory and see what it computes — without touching the process.</div></div>
          ) : (
            <>
              <table className="table mono">
                <thead><tr><th style={{ width: 18 }} /><th>Next instructions</th><th /></tr></thead>
                <tbody>{st.next.map((n, i) => (
                  <tr key={n.address} className={i === 0 ? "selected" : undefined}>
                    <td className="link" title="Toggle breakpoint" onClick={() => void toggleBp(n.address, !st.breakpoints.includes(n.address))}>{st.breakpoints.includes(n.address) ? "●" : i === 0 ? "▶" : ""}</td>
                    <td className="link" onClick={() => ui.goDisasm(n.address)}>{label(n.address)}</td>
                    <td>{n.text}</td>
                  </tr>
                ))}</tbody>
              </table>
              {st.api_calls && st.api_calls.length > 0 && (
                <div className="panel-section"><div className="label">API calls this run</div>
                  <div className="mono" style={{ fontSize: 12 }}>{st.api_calls.slice(0, 50).map((c, i) => <div key={i}>{c.api}{c.note ? ` (${c.note})` : ""} → {c.result}</div>)}</div></div>
              )}
              {st.layers && st.layers.length > 0 && (
                <div className="panel-section"><div className="label">Unpacking layers</div>
                  {st.layers.map((l) => <div key={l.entry} className="mono link accent" onClick={() => ui.goDisasm(l.entry)}>{label(l.entry)}</div>)}</div>
              )}
              <table className="table mono">
                <thead><tr><th>Stack</th><th>Value</th></tr></thead>
                <tbody>{st.stack.map((s) => <tr key={s.address}><td className="faint">{s.address}</td><td className="link" onClick={() => { setMemAddr(s.value); void readMem(s.value); }}>{label(s.value)}</td></tr>)}</tbody>
              </table>
              <div className="panel-section">
                <div className="label">Emulator memory {st.dirty_pages.length > 0 && <span className="faint">({st.dirty_pages.length} pages written in the session)</span>}</div>
                <div className="row">
                  <input className="input mono grow" placeholder="address" value={memAddr} onChange={(e) => setMemAddr(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void readMem()} />
                  <button className="btn small" onClick={() => void readMem()}>Read</button>
                </div>
                {mem && (
                  <>
                    <pre className="mcp-result">{(mem.data.match(/.{1,32}/g) ?? []).map((l, i) => `${fmtAddr(BigInt(mem.address) + BigInt(i * 16))}  ${l.replace(/(..)/g, "$1 ")}`).join("\n")}</pre>
                    <div className="row">
                      <input className="input mono grow" placeholder={`bytes to write at ${mem.address} (hex)`} value={patch} onChange={(e) => setPatch(e.target.value)} />
                      <button className="btn small" onClick={() => void writeMem()}>Write</button>
                    </div>
                  </>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
