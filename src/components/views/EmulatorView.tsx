import { useState } from "react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent } from "../ui";

type EmuResult = { error: number; error_name: string; fault_address: string; regs: Record<string, string>; trace: string[]; instructions: number };
const kRegs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"];

export default function EmulatorView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const [start, setStart] = useState(ui.selected ?? "");
  const [end, setEnd] = useState("");
  const [code, setCode] = useState("");
  const [regs, setRegs] = useState<Record<string, string>>({ rcx: "", rdx: "", r8: "", r9: "" });
  const [maxInsns, setMaxInsns] = useState(100000);
  const [trace, setTrace] = useState(true);
  const [res, setRes] = useState<EmuResult | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    const s = parseAddress(start, modules);
    const e = parseAddress(end, modules);
    if (s === null || e === null) return log("warn", "emu", "start and end must be addresses");
    const r: Record<string, string> = {};
    for (const [k, v] of Object.entries(regs)) {
      const a = v.trim() ? parseAddress(v, modules) : null;
      if (a !== null) r[k] = fmtAddr(a);
    }
    const cleanCode = code.replace(/[^0-9a-f]/gi, "");
    setBusy(true);
    const out = await attempt("emu", request<EmuResult>("emulate", { start: fmtAddr(s), end: fmtAddr(e), regs: r, max_insns: maxInsns, trace, ...(cleanCode ? { code: cleanCode.toLowerCase() } : {}) }));
    setBusy(false);
    if (out) {
      setRes(out);
      log(out.error === 0 ? "info" : "warn", "emu", `${out.error_name} after ${out.instructions} insns${out.error ? ` at ${out.fault_address}` : ""}`);
    }
  };

  return (
    <NeedsAgent ext>
      <div className="split-h" style={{ ["--fn-w" as string]: "360px" }}>
        <div className="list-col vlist">
          <div className="panel-section">
            <div className="label">Unicorn x86-64 · reads fault in from the target, which is never modified</div>
            <div className="row"><span style={{ width: 50 }}>start</span><input className="input mono grow" value={start} onChange={(e) => setStart(e.target.value)} placeholder="function address" /></div>
            <div className="row"><span style={{ width: 50 }}>end</span><input className="input mono grow" value={end} onChange={(e) => setEnd(e.target.value)} placeholder="stop address (e.g. after the call)" /></div>
            <div className="label">Registers (optional)</div>
            {Object.keys(regs).map((k) => (
              <div key={k} className="row">
                <span className="mono" style={{ width: 50 }}>{k}</span>
                <input className="input mono grow" value={regs[k]} onChange={(e) => setRegs({ ...regs, [k]: e.target.value })} />
              </div>
            ))}
            <div className="row">
              <select className="select" onChange={(e) => e.target.value && setRegs({ ...regs, [e.target.value]: "" })} value="">
                <option value="">+ register</option>
                {kRegs.filter((r) => !(r in regs)).map((r) => <option key={r}>{r}</option>)}
              </select>
            </div>
            <div className="label">Code bytes (optional, hex — otherwise the target's code runs)</div>
            <textarea className="textarea" rows={4} value={code} onChange={(e) => setCode(e.target.value)} placeholder="48 31 c0 c3" />
            <div className="row">
              <span>max insns</span><input className="input mono" style={{ width: 100 }} type="number" value={maxInsns} onChange={(e) => setMaxInsns(Number(e.target.value))} />
              <label className="row"><input type="checkbox" checked={trace} onChange={(e) => setTrace(e.target.checked)} />trace</label>
              <span className="grow" />
              <button className="btn primary" disabled={busy} onClick={() => void run()}>{busy ? "Running…" : "Emulate"}</button>
            </div>
          </div>
        </div>
        <div className="list-col vlist" style={{ borderRight: "none" }}>
          {!res ? (
            <div className="empty"><div className="empty-title">No run yet.</div><div className="empty-hint">Useful for decrypting pointers or evaluating small routines without touching the process.</div></div>
          ) : (
            <>
              <div className="panel-section">
                <div className={res.error === 0 ? "ok" : "warn"}>{res.error_name} · {res.instructions} instructions{res.error ? ` · fault ${res.fault_address}` : ""}</div>
              </div>
              <div className="kv">{kRegs.filter((r) => res.regs[r]).flatMap((r) => [<span key={r + "k"}>{r}</span>, <span key={r} className="link" onClick={() => ui.select(res.regs[r])}>{res.regs[r]}</span>])}</div>
              {res.trace.length > 0 && (
                <table className="table mono">
                  <thead><tr><th>Trace ({res.trace.length})</th></tr></thead>
                  <tbody>{res.trace.map((a, i) => <tr key={i} onClick={() => ui.goDisasm(a)}><td className="link">{labelAddr(a, modules)}</td></tr>)}</tbody>
                </table>
              )}
            </>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
