import { useState } from "react";
import { request } from "@/lib/client";
import { fmtAddr, hexToBytes, labelAddr, parseAddress } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent } from "../ui";

type MemBlob = { address: string; size: number; ok: boolean; data: string };
type MemAccess = { rip: string; address: string; size: number; access: "r" | "w" | "rw"; before: string; after?: string };
type EmuResult = {
  error: number;
  error_name: string;
  fault_address: string;
  regs: Record<string, string>;
  trace: string[];
  instructions: number;
  reached_end?: boolean;
  mem?: MemBlob[];
  mem_log?: MemAccess[];
  mem_log_truncated?: boolean;
  reg_trace?: { rip: string; changes?: Record<string, string> }[];
  api_calls?: { api: string; address: string; return_to: string; result: string; args: string; note?: string }[];
  api_call_count?: number;
  layers?: { entry: string; page: string }[];
  faults?: { address: string; rip: string }[];
  fault_count?: number;
  xmm?: Record<string, string>;
};

const kRegs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"];

/** A scratch buffer the emulator writes into, so a routine can be fed input. */
type Blob = { address: string; size: number; input: string; output: string };

export default function EmulatorView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const [start, setStart] = useState(ui.selected ?? "");
  const [end, setEnd] = useState("");
  const [code, setCode] = useState("");
  const [regs, setRegs] = useState<Record<string, string>>({ rcx: "", rdx: "", r8: "", r9: "" });
  const [maxInsns, setMaxInsns] = useState(100000);
  const [trace, setTrace] = useState(true);
  const [memLog, setMemLog] = useState(true);
  const [stubs, setStubs] = useState(true);
  const [layers, setLayers] = useState(false);
  const [zero, setZero] = useState(false);
  const [regTrace, setRegTrace] = useState(false);
  const [res, setRes] = useState<EmuResult | null>(null);
  const [busy, setBusy] = useState(false);
  // Oracle mode: a buffer that is written before the run and read back after it.
  const [oracle, setOracle] = useState(false);
  const [bufAddr, setBufAddr] = useState("0x7ff000000000");
  const [bufInput, setBufInput] = useState("");
  const [bufSize, setBufSize] = useState(64);
  const [blobs, setBlobs] = useState<Blob[]>([]);

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
    const write: { address: string; data: string }[] = [];
    const read: { address: string; size: number }[] = [];
    if (oracle) {
      const a = parseAddress(bufAddr, modules);
      if (a === null) return log("warn", "emu", "the buffer address does not parse");
      const bytes = hexToBytes(bufInput.replace(/[^0-9a-f]/gi, "") || "00");
      write.push({ address: fmtAddr(a), data: bytesToHexLocal(bytes).slice(0, bufSize * 2) });
      read.push({ address: fmtAddr(a), size: bufSize });
      // Point the first argument register at the buffer unless the user set one.
      if (!r.rcx) r.rcx = fmtAddr(a);
    }
    setBusy(true);
    const out = await attempt("emu", request<EmuResult>("emulate", {
      start: fmtAddr(s),
      end: fmtAddr(e),
      regs: r,
      max_insns: maxInsns,
      trace,
      mem_log: memLog,
      stubs,
      layers,
      trace_regs: regTrace,
      on_unmapped: zero ? "zero" : "stop",
      ...(cleanCode ? { code: cleanCode.toLowerCase() } : {}),
      ...(write.length ? { write } : {}),
      ...(read.length ? { read } : {}),
    }));
    setBusy(false);
    if (out) {
      setRes(out);
      if (out.mem?.length) {
        setBlobs(out.mem.map((m) => ({ address: m.address, size: m.size, input: bufInput.replace(/[^0-9a-f]/gi, ""), output: m.data })));
      }
      log(out.error === 0 ? "info" : "warn", "emu", `${out.error_name} after ${out.instructions} insns${out.error ? ` at ${out.fault_address}` : ""}`);
    }
  };

  return (
    <NeedsAgent ext>
      <div className="split-h" style={{ ["--fn-w" as string]: "380px" }}>
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
              <label className="row" title="Log every explicit memory read/write with its value"><input type="checkbox" checked={memLog} onChange={(e) => setMemLog(e.target.checked)} />memory</label>
            </div>
            <div className="row wrap">
              <label className="row" title="Simulate common API calls (VirtualAlloc, GetProcAddress, memcpy, strlen, …) and return to the caller, so unpackers and decryptors run to the end"><input type="checkbox" checked={stubs} onChange={(e) => setStubs(e.target.checked)} />API stand-ins</label>
              <label className="row" title="Report pages that were written and then executed: unpacking layers and their entry points"><input type="checkbox" checked={layers} onChange={(e) => setLayers(e.target.checked)} />unpack layers</label>
              <label className="row" title="Map a zero page on unmapped reads and keep going (every fault is listed)"><input type="checkbox" checked={zero} onChange={(e) => setZero(e.target.checked)} />zero unmapped</label>
              <label className="row" title="Record which registers change at every instruction"><input type="checkbox" checked={regTrace} onChange={(e) => setRegTrace(e.target.checked)} />register trace</label>
              <span className="grow" />
              <button className="btn primary" disabled={busy} onClick={() => void run()}>{busy ? "Running…" : "Emulate"}</button>
            </div>
          </div>

          <div className="panel-section">
            <div className="label">Decrypt oracle</div>
            <label className="row" style={{ fontSize: 12 }}>
              <input type="checkbox" checked={oracle} onChange={(e) => setOracle(e.target.checked)} />
              feed a buffer into the routine and read the result back
            </label>
            {oracle && (
              <>
                <div className="row">
                  <span style={{ width: 50 }}>buffer</span>
                  <input className="input mono grow" value={bufAddr} onChange={(e) => setBufAddr(e.target.value)} />
                </div>
                <div className="row">
                  <span style={{ width: 50 }}>size</span>
                  <input className="input mono" style={{ width: 80 }} type="number" value={bufSize} onChange={(e) => setBufSize(Number(e.target.value))} />
                  <span className="faint" style={{ fontSize: 12 }}>bytes</span>
                </div>
                <textarea className="textarea" rows={3} value={bufInput} onChange={(e) => setBufInput(e.target.value)} placeholder="ciphertext bytes, hex" />
                <div className="faint" style={{ fontSize: 12 }}>
                  The buffer is written into the emulator before the run and read back after it.
                  The target process is never touched.
                </div>
              </>
            )}
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
              {blobs.length > 0 && (
                <div className="panel-section">
                  <div className="label">Oracle buffer</div>
                  {blobs.map((b) => (
                    <div key={b.address} className="mono">
                      <div className="faint">{b.address}</div>
                      <div>in  {b.input}</div>
                      <div className="ok">out {b.output}</div>
                    </div>
                  ))}
                </div>
              )}
              {res.mem_log && res.mem_log.length > 0 && (
                <table className="table mono">
                  <colgroup><col style={{ width: "34%" }} /><col style={{ width: 36 }} /><col style={{ width: "30%" }} /><col /></colgroup>
                  <thead><tr><th>Memory ({res.mem_log.length}{res.mem_log_truncated ? ", limit hit" : ""})</th><th /><th>Address</th><th>Value</th></tr></thead>
                  <tbody>{res.mem_log.map((m, i) => (
                    <tr key={i}>
                      <td className="link" onClick={() => ui.goDisasm(m.rip)}>{labelAddr(m.rip, modules)}</td>
                      <td className={m.access === "r" ? "dim" : "warn"}>{m.access}</td>
                      <td className="link" onClick={() => ui.select(m.address)} title={`${m.size} bytes`}>{labelAddr(m.address, modules)}</td>
                      <td title={m.after !== undefined ? `${m.before || "?"} → ${m.after || "?"}` : m.before}>{m.after !== undefined ? <>{m.before || "?"} → <span className="ok">{m.after || "?"}</span></> : m.before || "?"}</td>
                    </tr>
                  ))}</tbody>
                </table>
              )}
              {res.layers && res.layers.length > 0 && (
                <table className="table mono">
                  <thead><tr><th>Unpacking layers ({res.layers.length})</th><th>written page</th></tr></thead>
                  <tbody>{res.layers.map((l, i) => <tr key={i}><td className="link accent" onClick={() => ui.goDisasm(l.entry)}>{labelAddr(l.entry, modules)}</td><td className="faint">{l.page}</td></tr>)}</tbody>
                </table>
              )}
              {res.api_calls && res.api_calls.length > 0 && (
                <table className="table mono">
                  <thead><tr><th>API calls ({res.api_call_count})</th><th>args</th><th>result</th></tr></thead>
                  <tbody>{res.api_calls.slice(0, 500).map((c, i) => <tr key={i}><td title={`from ${c.return_to}`}>{c.api}{c.note ? <span className="faint"> {c.note}</span> : null}</td><td className="faint ellipsis">{c.args}</td><td>{c.result}</td></tr>)}</tbody>
                </table>
              )}
              {res.faults && res.faults.length > 0 && (
                <div className="panel-section"><div className="label">Unmapped accesses ({res.fault_count})</div>
                  <div className="mono faint" style={{ fontSize: 12 }}>{res.faults.slice(0, 40).map((f) => `${f.address} (rip ${f.rip})`).join(" · ")}</div></div>
              )}
              {res.reg_trace && res.reg_trace.length > 0 && (
                <table className="table mono">
                  <thead><tr><th>Register trace ({res.reg_trace.length})</th><th>changes</th></tr></thead>
                  <tbody>{res.reg_trace.slice(0, 1000).map((t, i) => <tr key={i}><td className="link" onClick={() => ui.goDisasm(t.rip)}>{labelAddr(t.rip, modules)}</td><td className="faint ellipsis">{t.changes ? Object.entries(t.changes).map(([k, v]) => `${k}=${v}`).join(" ") : ""}</td></tr>)}</tbody>
                </table>
              )}
              {res.xmm && Object.values(res.xmm).some((v) => /[1-9a-f]/.test(v)) && (
                <div className="kv mono" style={{ fontSize: 12 }}>{Object.entries(res.xmm).filter(([, v]) => /[1-9a-f]/.test(v)).flatMap(([k, v]) => [<span key={k + "k"}>{k}</span>, <span key={k}>{v}</span>])}</div>
              )}
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

/** Lowercase hex of a byte array. */
function bytesToHexLocal(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}
