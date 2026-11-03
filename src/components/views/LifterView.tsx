// Lifter: x86-64 → expressions with symbolic execution (relay lift.rs). Three modes:
//   Block       straight-line code at an address: effects, dead code, the closing branch
//   Deobfuscate emulate a function against live memory, slice away junk, simplify (MBA too)
//   Devirt      find a VM dispatcher in the trace, lift every handler, list the virtual stream
import { useState } from "react";
import { Copy } from "lucide-react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent, Tabs } from "../ui";

type Effects = { registers: { register: string; value: string }[]; stores: { address: string; size: number; value: string }[]; unsupported: Record<string, number> };
type Block = Effects & { instructions: { address: string; text: string; effect: string; live: boolean }[]; end: { kind: string; condition?: string; opaque?: string; taken?: string; fallthrough?: string; instruction?: string } | null; dead: number };
type Trace = Effects & { executed: number; unique_addresses: number; live: number; removed: number; listing: ({ address: string; text: string; effect: string } | { loop: number; times: number })[]; conditions: { address: string; instruction: string; condition: string | null; taken: boolean | null; opaque: boolean }[]; opaque_predicates: number; emulation?: { error_name: string; instructions: number; reached_end: boolean } };
type Handler = Effects & { id: number; address: string; executions: number; length: number; body: string[] };
type Devirt = { dispatcher: string | null; note?: string; dispatch_targets?: number; handler_executions?: number; vip_register?: string | null; handlers?: Handler[]; virtual_trace?: number[]; virtual_trace_truncated?: boolean; emulation?: Trace["emulation"] };
type Mode = "block" | "trace" | "devirt";

/** "rcx=0x10, rdx=game.exe+0x40" → { rcx: "0x10", rdx: "0x…" } */
export function parseRegs(text: string, resolve: (s: string) => bigint | null): Record<string, string> | string {
  const out: Record<string, string> = {};
  for (const part of text.split(/[,;\s]+/).filter(Boolean)) {
    const m = /^([a-z0-9]+)=(.+)$/i.exec(part);
    if (!m) return `cannot read "${part}" (use reg=value)`;
    const v = resolve(m[2]);
    if (v === null) return `bad value for ${m[1]}: ${m[2]}`;
    out[m[1].toLowerCase()] = "0x" + v.toString(16);
  }
  return out;
}

/** Argument registers pointed at zeroed scratch pages, so pointer arguments are writable. */
export function scratchArgs(base = 0x7fe000000000n): { regs: Record<string, string>; write: { address: string; data: string }[] } {
  const regs: Record<string, string> = {};
  const write: { address: string; data: string }[] = [];
  ["rcx", "rdx", "r8", "r9", "rdi", "rsi"].forEach((r, i) => {
    const a = base + BigInt(i) * 0x10000n;
    regs[r] = "0x" + a.toString(16);
    write.push({ address: regs[r], data: "00".repeat(0x1000) });
  });
  return { regs, write };
}

const kModes: { id: Mode; label: string }[] = [{ id: "block", label: "Block" }, { id: "trace", label: "Deobfuscate trace" }, { id: "devirt", label: "Devirtualize" }];

function EffectsList({ e }: { e: Effects }) {
  const [all, setAll] = useState(false);
  const stores = all ? e.stores : e.stores.slice(0, 120);
  return (
    <div className="lift-effects mono">
      {e.registers.map((r) => <div key={r.register}><span className="accent">{r.register}</span> = {r.value}</div>)}
      {stores.map((s, i) => {
        const [addr, loop] = s.address.split("  for ");
        return <div key={i}><span className="warn">[{addr}]</span>{s.size < 8 ? `.${s.size * 8}` : ""} = {s.value}{loop && <span className="faint">{"   for "}{loop}</span>}</div>;
      })}
      {e.stores.length > stores.length && <button className="btn small" onClick={() => setAll(true)}>Show all {e.stores.length} stores</button>}
      {!e.registers.length && !e.stores.length && <div className="faint">no effect on registers or memory</div>}
      {Object.keys(e.unsupported).length > 0 && <div className="faint">not modelled (their outputs became unknowns): {Object.entries(e.unsupported).map(([k, n]) => `${k}×${n}`).join(", ")}</div>}
    </div>
  );
}

function effectsText(e: Effects): string {
  return [...e.registers.map((r) => `${r.register} = ${r.value}`), ...e.stores.map((s) => `[${s.address}] = ${s.value}`)].join("\n");
}

export default function LifterView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const [mode, setMode] = useState<Mode>("trace");
  const [start, setStart] = useState(ui.selected ?? "");
  const [end, setEnd] = useState("");
  const [budget, setBudget] = useState(200000);
  const [regsText, setRegsText] = useState("");
  const [scratch, setScratch] = useState(true);
  const [busy, setBusy] = useState(false);
  const [block, setBlock] = useState<Block | null>(null);
  const [trace, setTrace] = useState<Trace | null>(null);
  const [dv, setDv] = useState<Devirt | null>(null);
  const [showAll, setShowAll] = useState(false);
  const lab = (a: string) => labelAddr(a, modules);
  const copy = (t: string) => void navigator.clipboard?.writeText(t).then(() => log("info", "lift", "copied"));

  const run = async () => {
    const s = parseAddress(start, modules);
    if (s === null) return log("warn", "lift", "enter a start address (module+0x… works)");
    const e = end.trim() ? parseAddress(end, modules) : null;
    const args: Record<string, unknown> = { start: fmtAddr(s), max_insns: budget };
    if (e !== null) args.end = fmtAddr(e);
    const user = parseRegs(regsText, (x) => parseAddress(x, modules));
    if (typeof user === "string") return log("warn", "lift", user);
    if (scratch) {
      const sc = scratchArgs();
      args.regs = { ...sc.regs, ...user };
      args.write = sc.write;
    } else if (Object.keys(user).length) args.regs = user;
    setBusy(true);
    if (mode === "block") {
      const r = await attempt("lift", request<Block>("lift_block", { address: fmtAddr(s), max_insns: 512 }));
      if (r) setBlock(r);
    } else if (mode === "trace") {
      const r = await attempt("lift", request<Trace>("lift_trace", args));
      if (r) {
        setTrace(r);
        log("info", "lift", `${r.executed} instructions executed, ${r.live} kept, ${r.removed} removed, ${r.opaque_predicates} opaque predicates`);
      }
    } else {
      const r = await attempt("devirt", request<Devirt>("devirt", args));
      if (r) {
        setDv(r);
        log(r.dispatcher ? "info" : "warn", "devirt", r.dispatcher ? `dispatcher ${r.dispatcher}: ${r.handlers?.length} handlers, ${r.handler_executions} executions` : r.note ?? "no dispatcher");
      }
    }
    setBusy(false);
  };

  return (
    <NeedsAgent>
      <div className="vlist">
        <Tabs tabs={kModes} active={mode} onSelect={setMode} />
        <div className="toolbar wrap">
          <input className="input mono" style={{ width: 230 }} placeholder="start · module+0x…" value={start} onChange={(e) => setStart(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void run()} />
          {mode !== "block" && <input className="input mono" style={{ width: 170 }} placeholder="stop at (optional)" value={end} onChange={(e) => setEnd(e.target.value)} />}
          {mode !== "block" && <label className="row">budget <input className="input mono" style={{ width: 90 }} type="number" value={budget} onChange={(e) => setBudget(Math.max(1, Number(e.target.value)))} /></label>}
          {mode !== "block" && <input className="input mono" style={{ width: 210 }} placeholder="regs: rcx=0x10, rdx=…" value={regsText} onChange={(e) => setRegsText(e.target.value)} title="initial registers for the emulated run" />}
          {mode !== "block" && <label className="row" title="Point rcx/rdx/r8/r9/rdi/rsi at zeroed scratch pages so pointer arguments can be read and written (your regs override)"><input type="checkbox" checked={scratch} onChange={(e) => setScratch(e.target.checked)} />scratch args</label>}
          {ui.selected && ui.selected !== start && <button className="btn small" onClick={() => setStart(ui.selected!)}>use selection</button>}
          <button className="btn primary small" disabled={busy} onClick={() => void run()}>{busy ? "Lifting…" : mode === "block" ? "Lift block" : mode === "trace" ? "Emulate & deobfuscate" : "Emulate & devirtualize"}</button>
        </div>
        <div className="faint" style={{ padding: "0 10px 6px", fontSize: 12 }}>
          {mode === "block" && "Lifts code up to the next branch or return. Instructions that do not reach the final registers or memory are dimmed; a constant branch condition is an opaque predicate."}
          {mode === "trace" && "Emulates from the start against the live process (nothing is written to it), runs the path symbolically, keeps only what affects the result and simplifies every formula — junk code, push/pop noise and MBA disappear. Without a stop address the run ends when the function returns."}
          {mode === "devirt" && "For VM-protected code: emulates into the VM loop, finds the dispatcher (the indirect jump with the most targets), lifts each handler from a fresh state and lists the virtual instruction stream."}
        </div>

        {mode === "block" && block && (
          <>
            <div className="panel-section">
              <div className="row"><span className="label grow">Effects</span><IconButton tip="Copy effects" onClick={() => copy(effectsText(block))}><Copy size={13} /></IconButton></div>
              <EffectsList e={block} />
              {block.end?.kind === "branch" && (
                <div className={block.end.opaque ? "warn" : "faint"} style={{ fontSize: 12, marginTop: 6 }}>
                  {block.end.instruction}: {block.end.condition ?? "condition not modelled"} → {block.end.taken} / else {block.end.fallthrough}{block.end.opaque ? ` · opaque predicate (${block.end.opaque})` : ""}
                </div>
              )}
            </div>
            <table className="table mono">
              <thead><tr><th style={{ width: "28%" }}>Instruction ({block.dead} dead)</th><th>Effect</th></tr></thead>
              <tbody>{block.instructions.map((i) => (
                <tr key={i.address} className={i.live ? "" : "dim"} title={i.live ? "" : "does not affect the final state"}>
                  <td className="link" onClick={() => ui.goDisasm(i.address)}>{i.text}</td><td className="ellipsis">{i.effect}</td>
                </tr>
              ))}</tbody>
            </table>
          </>
        )}

        {mode === "trace" && trace && (
          <>
            <div className="panel-section">
              <div className="faint" style={{ fontSize: 12 }}>
                {trace.emulation && <>emulation: {trace.emulation.error_name}{trace.emulation.reached_end ? " · reached the stop address" : ""} · </>}
                {trace.executed} executed · {trace.unique_addresses} distinct · <span className="ok">{trace.live} kept</span> · {trace.removed} removed as junk · {trace.opaque_predicates} opaque predicates
              </div>
              <div className="row"><span className="label grow">Final effects</span><IconButton tip="Copy effects" onClick={() => copy(effectsText(trace))}><Copy size={13} /></IconButton></div>
              <EffectsList e={trace} />
            </div>
            <div className="panel-section">
              <div className="row"><span className="label grow">Deobfuscated listing ({trace.listing.length})</span><IconButton tip="Copy listing" onClick={() => copy(trace.listing.map((l) => ("loop" in l ? `    ; ↻ the previous ${l.loop} instructions repeat ×${l.times}` : `${l.address}  ${l.text.padEnd(36)} ; ${l.effect}`)).join("\n"))}><Copy size={13} /></IconButton></div>
              <table className="table mono"><tbody>{trace.listing.slice(0, showAll ? 2000 : 300).map((l, i) => ("loop" in l ? (
                <tr key={i}><td colSpan={3} className="accent" style={{ fontSize: 12 }}>↻ the previous {l.loop} instruction{l.loop === 1 ? "" : "s"} repeat ×{l.times} (first iteration shown)</td></tr>
              ) : (
                <tr key={i}><td className="link faint" style={{ width: 150 }} onClick={() => ui.goDisasm(l.address)}>{lab(l.address)}</td><td style={{ width: "34%" }}>{l.text}</td><td className="ellipsis faint">{l.effect}</td></tr>
              )))}</tbody></table>
              {trace.listing.length > 300 && !showAll && <button className="btn small" onClick={() => setShowAll(true)}>Show all {trace.listing.length}</button>}
            </div>
            {trace.conditions.length > 0 && (
              <div className="panel-section">
                <div className="label">Branches on the path</div>
                <table className="table mono"><tbody>{trace.conditions.slice(0, 300).map((c, i) => (
                  <tr key={i} className={c.opaque ? "warn" : ""}><td className="link" style={{ width: 150 }} onClick={() => ui.goDisasm(c.address)}>{lab(c.address)}</td><td>{c.instruction}</td><td className="ellipsis">{c.condition ?? "?"}</td><td style={{ width: 120 }}>{c.opaque ? "opaque" : c.taken === null ? "" : c.taken ? "taken" : "not taken"}</td></tr>
                ))}</tbody></table>
              </div>
            )}
          </>
        )}

        {mode === "devirt" && dv && (
          !dv.dispatcher ? <div className="empty"><div className="empty-title">No VM dispatcher found</div><div className="empty-hint">{dv.note} {dv.emulation ? `(emulation: ${dv.emulation.error_name}, ${dv.emulation.instructions} instructions)` : ""}</div></div> : (
            <>
              <div className="panel-section">
                <div className="kv">
                  <span>dispatcher</span><span className="mono link" onClick={() => ui.goDisasm(dv.dispatcher!)}>{lab(dv.dispatcher)}</span>
                  <span>handlers</span><span>{dv.handlers?.length} distinct · {dv.handler_executions} executions · {dv.dispatch_targets} dispatch targets</span>
                  <span>VIP register</span><span className="mono">{dv.vip_register ?? "not identified"}</span>
                </div>
              </div>
              <div className="panel-section">
                <div className="row"><span className="label grow">Virtual instruction stream</span><IconButton tip="Copy" onClick={() => copy((dv.virtual_trace ?? []).map((h) => `h${h}`).join(" "))}><Copy size={13} /></IconButton></div>
                <div className="mono vtrace">{(dv.virtual_trace ?? []).slice(0, 2000).map((h, i) => <span key={i} className="pill" title={dv.handlers?.[h] ? effectsText(dv.handlers[h]) : ""}>h{h}</span>)}{dv.virtual_trace_truncated ? " …" : ""}</div>
              </div>
              {dv.handlers?.map((h) => (
                <div key={h.id} className="panel-section">
                  <div className="row"><span className="label grow">h{h.id} · <span className="mono link" style={{ textTransform: "none" }} onClick={() => ui.goDisasm(h.address)}>{lab(h.address)}</span> · ×{h.executions} · {h.length} insns</span><IconButton tip="Copy handler" onClick={() => copy(`h${h.id} @ ${h.address}\n${effectsText(h)}\n\n${h.body.join("\n")}`)}><Copy size={13} /></IconButton></div>
                  <EffectsList e={h} />
                  <details><summary className="faint" style={{ fontSize: 12 }}>semantic instructions ({h.body.length})</summary><pre className="mcp-result">{h.body.join("\n")}</pre></details>
                </div>
              ))}
            </>
          )
        )}
        {!block && !trace && !dv && (
          <div className="empty"><div className="empty-title">Pick a start address and lift.</div><div className="empty-hint">Tip: select a function in Disassembly first — the start field picks up the selection. MCP clients get the same analyses as lift_block, lift_trace and devirt.</div></div>
        )}
      </div>
    </NeedsAgent>
  );
}
