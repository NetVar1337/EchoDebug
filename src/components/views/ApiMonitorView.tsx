// API call monitor: pick imports / exports (module!function), log each call with decoded
// arguments, the return value and the caller. Debugger breakpoints only: an int3 on each entry and
// a temporary one on the return address; nothing else is written into the target.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Download, ListPlus, Play, Search, Square, Trash2 } from "lucide-react";
import { request } from "@/lib/client";
import { buildIat } from "@/lib/analysis/iat";
import { callsToCsv, filterCalls, formatArgs, importSpecs, parseFunctionList, type ApiCall, type ApiHook, type ApiLog, type ApiSignature } from "@/lib/debugger";
import { labelAddr } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { saveText } from "@/lib/save";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { IconButton } from "../ui";
import VList from "../VList";
import { DebuggerGate } from "../DebuggerGate";

const kMax = 20000;
const kPresets: Record<string, string[]> = {
  windows: [
    "kernel32.dll!CreateFileW", "kernel32.dll!ReadFile", "kernel32.dll!WriteFile", "kernel32.dll!VirtualAlloc", "kernel32.dll!VirtualProtect",
    "kernel32.dll!LoadLibraryW", "kernel32.dll!GetProcAddress", "advapi32.dll!RegOpenKeyExW", "ws2_32.dll!connect", "ws2_32.dll!send", "ws2_32.dll!recv",
  ],
  ptrace: ["libc.so.6!open", "libc.so.6!openat", "libc.so.6!read", "libc.so.6!write", "libc.so.6!mmap", "libc.so.6!mprotect", "libc.so.6!connect", "libc.so.6!send", "libc.so.6!recv"],
};

export default function ApiMonitorView() {
  const { modules, debugger: dbg, target } = useConn();
  const ui = useUi();
  const [picks, setPicks] = useState("");
  const [log_, setLog] = useState<ApiCall[]>([]);
  const [hooks, setHooks] = useState<ApiHook[]>([]);
  const [active, setActive] = useState(false);
  const [info, setInfo] = useState({ total: 0, dropped: 0, pending: 0 });
  const [filter, setFilter] = useState("");
  const [follow, setFollow] = useState(true);
  const [sel, setSel] = useState<number | null>(null);
  const [sigs, setSigs] = useState<ApiSignature[]>([]);
  const [imports, setImports] = useState<string[]>([]);
  const [importFilter, setImportFilter] = useState("");
  const [mod, setMod] = useState("");
  const since = useRef(0);

  const poll = useCallback(async (reset = false) => {
    if (reset) since.current = 0;
    const r = await request<ApiLog>("dbg_api_log", { since: since.current, limit: 5000 }, true).catch(() => null);
    if (!r) return;
    since.current = r.next;
    setActive(r.active);
    setHooks(r.hooks);
    setInfo({ total: r.total, dropped: r.dropped, pending: r.pending_returns });
    // calls logged earlier may have returned since: refresh the not-yet-returned ones by seq
    setLog((cur) => {
      const base = reset ? [] : cur;
      const bySeq = new Map(base.map((c, i) => [c.seq, i]));
      const next = [...base];
      for (const e of r.entries) {
        const i = bySeq.get(e.seq);
        if (i === undefined) next.push(e);
        else next[i] = e;
      }
      return next.length > kMax ? next.slice(next.length - kMax) : next;
    });
  }, []);

  // re-read calls still waiting for their return value (they are updated in place on the relay)
  const refreshPending = useCallback(async () => {
    const open = log_.filter((c) => !c.returned);
    if (!open.length) return;
    const from = Math.min(...open.map((c) => c.seq)) - 1;
    const r = await request<ApiLog>("dbg_api_log", { since: from, limit: 5000 }, true).catch(() => null);
    if (!r) return;
    const upd = new Map(r.entries.map((e) => [e.seq, e]));
    setLog((cur) => cur.map((c) => (!c.returned && upd.has(c.seq) ? upd.get(c.seq)! : c)));
  }, [log_]);

  useEffect(() => {
    if (!dbg) return;
    void poll(true);
    void request<{ signatures: ApiSignature[] }>("dbg_api_signatures", {}, true).then((r) => setSigs(r.signatures)).catch(() => undefined);
  }, [dbg, poll]);
  useEffect(() => {
    if (!dbg) return;
    // fast while monitoring; slowly otherwise, so a monitor started over MCP shows up too
    const t = setInterval(() => { void poll(); if (active) void refreshPending(); }, active ? 500 : 2000);
    return () => clearInterval(t);
  }, [active, dbg, poll, refreshPending]);

  const start = async () => {
    const functions = parseFunctionList(picks);
    if (!functions.length) return log("warn", "api monitor", "pick at least one module!function");
    const r = await attempt("api monitor", request<{ hooked: { name: string; address: string }[]; unresolved: { name: string; error: string }[]; auto: boolean }>("dbg_api_start", { functions }));
    if (!r) return;
    for (const u of r.unresolved) log("warn", "api monitor", `${u.name}: ${u.error}`);
    log("info", "api monitor", `monitoring ${r.hooked.length} function${r.hooked.length === 1 ? "" : "s"}${r.auto ? " (the debugger attached for it and detaches when the monitor stops)" : ""}`);
    void poll();
  };
  const stop = async () => {
    const r = await attempt("api monitor", request<{ calls: number; detached?: boolean }>("dbg_api_stop"));
    if (r) log("info", "api monitor", `stopped after ${r.calls} calls${r.detached ? "; the debugger detached" : ""}`);
    await poll();
    setActive(false);
  };
  const clear = async () => {
    await attempt("api monitor", request("dbg_api_clear"));
    setLog([]);
    setSel(null);
    since.current = 0;
  };
  const exportCsv = async () => {
    const rows = filterCalls(log_, filter);
    await saveText(`api-calls-${target?.name ?? target?.pid ?? "target"}.csv`, callsToCsv(rows), { name: "CSV", extensions: ["csv"] });
  };
  const addPick = (spec: string) => setPicks((p) => (parseFunctionList(p).some((x) => x.toLowerCase() === spec.toLowerCase()) ? p : `${p.trim()}${p.trim() ? "\n" : ""}${spec}`));

  // imports of a PE module (Echo memory reads), offered as module!function picks
  const loadImports = async () => {
    const m = modules.find((x) => x.name === mod) ?? modules.find((x) => x.base === target?.base) ?? modules[0];
    if (!m) return log("warn", "api monitor", "no module list: attach to the process in Targets");
    const img = await attempt("imports", loadImage(m));
    if (!img) return;
    const specs = importSpecs(buildIat(img, BigInt(m.base)).entries);
    setImports(specs);
    setMod(m.name);
    log("info", "api monitor", specs.length ? `${specs.length} imports in ${m.name}` : `${m.name} has no PE import table (ELF modules: type libc.so.6!name or just the name)`);
  };

  const shown = useMemo(() => filterCalls(log_, filter), [log_, filter]);
  const selected = shown.find((c) => c.seq === sel) ?? null;
  const shownImports = useMemo(() => {
    const f = importFilter.toLowerCase();
    return imports.filter((i) => !f || i.toLowerCase().includes(f)).slice(0, 500);
  }, [imports, importFilter]);

  return (
    <DebuggerGate>
      <div className="split-h" style={{ gridTemplateColumns: "300px minmax(0, 1fr)" }}>
        <div className="list-col" style={{ overflow: "auto" }}>
          <div className="toolbar">
            {!active
              ? <button className="btn small primary" onClick={() => void start()}><Play size={13} /> Start monitor</button>
              : <button className="btn small" onClick={() => void stop()}><Square size={13} /> Stop</button>}
            <span className="grow" />
            <span className="faint" style={{ fontSize: 12 }}>{active ? `${hooks.length} hooked` : "stopped"}</span>
          </div>
          <div className="panel-section">
            <div className="label">Functions (module!function, one per line)</div>
            <textarea className="textarea" rows={7} value={picks} onChange={(e) => setPicks(e.target.value)} disabled={active}
              placeholder={dbg === "windows" ? "kernel32.dll!CreateFileW\nws2_32.dll!send\n0x7ff6a0001000=MyFunc" : "libc.so.6!open\nwrite\n0x401000=my_func"} />
            <div className="row wrap">
              {(kPresets[dbg] ?? []).map((p) => <button key={p} className="pill" onClick={() => addPick(p)} disabled={active} title="add">{p.split("!")[1]}</button>)}
            </div>
            <span className="faint">Arguments are decoded for {sigs.length} built-in signatures; other functions show the four argument registers. Hook kernelbase.dll to also catch calls made inside Windows.</span>
          </div>
          <div className="panel-section">
            <div className="label">Imports</div>
            <div className="row">
              <select className="select grow" value={mod} onChange={(e) => setMod(e.target.value)}>
                <option value="">main module</option>
                {modules.map((m) => <option key={m.base} value={m.name}>{m.name}</option>)}
              </select>
              <IconButton tip="Load the module's imports" onClick={() => void loadImports()}><ListPlus size={14} /></IconButton>
            </div>
            {imports.length > 0 && (
              <>
                <label className="search"><Search size={13} /><input placeholder="filter imports…" value={importFilter} onChange={(e) => setImportFilter(e.target.value)} /></label>
                <div style={{ maxHeight: 220, overflow: "auto" }}>
                  {shownImports.map((s) => (
                    <div key={s} className="row mono" style={{ fontSize: 12 }}>
                      <span className="grow ellipsis" title={s}>{s}</span>
                      <button className="row-action" disabled={active} onClick={() => addPick(s)}>add</button>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
          {hooks.length > 0 && (
            <div className="panel-section">
              <div className="label">Hooked</div>
              {hooks.map((h) => (
                <div key={h.address} className="row mono" style={{ fontSize: 12 }}>
                  <span className="link grow ellipsis" onClick={() => ui.goDisasm(h.address)} title={h.address}>{h.name}</span>
                  <span className="faint">{h.hits}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="list-col" style={{ borderRight: "none" }}>
          <div className="toolbar">
            <label className="search grow"><Search size={13} /><input placeholder="filter: function, argument, return value, thread… (!term excludes)" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
            <label className="row" style={{ fontSize: 12 }}><input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />follow</label>
            <IconButton tip="Export CSV (filtered rows)" onClick={() => void exportCsv()} disabled={!shown.length}><Download size={14} /></IconButton>
            <IconButton tip="Clear the log" onClick={() => void clear()} disabled={!log_.length}><Trash2 size={14} /></IconButton>
            <span className="faint" style={{ fontSize: 12 }}>{shown.length}/{log_.length} calls{info.dropped ? ` · ${info.dropped} dropped` : ""}{info.pending ? ` · ${info.pending} awaiting return` : ""}</span>
          </div>
          <div className="call-row head"><span>seq</span><span>thread</span><span>function</span><span>arguments</span><span>return</span><span>caller</span></div>
          {shown.length === 0 ? (
            <div className="faint" style={{ padding: 10, fontSize: 12 }}>{active ? "Waiting for calls…" : "Pick functions on the left and start the monitor. Each call is logged with its arguments, return value and caller."}</div>
          ) : (
            <VList className="vlist" count={shown.length} height={20} scrollTo={follow ? shown.length - 1 : null} row={(i) => {
              const c = shown[i];
              return (
                <div className="call-row" data-selected={c.seq === sel} onClick={() => setSel(c.seq)} onDoubleClick={() => ui.goDisasm(c.caller)} title="double-click: the call site">
                  <span className="faint">{c.seq}</span>
                  <span className="faint">{c.tid}</span>
                  <span className="accent">{c.function}</span>
                  <span>{formatArgs(c)}</span>
                  <span className={c.returned ? undefined : "faint"}>{c.returned ? c.ret_text : "…"}</span>
                  <span className="faint">{labelAddr(c.caller, modules)}</span>
                </div>
              );
            }} />
          )}
          {selected && (
            <div className="panel-section" style={{ maxHeight: 220, overflow: "auto" }}>
              <div className="row">
                <span className="accent mono grow">{selected.function}</span>
                <span className="faint">#{selected.seq} · thread {selected.tid} · {new Date(selected.t).toLocaleTimeString()}</span>
              </div>
              <table className="table mono"><tbody>
                {selected.args.map((a) => (
                  <tr key={a.name}><td className="faint" style={{ width: 130 }}>{a.name}</td><td style={{ width: 130 }}>{a.value}</td><td className="ellipsis" title={a.text}>{a.text}</td></tr>
                ))}
                <tr><td className="faint">return</td><td>{selected.ret ?? "—"}</td><td>{selected.ret_text}</td></tr>
                <tr><td className="faint">caller</td><td colSpan={2}><span className="link" onClick={() => ui.goDisasm(selected.caller)}>{labelAddr(selected.caller, modules)}</span></td></tr>
              </tbody></table>
            </div>
          )}
        </div>
      </div>
    </DebuggerGate>
  );
}
