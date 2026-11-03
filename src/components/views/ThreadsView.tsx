// Threads of the target with a call stack per thread (x64 unwinding in the relay: .pdata on PE,
// .eh_frame on ELF, frame-pointer / stack-scan fallback marked "guessed"), and its open handles.
import { useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { EchoError } from "@/lib/client";
import { labelAddr } from "@/lib/hex";
import { fetchHandles, fetchStack, fetchThreads, frameName, kEchoUnsupported, type HandleInfo, type StackFrame, type ThreadsReply } from "@/lib/threadslive";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { Empty, IconButton, NeedsAgent } from "../ui";

const kMethod: Record<StackFrame["method"], string> = {
  context: "registers", pdata: ".pdata", leaf: "leaf", cfi: ".eh_frame", "frame-pointer": "frame pointer", "stack-scan": "stack scan",
};

const kCol = { display: "flex", flexDirection: "column", flex: 1, height: "100%", minHeight: 0 } as const;

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function Stack({ frames }: { frames: StackFrame[] }) {
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  useNames((s) => s.names); // re-render when the user renames a frame's function
  if (!frames.length) return <div className="faint" style={{ padding: 8 }}>no frames</div>;
  return (
    <table className="table mono">
      <thead><tr><th style={{ width: 28 }}>#</th><th style={{ width: 120 }}>address</th><th style={{ width: "30%" }}>function</th><th>module+offset</th><th style={{ width: 110 }}>stack</th><th style={{ width: 84 }}>found by</th></tr></thead>
      <tbody>
        {frames.map((f) => (
          <tr key={f.index} title={f.guessed ? "recovered by a heuristic: no unwind data covered the frame below" : undefined}>
            <td className="faint">{f.index}</td>
            <td className="link" onClick={() => ui.goDisasm(f.address)}>{f.address}</td>
            <td className="ellipsis link" onClick={() => ui.goDisasm(f.address)}>{frameName(f, modules)}</td>
            <td className="ellipsis faint">{f.module ? `${f.module}+${f.offset}` : "(no module)"}</td>
            <td className="link faint" onClick={() => ui.goMemory(f.sp)}>{f.sp}</td>
            <td>{f.guessed ? <span className="pill badge-warn">guessed · {kMethod[f.method]}</span> : <span className="faint">{kMethod[f.method]}</span>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Threads() {
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [data, setData] = useState<ThreadsReply | null>(null);
  const [error, setError] = useState<{ code: number; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [allStacks, setAllStacks] = useState(true);
  const [sel, setSel] = useState<number | null>(null);
  const [stack, setStack] = useState<StackFrame[] | null>(null);

  const load = async () => {
    setBusy(true);
    try {
      const r = await fetchThreads({ stacks: allStacks, maxFrames: 64 });
      setData(r);
      setError(null);
      if (sel === null || !r.threads.some((t) => t.tid === sel)) setSel(r.threads.find((t) => t.main)?.tid ?? r.threads[0]?.tid ?? null);
      setStack(null);
    } catch (e) {
      setError({ code: e instanceof EchoError ? e.code : 0, text: errText(e) });
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => { void load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const thread = data?.threads.find((t) => t.tid === sel);
  // without "every stack", unwind the selected thread on demand
  useEffect(() => {
    if (!thread || thread.frames || allStacks) return;
    let live = true;
    fetchStack(thread.tid).then((f) => live && setStack(f), (e) => live && log("error", "stack", errText(e)));
    return () => { live = false; };
  }, [thread, allStacks]);
  const frames = thread?.frames ?? stack;

  if (error?.code === kEchoUnsupported)
    return <Empty title="The Echo backend can't list threads or call stacks." hint="Echo's script API has no thread enumeration, thread context or handle access, so the agent cannot read them. Threads, stacks and handles work on the local Linux backend (and natively on Windows when Echo is not connected). TLS callbacks and exception handlers (TLS & SEH view) work on every backend." />;

  const isWin = data?.platform === "windows";
  return (
    <div style={kCol}>
      <div className="toolbar">
        <IconButton tip="Refresh (stops every thread for a moment to read its registers)" onClick={() => void load()} disabled={busy}><RefreshCw size={14} /></IconButton>
        <label className="row small-label" title="Unwind every thread on refresh (otherwise only the selected one)"><input type="checkbox" checked={allStacks} onChange={(e) => setAllStacks(e.target.checked)} />every stack</label>
        {data && <span className="faint">{data.threads.length} threads · registers via {data.registers_from}</span>}
        {busy && <span className="faint">reading…</span>}
        {error && <span className="danger ellipsis" title={error.text}>{error.text}</span>}
      </div>
      {data && (
        <div style={{ maxHeight: "45%", overflow: "auto", flexShrink: 0 }}>
          <table className="table mono">
            <thead><tr>
              <th style={{ width: 104 }}>tid</th><th style={{ width: 110 }}>name</th><th style={{ width: 150 }}>state</th><th style={{ width: 44 }}>prio</th>
              <th>start</th><th style={{ width: 120 }}>{isWin ? "TEB" : "TLS (fs_base)"}</th><th style={{ width: 120 }}>rip</th><th style={{ width: 60 }}>cpu ms</th>
            </tr></thead>
            <tbody>
              {data.threads.map((t) => (
                <tr key={t.tid} data-selected={t.tid === sel} onClick={() => setSel(t.tid)} style={{ cursor: "pointer" }}>
                  <td>{t.tid}{t.main ? <span className="pill accent" style={{ marginLeft: 4 }}>main</span> : null}</td>
                  <td className="ellipsis">{t.name ?? ""}</td>
                  <td className="ellipsis" title={t.wait ?? undefined}>{t.state_name ?? String(t.state ?? "")}{t.wait ? <span className="faint"> · {t.wait}</span> : null}{t.suspend_count ? <span className="warn"> · suspended ×{t.suspend_count}</span> : null}</td>
                  <td className="faint">{t.priority ?? t.base_priority ?? ""}{t.nice ? ` (${t.nice})` : ""}</td>
                  <td className="ellipsis" title={t.start_source}>{t.start ? <span className="link" onClick={(e) => { e.stopPropagation(); ui.goDisasm(t.start!); }}>{t.start_label ?? labelAddr(t.start, modules)}</span> : <span className="faint">?</span>}</td>
                  <td>{(t.teb ?? t.tls) ? <span className="link faint" onClick={(e) => { e.stopPropagation(); ui.goMemory((t.teb ?? t.tls)!); }}>{t.teb ?? t.tls}</span> : ""}</td>
                  <td>{t.rip ? <span className="link" onClick={(e) => { e.stopPropagation(); ui.goDisasm(t.rip!); }}>{t.rip}</span> : <span className="faint" title={t.registers_error ?? t.error}>{t.registers_error || t.error ? "unreadable" : ""}</span>}</td>
                  <td className="faint">{t.time_ms ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {thread && (
        <div className="panel-section" style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
          <div className="label">Call stack of {thread.tid}{thread.name ? ` (${thread.name})` : ""}</div>
          {thread.registers_error && <div className="danger" style={{ fontSize: 12 }}>{thread.registers_error}</div>}
          {thread.registers && (
            <div className="mono faint" style={{ fontSize: 11, display: "flex", flexWrap: "wrap", gap: "2px 12px", padding: "2px 0 6px" }}>
              {Object.entries(thread.registers).map(([k, v]) => <span key={k}>{k}=<span className="link" onClick={() => ui.goMemory(v)}>{v}</span></span>)}
            </div>
          )}
          {frames ? <Stack frames={frames} /> : !thread.registers_error && <div className="faint">unwinding…</div>}
        </div>
      )}
    </div>
  );
}

function Handles() {
  const [list, setList] = useState<HandleInfo[] | null>(null);
  const [error, setError] = useState<{ code: number; text: string } | null>(null);
  const [filter, setFilter] = useState("");
  const load = async () => {
    try {
      setList(await fetchHandles());
      setError(null);
    } catch (e) {
      setError({ code: e instanceof EchoError ? e.code : 0, text: errText(e) });
    }
  };
  useEffect(() => { void load(); }, []);
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return (list ?? []).filter((h) => !f || h.type.toLowerCase().includes(f) || (h.name ?? "").toLowerCase().includes(f) || String(h.handle).includes(f));
  }, [list, filter]);
  const types = useMemo(() => {
    const m = new Map<string, number>();
    for (const h of list ?? []) m.set(h.type, (m.get(h.type) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [list]);
  if (error?.code === kEchoUnsupported)
    return <Empty title="The Echo backend can't list handles." hint="Echo's script API has no handle access. Handles are listed on the local Linux backend (/proc/<pid>/fd) and natively on Windows when Echo is not connected." />;
  return (
    <div style={kCol}>
      <div className="toolbar">
        <IconButton tip="Refresh" onClick={() => void load()}><RefreshCw size={14} /></IconButton>
        <input className="input grow" placeholder="filter by type, name or value" value={filter} onChange={(e) => setFilter(e.target.value)} />
        {list && <span className="faint">{shown.length} / {list.length}</span>}
        {error && <span className="danger ellipsis" title={error.text}>{error.text}</span>}
      </div>
      {types.length > 0 && <div className="row" style={{ padding: "4px 8px", flexWrap: "wrap", gap: 4 }}>{types.map(([t, n]) => <span key={t} className="pill link" onClick={() => setFilter(t)}>{t} {n}</span>)}</div>}
      <div style={{ flex: 1, minHeight: 0, overflow: "auto" }}>
        <table className="table mono">
          <thead><tr><th style={{ width: 110 }}>handle</th><th style={{ width: 120 }}>type</th><th>name / target</th><th style={{ width: 220 }}>access / flags</th></tr></thead>
          <tbody>
            {shown.slice(0, 5000).map((h) => (
              <tr key={String(h.handle)}>
                <td>{String(h.handle)}</td>
                <td>{h.type}</td>
                <td className="ellipsis" title={h.name ?? ""}>{h.name ?? <span className="faint">—</span>}</td>
                <td className="ellipsis faint">{h.access ?? (h.flags ?? []).join(" ")}{h.position ? ` · pos ${h.position}` : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function ThreadsView() {
  const backend = useConn((s) => s.backend);
  const [tab, setTab] = useState<"threads" | "handles">("threads");
  if (backend === "echo")
    return <Empty title="The Echo backend can't list threads, call stacks or handles." hint="Echo's script API exposes no thread enumeration, thread context (GetThreadContext) or handle access, so the agent cannot provide them. They work on the local Linux backend and natively on Windows without Echo. TLS callbacks and exception handlers (TLS & SEH view) work with Echo too." />;
  return (
    <NeedsAgent>
      <div style={kCol}>
        <div className="toolbar">
          <div className="segmented">
            <button data-active={tab === "threads"} onClick={() => setTab("threads")}>Threads &amp; stacks</button>
            <button data-active={tab === "handles"} onClick={() => setTab("handles")}>Handles</button>
          </div>
        </div>
        {tab === "threads" ? <Threads /> : <Handles />}
      </div>
    </NeedsAgent>
  );
}
