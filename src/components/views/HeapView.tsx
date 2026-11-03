// Heap explorer: glibc malloc arenas (Linux) or the process heaps of the PEB (Windows NT heap /
// segment heap), every chunk with its state and bin, stats per heap, a size histogram, RTTI type
// guesses, "who points here" and links into Memory and Structs.
import { useEffect, useMemo, useRef, useState } from "react";
import { RefreshCw, Search, X } from "lucide-react";
import { fmtAddr, labelAddr } from "@/lib/hex";
import { readBytes } from "@/lib/memory";
import { pointerClassifier } from "@/lib/ptrkind";
import { guessFields } from "@/lib/analysis/structguess";
import { exploreHeaps, cachedReport, resolveTypes, typeOf, whoPointsHere, type PointerHit } from "@/lib/heaplive";
import { filterChunks, heapStats, isFree, sizeHistogram, type HeapChunk, type HeapReport } from "@/lib/analysis/heap/model";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useTypes } from "@/store/types";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent } from "../ui";
import VList from "../VList";

const kStates = ["all", "used", "free", "in-use", "tcache", "fastbin", "unsorted", "smallbin", "largebin", "top", "mmapped", "lfh", "large", "internal"];

const size = (n: number) => (n >= 1 << 30 ? `${(n / (1 << 30)).toFixed(1)} GiB` : n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MiB` : n >= 1 << 10 ? `${(n / 1024).toFixed(1)} KiB` : `${n} B`);
const hx = (n: number) => `0x${n.toString(16)}`;
const parseSize = (s: string): number | undefined => {
  const t = s.trim();
  if (!t) return undefined;
  const v = /^0x/i.test(t) ? parseInt(t, 16) : Number(t);
  return Number.isFinite(v) && v >= 0 ? v : undefined;
};
const previewHex = (b?: Uint8Array) => (b ? Array.from(b.subarray(0, 8), (x) => x.toString(16).padStart(2, "0")).join(" ") : "");
const previewAscii = (b?: Uint8Array) => (b ? Array.from(b, (x) => (x >= 0x20 && x < 0x7f ? String.fromCharCode(x) : ".")).join("") : "");
/** reports already logged (two views, or StrictMode's double effect, share one walk) */
const logged = new WeakSet<HeapReport>();
const tone = (c: HeapChunk) => (isFree(c.state) ? "ok" : c.state === "top" || c.state === "fencepost" || c.state === "internal" ? "faint" : c.state === "lfh" || c.state === "large" || c.state === "mmapped" ? "warn" : "");

export default function HeapView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const pid = useConn((s) => s.target?.pid);
  const [report, setReport] = useState<HeapReport | null>(() => cachedReport());
  const [busy, setBusy] = useState("");
  const [heap, setHeap] = useState<string>("");
  const [state, setState] = useState("all");
  const [minS, setMinS] = useState("");
  const [maxS, setMaxS] = useState("");
  const [text, setText] = useState("");
  const [bin, setBin] = useState("");
  const [sel, setSel] = useState<HeapChunk | null>(null);
  const [typesTick, setTypesTick] = useState(0);
  const [refs, setRefs] = useState<{ chunk: HeapChunk; hits: PointerHit[]; scanned: number; done: boolean; truncated: boolean } | null>(null);
  const [side, setSide] = useState<"heaps" | "bins" | "errors">("heaps");
  const refSignal = useRef({ aborted: false });

  const scan = async (refresh: boolean) => {
    setBusy("walking heaps…");
    try {
      const r = await exploreHeaps({ refresh, onStatus: setBusy });
      setReport(r);
      setSel(null);
      setRefs(null);
      if (logged.has(r)) return;
      logged.add(r);
      log(r.errors.length ? "warn" : "info", "heap", `${r.heaps.length} heap(s), ${r.chunks.length} chunks; ${r.source}${r.errors.length ? `; ${r.errors.length} walk error(s)` : ""}`);
    } finally {
      setBusy("");
    }
  };

  useEffect(() => {
    if (pid && !cachedReport()) void attempt("heap", scan(false));
    else setReport(cachedReport());
  }, [pid]);

  // RTTI names for chunks that start with a module pointer, in the background
  useEffect(() => {
    if (!report) return;
    let live = true;
    void resolveTypes(report.chunks, modules, { max: 50_000, live: () => live, onBatch: () => live && setTypesTick((t) => t + 1) }).catch(() => 0);
    return () => { live = false; };
  }, [report, modules]);

  const shown = useMemo(() => {
    if (!report) return [];
    const list = filterChunks(report.chunks, { heap: heap || undefined, state, minSize: parseSize(minS), maxSize: parseSize(maxS), text }, typeOf);
    return bin ? list.filter((c) => c.bin === bin) : list;
  }, [report, heap, state, minS, maxS, text, bin, typesTick]);
  const hist = useMemo(() => sizeHistogram(shown).filter((b) => b.count), [shown]);
  const histMax = Math.max(1, ...hist.map((b) => b.count));

  const pointsHere = async (c: HeapChunk) => {
    refSignal.current.aborted = true;
    const signal = { aborted: false };
    refSignal.current = signal;
    setRefs({ chunk: c, hits: [], scanned: 0, done: false, truncated: false });
    const r = await whoPointsHere(c, { signal, onProgress: (scanned) => setRefs((x) => (x && x.chunk === c ? { ...x, scanned } : x)) });
    setRefs((x) => (x && x.chunk === c ? { chunk: c, ...r, done: true } : x));
    log("info", "heap", `${r.hits.length} pointer(s) into ${fmtAddr(c.address)} (${size(r.scanned)} scanned${r.truncated ? ", stopped at the limit" : ""})`);
  };

  const openStruct = async (c: HeapChunk) => {
    const n = Math.min(Math.max(c.userSize, 8), 0x800);
    const b = await readBytes(c.user, n);
    if (!b) return log("error", "heap", `${fmtAddr(c.user)} is not readable`);
    const fields = guessFields(b, { kindOf: await pointerClassifier(modules) });
    const t = typeOf(c);
    const id = useTypes.getState().add(`${t ? t.replace(/[^A-Za-z0-9_]/g, "_") : "Heap"}_${c.user.toString(16)}`, fields);
    ui.set({ structType: id });
    ui.goStruct(fmtAddr(c.user));
  };

  useEffect(() => () => { refSignal.current.aborted = true; }, []);

  const stats = useMemo(() => (report ? report.heaps.map((h) => ({ h, s: heapStats(report, h.id) })) : []), [report]);
  const total = useMemo(() => (report ? heapStats(report) : null), [report]);
  const bins = useMemo(() => (report ? report.bins.filter((b) => (!heap || b.heap === heap) && (b.entries.length || b.error || b.count)) : []), [report, heap]);
  const binName = (b: HeapReport["bins"][number]) => (b.kind === "lfh" ? `lfh ${hx(b.chunkSize)}` : b.kind === "tcache" || b.kind === "fastbin" ? `${b.kind}[${b.index}]` : b.kind === "unsorted" ? "unsorted" : `${b.kind}[${b.index}]`);

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "300px" }}>
        <div className="list-col">
          <div className="toolbar">
            <button className="btn primary small" disabled={!!busy || !pid} onClick={() => void attempt("heap", scan(true))}><RefreshCw size={12} /> {report ? "Rescan" : "Scan heaps"}</button>
            {(["heaps", "bins", "errors"] as const).map((t) => (
              <button key={t} className="btn small" data-active={side === t} onClick={() => setSide(t)}>
                {t}{t === "errors" && report?.errors.length ? <span className="danger"> {report.errors.length}</span> : null}
              </button>
            ))}
          </div>
          {busy && <div className="faint" style={{ padding: "6px 10px", fontSize: 12 }}>{busy}</div>}
          {!report && !busy && <div className="empty"><div className="empty-title">No heap walk yet.</div><div className="empty-hint">Walks glibc malloc arenas on Linux targets and PEB→ProcessHeaps (NT heap, segment heap) on Windows targets. Only reads memory.</div></div>}
          {report && (
            <div className="vlist">
              <div className="panel-section">
                <div className="faint" style={{ whiteSpace: "normal" }}>{report.source}{report.version ? ` · glibc ${report.version}` : ""}</div>
                {report.notes.map((n) => <div key={n} className="faint" style={{ whiteSpace: "normal" }}>{n}</div>)}
                {report.truncated && <div className="warn">walk stopped at the chunk limit</div>}
              </div>
              {side === "heaps" && (
                <>
                  <div className="fn-row" data-selected={heap === ""} onClick={() => { setHeap(""); setBin(""); }}>
                    <span className="grow">all heaps</span>
                    {total && <span className="faint">{total.chunks} chunks</span>}
                  </div>
                  {stats.map(({ h, s }) => (
                    <div key={h.id} className="panel-section" data-selected={heap === h.id} style={{ cursor: "pointer", background: heap === h.id ? "var(--selection)" : undefined }} onClick={() => { setHeap(h.id); setBin(""); }}>
                      <div className="row"><span className="mono grow ellipsis" title={h.id}>{h.label}</span><span className="pill">{h.kind}</span></div>
                      <div className="kv" style={{ padding: 0 }}>
                        <span>committed</span><span>{size(h.committed)}{h.reserved ? ` / ${size(h.reserved)} reserved` : ""}</span>
                        <span>in use</span><span>{size(s.inUse)} in {s.inUseCount}</span>
                        <span>free</span><span>{size(s.free)} in {s.freeCount} (largest {size(s.largestFree)})</span>
                        <span>fragmentation</span><span>{(s.fragmentation * 100).toFixed(1)}%</span>
                        {Object.entries(h.counters).slice(0, 6).map(([k, v]) => [<span key={`${k}k`}>{k.replace(/_/g, " ")}</span>, <span key={`${k}v`}>{typeof v === "number" && v > 4096 ? size(v) : String(v)}</span>])}
                      </div>
                      {h.notes.map((n) => <div key={n} className="faint" style={{ whiteSpace: "normal" }}>{n}</div>)}
                    </div>
                  ))}
                  {hist.length > 0 && (
                    <div className="panel-section">
                      <div className="label">Size histogram ({shown.length} chunks shown)</div>
                      {hist.map((b) => (
                        <div key={b.lo} className="row" style={{ cursor: "pointer", gap: 6 }} title={`${b.count} chunks, ${size(b.bytes)}: click to filter`} onClick={() => { setMinS(String(b.lo)); setMaxS(b.hi === Infinity ? "" : String(b.hi - 1)); }}>
                          <span className="mono faint" style={{ width: 64, textAlign: "right", flexShrink: 0 }}>{b.hi === Infinity ? `≥${size(b.lo)}` : size(b.lo)}</span>
                          <span style={{ flex: 1, minWidth: 0 }}><span style={{ display: "block", height: 8, width: `${(b.count / histMax) * 100}%`, minWidth: 2, background: "var(--accent)", borderRadius: 2 }} /></span>
                          <span className="mono faint" style={{ width: 52, textAlign: "right", flexShrink: 0 }}>{b.count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
              {side === "bins" && (
                <>
                  {bins.length === 0 && <div className="empty"><div className="empty-title">No non-empty bins.</div></div>}
                  {bins.map((b, i) => (
                    <div key={`${b.heap}${b.kind}${b.index}${i}`} className="fn-row" data-selected={bin === binName(b)} onClick={() => { setBin(bin === binName(b) ? "" : binName(b)); setHeap(b.heap); }} title={b.error ?? (b.owner !== undefined ? `owner ${fmtAddr(b.owner)}` : "")}>
                      <span className="grow ellipsis">{binName(b)}</span>
                      <span className="faint">{hx(b.chunkSize)}</span>
                      <span>{b.kind === "lfh" ? `${b.count}/${b.total}` : b.entries.length}</span>
                      {b.error && <span className="danger">!</span>}
                    </div>
                  ))}
                </>
              )}
              {side === "errors" && (
                <>
                  {report.errors.length === 0 && <div className="empty"><div className="empty-title">No walk errors.</div></div>}
                  {report.errors.map((e, i) => (
                    <div key={i} className="panel-section">
                      <span className="link mono" onClick={() => ui.goMemory(fmtAddr(e.address))}>{labelAddr(e.address, modules)}</span>
                      <span className="danger" style={{ whiteSpace: "normal" }}>{e.message}</span>
                    </div>
                  ))}
                </>
              )}
            </div>
          )}
        </div>
        <div className="list-col" style={{ borderRight: "none" }}>
          <div className="toolbar">
            <label className="search grow" style={{ minWidth: 150 }}><Search size={13} /><input placeholder="Filter address, bin or type…" value={text} onChange={(e) => setText(e.target.value)} /></label>
            <select className="select" value={state} onChange={(e) => setState(e.target.value)}>
              {kStates.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <input className="input mono" style={{ width: 80 }} placeholder="min size" value={minS} onChange={(e) => setMinS(e.target.value)} />
            <input className="input mono" style={{ width: 80 }} placeholder="max size" value={maxS} onChange={(e) => setMaxS(e.target.value)} />
            {(minS || maxS || text || bin || state !== "all") && <IconButton tip="Clear filters" onClick={() => { setMinS(""); setMaxS(""); setText(""); setBin(""); setState("all"); }}><X size={13} /></IconButton>}
            <span className="faint" style={{ fontSize: 12 }}>{shown.length}{report ? ` / ${report.chunks.length}` : ""}</span>
          </div>
          <div className="fn-row faint" style={{ borderBottom: "1px solid var(--border-soft)" }}>
            <span style={{ width: 130, flexShrink: 0 }}>address</span>
            <span style={{ width: 64, flexShrink: 0, textAlign: "right" }}>size</span>
            <span style={{ width: 80, flexShrink: 0 }}>state</span>
            <span style={{ flex: "0 1 170px", minWidth: 0 }} className="ellipsis">first bytes</span>
            <span className="grow">type / bin</span>
          </div>
          <VList count={shown.length} row={(i) => {
            const c = shown[i];
            const t = typeOf(c);
            return (
              <div className="fn-row" data-selected={sel === c} onClick={() => setSel(c)} onDoubleClick={() => ui.goMemory(fmtAddr(c.user))}>
                <span style={{ width: 130, flexShrink: 0 }}>{fmtAddr(c.address)}</span>
                <span style={{ width: 64, flexShrink: 0, textAlign: "right" }}>{hx(c.size)}</span>
                <span className={tone(c)} style={{ width: 80, flexShrink: 0 }}>{c.state}</span>
                <span className="faint ellipsis" style={{ flex: "0 1 170px", minWidth: 0 }} title={previewAscii(c.preview)}>{previewHex(c.preview)}</span>
                <span className="grow ellipsis">{t ? <span style={{ color: "var(--text)" }}>{t}</span> : null}{t && c.bin ? " · " : ""}{c.bin ? <span className="faint">{c.bin}</span> : null}{c.note ? <span className="faint"> {c.note}</span> : null}</span>
              </div>
            );
          }} />
          {sel && (
            <div className="panel-section" style={{ borderTop: "1px solid var(--border-soft)", maxHeight: 260, overflow: "auto", flexShrink: 0 }}>
              <div className="label">Chunk {fmtAddr(sel.address)}</div>
              <div className="row" style={{ flexWrap: "wrap", gap: 4 }}>
                <button className="btn small" onClick={() => ui.goMemory(fmtAddr(sel.user))}>Memory</button>
                <button className="btn small" onClick={() => void attempt("heap", openStruct(sel))}>Open as struct</button>
                <button className="btn small" disabled={!!refs && refs.chunk === sel && !refs.done} onClick={() => void attempt("heap", pointsHere(sel))}>Who points here</button>
                {refs && !refs.done && <button className="btn small" onClick={() => { refSignal.current.aborted = true; }}>Stop</button>}
              </div>
              <div className="kv" style={{ padding: 0 }}>
                <span>user</span><span className="link" onClick={() => ui.goMemory(fmtAddr(sel.user))}>{fmtAddr(sel.user)}</span>
                <span>size</span><span>{hx(sel.size)} ({sel.userSize} usable)</span>
                <span>state</span><span>{sel.state}{sel.bin ? ` · ${sel.bin}` : ""}</span>
                <span>flags</span><span>{sel.flags}</span>
                <span>heap</span><span>{report?.heaps.find((h) => h.id === sel.heap)?.label ?? sel.heap}</span>
                {typeOf(sel) && <><span>type</span><span>{typeOf(sel)}</span></>}
                {sel.note && <><span>note</span><span>{sel.note}</span></>}
                <span>bytes</span><span title={previewAscii(sel.preview)}>{sel.preview ? `${Array.from(sel.preview, (x) => x.toString(16).padStart(2, "0")).join(" ")}  ${previewAscii(sel.preview)}` : "-"}</span>
              </div>
              {refs && refs.chunk === sel && (
                <>
                  <div className="faint">{refs.done ? `${refs.hits.length} pointer(s) into this chunk, ${size(refs.scanned)} scanned${refs.truncated ? " (stopped at the limit)" : ""}` : `scanning… ${size(refs.scanned)}`}</div>
                  {refs.hits.map((h) => (
                    <div key={String(h.address)} className="row">
                      <span className="link mono" onClick={() => ui.goMemory(fmtAddr(h.address))}>{labelAddr(h.address, modules)}</span>
                      {h.inside && <span className="faint">inside the chunk</span>}
                    </div>
                  ))}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
