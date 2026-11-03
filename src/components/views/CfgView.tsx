// Control-flow graph of the function at the disassembly cursor: basic blocks laid out in layers,
// taken (green), fall-through (red) and unconditional/switch (accent) edges, blocks inside natural
// loops tinted. The Pseudocode mode decompiles the same instructions (decompile.ts: variables,
// calls with arguments, types, switch / for / else-if structuring); "raw" shows the older
// per-instruction output (pseudocode.ts). "Unflattened" removes control-flow flattening
// (unflatten.ts) and shows the recovered graph and its pseudocode.
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Maximize2, RefreshCw, ZoomIn, ZoomOut } from "lucide-react";
import { labelAddr, showAddr, toBig } from "@/lib/hex";
import { layoutCfg, type Block, type Cfg, type CfgEdge, type CfgLine } from "@/lib/analysis/cfg";
import { graphInfo } from "@/lib/analysis/structure";
import { pseudocode, type PseudoLine } from "@/lib/analysis/pseudocode";
import { decompile, irGraph, type Decompiled } from "@/lib/analysis/decompile";
import { analyzeCallees, directCallees, liveOptions, loadFunction, type LiveFunction } from "@/lib/decomplive";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { useTypes } from "@/store/types";
import { useDecomp, varTypesOf } from "@/store/decomp";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent, Progress } from "../ui";

const kLineH = 15;
const kWidth = 340;
const kMaxLines = 28;
const kAutoDecompile = 4000;
const blockH = (b: Block) => 22 + Math.min(b.lines.length, kMaxLines) * kLineH + (b.lines.length > kMaxLines ? kLineH : 0);

/** The recovered graph of an unflattened function, in the graph view's terms. */
function recoveredCfg(d: Decompiled, orig: Cfg): Cfg {
  const byAddr = new Map<string, CfgLine>();
  for (const b of orig.blocks) for (const l of b.lines) byAddr.set(toBig(l.address).toString(16), l);
  const g = irGraph(d.ir);
  const startOf = new Map(g.blocks.map((b) => [b.id, b.start]));
  const blocks: Block[] = g.blocks.map((b) => {
    const lines = b.insns.map((i) => byAddr.get(toBig(i.address).toString(16)) ?? { address: i.address, length: i.length, bytes: "", text: i.text });
    const last = lines[lines.length - 1];
    const t = d.ir.blocks[b.id].term;
    return {
      start: b.start,
      end: last ? toBig(last.address) + BigInt(last.length) : b.start,
      lines,
      terminator: t.k === "cond" ? "jcc" : t.k === "jump" ? "jmp" : t.k === "switch" || t.k === "ijump" ? "indirect" : t.k === "stop" ? "stop" : t.k === "end" ? "fall" : "ret",
    };
  });
  const edges: CfgEdge[] = g.edges.map((e) => ({ from: startOf.get(e.from)!, to: startOf.get(e.to)!, kind: e.kind, ...(e.label ? { label: e.label } : {}) }));
  return { entry: orig.entry, blocks, edges, truncated: orig.truncated };
}

/** Natural-loop membership of the blocks of a drawn graph. */
function loopsOf(cfg: Cfg): Map<bigint, "header" | "body"> {
  const idx = new Map(cfg.blocks.map((b, i) => [b.start, i]));
  const succ = cfg.blocks.map(() => [] as number[]);
  const pred = cfg.blocks.map(() => [] as number[]);
  for (const e of cfg.edges) {
    const a = idx.get(e.from);
    const b = idx.get(e.to);
    if (a === undefined || b === undefined) continue;
    succ[a].push(b);
    pred[b].push(a);
  }
  const entry = idx.get(cfg.entry) ?? 0;
  const info = graphInfo(cfg.blocks.length, (n) => succ[n], (n) => pred[n], entry);
  const m = new Map<bigint, "header" | "body">();
  for (const l of info.loops) for (const n of l.body) if (!m.has(cfg.blocks[n].start) || n === l.header) m.set(cfg.blocks[n].start, n === l.header ? "header" : "body");
  return m;
}

export default function CfgView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const backend = useConn((s) => s.backend);
  const names = useNames();
  const types = useTypes((s) => s.types);
  const decomp = useDecomp();
  const [mode, setMode] = useState<"graph" | "pseudo">("graph");
  const root = ui.disasmAt;
  const [fn, setFn] = useState<LiveFunction | null>(null);
  const [busy, setBusy] = useState(false);
  const [sel, setSel] = useState<bigint | null>(null);
  const [tick, setTick] = useState(0);
  const [calleeTick, setCalleeTick] = useState(0);
  const [force, setForce] = useState(false);
  const [zoom, setZoom] = useState(1);
  const wrap = useRef<HTMLDivElement>(null);
  const abi = backend === "local" ? "sysv" : "win64";

  useEffect(() => {
    if (!root) return;
    let live = true;
    setBusy(true);
    setFn(null);
    void (async () => {
      const f = await attempt("cfg", loadFunction(toBig(root), modules));
      if (!live) return;
      setBusy(false);
      if (f) {
        setFn(f);
        log("info", "cfg", `${f.cfg.blocks.length} blocks, ${f.cfg.edges.length} edges${f.cfg.truncated ? " (truncated)" : ""} at ${labelAddr(root, modules)}`);
      }
    })();
    return () => { live = false; };
  }, [root, tick]);

  const varTypes = varTypesOf(decomp.varTypes, root);
  const insnCount = useMemo(() => fn?.structure.blocks.reduce((n, b) => n + b.insns.length, 0) ?? 0, [fn]);
  // decompiling runs on the UI thread: very large functions only on request
  const tooBig = insnCount > kAutoDecompile && !force;
  useEffect(() => setForce(false), [root]);
  const needDecompile = !!fn && !tooBig && ((mode === "pseudo" && !decomp.raw) || decomp.unflatten);
  const dec = useMemo((): { d: Decompiled | null; error: string | null } => {
    if (!fn || !needDecompile) return { d: null, error: null };
    try {
      return { d: decompile(fn.structure, liveOptions(fn, { abi, userName: names.nameOf, types, varTypes, unflatten: decomp.unflatten })), error: null };
    } catch (e) {
      return { d: null, error: e instanceof Error ? e.message : String(e) };
    }
  }, [fn, needDecompile, abi, names, types, varTypes, decomp.unflatten, calleeTick]);

  // argument counts of the direct callees, from their own entry code; redraws once known
  useEffect(() => {
    if (!dec.d) return;
    let live = true;
    void analyzeCallees(directCallees(dec.d.ir), modules, abi).then((n) => live && n > 0 && setCalleeTick((t) => t + 1)).catch(() => undefined);
    return () => { live = false; };
  }, [dec.d?.ir]);

  const showRaw = mode === "pseudo" && (decomp.raw || !dec.d);
  const rawLines = useMemo(() => (fn && showRaw ? pseudocode(fn.structure, { abi, nameOf: names.nameOf }) : []), [fn, showRaw, abi, names]);
  const report = decomp.unflatten ? dec.d?.report ?? null : null;
  const cfg = useMemo(() => (fn && report?.flattened && dec.d ? recoveredCfg(dec.d, fn.cfg) : fn?.cfg ?? null), [fn, report, dec.d]);
  const pos = useMemo(() => (cfg ? layoutCfg(cfg, blockH, kWidth) : new Map()), [cfg]);
  const loopOf = useMemo(() => (cfg ? loopsOf(cfg) : new Map<bigint, "header" | "body">()), [cfg]);
  const loopCount = useMemo(() => new Set([...loopOf].filter(([, k]) => k === "header").map(([a]) => a)).size, [loopOf]);
  const width = Math.max(400, ...[...pos.values()].map((p) => p.x + p.w + 20));
  const height = Math.max(200, ...[...pos.values()].map((p) => p.y + p.h + 20));
  const fit = () => {
    const el = wrap.current;
    if (el) setZoom(Math.max(0.35, Math.min(1, (el.clientWidth - 30) / (width + 20), (el.clientHeight - 30) / height)));
  };
  // open on the entry block, not on the middle of a wide switch fan-out
  useLayoutEffect(() => {
    const el = wrap.current;
    const p = cfg ? pos.get(cfg.entry) : undefined;
    if (!el || !p) return;
    el.scrollLeft = Math.max(0, (p.x + p.w / 2) * zoom + 10 - el.clientWidth / 2);
    el.scrollTop = 0;
  }, [cfg, pos]);

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <span className="panel-title">CFG</span>
          <button className="btn small" data-active={mode === "graph"} onClick={() => setMode("graph")}>Graph</button>
          <button className="btn small" data-active={mode === "pseudo"} onClick={() => setMode("pseudo")}>Pseudocode</button>
          <label className="row" style={{ fontSize: 12 }} title="Detect an OLLVM-style dispatcher, recover each block's successor from the state it sets and rebuild the original graph">
            <input type="checkbox" checked={decomp.unflatten} onChange={(e) => decomp.setUnflatten(e.target.checked)} />unflattened
          </label>
          {mode === "pseudo" && (
            <label className="row" style={{ fontSize: 12 }} title="The older per-instruction output: registers stay registers, no types">
              <input type="checkbox" checked={decomp.raw} onChange={(e) => decomp.setRaw(e.target.checked)} />raw
            </label>
          )}
          <span className="mono faint ellipsis grow">{root ? `${names.nameOf(root) || labelAddr(root, modules)}` : "no function — open one in the disassembly"}{cfg ? ` · ${cfg.blocks.length} blocks · ${cfg.edges.length} edges · ${loopCount} loops` : ""}</span>
          {mode === "graph" && (
            <>
              <span className="faint" style={{ fontSize: 12 }}><span style={{ color: "var(--success)" }}>taken</span> · <span style={{ color: "var(--danger)" }}>fall-through</span> · <span style={{ color: "var(--accent)" }}>jump / case</span> · <span style={{ color: "var(--warning)" }}>loop</span></span>
              <IconButton tip="Zoom out" onClick={() => setZoom((z) => Math.max(0.15, z / 1.25))}><ZoomOut size={14} /></IconButton>
              <IconButton tip="Zoom in" onClick={() => setZoom((z) => Math.min(2, z * 1.25))}><ZoomIn size={14} /></IconButton>
              <IconButton tip="Fit" onClick={fit} disabled={!cfg}><Maximize2 size={14} /></IconButton>
            </>
          )}
          <IconButton tip="Rebuild" onClick={() => setTick((t) => t + 1)} disabled={!root}><RefreshCw size={14} /></IconButton>
        </div>
        {busy && <Progress value={0.5} />}
        {decomp.unflatten && fn && dec.d && <UnflattenNote report={dec.d.report} onGo={ui.goDisasm} />}
        {mode === "pseudo" ? (
          fn && fn.structure.blocks.length ? (
            showRaw || !dec.d ? (
              <>
              {tooBig && !decomp.raw && (
                <div className="toolbar" style={{ fontSize: 12 }}>
                  <span className="warn">{insnCount} instructions: not decompiled automatically</span>
                  <button className="btn small" onClick={() => setForce(true)}>Decompile anyway</button>
                </div>
              )}
              <Pseudo lines={rawLines} onGo={ui.goDisasm}
                note={`${dec.error ? `decompiler failed (${dec.error}); showing the raw output · ` : ""}raw pseudocode · registers stay registers, no types; calls show the ${abi === "win64" ? "rcx/rdx/r8/r9" : "rdi/rsi/rdx/rcx/r8/r9"} arguments written before them`} />
              </>
            ) : (
              <>
                <VarTypes d={dec.d} types={types.map((t) => t.name)} mapped={varTypes ?? {}} onSet={(v, t) => root && decomp.setVarType(root, v, t)} />
                <Pseudo lines={dec.d.lines} onGo={ui.goDisasm}
                  note="decompiled (experimental) · variables, calls with arguments and types are recovered from use and may be wrong; map a pointer to a Structs type for field names; unmodelled instructions stay as __asm" />
              </>
            )
          ) : (
            <div className="empty"><div className="empty-title">{busy ? "Disassembling…" : root ? "No instructions." : "Open a function in the disassembly."}</div></div>
          )
        ) : (
        <div className="cfg-wrap" ref={wrap}>
          {cfg && (
            <svg width={(width + 20) * zoom} height={height * zoom} viewBox={`0 0 ${width + 20} ${height}`} style={{ display: "block", margin: 10 }}>
              <defs>
                {["taken", "fallthrough", "jump"].map((k) => (
                  <marker key={k} id={`cfg-arrow-${k}`} viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
                    <path d="M0,0 L8,4 L0,8 z" fill={k === "taken" ? "var(--success)" : k === "fallthrough" ? "var(--danger)" : "var(--accent)"} />
                  </marker>
                ))}
              </defs>
              {cfg.edges.map((e, i) => {
                const a = pos.get(e.from);
                const b = pos.get(e.to);
                if (!a || !b) return null;
                const x1 = a.x + a.w / 2 + (e.kind === "taken" ? 30 : e.kind === "fallthrough" ? -30 : 0);
                const y1 = a.y + a.h;
                const x2 = b.x + b.w / 2;
                const y2 = b.y;
                const d = y2 > y1
                  ? `M${x1},${y1} C${x1},${y1 + 30} ${x2},${y2 - 30} ${x2},${y2 - 2}`
                  : `M${x1},${y1} C${x1 + 80},${y1 + 60} ${Math.max(a.x, b.x) + kWidth + 60},${y2 - 60} ${x2},${y2 - 2}`; // back edge loops around the right
                return (
                  <g key={i}>
                    <path className="cfg-edge" data-kind={e.kind} d={d} markerEnd={`url(#cfg-arrow-${e.kind === "case" ? "jump" : e.kind})`} />
                    {e.label && <text x={(x1 + x2) / 2} y={(y1 + y2) / 2} fontSize={10} fill="var(--text-faint)">{e.label}</text>}
                  </g>
                );
              })}
              {cfg.blocks.map((b) => {
                const p = pos.get(b.start);
                if (!p) return null;
                const nm = names.nameOf("0x" + b.start.toString(16));
                return (
                  <g key={String(b.start)} className="cfg-block" data-entry={b.start === cfg.entry} data-sel={sel === b.start} data-loop={loopOf.get(b.start)} transform={`translate(${p.x},${p.y})`}
                    onClick={() => setSel(b.start)} onDoubleClick={() => ui.goDisasm("0x" + b.start.toString(16))} style={{ cursor: "pointer" }}>
                    <rect width={p.w} height={p.h} rx={4} />
                    <text x={8} y={15} className="cfg-addr">{nm ? `${nm}  ` : ""}{showAddr(b.start).replace(/^0+/, "")}</text>
                    {b.lines.slice(0, kMaxLines).map((l, i) => (
                      <text key={l.address} x={8} y={30 + i * kLineH} onClick={(ev) => { ev.stopPropagation(); ui.select(l.address); }}>
                        {l.text.length > 46 ? l.text.slice(0, 45) + "…" : l.text}
                      </text>
                    ))}
                    {b.lines.length > kMaxLines && <text x={8} y={30 + kMaxLines * kLineH} className="cfg-addr">… {b.lines.length - kMaxLines} more</text>}
                  </g>
                );
              })}
            </svg>
          )}
        </div>
        )}
      </div>
    </NeedsAgent>
  );
}

function UnflattenNote({ report, onGo }: { report: Decompiled["report"]; onGo: (a: string) => void }) {
  if (!report) return null;
  if (!report.flattened) return <div className="pseudo-note">unflattened: {report.note}</div>;
  return (
    <div className="pseudo-note">
      flattening removed · dispatcher <span className="mono link" onClick={() => onGo(report.dispatcher!)}>{report.dispatcher}</span> on <span className="mono">{report.state}</span> ·
      {" "}{report.recovered.length} blocks rewired, {report.states} states, {report.dispatcherBlocks.length} dispatcher blocks
      {report.unresolved.length > 0 && (
        <> · <span className="warn">{report.unresolved.length} unresolved:</span>{" "}
          {report.unresolved.map((u, i) => <span key={u.block} className="mono link" title={u.reason} onClick={() => onGo(u.block)}>{i ? ", " : ""}{u.block}</span>)}
          {" "}(still routed through the dispatcher)</>
      )}
    </div>
  );
}

/** Maps a pointer variable to a Structs type, so its field accesses use the type's field names. */
function VarTypes({ d, types, mapped, onSet }: { d: Decompiled; types: string[]; mapped: Record<string, string>; onSet: (v: string, t: string | null) => void }) {
  const ptrs = d.vars.filter((v) => v.type.endsWith("*"));
  const [v, setV] = useState("");
  const cur = v || ptrs[0]?.name || "";
  if (!ptrs.length) return null;
  return (
    <div className="toolbar" style={{ fontSize: 12 }}>
      <span className="faint">struct type of</span>
      <select className="select" value={cur} onChange={(e) => setV(e.target.value)}>
        {ptrs.map((p) => <option key={p.name} value={p.name}>{p.name}{mapped[p.name] ? ` (${mapped[p.name]})` : ""}</option>)}
      </select>
      <select className="select" value={mapped[cur] ?? ""} onChange={(e) => onSet(cur, e.target.value || null)} disabled={!types.length}>
        <option value="">{types.length ? "— none —" : "no types in Structs"}</option>
        {types.map((t) => <option key={t} value={t}>{t}</option>)}
      </select>
      <span className="mono faint ellipsis grow">{d.signature}</span>
    </div>
  );
}

function Pseudo({ lines, note, onGo }: { lines: PseudoLine[]; note: string; onGo: (a: string) => void }) {
  return (
    <div className="vlist listing pseudo">
      <div className="pseudo-note">{note}</div>
      {lines.map((l, i) => (
        <div
          key={i}
          className="pseudo-line"
          data-kind={l.text.startsWith("//") || l.text.startsWith("__asm") ? "comment" : /^loc_\w+:$/.test(l.text) ? "label" : undefined}
          data-link={l.addr ? "true" : undefined}
          style={{ paddingLeft: `calc(${l.indent * 2}ch + 10px)` }}
          title={l.addr ? `${showAddr(l.addr)} · click to open in the disassembly` : undefined}
          onClick={() => l.addr && onGo(l.addr)}
        >
          {l.text}
        </div>
      ))}
    </div>
  );
}
