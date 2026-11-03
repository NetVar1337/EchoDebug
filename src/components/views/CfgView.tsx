// Control-flow graph of the function at the disassembly cursor: basic blocks laid out in layers,
// taken (green), fall-through (red) and unconditional/switch (accent) edges, blocks inside natural
// loops tinted. The Pseudocode mode structures the same instructions into if/else/while/goto
// (structure.ts + pseudocode.ts).
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Maximize2, RefreshCw, ZoomIn, ZoomOut } from "lucide-react";
import { request } from "@/lib/client";
import { labelAddr, moduleOf, showAddr, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { pdataFunctions } from "@/lib/live";
import { buildCfg, layoutCfg, type Block, type Cfg, type CfgLine } from "@/lib/analysis/cfg";
import { buildStructure } from "@/lib/analysis/structure";
import { pseudocode } from "@/lib/analysis/pseudocode";
import { resolveSwitch } from "@/lib/analysis/jumptables";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent, Progress } from "../ui";

const kLineH = 15;
const kWidth = 340;
const kMaxLines = 28;
const blockH = (b: Block) => 22 + Math.min(b.lines.length, kMaxLines) * kLineH + (b.lines.length > kMaxLines ? kLineH : 0);

export default function CfgView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const backend = useConn((s) => s.backend);
  const names = useNames();
  const [mode, setMode] = useState<"graph" | "pseudo">("graph");
  const root = ui.disasmAt;
  const [cfg, setCfg] = useState<Cfg | null>(null);
  const [busy, setBusy] = useState(false);
  const [sel, setSel] = useState<bigint | null>(null);
  const [tick, setTick] = useState(0);
  const [zoom, setZoom] = useState(1);
  const wrap = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!root) return;
    let live = true;
    setBusy(true);
    setCfg(null);
    void (async () => {
      const entry = toBig(root);
      const m = moduleOf(entry, modules);
      const img = m ? await loadImage(m).catch(() => null) : null;
      const mbase = m ? toBig(m.base) : 0n;
      // bounds: the .pdata range that holds the entry, else the module
      let bounds = m ? { lo: mbase, hi: mbase + BigInt(m.size) } : undefined;
      if (m) {
        const fn = (await pdataFunctions(m).catch(() => [])).find((f) => toBig(f.address) <= entry && entry < toBig(f.address) + BigInt(f.size));
        if (fn) bounds = { lo: toBig(fn.address), hi: toBig(fn.address) + BigInt(fn.size) };
      }
      const decode = async (a: bigint): Promise<CfgLine[]> => {
        const r = await request<{ results: CfgLine[] }>("disassemble", { address: "0x" + a.toString(16), size: 0x100 }, true).catch(() => null);
        return r?.results ?? [];
      };
      const g = await attempt("cfg", buildCfg(entry, decode, {
        maxInsns: 8000,
        bounds,
        switchTargets: img ? (lines, i) => resolveSwitch(lines, i, img, mbase)?.targets ?? null : undefined,
      }));
      if (!live) return;
      setBusy(false);
      if (g) {
        setCfg(g);
        log("info", "cfg", `${g.blocks.length} blocks, ${g.edges.length} edges${g.truncated ? " (truncated)" : ""} at ${labelAddr(root, modules)}`);
      }
    })();
    return () => { live = false; };
  }, [root, tick]);

  const pos = useMemo(() => (cfg ? layoutCfg(cfg, blockH, kWidth) : new Map()), [cfg]);
  // the discovered instructions in address order, re-split for dominators / loops / structuring
  const structure = useMemo(() => {
    if (!cfg) return null;
    const lines = cfg.blocks.flatMap((b) => b.lines).sort((a, b) => (toBig(a.address) < toBig(b.address) ? -1 : 1));
    return buildStructure(lines);
  }, [cfg]);
  const loopOf = useMemo(() => {
    const m = new Map<bigint, "header" | "body">();
    if (!cfg || !structure) return m;
    const starts = structure.blocks.map((b) => b.start);
    for (const b of cfg.blocks) {
      // the structural block that holds this block's first instruction
      let i = starts.length - 1;
      while (i > 0 && starts[i] > b.start) i--;
      const s = structure.blocks[i];
      if (s?.inLoop) m.set(b.start, s.loopHeader && s.start === b.start ? "header" : "body");
    }
    return m;
  }, [cfg, structure]);
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
          <span className="mono faint ellipsis grow">{root ? `${names.nameOf(root) || labelAddr(root, modules)}` : "no function — open one in the disassembly"}{cfg ? ` · ${cfg.blocks.length} blocks · ${cfg.edges.length} edges · ${structure?.loops.length ?? 0} loops` : ""}</span>
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
        {mode === "pseudo" ? (
          structure && structure.blocks.length ? (
            <Pseudo structure={structure} abi={backend === "local" ? "sysv" : "win64"} nameOf={names.nameOf} onGo={ui.goDisasm} />
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

function Pseudo({ structure, abi, nameOf, onGo }: { structure: ReturnType<typeof buildStructure>; abi: "win64" | "sysv"; nameOf: (a: string) => string; onGo: (a: string) => void }) {
  const out = useMemo(() => pseudocode(structure, { abi, nameOf }), [structure, abi, nameOf]);
  return (
    <div className="vlist listing pseudo">
      <div className="pseudo-note">
        structured pseudocode (experimental) · registers stay registers, no types are recovered, calls show the {abi === "win64" ? "rcx/rdx/r8/r9" : "rdi/rsi/rdx/rcx/r8/r9"} arguments
        written before them, switch jump tables are not structured, anything unrecognised is kept as the asm line in a comment
      </div>
      {out.map((l, i) => (
        <div
          key={i}
          className="pseudo-line"
          data-kind={l.text.startsWith("//") ? "comment" : /^loc_\w+:$/.test(l.text) ? "label" : undefined}
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
