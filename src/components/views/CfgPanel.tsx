// Control-flow graph and structured pseudocode of the function under the
// cursor; the CFG and Pseudocode modes of the Graph view.
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { request } from "@/lib/client";
import { labelAddr, showAddr, toBig } from "@/lib/hex";
import { buildCfg, layoutCfg, reachableListing, type Cfg, type EdgeKind } from "@/lib/analysis/cfg";
import { pseudocode } from "@/lib/analysis/pseudocode";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import type { Line } from "./DisassemblyView";

type Fn = { address: string; size: number };

const fnCache = new Map<string, Fn[]>();
const kMaxBytes = 0x10000;
const kWindow = 0x1000;
const kLineH = 15;
const kCharW = 6.9;
const kMaxChars = 64;
const kEdgeColor: Record<EdgeKind, string> = { true: "var(--success)", false: "var(--danger)", jump: "var(--text-faint)", fall: "var(--text-faint)" };

/** The listed function that contains `addr`, from `enumerate_functions` of its module. */
async function functionAt(addr: string, modules: { name: string; base: string; size: number }[]): Promise<Fn | null> {
  const a = toBig(addr);
  const mod = modules.find((m) => a >= toBig(m.base) && a < toBig(m.base) + BigInt(m.size));
  if (!mod) return null;
  let fns = fnCache.get(mod.name);
  if (!fns) {
    const r = await attempt("cfg", request<{ results: Fn[] }>("enumerate_functions", { module: mod.name }));
    if (!r) return null;
    fns = r.results;
    fnCache.set(mod.name, fns);
  }
  let best: Fn | null = null;
  for (const f of fns) {
    const s = toBig(f.address);
    if (s <= a && a < s + BigInt(Math.max(1, f.size)) && (!best || s > toBig(best.address))) best = f;
  }
  return best;
}

const clip = (s: string) => (s.length > kMaxChars ? s.slice(0, kMaxChars - 1) + "…" : s);

export default function CfgPanel({ mode, root, modes }: { mode: "cfg" | "pseudo"; root: string; modes: ReactNode }) {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const backend = useConn((s) => s.backend);
  const names = useNames();
  const [fn, setFn] = useState<Fn | null>(null);
  const [lines, setLines] = useState<Line[]>([]);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setBusy(true);
    const f = await functionAt(root, modules);
    // The listed size bounds the function. Without one, Echo's function mode (size 0) decides;
    // the local backend has no such mode, so take a window and keep what the entry reaches.
    const window = !f && backend === "local";
    const size = f ? Math.min(f.size, kMaxBytes) : window ? kWindow : 0;
    const r = await attempt("cfg", request<{ results: Line[] }>("disassemble", { address: f?.address ?? root, size }));
    setBusy(false);
    if (!r) return;
    setFn(f);
    setLines(window ? reachableListing(r.results) : r.results);
    if (f && f.size > kMaxBytes) log("warn", "cfg", `function is ${f.size} bytes; only the first ${kMaxBytes} are graphed`);
  }, [root, modules, backend]);

  useEffect(() => void load(), [load]);

  const cfg = useMemo(() => buildCfg(lines), [lines]);
  const start = fn?.address ?? root;

  return (
    <>
      <div className="toolbar">
        {modes}
        <span className="mono faint ellipsis grow">
          {names.nameOf(start) || labelAddr(start, modules)} · {cfg.blocks.length} blocks · {cfg.edges.length} edges · {cfg.loops.length} loops
        </span>
        <button className="btn small" disabled={busy} onClick={() => void load()}>{busy ? "Loading…" : "Reload"}</button>
      </div>
      {lines.length === 0 ? (
        <div className="empty"><div className="empty-title">{busy ? "Disassembling…" : "No instructions."}</div></div>
      ) : mode === "cfg" ? (
        <CfgCanvas cfg={cfg} onGo={ui.goDisasm} />
      ) : (
        <Pseudo cfg={cfg} abi={backend === "local" ? "sysv" : "win64"} nameOf={names.nameOf} onGo={ui.goDisasm} />
      )}
    </>
  );
}

function CfgCanvas({ cfg, onGo }: { cfg: Cfg; onGo: (a: string) => void }) {
  const box = useRef<HTMLDivElement>(null);
  const drag = useRef<{ x: number; y: number; moved: boolean } | null>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });

  const sizes = useMemo(() => cfg.blocks.map((b) => {
    const chars = Math.max(18, ...b.insns.map((i) => 13 + clip(i.text).length));
    return { w: Math.round(chars * kCharW + 16), h: (b.insns.length + 1) * kLineH + 10 };
  }), [cfg]);
  const lay = useMemo(() => layoutCfg(cfg, sizes), [cfg, sizes]);

  const fit = useCallback(() => {
    const el = box.current;
    if (!el || !lay.width) return;
    const k = Math.min(1, el.clientWidth / lay.width, Math.max(0.35, el.clientHeight / lay.height));
    const entry = lay.nodes[0];
    setView({ k, x: el.clientWidth / 2 - (lay.width < el.clientWidth / k ? lay.width / 2 : entry.x + entry.w / 2) * k, y: 12 });
  }, [lay]);
  useEffect(fit, [fit]);

  // wheel zoom around the cursor; React's wheel listener is passive, so attach natively
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      const px = e.clientX - r.left;
      const py = e.clientY - r.top;
      setView((v) => {
        const k = Math.min(3, Math.max(0.1, v.k * Math.exp(-e.deltaY * 0.0015)));
        return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k };
      });
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const zoom = (f: number) => setView((v) => ({ ...v, k: Math.min(3, Math.max(0.1, v.k * f)) }));

  return (
    <div
      ref={box}
      className="cfg-canvas"
      onPointerDown={(e) => {
        drag.current = { x: e.clientX, y: e.clientY, moved: false };
      }}
      onPointerMove={(e) => {
        const d = drag.current;
        if (!d || !(e.buttons & 1)) return;
        const dx = e.clientX - d.x;
        const dy = e.clientY - d.y;
        if (!d.moved && Math.abs(dx) + Math.abs(dy) < 4) return;
        d.moved = true;
        d.x = e.clientX;
        d.y = e.clientY;
        setView((v) => ({ ...v, x: v.x + dx, y: v.y + dy }));
      }}
      onPointerUp={() => setTimeout(() => (drag.current = null))}
    >
      <svg width="100%" height="100%" style={{ display: "block" }}>
        <defs>
          {(["success", "danger", "text-faint", "warning"] as const).map((c) => (
            <marker key={c} id={`cfg-arrow-${c}`} markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L0,6 L7,3 z" fill={`var(--${c})`} />
            </marker>
          ))}
        </defs>
        <g transform={`translate(${view.x}, ${view.y}) scale(${view.k})`}>
          {lay.edges.map((e, i) => {
            const color = e.back ? "var(--warning)" : kEdgeColor[e.kind];
            return (
              <polyline
                key={i}
                points={e.points.map((p) => p.join(",")).join(" ")}
                fill="none"
                stroke={color}
                strokeWidth={e.back ? 1.6 : 1.2}
                strokeDasharray={e.kind === "fall" ? "4 3" : undefined}
                markerEnd={`url(#cfg-arrow-${color.slice(6, -1)})`}
              />
            );
          })}
          {lay.nodes.map((n) => {
            const b = cfg.blocks[n.id];
            return (
              <g key={n.id} transform={`translate(${n.x}, ${n.y})`}>
                <rect
                  width={n.w} height={n.h} rx={3}
                  fill={b.inLoop ? "color-mix(in srgb, var(--warning) 9%, var(--bg-2))" : "var(--bg-2)"}
                  stroke={n.id === 0 ? "var(--accent)" : b.inLoop ? "var(--warning)" : "var(--border)"}
                  strokeWidth={b.loopHeader ? 2 : 1}
                  opacity={b.reachable ? 1 : 0.6}
                />
                <text x={8} y={kLineH} className="cfg-head">
                  loc_{b.start.toString(16)}{b.loopHeader ? "  · loop header" : ""}{b.reachable ? "" : "  · unreachable"}
                </text>
                {b.insns.map((insn, i) => (
                  // a full-width rect per line: <text> alone only hit-tests its glyphs
                  <g key={insn.address} className="cfg-insn" onClick={() => !drag.current?.moved && onGo(insn.address)}>
                    <title>{`${showAddr(insn.address)}  ${insn.text}\nclick to open in the disassembly`}</title>
                    <rect x={2} y={kLineH * (i + 1) + 3} width={n.w - 4} height={kLineH} />
                    <text x={8} y={kLineH * (i + 2)}>
                      <tspan className="faint">{insn.address.slice(-6).padStart(6, "0")}  </tspan>
                      <tspan>{clip(insn.text)}</tspan>
                    </text>
                  </g>
                ))}
              </g>
            );
          })}
        </g>
      </svg>
      <div className="cfg-zoom">
        <button className="btn small" onClick={() => zoom(1.25)}>+</button>
        <button className="btn small" onClick={() => zoom(0.8)}>−</button>
        <button className="btn small" onClick={fit}>Fit</button>
      </div>
    </div>
  );
}

function Pseudo({ cfg, abi, nameOf, onGo }: { cfg: Cfg; abi: "win64" | "sysv"; nameOf: (a: string) => string; onGo: (a: string) => void }) {
  const out = useMemo(() => pseudocode(cfg, { abi, nameOf }), [cfg, abi, nameOf]);
  return (
    <div className="vlist listing pseudo">
      <div className="pseudo-note">
        structured pseudocode (experimental) · registers stay registers, no types are recovered, calls show the {abi === "win64" ? "rcx/rdx/r8/r9" : "rdi/rsi/rdx/rcx/r8/r9"} arguments
        written before them, anything unrecognised is kept as the asm line in a comment
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
