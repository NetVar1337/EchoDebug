// Control-flow graph of the function at the disassembly cursor: basic blocks laid out in layers,
// taken (green), fall-through (red) and unconditional/switch (accent) edges.
import { useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { request } from "@/lib/client";
import { labelAddr, moduleOf, showAddr, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { pdataFunctions } from "@/lib/live";
import { buildCfg, layoutCfg, type Block, type Cfg, type CfgLine } from "@/lib/analysis/cfg";
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
  const names = useNames();
  const root = ui.disasmAt;
  const [cfg, setCfg] = useState<Cfg | null>(null);
  const [busy, setBusy] = useState(false);
  const [sel, setSel] = useState<bigint | null>(null);
  const [tick, setTick] = useState(0);

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
  const width = Math.max(400, ...[...pos.values()].map((p) => p.x + p.w + 20));
  const height = Math.max(200, ...[...pos.values()].map((p) => p.y + p.h + 20));

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <span className="panel-title">CFG</span>
          <span className="mono faint ellipsis grow">{root ? `${names.nameOf(root) || labelAddr(root, modules)}` : "no function — open one in the disassembly"}{cfg ? ` · ${cfg.blocks.length} blocks · ${cfg.edges.length} edges` : ""}</span>
          <span className="faint" style={{ fontSize: 12 }}><span style={{ color: "var(--success)" }}>taken</span> · <span style={{ color: "var(--danger)" }}>fall-through</span> · <span style={{ color: "var(--accent)" }}>jump / case</span></span>
          <IconButton tip="Rebuild" onClick={() => setTick((t) => t + 1)} disabled={!root}><RefreshCw size={14} /></IconButton>
        </div>
        {busy && <Progress value={0.5} />}
        <div className="cfg-wrap">
          {cfg && (
            <svg width={width + 20} height={height} style={{ display: "block", margin: 10 }}>
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
                  <g key={String(b.start)} className="cfg-block" data-entry={b.start === cfg.entry} data-sel={sel === b.start} transform={`translate(${p.x},${p.y})`}
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
      </div>
    </NeedsAgent>
  );
}
