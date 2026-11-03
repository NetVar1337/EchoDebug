// Value graphs: watched addresses plotted over time on a canvas. Wheel zooms the time axis
// around the cursor, drag pans, double-click goes back to the live edge; hover shows each
// series' value at that moment. Sampling runs in store/graphs.ts.
import { useEffect, useMemo, useRef, useState } from "react";
import { Download, Pause, Play, Plus, Trash2, X } from "lucide-react";
import { bufferOf, useGraphs } from "@/store/graphs";
import { useConn } from "@/store/conn";
import { useWatch } from "@/store/watch";
import { useUi } from "@/store/ui";
import { log } from "@/store/output";
import { fmtAddr, labelAddr, parseAddress } from "@/lib/hex";
import { downsample, fmtSpan, fmtValue, graphTypeOf, kGraphTypes, nearest, niceTicks, stats, toCsv, yRange, type GraphType, type Point } from "@/lib/graphs";
import { saveText } from "@/lib/save";
import { Empty, IconButton } from "../ui";

const kSpans = [5_000, 30_000, 60_000, 300_000, 1_800_000];
const kMargin = { left: 64, right: 12, top: 10, bottom: 22 };

type Window = { follow: boolean; span: number; end: number };

function cssVar(el: Element, name: string, fallback: string): string {
  return getComputedStyle(el).getPropertyValue(name).trim() || fallback;
}

export default function ValueGraphView() {
  const g = useGraphs();
  const watches = useWatch((s) => s.watches);
  const modules = useConn((s) => s.modules);
  const target = useConn((s) => s.target);
  const ui = useUi();
  const wrap = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [size, setSize] = useState({ w: 600, h: 300 });
  const [win, setWin] = useState<Window>({ follow: true, span: 30_000, end: 0 });
  const [hoverX, setHoverX] = useState<number | null>(null);
  const [addr, setAddr] = useState("");
  const [type, setType] = useState<GraphType>("i32");
  const drag = useRef<{ x: number; end: number } | null>(null);

  // the live edge: newest sample of any series (falls back to now)
  const liveEnd = () => {
    let t = 0;
    for (const s of g.series) t = Math.max(t, bufferOf(s.id).last()?.t ?? 0);
    return t || Date.now();
  };
  const end = win.follow ? liveEnd() : win.end;
  const start = end - win.span;
  const plotW = Math.max(10, size.w - kMargin.left - kMargin.right);
  const plotH = Math.max(10, size.h - kMargin.top - kMargin.bottom);
  const visible = g.series.filter((s) => s.visible);

  const points = useMemo(() => {
    const m = new Map<string, Point[]>();
    for (const s of visible) m.set(s.id, downsample(bufferOf(s.id), start, end, Math.ceil(plotW / 2)));
    return m;
    // g.tick changes when new samples arrive
  }, [g.tick, g.series, start, end, plotW, g.capacity]);
  const [ylo, yhi] = yRange([...points.values()]);

  useEffect(() => {
    const el = wrap.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: el.clientHeight }));
    ro.observe(el);
    setSize({ w: el.clientWidth, h: el.clientHeight });
    return () => ro.disconnect();
  }, []);

  // wheel zoom (native listener: React's wheel handler is passive and cannot preventDefault)
  useEffect(() => {
    const el = canvas.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const frac = Math.min(1, Math.max(0, (e.clientX - rect.left - kMargin.left) / plotW));
      setWin((w) => {
        const curEnd = w.follow ? liveEnd() : w.end;
        const span = Math.min(24 * 3_600_000, Math.max(200, w.span * (e.deltaY > 0 ? 1.25 : 0.8)));
        if (w.follow) return { ...w, span };
        const at = curEnd - w.span + frac * w.span;
        return { follow: false, span, end: at + (curEnd - at) * (span / w.span) };
      });
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  });

  // draw
  useEffect(() => {
    const el = canvas.current;
    if (!el) return;
    const dpr = window.devicePixelRatio || 1;
    el.width = Math.floor(size.w * dpr);
    el.height = Math.floor(size.h * dpr);
    const ctx = el.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, size.w, size.h);
    const grid = cssVar(el, "--border-soft", "#222");
    const faint = cssVar(el, "--text-faint", "#888");
    const text = cssVar(el, "--text", "#ddd");
    const mono = cssVar(el, "--font-mono", "monospace");
    const xOf = (t: number) => kMargin.left + ((t - start) / win.span) * plotW;
    const yOf = (v: number) => kMargin.top + (1 - (v - ylo) / (yhi - ylo)) * plotH;
    ctx.font = `11px ${mono}`;
    ctx.lineWidth = 1;
    // y grid
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (const v of niceTicks(ylo, yhi, Math.max(2, Math.floor(plotH / 40)))) {
      const y = Math.round(yOf(v)) + 0.5;
      ctx.strokeStyle = grid;
      ctx.beginPath();
      ctx.moveTo(kMargin.left, y);
      ctx.lineTo(kMargin.left + plotW, y);
      ctx.stroke();
      ctx.fillStyle = faint;
      ctx.fillText(fmtValue(v), kMargin.left - 6, y);
    }
    // x grid: seconds before the right edge
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    for (const dt of niceTicks(0, win.span, Math.max(2, Math.floor(plotW / 90)))) {
      const x = Math.round(xOf(end - dt)) + 0.5;
      if (x < kMargin.left) continue;
      ctx.strokeStyle = grid;
      ctx.beginPath();
      ctx.moveTo(x, kMargin.top);
      ctx.lineTo(x, kMargin.top + plotH);
      ctx.stroke();
      ctx.fillStyle = faint;
      ctx.fillText(dt === 0 ? (win.follow ? "now" : new Date(end).toLocaleTimeString()) : `-${fmtSpan(dt)}`, x, kMargin.top + plotH + 5);
    }
    // series
    ctx.save();
    ctx.beginPath();
    ctx.rect(kMargin.left, kMargin.top, plotW, plotH);
    ctx.clip();
    ctx.lineWidth = 1.5;
    ctx.lineJoin = "round";
    for (const s of visible) {
      const pts = points.get(s.id) ?? [];
      if (!pts.length) continue;
      ctx.strokeStyle = s.color;
      ctx.beginPath();
      // step line: a sampled value holds until the next sample
      pts.forEach((p, i) => {
        const x = xOf(p.t);
        const y = yOf(p.v);
        if (i === 0) ctx.moveTo(x, y);
        else {
          ctx.lineTo(x, yOf(pts[i - 1].v));
          ctx.lineTo(x, y);
        }
      });
      ctx.lineTo(xOf(Math.min(end, Math.max(pts[pts.length - 1].t, win.follow ? end : pts[pts.length - 1].t))), yOf(pts[pts.length - 1].v));
      ctx.stroke();
    }
    ctx.restore();
    // hover cursor
    if (hoverX !== null && hoverX >= kMargin.left && hoverX <= kMargin.left + plotW) {
      ctx.strokeStyle = text;
      ctx.globalAlpha = 0.5;
      ctx.beginPath();
      ctx.moveTo(Math.round(hoverX) + 0.5, kMargin.top);
      ctx.lineTo(Math.round(hoverX) + 0.5, kMargin.top + plotH);
      ctx.stroke();
      ctx.globalAlpha = 1;
      const t = start + ((hoverX - kMargin.left) / plotW) * win.span;
      for (const s of visible) {
        const p = nearest(bufferOf(s.id), t);
        if (!p || p.t < start || p.t > end) continue;
        ctx.fillStyle = s.color;
        ctx.beginPath();
        ctx.arc(xOf(p.t), yOf(p.v), 3, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }, [points, size, hoverX, ylo, yhi, start, end, win.span, win.follow, plotW, plotH, visible]);

  const hoverT = hoverX !== null ? start + ((hoverX - kMargin.left) / plotW) * win.span : null;
  const readout = hoverT !== null && hoverX! >= kMargin.left && hoverX! <= kMargin.left + plotW
    ? visible.map((s) => ({ s, p: nearest(bufferOf(s.id), hoverT) })).filter((r) => r.p && r.p.t >= start && r.p.t <= end)
    : [];

  const add = (address: string, t: GraphType, label = "") => {
    const a = parseAddress(address, modules);
    if (a === null) return log("warn", "graph", `cannot parse ${address}`);
    g.add(fmtAddr(a), t, label);
    setAddr("");
  };

  const exportCsv = async () => {
    const csv = toCsv(g.series.map((s) => ({ label: `${s.label || labelAddr(s.address, modules)} (${s.type})`, buf: bufferOf(s.id) })));
    await saveText(`graphs_${new Date().toISOString().replace(/[:.]/g, "-")}.csv`, csv, { name: "CSV", extensions: ["csv"] });
  };

  const graphable = watches.filter((w) => graphTypeOf(w.type) && !g.series.some((s) => s.address === w.address));

  return (
    <div className="vgraph">
      <div className="panel-section">
        <div className="row" style={{ flexWrap: "wrap" }}>
          <IconButton tip={g.paused ? "Resume sampling" : "Pause sampling"} onClick={() => g.set({ paused: !g.paused })}>{g.paused ? <Play size={14} /> : <Pause size={14} />}</IconButton>
          <div className="row" style={{ gap: 2 }}>
            {kSpans.map((s) => <button key={s} className="btn small" data-active={win.span === s} onClick={() => setWin((w) => ({ ...w, span: s }))}>{fmtSpan(s)}</button>)}
          </div>
          <button className="btn small" data-active={win.follow} title="Follow the newest samples (double-click the graph)" onClick={() => setWin((w) => ({ ...w, follow: true }))}>Live</button>
          <span className="grow" />
          <label className="row faint" title="Poll interval">every <input className="input mono" style={{ width: 56 }} type="number" min={20} value={g.intervalMs} onChange={(e) => g.set({ intervalMs: Number(e.target.value) || 100 })} /> ms</label>
          <label className="row faint" title="Samples kept per series (ring buffer)">keep <input className="input mono" style={{ width: 72 }} type="number" min={100} step={1000} value={g.capacity} onChange={(e) => g.set({ capacity: Number(e.target.value) || 6000 })} /></label>
          <IconButton tip="Clear history" onClick={() => g.clearSamples()}><Trash2 size={13} /></IconButton>
          <IconButton tip="Export CSV" disabled={!g.series.length} onClick={() => void exportCsv()}><Download size={13} /></IconButton>
        </div>
        <div className="row">
          <input className="input mono grow" placeholder="address or module+0x… to plot" value={addr} onChange={(e) => setAddr(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add(addr, type)} />
          <select className="select" value={type} onChange={(e) => setType(e.target.value as GraphType)}>{kGraphTypes.map((t) => <option key={t}>{t}</option>)}</select>
          <IconButton tip="Plot" onClick={() => add(addr, type)}><Plus size={14} /></IconButton>
          {graphable.length > 0 && (
            <select className="select" value="" onChange={(e) => {
              const w = watches.find((x) => x.id === e.target.value);
              if (w) add(w.address, graphTypeOf(w.type)!, w.label);
            }}>
              <option value="">from watchlist…</option>
              {graphable.map((w) => <option key={w.id} value={w.id}>{w.label || labelAddr(w.address, modules)} ({w.type})</option>)}
            </select>
          )}
        </div>
      </div>
      <div
        className="vgraph-plot"
        ref={wrap}
        onMouseMove={(e) => {
          const x = e.clientX - e.currentTarget.getBoundingClientRect().left;
          setHoverX(x);
          if (drag.current) {
            const dt = ((x - drag.current.x) / plotW) * win.span;
            setWin((w) => ({ ...w, follow: false, end: drag.current!.end - dt }));
          }
        }}
        onMouseLeave={() => { setHoverX(null); drag.current = null; }}
        onMouseDown={(e) => { drag.current = { x: e.clientX - e.currentTarget.getBoundingClientRect().left, end }; }}
        onMouseUp={() => { drag.current = null; }}
        onDoubleClick={() => setWin((w) => ({ ...w, follow: true }))}
      >
        <canvas ref={canvas} style={{ width: size.w, height: size.h, cursor: drag.current ? "grabbing" : "crosshair" }} />
        {g.series.length === 0 && (
          <div className="vgraph-empty">
            <Empty title="Nothing plotted yet." hint={<>Add an address above, pick one from the watchlist, or right-click a watch → <b>Graph this</b>.</>} />
          </div>
        )}
        {g.series.length > 0 && !target && <div className="vgraph-note faint">Not attached: sampling resumes when a target is attached.</div>}
        {g.paused && <div className="vgraph-note warn">Paused</div>}
        {readout.length > 0 && hoverT !== null && (
          <div className="vgraph-tip" style={{ left: Math.min(hoverX! + 12, size.w - 190), top: kMargin.top + 4 }}>
            <div className="faint mono">{new Date(hoverT).toLocaleTimeString()}.{String(Math.floor(hoverT % 1000)).padStart(3, "0")}</div>
            {readout.map(({ s, p }) => (
              <div key={s.id} className="row mono"><span className="vgraph-swatch" style={{ background: s.color }} /><span className="grow ellipsis">{s.label || labelAddr(s.address, modules)}</span><b>{fmtValue(p!.v)}</b></div>
            ))}
          </div>
        )}
      </div>
      <table className="table mono vgraph-stats">
        <thead><tr><th style={{ width: 24 }} /><th>Series</th><th style={{ width: 64 }}>Type</th><th>Last</th><th>Min</th><th>Max</th><th>Avg</th><th style={{ width: 70 }}>Samples</th><th style={{ width: 28 }} /></tr></thead>
        <tbody>
          {g.series.map((s) => {
            const st = stats(bufferOf(s.id), start, end);
            return (
              <tr key={s.id} style={{ opacity: s.visible ? 1 : 0.5 }}>
                <td><input type="checkbox" checked={s.visible} title="Show" onChange={(e) => g.update(s.id, { visible: e.target.checked })} style={{ accentColor: s.color }} /></td>
                <td className="ellipsis"><span className="vgraph-swatch" style={{ background: s.color }} /> <span className="link" onClick={() => ui.goMemory(s.address)}>{s.label || labelAddr(s.address, modules)}</span></td>
                <td><select className="select" value={s.type} onChange={(e) => g.update(s.id, { type: e.target.value as GraphType })}>{kGraphTypes.map((t) => <option key={t}>{t}</option>)}</select></td>
                <td>{st ? fmtValue(st.last) : "–"}</td>
                <td>{st ? fmtValue(st.min) : "–"}</td>
                <td>{st ? fmtValue(st.max) : "–"}</td>
                <td>{st ? fmtValue(st.avg) : "–"}</td>
                <td className="faint">{st?.count ?? 0}</td>
                <td><IconButton tip="Remove" onClick={() => g.remove(s.id)}><X size={12} /></IconButton></td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="faint vgraph-help">Wheel zooms, drag pans, double-click returns to live. Stats cover the visible window.</div>
    </div>
  );
}
