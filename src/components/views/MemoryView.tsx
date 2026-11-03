import { useEffect, useMemo, useRef, useState } from "react";
import { Bookmark, ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Copy, Map as MapIcon, Pause, PanelRight, Play, Search, Tag } from "lucide-react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress, showAddr, toBig } from "@/lib/hex";
import { readBytes } from "@/lib/memory";
import { writeJournaled } from "@/lib/patch";
import { searchMemory } from "@/lib/memsearch";
import { buildNeedle, formatAs, inspect, kCopyFormats, type CopyFormat, type NeedleMode } from "@/lib/analysis/bytes";
import { encode, type ValueType } from "@/lib/analysis/values";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { CommitInput, IconButton, NeedsAgent, Progress } from "../ui";

type Region = { base: string; size: number; present: boolean; writable: boolean; executable: boolean };
const kWindow = 0x800;
const kModes: NeedleMode[] = ["hex", "ascii", "utf16", "i32", "u32", "i64", "u64", "f32", "f64", "i16", "u16", "u8"];
const kWritable: Record<string, ValueType> = { u8: "u8", i8: "i8", u16: "u16", i16: "i16", u32: "u32", i32: "i32", u64: "u64", i64: "i64", f32: "f32", f64: "f64" };

function Regions({ onPick }: { onPick: (a: string) => void }) {
  const { modules, extOk: ext } = useConn();
  const [regions, setRegions] = useState<Region[]>([]);
  const [filter, setFilter] = useState("");
  useEffect(() => {
    if (!ext) return;
    void attempt("regions", request<{ regions: Region[]; truncated: boolean }>("regions", { max: 20000 })).then((r) => r && setRegions(r.regions));
  }, [ext]);
  if (!ext) return <div className="panel-section faint">Region map needs the EchoDebug agent.</div>;
  const f = filter.toLowerCase();
  const shown = regions.filter((r) => {
    if (!f) return true;
    if (r.base.toLowerCase().includes(f)) return true;
    const m = modules.find((x) => {
      const b = toBig(x.base);
      const a = toBig(r.base);
      return a >= b && a < b + BigInt(x.size);
    });
    return m ? m.name.toLowerCase().includes(f) : false;
  });
  return (
    <>
      <div className="toolbar">
        <label className="search grow"><Search size={13} /><input placeholder="Filter regions…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
      </div>
      <table className="table">
        <colgroup><col /><col style={{ width: 70 }} /><col style={{ width: 40 }} /></colgroup>
        <thead><tr><th>Base</th><th>Size</th><th>Prot</th></tr></thead>
        <tbody>
          {shown.map((r) => (
            <tr key={r.base} onClick={() => onPick(r.base)} title={labelAddr(r.base, modules)}>
              <td className="mono">{showAddr(r.base).replace(/^0{4}/, "")}</td>
              <td className="mono faint">{r.size >= 1048576 ? `${(r.size / 1048576).toFixed(1)}M` : `${(r.size / 1024).toFixed(0)}K`}</td>
              <td className="mono dim">{r.writable ? "RW" : "R-"}{r.executable ? "X" : "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export default function MemoryView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const names = useNames();
  const { bookmarks, addBookmark } = useWatch();
  const base = ui.memoryAt ? toBig(ui.memoryAt) & ~0xfn : null;
  const [data, setData] = useState<Uint8Array | null>(null);
  const prev = useRef<Uint8Array | null>(null);
  const [live, setLive] = useState(true);
  const [showRegions, setShowRegions] = useState(false);
  const [showInspect, setShowInspect] = useState(true);
  const [edit, setEdit] = useState<number | null>(null);
  const [tick, setTick] = useState(0);
  const [selEnd, setSelEnd] = useState<bigint | null>(null);
  const [findMode, setFindMode] = useState<NeedleMode>("hex");
  const [findText, setFindText] = useState("");
  const [finding, setFinding] = useState<number | null>(null);
  const findAbort = useRef({ aborted: false });
  const [littleEndian, setLittleEndian] = useState(true);
  const [copyFmt, setCopyFmt] = useState<CopyFormat>("spaced");

  useEffect(() => {
    if (base === null) return;
    let alive = true;
    const load = async () => {
      const b = await readBytes(base, kWindow).catch(() => null);
      if (!alive) return;
      setData((cur) => {
        prev.current = cur;
        return b;
      });
    };
    prev.current = null;
    void load();
    const t = live ? setInterval(() => void load(), 500) : undefined;
    return () => { alive = false; clearInterval(t); };
  }, [base, live, tick]);

  const go = (a: string) => {
    const v = parseAddress(a, modules);
    if (v === null) return log("warn", "memory", `cannot parse ${a}`);
    ui.goMemory(fmtAddr(v));
  };
  const shift = (d: number) => base !== null && ui.goMemory(fmtAddr(base + BigInt(d) < 0n ? 0n : base + BigInt(d)));
  const sel = ui.selected ? toBig(ui.selected) : null;
  const [rangeLo, rangeHi] = useMemo(() => {
    if (sel === null) return [null, null] as const;
    const e = selEnd ?? sel;
    return (e < sel ? [e, sel] : [sel, e]) as [bigint, bigint];
  }, [sel, selEnd]);
  const rangeLen = rangeLo !== null && rangeHi !== null ? Number(rangeHi - rangeLo) + 1 : 0;
  // published for the assistant's @selection
  useEffect(() => {
    useUi.getState().set({ memSel: rangeLo !== null && rangeHi !== null ? { from: fmtAddr(rangeLo), to: fmtAddr(rangeHi) } : null });
  }, [rangeLo, rangeHi]);
  const inRange = (a: bigint) => rangeLo !== null && rangeHi !== null && a >= rangeLo && a <= rangeHi;

  const write = async (addr: bigint, bytes: Uint8Array | string, note: string) => {
    if (await writeJournaled(addr, bytes, note)) setTick((t) => t + 1);
  };
  const writeCell = async (off: number, text: string) => {
    setEdit(null);
    if (base === null || !/^[0-9a-f]{1,2}$/i.test(text)) return;
    await write(base + BigInt(off), text.padStart(2, "0").toLowerCase(), "memory view");
  };
  const at = () => {
    const a = rangeLo ?? base;
    if (a === null) log("warn", "memory", "select an address first");
    return a;
  };
  const paste = async () => {
    const a = at();
    if (a === null) return;
    const text = window.prompt(`Bytes to write at ${labelAddr(a, modules)} (hex, spaces optional)`, "");
    if (!text) return;
    const clean = text.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "");
    if (!clean || clean.length % 2 !== 0) return log("warn", "memory", "need an even number of hex digits");
    await write(a, clean.toLowerCase(), "paste");
  };
  const fill = async () => {
    const a = at();
    if (a === null) return;
    const spec = window.prompt(`Fill at ${labelAddr(a, modules)}: "<byte> <count>" (hex byte, decimal or 0x count)`, `90 ${rangeLen || 16}`);
    if (!spec) return;
    const [bs, cs] = spec.trim().split(/\s+/);
    const byte = parseInt(bs ?? "", 16);
    const count = Number(cs);
    if (!(byte >= 0 && byte <= 255) || !(count > 0 && count <= 0x100000)) return log("warn", "memory", "use '<hex byte> <count>' with count up to 1 MiB");
    await write(a, new Uint8Array(count).fill(byte), `fill ${byte.toString(16).padStart(2, "0")} × ${count}`);
  };
  /** Bytes of the selection (from the window, else read fresh). */
  const selectionBytes = async (): Promise<Uint8Array | null> => {
    if (rangeLo === null) return null;
    if (base !== null && data && rangeLo >= base && rangeLo + BigInt(rangeLen) <= base + BigInt(data.length)) {
      const o = Number(rangeLo - base);
      return data.slice(o, o + rangeLen);
    }
    return readBytes(rangeLo, rangeLen);
  };
  const copyAs = async () => {
    const b = await selectionBytes();
    if (!b) return log("warn", "memory", "select bytes first (shift-click extends the selection)");
    const text = formatAs(b, copyFmt, `data_${rangeLo!.toString(16)}`);
    await navigator.clipboard?.writeText(text).catch(() => undefined);
    log("info", "memory", `copied ${b.length} bytes as ${kCopyFormats.find((f) => f.id === copyFmt)?.label}`);
  };
  const find = async (dir: 1 | -1) => {
    let needle;
    try { needle = buildNeedle(findText, findMode, littleEndian); } catch (e) { return log("warn", "find", String(e instanceof Error ? e.message : e)); }
    const from = sel ?? base ?? 0n;
    findAbort.current = { aborted: false };
    setFinding(0);
    const hit = await attempt("find", searchMemory(from, needle, dir, { onProgress: setFinding, signal: findAbort.current }));
    setFinding(null);
    if (hit === null || hit === undefined) return log("info", "find", `no ${dir === 1 ? "later" : "earlier"} match for ${findMode} "${findText}"`);
    ui.goMemory(fmtAddr(hit));
    ui.select(fmtAddr(hit));
    setSelEnd(hit + BigInt(needle.bytes.length - 1));
  };
  const label = () => {
    const a = at();
    if (a === null) return;
    const next = window.prompt(`Label for ${labelAddr(a, modules)}`, names.nameOf(fmtAddr(a)));
    if (next !== null) names.rename(fmtAddr(a), next);
  };

  // data inspector: bytes at the selection start
  const inspectBytes = useMemo(() => {
    if (sel === null || base === null || !data || sel < base || sel >= base + BigInt(data.length)) return null;
    const o = Number(sel - base);
    return data.slice(o, o + 64);
  }, [sel, base, data]);
  const editValue = async (type: string, cur: string) => {
    const vt = kWritable[type];
    if (!vt || sel === null) return;
    const next = window.prompt(`New ${type} value at ${labelAddr(sel, modules)}${littleEndian ? "" : " (written little-endian)"}`, cur);
    if (next === null) return;
    try {
      await write(sel, encode(next, vt), `inspector ${type}`);
    } catch (e) {
      log("warn", "memory", String(e instanceof Error ? e.message : e));
    }
  };

  const bookmarked = useMemo(() => new Set(bookmarks.map((b) => toBig(b.address))), [bookmarks]);
  const named = useMemo(() => new Map(names.names.filter((n) => n.name).map((n) => [toBig("0x" + n.address), n.name])), [names.names]);

  return (
    <NeedsAgent>
      <div className="split-h" style={{ gridTemplateColumns: showRegions ? "260px minmax(0, 1fr)" : "minmax(0, 1fr)" }}>
        {showRegions && (
          <div className="list-col" style={{ overflow: "auto" }}>
            <Regions onPick={go} />
          </div>
        )}
        <div className="list-col" style={{ borderRight: "none" }}>
          <div className="toolbar">
            <IconButton tip="Regions" onClick={() => setShowRegions(!showRegions)}><MapIcon size={14} /></IconButton>
            <CommitInput value={ui.memoryAt ?? ""} placeholder="address · module+0x…" onCommit={go} width={220} />
            <IconButton tip="Up 0x800" onClick={() => shift(-kWindow)} disabled={base === null}><ChevronUp size={14} /></IconButton>
            <IconButton tip="Down 0x800" onClick={() => shift(kWindow)} disabled={base === null}><ChevronDown size={14} /></IconButton>
            <IconButton tip={live ? "Pause live refresh" : "Resume live refresh"} onClick={() => setLive(!live)}>{live ? <Pause size={14} /> : <Play size={14} />}</IconButton>
            <button className="btn small" onClick={() => void paste()} disabled={base === null}>Paste hex…</button>
            <button className="btn small" onClick={() => void fill()} disabled={base === null}>Fill…</button>
            <select className="select" value={copyFmt} onChange={(e) => setCopyFmt(e.target.value as CopyFormat)} title="copy format">
              {kCopyFormats.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
            </select>
            <IconButton tip="Copy selection as…" onClick={() => void copyAs()} disabled={rangeLo === null}><Copy size={14} /></IconButton>
            <IconButton tip="Label selection" onClick={label} disabled={sel === null}><Tag size={14} /></IconButton>
            <IconButton tip="Bookmark selection" onClick={() => sel !== null && addBookmark(fmtAddr(sel))} disabled={sel === null}><Bookmark size={14} /></IconButton>
            <IconButton tip="Data inspector" onClick={() => setShowInspect(!showInspect)}><PanelRight size={14} /></IconButton>
            <span className="mono faint ellipsis grow">{ui.memoryAt ? labelAddr(ui.memoryAt, modules) : ""}{rangeLen > 1 ? ` · ${rangeLen} bytes selected` : ""}</span>
          </div>
          <div className="toolbar">
            <select className="select" value={findMode} onChange={(e) => setFindMode(e.target.value as NeedleMode)}>{kModes.map((m) => <option key={m}>{m}</option>)}</select>
            <label className="search grow"><Search size={13} /><input placeholder={findMode === "hex" ? "find bytes: 48 8b ?? 05" : `find ${findMode}`} value={findText} onChange={(e) => setFindText(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void find(e.shiftKey ? -1 : 1); }} /></label>
            <IconButton tip="Find previous (Shift+Enter)" onClick={() => void find(-1)} disabled={!findText || finding !== null}><ChevronLeft size={14} /></IconButton>
            <IconButton tip="Find next (Enter)" onClick={() => void find(1)} disabled={!findText || finding !== null}><ChevronRight size={14} /></IconButton>
            {finding !== null && <><span className="faint" style={{ fontSize: 12 }}>{(finding / 1048576).toFixed(0)} MiB…</span><button className="btn small" onClick={() => { findAbort.current.aborted = true; }}>Stop</button></>}
            <span className="faint" style={{ fontSize: 12 }}>click selects · shift-click extends · double-click edits</span>
          </div>
          {finding !== null && <Progress value={0.5} />}
          <div className="split-h" style={{ gridTemplateColumns: showInspect ? "minmax(0, 1fr) 250px" : "minmax(0, 1fr)", flex: 1, minHeight: 0, height: "auto" }}>
            {base === null ? (
              <div className="empty">
                <div className="empty-title">Enter an address or pick a region.</div>
                <div className="row wrap" style={{ justifyContent: "center" }}>
                  {ui.selected && <button className="btn small primary" onClick={() => ui.goMemory(ui.selected!)}>Selection {ui.selected}</button>}
                  {modules.slice().sort((a, b) => Number(b.base === useConn.getState().target?.base) - Number(a.base === useConn.getState().target?.base) || b.size - a.size).slice(0, 3).map((m) => <button key={m.base} className="btn small" onClick={() => ui.goMemory(m.base)}>{m.name}</button>)}
                  {bookmarks.slice(0, 3).map((b) => <button key={b.address} className="btn small" onClick={() => ui.goMemory(b.address)}>★ {b.label || b.address}</button>)}
                </div>
              </div>
            ) : !data ? (
              <div className="empty"><div className="empty-title">Unreadable memory.</div><div className="empty-hint">{fmtAddr(base)} could not be read.</div></div>
            ) : (
              <div className="vlist hex selectable">
                {Array.from({ length: data.length / 16 }, (_, r) => {
                  const rowAddr = base + BigInt(r * 16);
                  const rowMarked = Array.from({ length: 16 }, (_, c) => bookmarked.has(rowAddr + BigInt(c))).some(Boolean);
                  return (
                    <div key={r} className="hex-row">
                      <span className="hex-addr" data-bookmark={rowMarked}>{showAddr(rowAddr)}</span>
                      <span className="hex-cells">
                        {Array.from(data.subarray(r * 16, r * 16 + 16), (b, c) => {
                          const off = r * 16 + c;
                          const a = rowAddr + BigInt(c);
                          if (edit === off) return <input key={c} autoFocus className="hex-edit" defaultValue={b.toString(16).padStart(2, "0")} onBlur={(e) => void writeCell(off, e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void writeCell(off, e.currentTarget.value); if (e.key === "Escape") setEdit(null); }} />;
                          const nm = named.get(a);
                          return (
                            <span key={c} className="hex-cell" data-zero={b === 0} data-changed={prev.current ? prev.current[off] !== b : false} data-sel={sel === a} data-range={inRange(a) && sel !== a} data-named={Boolean(nm)} title={nm}
                              onClick={(e) => { if (e.shiftKey && sel !== null) setSelEnd(a); else { setSelEnd(null); ui.select(fmtAddr(a)); } }} onDoubleClick={() => setEdit(off)}>
                              {b.toString(16).padStart(2, "0").toUpperCase()}
                            </span>
                          );
                        })}
                      </span>
                      <span className="hex-ascii">
                        {Array.from(data.subarray(r * 16, r * 16 + 16), (b, c) => (
                          <span key={c} data-sel={sel === rowAddr + BigInt(c) || inRange(rowAddr + BigInt(c))}>{b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."}</span>
                        ))}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
            {showInspect && (
              <div className="list-col" style={{ borderLeft: "1px solid var(--border-soft)", borderRight: "none", overflow: "auto" }}>
                <div className="toolbar">
                  <span className="panel-title grow">Inspector</span>
                  <label className="row" style={{ fontSize: 12 }}><input type="checkbox" checked={!littleEndian} onChange={(e) => setLittleEndian(!e.target.checked)} />big-endian</label>
                </div>
                {!inspectBytes ? (
                  <div className="faint" style={{ padding: 8, fontSize: 12 }}>Select a byte in the window.</div>
                ) : (
                  <table className="table mono"><tbody>
                    {inspect(inspectBytes, littleEndian).map((r) => (
                      <tr key={r.type} onDoubleClick={() => littleEndian && void editValue(r.type, r.value)} title={kWritable[r.type] && littleEndian ? "double-click to write" : undefined}>
                        <td className="faint" style={{ width: 70 }}>{r.type}</td><td className="ellipsis">{r.value}</td>
                      </tr>
                    ))}
                  </tbody></table>
                )}
                {sel !== null && named.get(sel) && <div className="panel-section"><div className="label">Label</div><div className="accent mono">{named.get(sel)}</div></div>}
              </div>
            )}
          </div>
        </div>
      </div>
    </NeedsAgent>
  );
}

