import { useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronUp, Map as MapIcon, Pause, Play, Search } from "lucide-react";
import { request } from "@/lib/client";
import { bytesToHex, fmtAddr, labelAddr, parseAddress, showAddr, toBig } from "@/lib/hex";
import { readBytes } from "@/lib/memory";
import { useConn } from "@/store/conn";
import { usePatches } from "@/store/patches";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, IconButton, NeedsAgent } from "../ui";

type Region = { base: string; size: number; present: boolean; writable: boolean; executable: boolean };
const kWindow = 0x800;

function Regions({ onPick }: { onPick: (a: string) => void }) {
  const { modules, ext } = useConn();
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
  const patches = usePatches();
  const base = ui.memoryAt ? toBig(ui.memoryAt) & ~0xfn : null;
  const [data, setData] = useState<Uint8Array | null>(null);
  const prev = useRef<Uint8Array | null>(null);
  const [live, setLive] = useState(true);
  const [showRegions, setShowRegions] = useState(false);
  const [edit, setEdit] = useState<number | null>(null);
  const [tick, setTick] = useState(0);

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
  /** Writes bytes and records the previous content so the write can be reverted. */
  const writeBytes = async (addr: bigint, data: string, note: string): Promise<boolean> => {
    const before = await attempt("write", readBytes(addr, data.length / 2));
    if (!before) {
      log("error", "write", "could not read the current bytes");
      return false;
    }
    const ok = await attempt("write", request("write", { address: fmtAddr(addr), data }));
    if (!ok) return false;
    patches.add({
      id: Math.random().toString(36).slice(2, 10),
      address: fmtAddr(addr),
      written: data,
      before: bytesToHex(before),
      note,
      created: Date.now(),
      reverted: false,
    });
    setTick(tick + 1);
    return true;
  };
  const write = async (off: number, text: string) => {
    setEdit(null);
    if (base === null || !/^[0-9a-f]{1,2}$/i.test(text)) return;
    await writeBytes(base + BigInt(off), text.padStart(2, "0").toLowerCase(), "memory view");
  };
  /** Writes a run of bytes at the selection (or the window base). */
  const patch = async () => {
    const at = sel ?? base;
    if (at === null) return log("warn", "memory", "select an address first");
    const text = window.prompt("Bytes to write (hex, spaces optional)", "");
    if (!text) return;
    const clean = text.replace(/[^0-9a-f]/gi, "");
    if (!clean || clean.length % 2 !== 0) return log("warn", "memory", "need an even number of hex digits");
    const ok = await writeBytes(at, clean.toLowerCase(), "memory view");
    if (ok) log("info", "write", `wrote ${clean.length / 2} bytes at ${fmtAddr(at)}`);
  };

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: showRegions ? "260px" : "0px" }}>
        <div className="list-col" style={{ overflow: "auto", display: showRegions ? "flex" : "none" }}>
          <Regions onPick={go} />
        </div>
        <div className="list-col" style={{ borderRight: "none" }}>
          <div className="toolbar">
            <IconButton tip="Regions" onClick={() => setShowRegions(!showRegions)}><MapIcon size={14} /></IconButton>
            <CommitInput value={ui.memoryAt ?? ""} placeholder="address · module+0x…" onCommit={go} width={260} />
            <IconButton tip="Up 0x800" onClick={() => shift(-kWindow)} disabled={base === null}><ChevronUp size={14} /></IconButton>
            <IconButton tip="Down 0x800" onClick={() => shift(kWindow)} disabled={base === null}><ChevronDown size={14} /></IconButton>
            <IconButton tip={live ? "Pause live refresh" : "Resume live refresh"} onClick={() => setLive(!live)}>{live ? <Pause size={14} /> : <Play size={14} />}</IconButton>
            <button className="btn small" onClick={() => void patch()} disabled={base === null}>Patch bytes…</button>
            <span className="mono faint ellipsis grow">{ui.memoryAt ? labelAddr(ui.memoryAt, modules) : ""}</span>
            <span className="faint" style={{ fontSize: 12 }}>double-click a byte to edit</span>
          </div>
          {base === null ? (
            <div className="empty"><div className="empty-title">Enter an address or pick a region.</div></div>
          ) : !data ? (
            <div className="empty"><div className="empty-title">Unreadable memory.</div><div className="empty-hint">{fmtAddr(base)} could not be read.</div></div>
          ) : (
            <div className="vlist hex selectable">
              {Array.from({ length: data.length / 16 }, (_, r) => {
                const rowAddr = base + BigInt(r * 16);
                return (
                  <div key={r} className="hex-row">
                    <span className="hex-addr">{showAddr(rowAddr)}</span>
                    <span className="hex-cells">
                      {Array.from(data.subarray(r * 16, r * 16 + 16), (b, c) => {
                        const off = r * 16 + c;
                        const a = rowAddr + BigInt(c);
                        if (edit === off) return <input key={c} autoFocus className="hex-edit" defaultValue={b.toString(16).padStart(2, "0")} onBlur={(e) => void write(off, e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") void write(off, e.currentTarget.value); if (e.key === "Escape") setEdit(null); }} />;
                        return (
                          <span key={c} className="hex-cell" data-zero={b === 0} data-changed={prev.current ? prev.current[off] !== b : false} data-sel={sel === a}
                            onClick={() => ui.select(fmtAddr(a))} onDoubleClick={() => setEdit(off)}>
                            {b.toString(16).padStart(2, "0").toUpperCase()}
                          </span>
                        );
                      })}
                    </span>
                    <span className="hex-ascii">
                      {Array.from(data.subarray(r * 16, r * 16 + 16), (b, c) => (
                        <span key={c} data-sel={sel === rowAddr + BigInt(c)}>{b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."}</span>
                      ))}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
