import { useState } from "react";
import { request } from "@/lib/client";
import { bytesToHex, fmtAddr, hexToBytes, labelAddr, parseAddress } from "@/lib/hex";
import { readManyChunked } from "@/lib/batch";
import { saveText } from "@/lib/save";
import { floatScanFields, groupMatches, groupSpan, keep, kNumSize, parseGroup, type Compare, type FloatMode, type GroupMember, type NumType } from "@/lib/analysis/scancmp";
import { decode, type ValueType } from "@/lib/analysis/values";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { NeedsAgent, Panel, Progress, Tabs } from "./ui";

type Mode = "value" | "group" | "aob" | "string";
type ScanType = "u8" | "u16" | "u32" | "u64" | "i8" | "i16" | "i32" | "i64" | "f32" | "f64" | "bytes" | "string" | "wstring";
type Hit = { address: string; value: string; previous?: string };

const kTypes: ScanType[] = ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "bytes", "string", "wstring"];
const kFirst = ["exact", "unknown", "greater", "less", "between"];
const kNext = ["exact", "changed", "unchanged", "increased", "decreased", "greater", "less", "between"];
const kPage = 200;

function show(hex: string | undefined, t: ScanType): string {
  if (!hex) return "";
  const b = hexToBytes(hex);
  if (t === "bytes") return hex;
  if (t === "string") return decode(b, 0, "ascii");
  if (t === "wstring") return decode(b, 0, "utf16");
  return decode(b, 0, t as ValueType);
}

function ModuleSelect({ value, onChange, allowAll = true }: { value: string; onChange: (v: string) => void; allowAll?: boolean }) {
  const modules = useConn((s) => s.modules);
  return (
    <select className="select grow" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{allowAll ? "<all memory>" : "<main module>"}</option>
      {modules.map((m) => <option key={m.base} value={m.name}>{m.name}</option>)}
    </select>
  );
}

function HitTable({ hits, type }: { hits: Hit[]; type?: ScanType }) {
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const addWatch = useWatch((s) => s.addWatch);
  return (
    <table className="table">
      <colgroup><col /><col style={{ width: type ? 90 : 0 }} /><col style={{ width: 54 }} /></colgroup>
      <thead><tr><th>Address</th>{type ? <th>Value</th> : <th />}<th /></tr></thead>
      <tbody>
        {hits.map((h) => (
          <tr key={h.address} data-selected={ui.selected === h.address} onClick={() => ui.select(h.address)} onDoubleClick={() => (type ? ui.goMemory(h.address) : ui.goDisasm(h.address))}>
            <td className="mono" title={h.address}>{labelAddr(h.address, modules)}</td>
            <td className="mono dim">{type ? show(h.value, type) : ""}</td>
            <td><button className="row-action" onClick={() => addWatch(h.address, type && !["bytes", "string", "wstring"].includes(type) ? (type as ValueType) : "i32")}>+watch</button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

type LocalHit = { address: string; value: string };
type ScanFile = { format: "echodebug.scan"; version: 1; type: ScanType; savedAt: string; entries: LocalHit[] };
/** Below this many candidates the app narrows the list itself (undo, save, load). */
const kLocalMax = 50_000;
const kAligns = [["natural", 0], ["1", 1], ["2", 2], ["4", 4], ["8", 8]] as const;
const isNum = (t: ScanType) => !["bytes", "string", "wstring"].includes(t);

function ValueScan() {
  const progress = useConn((s) => s.progress);
  const [type, setType] = useState<ScanType>("i32");
  const [compare, setCompare] = useState("exact");
  const [value, setValue] = useState("");
  const [value2, setValue2] = useState("");
  const [module, setModule] = useState("");
  const [rangeLo, setRangeLo] = useState("");
  const [rangeHi, setRangeHi] = useState("");
  const [writable, setWritable] = useState(true);
  const [align, setAlign] = useState(0);
  const [floatMode, setFloatMode] = useState<FloatMode>("rounded");
  const [eps, setEps] = useState("0.0001");
  const [count, setCount] = useState<number | null>(null);
  const [hits, setHits] = useState<Hit[]>([]);
  const [offset, setOffset] = useState(0);
  const [busy, setBusy] = useState(false);
  // client-side candidate list + undo history (only when small enough)
  const [local, setLocal] = useState<LocalHit[] | null>(null);
  const [history, setHistory] = useState<LocalHit[][]>([]);
  const [pulled, setPulled] = useState(0);
  const modules = useConn((s) => s.modules);

  const showLocal = (list: LocalHit[], off = 0) => {
    setCount(list.length);
    setOffset(off);
    setHits(list.slice(off, off + kPage));
  };
  const page = async (off: number) => {
    if (local) return showLocal(local, off);
    const r = await attempt("scan", request<{ count: number; results: Hit[] }>("scan_results", { offset: off, limit: kPage }));
    if (r) { setHits(r.results); setCount(r.count); setOffset(off); }
  };
  /** Pulls the agent's whole candidate list into the app once it is small. */
  const pullLocal = async (n: number) => {
    const all: LocalHit[] = [];
    for (let off = 0; off < n; off += 2000) {
      const r = await request<{ results: Hit[] }>("scan_results", { offset: off, limit: 2000 }).catch(() => null);
      if (!r) return null;
      all.push(...r.results.map((h) => ({ address: h.address, value: h.value })));
      setPulled(all.length);
    }
    return all;
  };
  const valueFields = (): Record<string, unknown> => {
    if ((type === "f32" || type === "f64") && compare === "exact") return floatScanFields(value, floatMode, Number(eps) || 0.0001);
    const f: Record<string, unknown> = { compare, value, value2 };
    if (type === "f32" || type === "f64") f.float_epsilon = Number(eps) || 0.0001;
    return f;
  };
  const run = async (verb: "scan_new" | "scan_next") => {
    if (verb === "scan_next" && local) return runLocal();
    setBusy(true);
    const fields = valueFields();
    if (verb === "scan_new") {
      Object.assign(fields, { value_type: type, writable_only: writable, ...(align ? { alignment: align } : {}) });
      if (module === "__range") {
        const lo = parseAddress(rangeLo, modules);
        const hi = parseAddress(rangeHi, modules);
        if (lo === null || hi === null || hi <= lo) { setBusy(false); return log("warn", "scan", "enter a start and end address for the range"); }
        Object.assign(fields, { start: fmtAddr(lo), end: fmtAddr(hi) });
      } else if (module) fields.module = module;
    }
    const r = await attempt("scan", request<{ count: number }>(verb, fields));
    if (r) {
      log("info", "scan", `${verb === "scan_new" ? "first" : "next"} scan: ${r.count} results`);
      if (r.count <= kLocalMax && isNum(type)) {
        const list = await pullLocal(r.count);
        if (list) {
          setLocal(list);
          setHistory([]);
          showLocal(list);
          log("info", "scan", `${list.length} candidates held in the app: next scans run here, with undo and save`);
        } else await page(0);
      } else await page(0);
    }
    setBusy(false);
  };
  const runLocal = async () => {
    if (!local) return;
    setBusy(true);
    const t = type as NumType;
    const size = kNumSize[t];
    const fields = valueFields();
    const cmp = String(fields.compare) as Compare;
    const cur = await readManyChunked(local.map((h) => ({ address: h.address, size })), 1024, setPulled);
    const next: LocalHit[] = [];
    local.forEach((h, i) => {
      const b = cur[i];
      if (!b) return;
      if (keep(t, cmp, b, hexToBytes(h.value), String(fields.value ?? ""), String(fields.value2 ?? ""), Number(fields.float_epsilon ?? eps) || 0.0001)) next.push({ address: h.address, value: bytesToHex(b) });
    });
    setHistory((hs) => [...hs.slice(-31), local]);
    setLocal(next);
    showLocal(next);
    setBusy(false);
    log("info", "scan", `next scan (in app): ${next.length} results`);
  };
  const undo = () => {
    const prevList = history[history.length - 1];
    if (!prevList) return;
    setHistory(history.slice(0, -1));
    setLocal(prevList);
    showLocal(prevList);
    log("info", "scan", `undo: back to ${prevList.length} results`);
  };
  const save = async () => {
    if (!local) return;
    const f: ScanFile = { format: "echodebug.scan", version: 1, type, savedAt: new Date().toISOString(), entries: local };
    await saveText(`scan-${type}-${local.length}.json`, JSON.stringify(f));
  };
  const load = async () => {
    const input = Object.assign(document.createElement("input"), { type: "file", accept: ".json,application/json" });
    const { promise, resolve } = Promise.withResolvers<File | null>();
    input.onchange = () => resolve(input.files?.[0] ?? null);
    input.click();
    const file = await promise;
    if (!file) return;
    try {
      const f = JSON.parse(await file.text()) as ScanFile;
      if (f.format !== "echodebug.scan" || !Array.isArray(f.entries)) throw new Error("not an EchoDebug scan file");
      setType(f.type);
      setLocal(f.entries);
      setHistory([]);
      setCompare("unchanged");
      showLocal(f.entries);
      log("info", "scan", `loaded ${f.entries.length} candidates (${f.type}); the next scan compares against the saved values`);
    } catch (e) {
      log("error", "scan", String(e instanceof Error ? e.message : e));
    }
  };
  const reset = async () => {
    await attempt("scan", request("scan_clear"));
    setCount(null); setHits([]); setCompare("exact"); setLocal(null); setHistory([]);
  };
  const started = count !== null;
  const needsValue = !["unknown", "changed", "unchanged", "increased", "decreased"].includes(compare);
  const isFloat = type === "f32" || type === "f64";
  return (
    <>
      <div className="panel-section">
        <div className="row">
          <select className="select" value={type} disabled={started} onChange={(e) => setType(e.target.value as ScanType)}>{kTypes.map((t) => <option key={t}>{t}</option>)}</select>
          <select className="select grow" value={compare} onChange={(e) => setCompare(e.target.value)}>{(started ? kNext : kFirst).map((c) => <option key={c}>{c}</option>)}</select>
        </div>
        {needsValue && (
          <div className="row">
            <input className="input mono grow" placeholder={type === "bytes" ? "48 8b ?? …" : "value"} value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void run(started ? "scan_next" : "scan_new")} />
            {compare === "between" && <input className="input mono grow" placeholder="to" value={value2} onChange={(e) => setValue2(e.target.value)} />}
          </div>
        )}
        {isFloat && (
          <div className="row">
            <select className="select grow" value={floatMode} onChange={(e) => setFloatMode(e.target.value as FloatMode)} title="how an exact float value matches">
              <option value="rounded">rounded (1.5 ≈ 1.45…1.55)</option>
              <option value="truncated">truncated (1.5 ≈ 1.50…1.59)</option>
              <option value="epsilon">within ± epsilon</option>
            </select>
            {floatMode === "epsilon" && <input className="input mono" style={{ width: 80 }} value={eps} onChange={(e) => setEps(e.target.value)} title="epsilon" />}
          </div>
        )}
        {!started && (
          <>
            <div className="row">
              <select className="select grow" value={module} onChange={(e) => setModule(e.target.value)}>
                <option value="">{"<all memory>"}</option>
                <option value="__range">{"<address range…>"}</option>
                {modules.map((m) => <option key={m.base} value={m.name}>{m.name}</option>)}
              </select>
              <label className="row" style={{ fontSize: 12 }}><input type="checkbox" checked={writable} onChange={(e) => setWritable(e.target.checked)} />writable</label>
            </div>
            {module === "__range" && (
              <div className="row">
                <input className="input mono grow" placeholder="start" value={rangeLo} onChange={(e) => setRangeLo(e.target.value)} />
                <input className="input mono grow" placeholder="end" value={rangeHi} onChange={(e) => setRangeHi(e.target.value)} />
              </div>
            )}
            <div className="row">
              <span className="faint" style={{ fontSize: 12 }}>alignment</span>
              <select className="select" value={align} onChange={(e) => setAlign(Number(e.target.value))} title="fast scan: only addresses divisible by this">{kAligns.map(([l, v]) => <option key={l} value={v}>{l}</option>)}</select>
            </div>
          </>
        )}
        <div className="row">
          {!started ? <button className="btn primary" disabled={busy} onClick={() => void run("scan_new")}>First scan</button> : <button className="btn primary" disabled={busy} onClick={() => void run("scan_next")}>Next scan</button>}
          <button className="btn" disabled={busy || !local || history.length === 0} onClick={undo} title="restore the candidates before the last next scan">Undo</button>
          <button className="btn" disabled={busy || !started} onClick={() => void reset()}>Reset</button>
          <span className="grow" />
          {count !== null && <span className="faint" title={local ? "held in the app" : "held by the agent"}>{count.toLocaleString()} results{local ? " · in app" : ""}</span>}
        </div>
        <div className="row">
          <button className="btn small" disabled={!local} onClick={() => void save()}>Save results…</button>
          <button className="btn small" disabled={busy} onClick={() => void load()}>Load…</button>
          <span className="faint" style={{ fontSize: 11 }}>{local ? "" : `undo/save once ≤ ${kLocalMax.toLocaleString()} results`}</span>
        </div>
        {busy && (local ? <Progress value={pulled / Math.max(1, local.length)} /> : progress && <Progress value={progress.done / Math.max(1, progress.total)} />)}
      </div>
      <div className="panel-body"><HitTable hits={hits} type={type} /></div>
      {count !== null && count > kPage && (
        <div className="toolbar">
          <button className="btn small" disabled={offset === 0} onClick={() => void page(Math.max(0, offset - kPage))}>Prev</button>
          <span className="faint grow" style={{ textAlign: "center", fontSize: 12 }}>{offset + 1}–{Math.min(count, offset + kPage)}</span>
          <button className="btn small" disabled={offset + kPage >= count} onClick={() => void page(offset + kPage)}>Next</button>
        </div>
      )}
    </>
  );
}

/** Several values at fixed offsets: scan the anchor, then check the others in the app. */
function GroupScan() {
  const modules = useConn((s) => s.modules);
  const [spec, setSpec] = useState("i32:100; +4 f32:1.5");
  const [module, setModule] = useState("");
  const [hits, setHits] = useState<Hit[]>([]);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const run = async () => {
    let g: GroupMember[];
    try { g = parseGroup(spec); } catch (e) { return log("warn", "group", String(e instanceof Error ? e.message : e)); }
    setBusy(true);
    setHits([]);
    const a = g[0];
    const fields: Record<string, unknown> = { value_type: a.type, compare: "exact", value: a.value, writable_only: true, ...(module ? { module } : {}) };
    if (a.type === "f32" || a.type === "f64") Object.assign(fields, floatScanFields(a.value!, "rounded"));
    const r = await attempt("group", request<{ count: number }>("scan_new", fields));
    if (!r) return setBusy(false);
    if (r.count > 200_000) {
      setBusy(false);
      setNote(`${r.count.toLocaleString()} anchors: make the first member more specific or restrict to a module`);
      return;
    }
    const anchors: string[] = [];
    for (let off = 0; off < r.count; off += 2000) {
      const p = await request<{ results: Hit[] }>("scan_results", { offset: off, limit: 2000 }).catch(() => null);
      if (!p) break;
      anchors.push(...p.results.map((h) => h.address));
    }
    const span = groupSpan(g);
    const bytes = await readManyChunked(anchors.map((x) => ({ address: x, size: span })));
    const out: Hit[] = [];
    anchors.forEach((x, i) => {
      const b = bytes[i];
      if (b && groupMatches(g, b)) out.push({ address: x, value: bytesToHex(b) });
    });
    setHits(out.slice(0, 5000));
    setNote(`${anchors.length.toLocaleString()} anchors → ${out.length.toLocaleString()} groups (${span} bytes each)`);
    log("info", "group", `group scan: ${out.length} matches`);
    setBusy(false);
  };
  return (
    <>
      <div className="panel-section">
        <input className="input mono" value={spec} onChange={(e) => setSpec(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void run()} placeholder="i32:100; +4 f32:1.5; +8 i32:*" />
        <div className="faint" style={{ fontSize: 11 }}>members: <span className="mono">[+offset] type:value</span>, <span className="mono">*</span> = any; offsets default to right after the previous member</div>
        <div className="row">
          <select className="select grow" value={module} onChange={(e) => setModule(e.target.value)}>
            <option value="">{"<all memory>"}</option>
            {modules.map((m) => <option key={m.base} value={m.name}>{m.name}</option>)}
          </select>
          <button className="btn primary" disabled={busy} onClick={() => void run()}>Scan</button>
        </div>
        <span className="faint" style={{ fontSize: 12 }}>{note}</span>
      </div>
      <div className="panel-body"><HitTable hits={hits} type="bytes" /></div>
    </>
  );
}

function PatternScan({ mode }: { mode: "aob" | "string" }) {
  const modules = useConn((s) => s.modules);
  const target = useConn((s) => s.target);
  const [q, setQ] = useState("");
  const [module, setModule] = useState("");
  const [hits, setHits] = useState<Hit[]>([]);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (!q.trim()) return;
    setBusy(true);
    const mod = module || modules.find((m) => m.base === target?.base)?.name || modules[0]?.name;
    const r = await attempt(mode, request<{ results: string[]; success: boolean }>(
      mode === "aob" ? "sig_scan_ida" : "string_scan",
      mode === "aob" ? { pattern: q.trim(), module: mod, find_all: true } : { text: q, module: mod, find_all: true },
      true,
    ));
    setBusy(false);
    const res = r?.success ? r.results ?? [] : [];
    setHits(res.map((address) => ({ address, value: "" })));
    log("info", mode, `${res.length} hits in ${mod}`);
  };
  return (
    <>
      <div className="panel-section">
        <input className="input mono" placeholder={mode === "aob" ? "48 8B 05 ? ? ? ? 48 85 C0" : "text to find"} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void run()} />
        <div className="row">
          <ModuleSelect value={module} onChange={setModule} allowAll={false} />
          <button className="btn primary" disabled={busy} onClick={() => void run()}>Scan</button>
        </div>
        <span className="faint" style={{ fontSize: 12 }}>{hits.length} hits</span>
      </div>
      <div className="panel-body"><HitTable hits={hits} /></div>
    </>
  );
}

export default function ScannerPanel() {
  const [mode, setMode] = useState<Mode>("value");
  return (
    <Panel>
      <Tabs tabs={[{ id: "value", label: "Value scan" }, { id: "group", label: "Group" }, { id: "aob", label: "AOB" }, { id: "string", label: "String" }]} active={mode} onSelect={setMode} />
      <NeedsAgent ext={mode === "value" || mode === "group"}>
        {mode === "value" ? <ValueScan /> : mode === "group" ? <GroupScan /> : <PatternScan key={mode} mode={mode} />}
      </NeedsAgent>
    </Panel>
  );
}
