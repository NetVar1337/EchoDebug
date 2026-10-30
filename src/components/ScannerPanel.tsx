import { useState } from "react";
import { request } from "@/lib/client";
import { hexToBytes, labelAddr } from "@/lib/hex";
import { decode, type ValueType } from "@/lib/analysis/values";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { NeedsAgent, Panel, Progress, Tabs } from "./ui";

type Mode = "value" | "aob" | "string";
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

function ValueScan() {
  const progress = useConn((s) => s.progress);
  const [type, setType] = useState<ScanType>("i32");
  const [compare, setCompare] = useState("exact");
  const [value, setValue] = useState("");
  const [value2, setValue2] = useState("");
  const [module, setModule] = useState("");
  const [writable, setWritable] = useState(true);
  const [count, setCount] = useState<number | null>(null);
  const [hits, setHits] = useState<Hit[]>([]);
  const [offset, setOffset] = useState(0);
  const [busy, setBusy] = useState(false);

  const page = async (off: number) => {
    const r = await attempt("scan", request<{ count: number; results: Hit[] }>("scan_results", { offset: off, limit: kPage }));
    if (r) { setHits(r.results); setCount(r.count); setOffset(off); }
  };
  const run = async (verb: "scan_new" | "scan_next") => {
    setBusy(true);
    const fields: Record<string, unknown> = { compare, value, value2 };
    if (verb === "scan_new") Object.assign(fields, { value_type: type, writable_only: writable, ...(module ? { module } : {}) });
    const r = await attempt("scan", request<{ count: number }>(verb, fields));
    setBusy(false);
    if (r) {
      log("info", "scan", `${verb === "scan_new" ? "first" : "next"} scan: ${r.count} results`);
      await page(0);
    }
  };
  const reset = async () => {
    await attempt("scan", request("scan_clear"));
    setCount(null); setHits([]); setCompare("exact");
  };
  const started = count !== null;
  const needsValue = !["unknown", "changed", "unchanged", "increased", "decreased"].includes(compare);
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
        {!started && (
          <div className="row">
            <ModuleSelect value={module} onChange={setModule} />
            <label className="row" style={{ fontSize: 12 }}><input type="checkbox" checked={writable} onChange={(e) => setWritable(e.target.checked)} />writable</label>
          </div>
        )}
        <div className="row">
          {!started ? <button className="btn primary" disabled={busy} onClick={() => void run("scan_new")}>First scan</button> : <button className="btn primary" disabled={busy} onClick={() => void run("scan_next")}>Next scan</button>}
          <button className="btn" disabled={busy || !started} onClick={() => void reset()}>Reset</button>
          <span className="grow" />
          {count !== null && <span className="faint">{count.toLocaleString()} results</span>}
        </div>
        {busy && progress && <Progress value={progress.done / Math.max(1, progress.total)} />}
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
      <Tabs tabs={[{ id: "value", label: "Value scan" }, { id: "aob", label: "AOB" }, { id: "string", label: "String" }]} active={mode} onSelect={setMode} />
      <NeedsAgent ext={mode === "value"}>
        {mode === "value" ? <ValueScan /> : <PatternScan key={mode} mode={mode} />}
      </NeedsAgent>
    </Panel>
  );
}
