// Signature tools: catalog health check and repair, batch signature generation, FLIRT export.
import { useMemo, useRef, useState } from "react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, moduleOf, toBig, type Module } from "@/lib/hex";
import { genInput, moduleFunctions } from "@/lib/flirtlive";
import { saveBinary, saveText } from "@/lib/save";
import { makeSignature, toCode, toIda, type Insn, type Pattern } from "@/lib/analysis/sigmaker";
import { health, locate, type Health } from "@/lib/analysis/sigrepair";
import { parseFlirt } from "@/lib/analysis/flirt";
import { toPatEntry, toPatFile, writeSig, type PatEntry } from "@/lib/analysis/flirtgen";
import { useConn } from "@/store/conn";
import { useFlirt } from "@/store/flirt";
import { useNames } from "@/store/names";
import { log } from "@/store/output";
import { useSigs } from "@/store/sigs";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { NeedsAgent, Progress, Tabs } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

async function scan(ida: string, module: string): Promise<string[]> {
  const r = await request<{ results: string[]; success: boolean }>("sig_scan_ida", { pattern: ida, module, find_all: true }, true).catch(() => null);
  return r?.success ? r.results ?? [] : [];
}

async function uniqueAt(addr: string, module: string): Promise<{ pattern: Pattern } | null> {
  const r = await request<{ results: Insn[] }>("disassemble", { address: addr, size: 0x200 }, true).catch(() => null);
  return r?.results?.length ? makeSignature(r.results, async (p) => (await scan(p, module)).length) : null;
}

function HealthTab() {
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const catalog = useSigs();
  const [state, setState] = useState<Record<string, { health: Health; hits: number; note?: string; candidates?: string[] }>>({});
  const [busy, setBusy] = useState(0);
  const mainName = () => modules.find((m) => m.base === useConn.getState().target?.base)?.name ?? modules[0]?.name ?? "";

  const check = async () => {
    const out: typeof state = {};
    for (const [i, s] of catalog.sigs.entries()) {
      const hits = await scan(s.ida, s.module || mainName());
      out[s.id] = { health: health(hits.length), hits: hits.length };
      setBusy((i + 1) / catalog.sigs.length);
    }
    setState(out);
    setBusy(0);
    const bad = Object.values(out).filter((x) => x.health !== "ok").length;
    log(bad ? "warn" : "info", "sigs", `${catalog.sigs.length - bad} of ${catalog.sigs.length} signatures match exactly once`);
  };
  const repair = async (id: string) => {
    const s = catalog.sigs.find((x) => x.id === id);
    if (!s) return;
    const mod = s.module || mainName();
    const r = await locate(s.pattern, (ida) => scan(ida, mod));
    if (r.status === "repaired" && r.at) {
      const fresh = await uniqueAt(r.at, mod);
      if (!fresh) return setState((st) => ({ ...st, [id]: { ...st[id], note: `found at ${labelAddr(r.at!, modules)}, but no new unique signature there` } }));
      catalog.update(id, { pattern: fresh.pattern, address: r.at, hits: 1, note: `${s.note ? s.note + " · " : ""}repaired ${new Date().toISOString().slice(0, 10)} (was ${s.address})` });
      setState((st) => ({ ...st, [id]: { health: "ok", hits: 1, note: `repaired: now at ${labelAddr(r.at!, modules)}` } }));
      log("info", "sigs", `${s.name}: repaired at ${labelAddr(r.at, modules)}`);
    } else if (r.status === "ambiguous") {
      setState((st) => ({ ...st, [id]: { ...st[id], note: `${r.candidates.length} candidates with a ${r.prefix}-byte prefix`, candidates: r.candidates } }));
    } else setState((st) => ({ ...st, [id]: { ...st[id], note: "no prefix of the pattern matches any more" } }));
  };

  return (
    <>
      <div className="toolbar">
        <button className="btn small primary" disabled={!catalog.sigs.length || busy > 0} onClick={() => void check()}>Check all {catalog.sigs.length} signatures</button>
        <span className="faint" style={{ fontSize: 12 }}>Each saved signature is scanned in its module: it must match exactly once. Repair shortens a broken pattern until it finds the function again, then derives a new unique one there.</span>
      </div>
      {busy > 0 && <Progress value={busy} />}
      <div className="vlist">
        <table className="table mono">
          <thead><tr><th>Name</th><th>Module</th><th>Status</th><th>Pattern</th><th /></tr></thead>
          <tbody>
            {catalog.sigs.map((s) => {
              const st = state[s.id];
              return (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td className="faint">{s.module || "main"}</td>
                  <td className={st?.health === "ok" ? "ok" : st ? "danger" : "faint"} title={st?.note}>
                    {st ? `${st.health}${st.health !== "ok" ? ` (${st.hits})` : ""}` : "—"}{st?.note ? <div className="faint" style={{ fontSize: 11 }}>{st.note}</div> : null}
                    {st?.candidates?.slice(0, 6).map((c) => <div key={c} className="link" style={{ fontSize: 11 }} onClick={() => ui.goDisasm(c)}>{labelAddr(c, modules)}</div>)}
                  </td>
                  <td className="ellipsis" title={s.ida}>{s.ida}</td>
                  <td>{st && st.health !== "ok" && <button className="row-action" onClick={() => void repair(s.id)}>repair</button>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!catalog.sigs.length && <div className="empty"><div className="empty-title">The catalog is empty.</div><div className="empty-hint">Save signatures from the Signatures tab or the batch sigmaker.</div></div>}
      </div>
    </>
  );
}

type Target = { address: string; name: string };
type BatchRow = Target & { ida?: string; error?: string };

function BatchTab() {
  const m = useFocusedModule();
  const modules = useConn((s) => s.modules);
  const names = useNames();
  const bookmarks = useWatch((s) => s.bookmarks);
  const catalog = useSigs();
  const [source, setSource] = useState<"named" | "bookmarks" | "all">("named");
  const [rows, setRows] = useState<BatchRow[]>([]);
  const [busy, setBusy] = useState(0);
  const abort = useRef({ aborted: false });

  const targets = async (): Promise<Target[]> => {
    if (!m) return [];
    const inMod = (a: string) => moduleOf(toBig(a), modules)?.name === m.name;
    if (source === "bookmarks") return bookmarks.filter((b) => inMod(b.address)).map((b) => ({ address: b.address, name: names.nameOf(b.address) || b.label || `loc_${toBig(b.address).toString(16)}` }));
    if (source === "named") return names.names.filter((n) => n.name && inMod("0x" + n.address)).map((n) => ({ address: fmtAddr(toBig("0x" + n.address)), name: n.name }));
    return (await moduleFunctions(m)).slice(0, 500).map((f) => ({ address: f.address, name: names.nameOf(f.address) || `sub_${toBig(f.address).toString(16)}` }));
  };
  const run = async () => {
    if (!m) return;
    abort.current = { aborted: false };
    const list = await targets();
    if (!list.length) return log("warn", "batch", "no targets in this module for that source");
    const out: BatchRow[] = [];
    setBusy(0.01);
    for (const [i, t] of list.entries()) {
      if (abort.current.aborted) break;
      const s = await uniqueAt(t.address, m.name).catch(() => null);
      out.push(s ? { ...t, ida: toIda(s.pattern) } : { ...t, error: "no unique signature within 512 bytes" });
      setRows([...out]);
      setBusy((i + 1) / list.length);
    }
    setBusy(0);
    log("info", "batch", `${out.filter((r) => r.ida).length} of ${out.length} signatures made`);
  };
  const ok = rows.filter((r) => r.ida);
  const saveAll = () => {
    for (const r of ok) {
      const pattern: Pattern = r.ida!.split(" ").map((b) => (b === "?" ? null : parseInt(b, 16)));
      catalog.add({ name: r.name, address: r.address, module: m?.name ?? "", pattern, note: "batch", hits: 1 });
    }
    log("info", "batch", `saved ${ok.length} signatures to the catalog`);
  };
  const exportHeader = async () => {
    const lines = ["// EchoDebug signatures", `// module: ${m?.name}`, "#pragma once", ""];
    for (const r of ok) {
      const c = toCode(r.ida!.split(" ").map((b) => (b === "?" ? null : parseInt(b, 16))));
      const id = r.name.replace(/\W/g, "_");
      lines.push(`// ${labelAddr(r.address, modules)}`, `constexpr const char* ${id}_ida = "${r.ida}";`, `constexpr const char* ${id}_mask = "${c.mask}";`, "");
    }
    await saveText(`${m?.name ?? "module"}-signatures.h`, lines.join("\n"));
  };

  return (
    <>
      <div className="toolbar">
        <ModulePicker />
        <select className="select" value={source} onChange={(e) => setSource(e.target.value as typeof source)}>
          <option value="named">named addresses</option>
          <option value="bookmarks">bookmarks</option>
          <option value="all">every function (first 500)</option>
        </select>
        <button className="btn small primary" disabled={busy > 0} onClick={() => void run()}>Generate</button>
        {busy > 0 && <button className="btn small" onClick={() => { abort.current.aborted = true; }}>Stop</button>}
        <span className="grow" />
        <button className="btn small" disabled={!ok.length} onClick={saveAll}>Save {ok.length} to catalog</button>
        <button className="btn small" disabled={!ok.length} onClick={() => void exportHeader()}>Export .h</button>
        <button className="btn small" disabled={!ok.length} onClick={() => void saveText(`${m?.name ?? "module"}-signatures.json`, JSON.stringify(ok, null, 2))}>Export .json</button>
      </div>
      {busy > 0 && <Progress value={busy} />}
      <div className="vlist">
        <table className="table mono"><tbody>
          {rows.map((r) => <tr key={r.address}><td>{r.name}</td><td className="faint">{labelAddr(r.address, modules)}</td><td className={r.ida ? undefined : "danger"}>{r.ida ?? r.error}</td></tr>)}
        </tbody></table>
      </div>
    </>
  );
}

function FlirtTab() {
  const m = useFocusedModule();
  const names = useNames();
  const flirt = useFlirt();
  const [onlyNamed, setOnlyNamed] = useState(true);
  const [lib, setLib] = useState("");
  const [entries, setEntries] = useState<PatEntry[]>([]);
  const [busy, setBusy] = useState(0);
  const abort = useRef({ aborted: false });
  const libName = lib || `${m?.name ?? "module"} (EchoDebug)`;

  const generate = async (mod: Module) => {
    abort.current = { aborted: false };
    setBusy(0.01);
    const fns = (await moduleFunctions(mod)).map((f) => ({ ...f, name: names.nameOf(f.address) }))
      .filter((f) => !onlyNamed || f.name)
      .map((f) => ({ ...f, name: f.name || `sub_${(toBig(f.address) - toBig(mod.base)).toString(16)}` }));
    if (!fns.length) {
      setBusy(0);
      return log("warn", "flirt", onlyNamed ? "no named functions in this module: name some (N in the disassembly) or include unnamed ones" : "no functions found");
    }
    const input = await genInput(fns, (d) => setBusy(d / fns.length), abort.current);
    const list = input.map(toPatEntry).filter((e): e is PatEntry => e !== null);
    setEntries(list);
    setBusy(0);
    log("info", "flirt", `${list.length} FLIRT patterns from ${fns.length} functions in ${mod.name}`);
  };
  const sig = useMemo(() => (entries.length ? writeSig(entries, { libraryName: libName }) : null), [entries, libName]);

  return (
    <>
      <div className="toolbar">
        <ModulePicker />
        <label className="row" style={{ fontSize: 12 }}><input type="checkbox" checked={onlyNamed} onChange={(e) => setOnlyNamed(e.target.checked)} />named functions only</label>
        <input className="input" style={{ width: 200 }} placeholder="library name" value={lib} onChange={(e) => setLib(e.target.value)} />
        <button className="btn small primary" disabled={!m || busy > 0} onClick={() => m && void generate(m)}>Generate patterns</button>
        {busy > 0 && <button className="btn small" onClick={() => { abort.current.aborted = true; }}>Stop</button>}
        <span className="grow" />
        <button className="btn small" disabled={!entries.length} onClick={() => void saveText(`${m?.name ?? "module"}.pat`, toPatFile(entries))}>Save .pat</button>
        <button className="btn small" disabled={!sig} onClick={() => sig && void saveBinary(`${m?.name ?? "module"}.sig`, sig)}>Save .sig</button>
        <button className="btn small" disabled={!sig} onClick={() => { if (sig) { flirt.set(`${m?.name}.sig (generated)`, parseFlirt(sig)); log("info", "flirt", "generated signature loaded into the FLIRT matcher (Signatures tab)"); } }}>Load into matcher</button>
      </div>
      {busy > 0 && <Progress value={busy} />}
      <div className="faint" style={{ fontSize: 12, padding: "4px 10px" }}>
        .pat feeds FLAIR's <span className="mono">sigmake</span>; .sig is an uncompressed version 10 file that IDA, rizin and this app load. Relocated operands (rel32 / disp32) are wildcarded; the CRC covers the bytes after the 32-byte pattern up to the first wildcard.
      </div>
      <div className="vlist">
        <table className="table mono"><tbody>
          {entries.slice(0, 2000).map((e, i) => (
            <tr key={i}><td>{e.name}</td><td className="faint ellipsis">{e.pattern.map((b) => (b < 0 ? ".." : b.toString(16).padStart(2, "0"))).join("")}</td><td className="faint">{e.crcLength} · {e.crc.toString(16).padStart(4, "0")} · {e.length}</td></tr>
          ))}
        </tbody></table>
      </div>
    </>
  );
}

export default function SigToolsView() {
  const [tab, setTab] = useState<"health" | "batch" | "flirt">("health");
  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <Tabs tabs={[{ id: "health", label: "Catalog health" }, { id: "batch", label: "Batch sigmaker" }, { id: "flirt", label: "FLIRT export" }]} active={tab} onSelect={setTab} />
        {tab === "health" ? <HealthTab /> : tab === "batch" ? <BatchTab /> : <FlirtTab />}
      </div>
    </NeedsAgent>
  );
}
