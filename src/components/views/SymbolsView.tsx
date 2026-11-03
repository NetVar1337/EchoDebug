// Symbols: the PDB of each module — what the image asks for (GUID/age), what was found or
// downloaded and whether it matches, download progress and errors, and a searchable symbol and type
// browser. Downloads happen only on a click here (or with auto-download enabled in Settings).
import { useEffect, useMemo, useState } from "react";
import { CloudDownload, FolderSearch, RefreshCw, Search, Settings2, X } from "lucide-react";
import { codeviewOf, loadPdb, protoText, type CodeViewId } from "@/lib/pdb";
import { fmtAddr, toBig, type Module } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { entryId, useSymbols, type PdbEntry } from "@/store/symbols";
import { useUi } from "@/store/ui";
import { IconButton, NeedsAgent, Progress, Tabs } from "../ui";
import VList from "../VList";
import TypeBrowser from "./symbols/TypeBrowser";

const fmtBytes = (n: number) => (n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MiB` : n >= 1024 ? `${(n / 1024).toFixed(0)} KiB` : `${n} B`);

function statusOf(e: PdbEntry | undefined): { dot: "ok" | "warn" | "bad" | "busy" | undefined; text: string } {
  if (!e) return { dot: undefined, text: "" };
  switch (e.status) {
    case "loaded": return e.matched ? { dot: "ok", text: "matched" } : { dot: "warn", text: "other build" };
    case "loading": return { dot: "busy", text: "loading…" };
    case "downloading": return { dot: "busy", text: e.progress?.total ? `${Math.round((100 * e.progress.done) / e.progress.total)}%` : e.progress?.done ? fmtBytes(e.progress.done) : "downloading…" };
    case "missing": return { dot: "warn", text: e.mismatches?.length ? "other build only" : "not found" };
    case "error": return { dot: "bad", text: "error" };
    default: return { dot: undefined, text: "" };
  }
}

export default function SymbolsView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const target = useConn((s) => s.target);
  const entries = useSymbols((s) => s.entries);
  const autoDownload = useSymbols((s) => s.autoDownload);
  const [pick, setPick] = useState<string>("");
  const [filter, setFilter] = useState("");
  const [onlyPdb, setOnlyPdb] = useState(false);
  const mainMod = modules.find((m) => m.base === target?.base) ?? modules[0];
  const m = modules.find((x) => x.name === pick) ?? mainMod;
  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return modules.filter((x) => (!f || x.name.toLowerCase().includes(f)) && (!onlyPdb || entries[entryId(x)]));
  }, [modules, filter, onlyPdb, entries]);

  const loadAll = async () => {
    let n = 0;
    for (const x of modules) {
      const e = await loadPdb(x, { download: autoDownload }).catch(() => null);
      if (e?.status === "loaded") n++;
    }
    log("info", "symbols", `${n} of ${modules.length} modules have a PDB loaded${autoDownload ? "" : " (local copies only; auto-download is off)"}`);
  };

  return (
    <NeedsAgent>
      <div className="split-h" style={{ gridTemplateColumns: "240px minmax(0, 1fr)" }}>
        <div className="list-col">
          <div className="toolbar">
            <label className="search grow"><Search size={13} /><input placeholder={`Filter ${modules.length} modules…`} value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
            <IconButton tip="Symbol settings (path, servers, auto-download)" onClick={() => ui.set({ settingsOpen: true })}><Settings2 size={14} /></IconButton>
          </div>
          <div className="toolbar">
            <button className="btn small grow" onClick={() => void loadAll()} title={autoDownload ? "every module: local copies, then the symbol servers" : "every module: local copies and the cache only (no network)"}>
              <FolderSearch size={12} /> Load all{autoDownload ? "" : " (local)"}
            </button>
            <label className="row" title="only modules with a PDB entry"><input type="checkbox" checked={onlyPdb} onChange={(e) => setOnlyPdb(e.target.checked)} />tried</label>
          </div>
          <VList count={shown.length} row={(i) => {
            const x = shown[i];
            const st = statusOf(entries[entryId(x)]);
            return (
              <div className="fn-row" data-selected={m?.name === x.name} onClick={() => setPick(x.name)} title={entries[entryId(x)]?.error}>
                {st.dot ? <span className="dot" data-state={st.dot} /> : <span style={{ width: 7 }} />}
                <span className="grow ellipsis">{x.name}</span>
                <span className="faint" style={{ fontSize: 11 }}>{st.text}</span>
              </div>
            );
          }} />
        </div>
        {m ? <ModulePdb key={m.name + m.base} m={m} /> : <div className="empty"><div className="empty-title">No modules.</div></div>}
      </div>
    </NeedsAgent>
  );
}

function ModulePdb({ m }: { m: Module }) {
  const e = useSymbols((s) => s.entries[entryId(m)]);
  const autoDownload = useSymbols((s) => s.autoDownload);
  const servers = useSymbols((s) => s.servers);
  const [cv, setCv] = useState<CodeViewId | null | undefined>(undefined);
  const [tab, setTab] = useState<"symbols" | "types">("symbols");
  useEffect(() => {
    let live = true;
    void codeviewOf(m).then((c) => live && setCv(c)).catch(() => live && setCv(null));
    return () => { live = false; };
  }, [m.name, m.base]);

  const busy = e?.status === "loading" || e?.status === "downloading";
  const load = (download: boolean, allowMismatch = false) => void attempt("symbols", loadPdb(m, { download, allowMismatch }));
  const unload = () => useSymbols.getState().remove(entryId(m));
  const prog = e?.progress;

  return (
    <div className="list-col" style={{ borderRight: "none" }}>
      <div className="toolbar">
        <span className="panel-title grow ellipsis">{m.name}</span>
        <button className="btn small" disabled={!cv || busy} onClick={() => load(false)} title="symbol path, the image's folder and the cache; never the network"><RefreshCw size={12} /> Load local</button>
        <button className="btn small primary" disabled={!cv || busy} onClick={() => load(true)} title={`look locally, then download from ${servers.join(", ")}`}><CloudDownload size={12} /> Download</button>
        {e?.status === "missing" && e.mismatches?.length ? <button className="btn small" onClick={() => load(false, true)} title="load a PDB of a different build anyway (names may be wrong)">Load other build</button> : null}
        {e?.status === "loaded" && <button className="btn small" onClick={() => void attempt("symbols", loadPdb(m, { applyNames: true }))} title="copy the PDB names into the Names list (exported with the session; views already show them)">Copy names</button>}
        {e && !busy && <IconButton tip="Forget this PDB (copied names stay)" onClick={unload}><X size={14} /></IconButton>}
      </div>
      <div className="kv">
        <span>expects</span>
        <span className="selectable">{cv === undefined ? "reading image…" : cv ? `${cv.pdb}  ·  ${cv.guid} / age ${cv.age}` : "no CodeView (RSDS) entry: the image names no PDB"}</span>
        {cv && <><span>symbol key</span><span className="selectable">{cv.key}</span></>}
        {e?.status === "loaded" && (
          <>
            <span>loaded</span><span className="selectable" title={e.path}>{e.path}</span>
            <span>match</span>
            <span className={e.matched ? "ok" : "warn"}>{e.matched ? `GUID and age match (${e.loadedGuid} / ${e.loadedAge})` : `DIFFERENT BUILD: ${e.loadedGuid} / age ${e.loadedAge}`}</span>
            <span>source</span><span>{e.source}</span>
            <span>contents</span><span>{e.counts ? `${e.counts.symbols} symbols (${e.counts.functions} functions) · ${e.counts.types} type records · ${e.counts.lines} line records in ${e.counts.files} files` : ""}</span>
          </>
        )}
        {(e?.status === "missing" || e?.status === "error") && <><span>{e.status}</span><span className={e.status === "error" ? "danger" : "warn"} style={{ whiteSpace: "normal" }}>{e.error}</span></>}
      </div>
      {e?.status === "downloading" && (
        <div className="panel-section">
          <div className="faint mono ellipsis" style={{ fontSize: 12 }} title={prog?.url}>{prog?.url || "contacting the symbol server…"} · {fmtBytes(prog?.done ?? 0)}{prog?.total ? ` of ${fmtBytes(prog.total)}` : ""}</div>
          <Progress value={prog?.total ? prog.done / prog.total : 0} />
        </div>
      )}
      {e?.tried?.length && e.status !== "loaded" ? (
        <details className="panel-section" style={{ fontSize: 12 }}>
          <summary className="faint">looked in {e.tried.length} places</summary>
          <pre className="code-block" style={{ maxHeight: 160 }}>{e.tried.join("\n")}</pre>
        </details>
      ) : null}
      {!e && cv && (
        <div className="empty">
          <div className="empty-title">No PDB loaded for {m.name}.</div>
          <div className="empty-hint">
            Load local looks in the symbol path, next to the image and in the cache. Download asks {servers.length === 1 ? servers[0] : `${servers.length} symbol servers`} (network access) and caches the file
            in the standard <span className="mono">{"<pdb>/<GUID><age>/<pdb>"}</span> layout.{autoDownload ? " Auto-download is on." : ""}
          </div>
        </div>
      )}
      {e?.status === "loaded" && (
        <>
          <Tabs tabs={[{ id: "symbols", label: `Symbols (${e.symbols.length})` }, { id: "types", label: `Types` }] as const} active={tab} onSelect={setTab} />
          <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
            {tab === "symbols" ? <SymbolList e={e} m={m} /> : <TypeBrowser entry={e} />}
          </div>
        </>
      )}
    </div>
  );
}

function SymbolList({ e, m }: { e: PdbEntry; m: Module }) {
  const ui = useUi();
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<"all" | "function" | "data">("all");
  const base = toBig(m.base);
  const list = useMemo(() => {
    const f = q.toLowerCase();
    return e.symbols.filter((s) => (kind === "all" || s.kind === kind) && (!f || s.name.toLowerCase().includes(f) || (s.mangled ?? "").toLowerCase().includes(f)));
  }, [e.symbols, q, kind]);
  return (
    <>
      <div className="toolbar">
        <label className="search grow"><Search size={13} /><input placeholder={`Search ${e.symbols.length} symbols (name or decorated name)…`} value={q} onChange={(ev) => setQ(ev.target.value)} /></label>
        <div className="segmented">
          {(["all", "function", "data"] as const).map((k) => <button key={k} data-active={kind === k} onClick={() => setKind(k)}>{k}</button>)}
        </div>
        <span className="faint" style={{ fontSize: 12 }}>{list.length}</span>
      </div>
      <VList count={list.length} row={(i) => {
        const s = list[i];
        const a = fmtAddr(base + BigInt(s.rva));
        return (
          <div className="fn-row" data-selected={ui.selected === a} onClick={() => ui.select(a)} onDoubleClick={() => (s.kind === "function" ? ui.goDisasm(a) : ui.goMemory(a))}
            title={`${protoText(s)}${s.mangled ? `\n${s.mangled}` : ""}\ndouble-click: ${s.kind === "function" ? "disassembly" : "memory"}`}>
            <span className="faint" style={{ width: 70 }}>+{s.rva.toString(16)}</span>
            <span className={s.kind === "function" ? "accent ellipsis" : "ellipsis"} style={{ maxWidth: "40%" }}>{s.name}</span>
            <span className="faint ellipsis grow">{s.params ? protoText(s).slice(0, 160) : s.type ?? ""}</span>
            <span className="faint">{s.size ? `0x${s.size.toString(16)}` : ""}</span>
          </div>
        );
      }} />
    </>
  );
}
