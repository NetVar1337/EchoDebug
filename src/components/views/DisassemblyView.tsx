import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowLeft, Bookmark, Crosshair, Fingerprint, Search } from "lucide-react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress, showAddr, toBig } from "@/lib/hex";
import { xrefsTo, type LiveXref } from "@/lib/live";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { CommitInput, IconButton, NeedsAgent } from "../ui";
import VList from "../VList";

type Fn = { address: string; size: number };
export type Line = { address: string; length: number; bytes: string; text: string };

const fnCache = new Map<string, Fn[]>();
const kBranch = /^(j[a-z]+|call|loop[a-z]*)$/;

function InsnText({ text, onGo }: { text: string; onGo: (a: string) => void }) {
  const sp = text.indexOf(" ");
  const mn = (sp < 0 ? text : text.slice(0, sp)).toLowerCase();
  const ops = sp < 0 ? "" : text.slice(sp);
  const cls = kBranch.test(mn) ? "mn branch" : mn.startsWith("ret") ? "mn ret" : "mn";
  const parts = ops.split(/(0x[0-9a-f]{6,16})/i);
  return (
    <span className="insn-text">
      <span className={cls}>{mn}</span>
      {parts.map((p, i) => (i % 2 === 1 ? <span key={i} className="num link" onDoubleClick={() => onGo(p)} title="double-click to follow">{p}</span> : <span key={i}>{p}</span>))}
    </span>
  );
}

export default function DisassemblyView() {
  const { modules, target } = useConn();
  const ui = useUi();
  const addBookmark = useWatch((s) => s.addBookmark);
  const mainMod = modules.find((m) => m.base === target?.base)?.name ?? modules[0]?.name ?? "";
  const modName = ui.module && modules.some((m) => m.name === ui.module) ? ui.module : mainMod;
  const [fns, setFns] = useState<Fn[]>([]);
  const [filter, setFilter] = useState("");
  const [lines, setLines] = useState<Line[]>([]);
  const [linear, setLinear] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [xrefs, setXrefs] = useState<{ to: string; list: LiveXref[] } | null>(null);
  const at = ui.disasmAt;

  useEffect(() => {
    if (!modName) return;
    const hit = fnCache.get(modName);
    if (hit) return setFns(hit);
    setFns([]);
    void attempt("functions", request<{ results: Fn[] }>("enumerate_functions", { module: modName })).then((r) => {
      if (!r) return;
      fnCache.set(modName, r.results);
      setFns(r.results);
      log("info", "functions", `${r.results.length} functions in ${modName}`);
    });
  }, [modName]);

  useEffect(() => {
    if (!at) return;
    let live = true;
    void attempt("disasm", request<{ results: Line[] }>("disassemble", { address: at, size: linear ? 0x600 : 0 })).then((r) => {
      if (live && r) setLines(r.results);
    });
    return () => { live = false; };
  }, [at, linear]);

  const go = useCallback((a: string) => {
    const v = parseAddress(a, modules);
    if (v === null) return log("warn", "disasm", `cannot parse ${a}`);
    if (at) setHistory((h) => [...h.slice(-63), at]);
    ui.goDisasm(fmtAddr(v));
  }, [at, modules, ui]);

  const back = () => {
    const prev = history[history.length - 1];
    if (!prev) return;
    setHistory(history.slice(0, -1));
    ui.goDisasm(prev);
  };

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.altKey && e.key === "ArrowLeft") back();
      if (e.key === "x" && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement)) void findRefs();
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  });

  const findRefs = async () => {
    const sel = ui.selected ?? at;
    if (!sel) return;
    const list = await attempt("xrefs", xrefsTo(sel, modules));
    if (!list) return;
    setXrefs({ to: sel, list });
    log("info", "xrefs", `${list.length} references to ${labelAddr(sel, modules)}`);
  };

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return f ? fns.filter((fn) => fn.address.toLowerCase().includes(f) || labelAddr(fn.address, modules).toLowerCase().includes(f)) : fns;
  }, [fns, filter, modules]);
  const fnIndex = useMemo(() => (at ? shown.findIndex((f) => toBig(f.address) === toBig(at)) : -1), [shown, at]);

  return (
    <NeedsAgent>
      <div className="split-h">
        <div className="list-col">
          <div className="toolbar">
            <select className="select grow" value={modName} onChange={(e) => ui.set({ module: e.target.value })}>
              {modules.map((m) => <option key={m.base}>{m.name}</option>)}
            </select>
          </div>
          <div className="toolbar">
            <label className="search grow"><Search size={13} /><input placeholder={`Filter ${fns.length} functions…`} value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
          </div>
          <VList count={shown.length} scrollTo={fnIndex} row={(i) => {
            const f = shown[i];
            return (
              <div className="fn-row" data-selected={i === fnIndex} onClick={() => go(f.address)}>
                <span>sub_{showAddr(f.address).replace(/^0+/, "")}</span>
                <span className="faint">{f.size}</span>
              </div>
            );
          }} />
        </div>
        <div className="list-col" style={{ borderRight: "none" }}>
          <div className="toolbar">
            <IconButton tip="Back (Alt+←)" onClick={back} disabled={history.length === 0}><ArrowLeft size={14} /></IconButton>
            <CommitInput value={at ?? ""} placeholder="address · module+0x…  (Ctrl+G)" onCommit={go} width={260} />
            <span className="mono faint ellipsis grow">{at ? labelAddr(at, modules) : ""} · {lines.length} insns</span>
            <label className="row" style={{ fontSize: 12 }}><input type="checkbox" checked={linear} onChange={(e) => setLinear(e.target.checked)} />linear</label>
            <IconButton tip="Xrefs to selection (X)" onClick={() => void findRefs()}><Crosshair size={14} /></IconButton>
            <IconButton tip="Make signature" onClick={() => ui.goSig(ui.selected ?? at ?? "")} disabled={!at}><Fingerprint size={14} /></IconButton>
            <IconButton tip="Bookmark" onClick={() => at && addBookmark(ui.selected ?? at)} disabled={!at}><Bookmark size={14} /></IconButton>
          </div>
          {!at ? (
            <div className="empty"><div className="empty-title">Pick a function or press Ctrl+G.</div></div>
          ) : (
            <VList className="vlist listing" count={lines.length} row={(i) => {
              const l = lines[i];
              return (
                <div className="insn-row" data-selected={ui.selected === l.address} onClick={() => ui.select(l.address)}>
                  <span className="insn-va">{showAddr(l.address)}</span>
                  <span className="insn-bytes">{l.bytes.replace(/(..)/g, "$1 ").trim()}</span>
                  <InsnText text={l.text} onGo={go} />
                </div>
              );
            }} />
          )}
          {xrefs && (
            <div style={{ maxHeight: 180, overflow: "auto", borderTop: "1px solid var(--border-soft)" }}>
              <div className="toolbar"><span className="panel-title">Xrefs to {labelAddr(xrefs.to, modules)}</span><span className="grow" /><button className="row-action" onClick={() => setXrefs(null)}>close</button></div>
              <table className="table"><tbody>
                {xrefs.list.map((x) => {
                  const a = fmtAddr(x.address);
                  return <tr key={x.rva} onClick={() => go(a)}><td className="mono link">{labelAddr(a, modules)}</td><td className="faint">{x.kind}</td></tr>;
                })}
              </tbody></table>
            </div>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
