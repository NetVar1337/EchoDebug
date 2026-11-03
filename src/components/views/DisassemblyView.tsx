import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeft, Bookmark, Crosshair, Download, Fingerprint, GitBranch, Hammer, Search, Tag } from "lucide-react";
import { request } from "@/lib/client";
import { fmtAddr, hexToBytes, labelAddr, moduleOf, parseAddress, showAddr, toBig } from "@/lib/hex";
import { moduleXrefIndex, pdataFunctions, searchModuleCode, xrefsTo, type CodeHit, type LiveXref } from "@/lib/live";
import { loadImage } from "@/lib/memory";
import { writeJournaled } from "@/lib/patch";
import { saveText } from "@/lib/save";
import { buildIat, ripDisplacement, type IatMap } from "@/lib/analysis/iat";
import { buildExports, type ExportMap } from "@/lib/analysis/exports";
import { operandAddresses, stringAt } from "@/lib/analysis/annotate";
import { assemble, forceJmp, invertJcc, nops } from "@/lib/analysis/asm";
import { resolveSwitch, type JumpTable } from "@/lib/analysis/jumptables";
import { toAsm, toCArray } from "@/lib/analysis/listing";
import type { XrefIndex } from "@/lib/analysis/xrefindex";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { CommitInput, IconButton, NeedsAgent, Progress } from "../ui";
import VList from "../VList";

type Fn = { address: string; size: number; source?: "echo" | "pdata" | "both" };
export type Line = { address: string; length: number; bytes: string; text: string };

const fnCache = new Map<string, Fn[]>();
const kBranch = /^(j[a-z]+|call|loop[a-z]*)$/;

/** IAT symbol for a RIP-relative operand, e.g. `KERNEL32.CreateFileW`. */
function iatSymbol(line: Line, iat: IatMap | null): string | null {
  if (!iat) return null;
  const disp = ripDisplacement(line.text);
  if (disp === null) return null;
  const target = toBig(line.address) + BigInt(line.length) + disp;
  const entry = iat.byAddress.get("0x" + target.toString(16));
  return entry ? `${entry.dll}!${entry.name}` : null;
}

/** Exported symbol for a direct branch, e.g. `CreateFileW`. */
function exportSymbol(line: Line, expMap: ExportMap | null): string | null {
  if (!expMap) return null;
  const m = /\b(call|jmp)\s+(0x[0-9a-f]+)\b/i.exec(line.text);
  if (!m) return null;
  const entry = expMap.byAddress.get("0x" + BigInt(m[2]).toString(16));
  return entry ? entry.name : null;
}

function InsnText({ text, notes, onGo }: { text: string; notes: { cls: string; text: string; title: string }[]; onGo: (a: string) => void }) {
  const sp = text.indexOf(" ");
  const mn = (sp < 0 ? text : text.slice(0, sp)).toLowerCase();
  const ops = sp < 0 ? "" : text.slice(sp);
  const cls = kBranch.test(mn) ? "mn branch" : mn.startsWith("ret") ? "mn ret" : "mn";
  const parts = ops.split(/(0x[0-9a-f]{6,16})/i);
  return (
    <span className="insn-text">
      <span className={cls}>{mn}</span>
      {parts.map((p, i) => (i % 2 === 1 ? <span key={i} className="num link" onDoubleClick={() => onGo(p)} title="double-click to follow">{p}</span> : <span key={i}>{p}</span>))}
      {notes.map((n, i) => <span key={i} className={n.cls} title={n.title}>{n.text}</span>)}
    </span>
  );
}

export default function DisassemblyView() {
  const { modules, target } = useConn();
  const ui = useUi();
  const names = useNames();
  const addBookmark = useWatch((s) => s.addBookmark);
  const mainMod = modules.find((m) => m.base === target?.base)?.name ?? modules[0]?.name ?? "";
  const modName = ui.module && modules.some((m) => m.name === ui.module) ? ui.module : mainMod;
  const mod = modules.find((x) => x.name === modName);
  const [fns, setFns] = useState<Fn[]>([]);
  const [filter, setFilter] = useState("");
  const [lines, setLines] = useState<Line[]>([]);
  const [linear, setLinear] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [xrefs, setXrefs] = useState<{ to: string; list: LiveXref[] } | null>(null);
  const [iat, setIat] = useState<IatMap | null>(null);
  const [expMap, setExports] = useState<ExportMap | null>(null);
  const [img, setImg] = useState<Uint8Array | null>(null);
  const [xidx, setXidx] = useState<XrefIndex | null>(null);
  const [showRefs, setShowRefs] = useState(false);
  const [search, setSearch] = useState("");
  const [hits, setHits] = useState<CodeHit[] | null>(null);
  const [searchProgress, setSearchProgress] = useState(1);
  const searchAbort = useRef({ aborted: false });
  const [patchMenu, setPatchMenu] = useState(false);
  const [tick, setTick] = useState(0);
  const at = ui.disasmAt;

  // The IAT and the export table are per module; load them once so
  // RIP-relative calls show their import and direct calls show their export.
  useEffect(() => {
    if (!mod) return;
    let live = true;
    void loadImage(mod).then((image) => {
      if (!live || !image) return;
      setImg(image);
      try {
        setIat(buildIat(image, toBig(mod.base)));
        setExports(buildExports(image, toBig(mod.base)));
      } catch { /* not a PE image */ }
    }).catch(() => undefined);
    return () => { live = false; };
  }, [mod?.name, mod?.base]);

  useEffect(() => {
    if (!showRefs || !mod) return setXidx(null);
    let live = true;
    void attempt("xrefs", moduleXrefIndex(mod)).then((x) => live && x && setXidx(x));
    return () => { live = false; };
  }, [showRefs, mod?.name, mod?.base]);

  // Echo's function list, merged with the starts the x64 exception directory (.pdata) knows.
  useEffect(() => {
    if (!modName || !mod) return;
    const hit = fnCache.get(modName);
    if (hit) return setFns(hit);
    setFns([]);
    let live = true;
    void (async () => {
      const [echo, pdata] = await Promise.all([
        request<{ results: Fn[] }>("enumerate_functions", { module: modName }).then((r) => r.results).catch(() => [] as Fn[]),
        pdataFunctions(mod).catch(() => []),
      ]);
      const byAddr = new Map<string, Fn>();
      for (const f of echo) byAddr.set(fmtAddr(toBig(f.address)), { ...f, address: fmtAddr(toBig(f.address)), source: "echo" });
      for (const f of pdata) {
        const cur = byAddr.get(f.address);
        byAddr.set(f.address, cur ? { ...cur, size: Math.max(cur.size, f.size), source: "both" } : { ...f, source: "pdata" });
      }
      const merged = [...byAddr.values()].sort((a, b) => (toBig(a.address) < toBig(b.address) ? -1 : 1));
      if (!live) return;
      fnCache.set(modName, merged);
      setFns(merged);
      log("info", "functions", `${merged.length} functions in ${modName} (${echo.length} enumerated, ${pdata.length} from .pdata)`);
    })();
    return () => { live = false; };
  }, [modName, mod?.base]);

  /** The function that contains `at`, from the merged list. */
  const curFn = useMemo(() => {
    if (!at) return null;
    const a = toBig(at);
    let best: Fn | null = null;
    for (const f of fns) {
      const s = toBig(f.address);
      if (s <= a && a < s + BigInt(Math.max(1, f.size))) best = f;
    }
    return best;
  }, [fns, at]);

  useEffect(() => {
    if (!at) return;
    let live = true;
    const size = linear ? 0x600 : curFn && toBig(curFn.address) === toBig(at) && curFn.size > 0 ? Math.min(curFn.size, 0x10000) : 0;
    void attempt("disasm", request<{ results: Line[] }>("disassemble", { address: at, size })).then((r) => {
      if (live && r) setLines(r.results);
    });
    return () => { live = false; };
  }, [at, linear, curFn?.address, tick]);

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

  const selLine = lines.find((l) => l.address === ui.selected) ?? null;

  // --- patching -------------------------------------------------------------------------
  const patchWith = async (l: Line, bytes: Uint8Array, note: string) => {
    if (bytes.length > l.length) {
      const ok = window.confirm(`The patch is ${bytes.length} bytes but the instruction is ${l.length}. Overwrite the following instructions too? (the remainder of the last one is NOP-filled)`);
      if (!ok) return;
      let covered = 0;
      for (const x of lines.slice(lines.indexOf(l))) {
        covered += x.length;
        if (covered >= bytes.length) break;
      }
      const padded = new Uint8Array(covered);
      padded.set(bytes);
      padded.set(nops(covered - bytes.length), bytes.length);
      bytes = padded;
    } else if (bytes.length < l.length) {
      const padded = new Uint8Array(l.length);
      padded.set(bytes);
      padded.set(nops(l.length - bytes.length), bytes.length);
      bytes = padded;
    }
    if (await writeJournaled(toBig(l.address), bytes, note)) {
      log("info", "patch", `${note} at ${labelAddr(l.address, modules)} (${bytes.length} bytes)`);
      setTick((t) => t + 1);
    }
  };
  const doAssemble = async () => {
    if (!selLine) return log("warn", "patch", "select an instruction first");
    const src = window.prompt(`Assemble at ${labelAddr(selLine.address, modules)} (';' separates instructions; branch targets are absolute)`, selLine.text);
    if (!src) return;
    try {
      await patchWith(selLine, assemble(src, toBig(selLine.address)), `asm: ${src}`);
    } catch (e) {
      log("error", "patch", String(e instanceof Error ? e.message : e));
    }
  };
  const doNop = () => selLine && void patchWith(selLine, nops(selLine.length), "nop");
  const doInvert = () => {
    if (!selLine) return;
    const b = invertJcc(hexToBytes(selLine.bytes));
    if (!b) return log("warn", "patch", "not a conditional jump");
    void patchWith(selLine, b, "invert jcc");
  };
  const doForce = () => {
    if (!selLine) return;
    const b = forceJmp(hexToBytes(selLine.bytes), toBig(selLine.address));
    if (!b) return log("warn", "patch", "not a conditional jump");
    void patchWith(selLine, b, "jcc → jmp");
  };

  // --- export ---------------------------------------------------------------------------
  const exportAsm = async (kind: "asm" | "c") => {
    if (!lines.length) return;
    const title = `${labelAddr(lines[0].address, modules)} (${names.nameOf(lines[0].address) || "listing"})`;
    const text = kind === "asm"
      ? toAsm(lines, { title, nameOf: names.nameOf, commentOf: names.commentOf, label: (a) => labelAddr(a, modules) })
      : toCArray(lines, (names.nameOf(lines[0].address) || `sub_${toBig(lines[0].address).toString(16)}`).replace(/\W/g, "_"));
    await saveText(`${toBig(lines[0].address).toString(16)}.${kind === "asm" ? "asm" : "h"}`, text);
  };

  // --- search ---------------------------------------------------------------------------
  const runModuleSearch = async () => {
    if (!mod || !search.trim()) return;
    let re: RegExp;
    try { re = new RegExp(search, "i"); } catch (e) { return log("warn", "search", String(e)); }
    searchAbort.current = { aborted: false };
    setHits([]);
    setSearchProgress(0);
    const found = await attempt("search", searchModuleCode(mod, re, { onProgress: setSearchProgress, signal: searchAbort.current }));
    setSearchProgress(1);
    setHits(found ?? []);
    log("info", "search", `${found?.length ?? 0} instructions in ${mod.name} match /${search}/`);
  };
  const listingMatches = useMemo(() => {
    if (!search.trim()) return new Set<string>();
    try {
      const re = new RegExp(search, "i");
      return new Set(lines.filter((l) => re.test(l.text) || re.test(l.address)).map((l) => l.address));
    } catch { return new Set<string>(); }
  }, [search, lines]);
  const nextMatch = (dir: 1 | -1) => {
    const list = lines.filter((l) => listingMatches.has(l.address));
    if (!list.length) return;
    const cur = lines.findIndex((l) => l.address === ui.selected);
    const pick = dir === 1 ? list.find((l) => lines.indexOf(l) > cur) ?? list[0] : [...list].reverse().find((l) => lines.indexOf(l) < cur) ?? list[list.length - 1];
    ui.select(pick.address);
  };

  // --- annotations ----------------------------------------------------------------------
  const base = mod ? toBig(mod.base) : 0n;
  const switches = useMemo(() => {
    const out = new Map<string, JumpTable>();
    if (!img || !mod) return out;
    lines.forEach((l, i) => {
      if (/^jmp/i.test(l.text) && !/0x[0-9a-f]+$/i.test(l.text.trim())) {
        const t = resolveSwitch(lines, i, img, base);
        if (t) out.set(l.address, t);
      }
    });
    return out;
  }, [lines, img, mod?.base]);
  const notesFor = (l: Line) => {
    const notes: { cls: string; text: string; title: string }[] = [];
    const exp = exportSymbol(l, expMap);
    if (exp) notes.push({ cls: "iat-symbol", text: exp, title: "exported symbol" });
    const imp = iatSymbol(l, iat);
    if (imp) notes.push({ cls: "iat-symbol", text: imp, title: "resolved import" });
    if (img && mod && !imp) {
      for (const a of operandAddresses(l.text, toBig(l.address), l.length)) {
        if (a < base || a >= base + BigInt(img.length)) continue;
        const s = stringAt(img, Number(a - base));
        if (s) {
          notes.push({ cls: "insn-string", text: s, title: `string at ${labelAddr(a, modules)}` });
          break;
        }
      }
    }
    const sw = switches.get(l.address);
    if (sw) notes.push({ cls: "iat-symbol", text: `switch · ${sw.count} cases`, title: `${sw.kind} jump table at ${labelAddr(sw.table, modules)}: ${sw.targets.slice(0, 16).map((t) => labelAddr(t, modules)).join(", ")}${sw.count > 16 ? " …" : ""}` });
    if (xidx && mod) {
      const refs = xidx.to.get(Number(toBig(l.address) - base))?.length ?? 0;
      if (refs) notes.push({ cls: "insn-refs", text: `↑${refs}`, title: `${refs} references (X lists them)` });
    }
    return notes;
  };

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
      if (e.altKey && e.key === "ArrowLeft") back();
      if (typing) return;
      if (e.key === "x") void findRefs();
      if (e.key === "a" && selLine) void doAssemble();
      if (e.key === "F3") nextMatch(e.shiftKey ? -1 : 1);
      if (e.key === "n") {
        const addr = ui.selected ?? at;
        if (!addr) return;
        const cur = names.nameOf(addr);
        const next = window.prompt("Name", cur);
        if (next !== null) names.rename(addr, next);
      }
      if (e.key === ";") {
        const addr = ui.selected ?? at;
        if (!addr) return;
        const cur = names.commentOf(addr);
        const next = window.prompt("Comment", cur);
        if (next !== null) names.comment(addr, next);
      }
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
    return f ? fns.filter((fn) => fn.address.toLowerCase().includes(f) || labelAddr(fn.address, modules).toLowerCase().includes(f) || names.nameOf(fn.address).toLowerCase().includes(f)) : fns;
  }, [fns, filter, modules, names]);
  const fnIndex = useMemo(() => (at ? shown.findIndex((f) => toBig(f.address) === toBig(at)) : -1), [shown, at]);
  const isJcc = selLine ? /^j(?!mp)[a-z]+\s/i.test(selLine.text) : false;

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
            const user = names.nameOf(f.address);
            return (
              <div className="fn-row" data-selected={i === fnIndex} onClick={() => go(f.address)} title={f.source === "pdata" ? "from the exception directory (.pdata)" : undefined}>
                <span className={user ? "accent" : undefined}>{user || `sub_${showAddr(f.address).replace(/^0+/, "")}`}</span>
                <span className="faint">{f.source === "pdata" ? "·" : ""}{f.size}</span>
              </div>
            );
          }} />
        </div>
        <div className="list-col" style={{ borderRight: "none" }}>
          <div className="toolbar">
            <IconButton tip="Back (Alt+←)" onClick={back} disabled={history.length === 0}><ArrowLeft size={14} /></IconButton>
            <CommitInput value={at ?? ""} placeholder="address · module+0x…  (Ctrl+G)" onCommit={go} width={220} />
            <span className="mono faint ellipsis grow">{at ? labelAddr(at, modules) : ""} · {lines.length} insns</span>
            <label className="row" style={{ fontSize: 12 }}><input type="checkbox" checked={linear} onChange={(e) => setLinear(e.target.checked)} />linear</label>
            <label className="row" style={{ fontSize: 12 }} title="show how many references point at each instruction"><input type="checkbox" checked={showRefs} onChange={(e) => setShowRefs(e.target.checked)} />refs</label>
            <IconButton tip="Xrefs to selection (X)" onClick={() => void findRefs()}><Crosshair size={14} /></IconButton>
            <IconButton tip="Control-flow graph" onClick={() => at && ui.set({ tab: "cfg" })} disabled={!at}><GitBranch size={14} /></IconButton>
            <IconButton tip="Make signature" onClick={() => ui.goSig(ui.selected ?? at ?? "")} disabled={!at}><Fingerprint size={14} /></IconButton>
            <div style={{ position: "relative" }}>
              <IconButton tip="Patch selection (A assembles)" onClick={() => setPatchMenu(!patchMenu)} disabled={!selLine}><Hammer size={14} /></IconButton>
              {patchMenu && selLine && (
                <div className="menu-pop" onMouseLeave={() => setPatchMenu(false)}>
                  <button className="menu-item" onClick={() => { setPatchMenu(false); void doAssemble(); }}>Assemble…</button>
                  <button className="menu-item" onClick={() => { setPatchMenu(false); doNop(); }}>NOP instruction ({selLine.length} B)</button>
                  <button className="menu-item" disabled={!isJcc} onClick={() => { setPatchMenu(false); doInvert(); }}>Invert condition</button>
                  <button className="menu-item" disabled={!isJcc} onClick={() => { setPatchMenu(false); doForce(); }}>Make unconditional</button>
                </div>
              )}
            </div>
            <IconButton tip="Rename (N)" onClick={() => {
              const addr = ui.selected ?? at;
              if (!addr) return;
              const next = window.prompt("Name", names.nameOf(addr));
              if (next !== null) names.rename(addr, next);
            }} disabled={!at}><Tag size={14} /></IconButton>
            <IconButton tip="Bookmark" onClick={() => at && addBookmark(ui.selected ?? at)} disabled={!at}><Bookmark size={14} /></IconButton>
            <IconButton tip="Export listing as .asm (shift: C array)" onClick={(e) => void exportAsm(e.shiftKey ? "c" : "asm")} disabled={!lines.length}><Download size={14} /></IconButton>
          </div>
          <div className="toolbar">
            <label className="search grow"><Search size={13} /><input placeholder="Search: regex over this listing (F3 next) or the whole module" value={search} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") nextMatch(e.shiftKey ? -1 : 1); }} /></label>
            <span className="faint" style={{ fontSize: 12 }}>{search ? `${listingMatches.size} here` : ""}</span>
            <button className="btn small" disabled={!search.trim() || !mod} onClick={() => void runModuleSearch()}>Search module</button>
            {searchProgress < 1 && <button className="btn small" onClick={() => { searchAbort.current.aborted = true; }}>Stop</button>}
          </div>
          {searchProgress < 1 && <Progress value={searchProgress} />}
          {!at ? (
            <div className="empty"><div className="empty-title">Pick a function or press Ctrl+G.</div></div>
          ) : (
            <VList className="vlist listing" count={lines.length} row={(i) => {
              const l = lines[i];
              const cmt = names.commentOf(l.address);
              const nm = names.nameOf(l.address);
              return (
                <div className="insn-row" data-selected={ui.selected === l.address} data-match={listingMatches.has(l.address)} onClick={() => ui.select(l.address)}>
                  <span className="insn-va">{showAddr(l.address)}</span>
                  <span className="insn-bytes">{l.bytes.replace(/(..)/g, "$1 ").trim()}</span>
                  <InsnText text={l.text} notes={notesFor(l)} onGo={go} />
                  {nm && i > 0 && <span className="insn-comment accent">{nm}:</span>}
                  {cmt && <span className="insn-comment" title={cmt}>{cmt}</span>}
                </div>
              );
            }} />
          )}
          {hits && (
            <div style={{ maxHeight: 200, overflow: "auto", borderTop: "1px solid var(--border-soft)" }}>
              <div className="toolbar"><span className="panel-title">{hits.length} matches for /{search}/ in {modName}</span><span className="grow" /><button className="row-action" onClick={() => setHits(null)}>close</button></div>
              <table className="table mono"><tbody>
                {hits.map((h) => <tr key={h.address} onClick={() => { go(h.address); ui.select(h.address); }}><td className="link">{labelAddr(h.address, modules)}</td><td>{h.text}</td></tr>)}
              </tbody></table>
            </div>
          )}
          {xrefs && (
            <div style={{ maxHeight: 180, overflow: "auto", borderTop: "1px solid var(--border-soft)" }}>
              <div className="toolbar"><span className="panel-title">Xrefs to {labelAddr(xrefs.to, modules)}</span><span className="grow" /><button className="row-action" onClick={() => setXrefs(null)}>close</button></div>
              <table className="table"><tbody>
                {xrefs.list.map((x) => {
                  const a = fmtAddr(x.address);
                  return <tr key={x.rva} onClick={() => go(a)}><td className="mono link">{labelAddr(a, modules)}</td><td className="faint">{x.kind}</td><td className="faint">{moduleOf(x.address, modules)?.name}</td></tr>;
                })}
              </tbody></table>
            </div>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
