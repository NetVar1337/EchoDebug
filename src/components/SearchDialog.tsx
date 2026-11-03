// Ctrl+Shift+F: one box over names, comments, bookmarks, signatures, struct types, module
// exports and already-extracted strings. Grouped, fuzzy-ranked, keyboard driven; Enter jumps.
import { useEffect, useMemo, useRef, useState } from "react";
import { useUi } from "@/store/ui";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { flatten, highlight, searchAll, type Ranked } from "@/lib/search";
import { collectItems, extractAllStrings, loadExports, stringModules } from "@/lib/searchsources";
import { Progress } from "./ui";

export default function SearchDialog() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const mem = useConn((s) => s.mem);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [gen, setGen] = useState(0); // bumps when a cache fills
  const [exportsN, setExportsN] = useState<number | null>(null);
  const [strProgress, setStrProgress] = useState<number | null>(null);
  const abort = useRef({ aborted: false });
  const listRef = useRef<HTMLDivElement>(null);
  const close = () => { abort.current.aborted = true; ui.set({ searchOpen: false }); };

  // exports are cheap (header page + export directory per module): index them on open
  useEffect(() => {
    if (!mem || !modules.length) return;
    let live = true;
    void loadExports(modules).then((n) => { if (live) { setExportsN(n); setGen((g) => g + 1); } }).catch(() => undefined);
    return () => { live = false; };
  }, [modules, mem]);

  const items = useMemo(() => collectItems(modules), [modules, gen]);
  const groups = useMemo(() => searchAll(items, q, 8), [items, q]);
  const flat = useMemo(() => flatten(groups), [groups]);
  useEffect(() => setSel(0), [q]);
  useEffect(() => { listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: "nearest" }); }, [sel]);

  const jump = (r: Ranked) => {
    const { item } = r;
    close();
    switch (item.kind) {
      case "type":
      case "field":
        ui.set({ structType: item.ref ?? null });
        ui.setTab("structs");
        return;
      case "module":
        if (item.ref) ui.goModule(item.ref, "pe");
        return;
      case "signature":
        if (item.address) ui.goSig(item.address);
        else ui.setTab("signatures");
        return;
      case "string":
        if (item.address) ui.goMemory(item.address);
        return;
      case "bookmark":
        if (item.address) (item.ref === "watch" ? ui.goMemory : ui.goDisasm)(item.address);
        return;
      default:
        if (item.address) ui.goDisasm(item.address);
    }
  };

  const scanStrings = async () => {
    abort.current = { aborted: false };
    setStrProgress(0);
    const n = await extractAllStrings(modules, (d, t) => setStrProgress(d / t), abort.current).catch((e) => { log("error", "search", String(e)); return 0; });
    setStrProgress(null);
    setGen((g) => g + 1);
    log("info", "search", `indexed ${n} strings from ${stringModules()} modules`);
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") close();
    else if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(flat.length - 1, s + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
    else if (e.key === "PageDown") { e.preventDefault(); setSel((s) => Math.min(flat.length - 1, s + 8)); }
    else if (e.key === "PageUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 8)); }
    else if (e.key === "Enter" && flat[sel]) { e.preventDefault(); jump(flat[sel]); }
  };

  let i = -1;
  return (
    <div className="modal-scrim" onMouseDown={(e) => e.target === e.currentTarget && close()}>
      <div className="modal palette search-dialog" role="dialog" aria-label="Search everything">
        <input autoFocus className="palette-input" placeholder="Search names, comments, bookmarks, signatures, types, exports, strings…" value={q} spellCheck={false} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} />
        <div className="palette-list" ref={listRef}>
          {!q.trim() && <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>Type to search. Several words must all match; an address finds the items at it.</div>}
          {q.trim() && flat.length === 0 && <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>Nothing matches.</div>}
          {groups.map((g) => (
            <div key={g.kind}>
              <div className="palette-group">{g.label}{g.total > g.results.length ? <span className="faint"> · {g.total} matches, best {g.results.length} shown</span> : null}</div>
              {g.results.map((r) => {
                i++;
                const k = i;
                return (
                  <button key={`${g.kind}:${k}`} className="palette-item" data-active={k === sel} onMouseEnter={() => setSel(k)} onClick={() => jump(r)}>
                    <span className="grow ellipsis mono">{highlight(r.item.text, r.hits).map((p, j) => (p.hit ? <b key={j} className="accent">{p.s}</b> : <span key={j}>{p.s}</span>))}</span>
                    {r.item.detail && <span className="faint ellipsis mono" style={{ maxWidth: "45%" }}>{r.item.detail}</span>}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
        <div className="search-foot faint">
          <span>{exportsN === null ? (mem ? "indexing exports…" : "attach to search exports") : `${exportsN} exports`} · strings of {stringModules()} module{stringModules() === 1 ? "" : "s"}</span>
          <span className="grow" />
          {strProgress !== null ? (
            <span className="row" style={{ width: 200 }}><Progress value={strProgress} /><button className="btn small" onClick={() => { abort.current.aborted = true; }}>Stop</button></span>
          ) : (
            <button className="btn small" disabled={!mem || !modules.length} title="Reads every module image once and extracts its strings (can take a while for big targets)" onClick={() => void scanStrings()}>Search strings in all modules</button>
          )}
          <span>↑↓ · Enter · Esc</span>
        </div>
      </div>
    </div>
  );
}
