// Searchable list of the PDB's structs / classes / unions / enums / typedefs with a C preview of the
// selected one; "Import" turns it (and the structs it embeds) into Structs catalog entries.
import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { importPdbType, pdbType, pdbTypes, type PdbTypeRow } from "@/lib/pdb";
import { pdbDecl, type PdbLayout } from "@/lib/analysis/pdbtypes";
import { attempt, log } from "@/store/output";
import type { PdbEntry } from "@/store/symbols";
import { useUi } from "@/store/ui";
import { copy } from "../../ui";
import VList from "../../VList";

export default function TypeBrowser({ entry, onImported, compact = false }: { entry: PdbEntry; onImported?: (id: string) => void; compact?: boolean }) {
  const ui = useUi();
  const [filter, setFilter] = useState("");
  const [rows, setRows] = useState<{ total: number; types: PdbTypeRow[] } | null>(null);
  const [sel, setSel] = useState<PdbTypeRow | null>(null);
  const [layout, setLayout] = useState<(PdbLayout & { text: string }) | null>(null);
  const [nested, setNested] = useState(true);
  const [err, setErr] = useState("");

  useEffect(() => {
    let live = true;
    const t = setTimeout(() => {
      void pdbTypes(entry, filter.trim(), 3000).then((r) => live && setRows(r)).catch((e) => live && setErr(String(e instanceof Error ? e.message : e)));
    }, 180);
    return () => { live = false; clearTimeout(t); };
  }, [entry.path, filter]);

  useEffect(() => {
    setLayout(null);
    setErr("");
    if (!sel) return;
    let live = true;
    void pdbType(entry, { index: sel.index }).then((l) => live && setLayout(l)).catch((e) => live && setErr(String(e instanceof Error ? e.message : e)));
    return () => { live = false; };
  }, [sel?.index, entry.path]);

  const decl = useMemo(() => (layout ? [pdbDecl(layout), ...(layout.nested ?? []).map(pdbDecl)].join("\n\n") : ""), [layout]);

  const doImport = async () => {
    if (!sel) return;
    const r = await attempt("structs", importPdbType(entry, { index: sel.index }, { nested }));
    if (!r) return;
    log("info", "structs", `imported ${r.imported.join(", ")} from ${entry.pdb}`);
    if (onImported) onImported(r.id);
    else {
      ui.set({ structTypeId: r.id });
      ui.setTab("structs");
    }
  };

  const list = rows?.types ?? [];
  return (
    <div className="split-h" style={{ gridTemplateColumns: compact ? "200px minmax(0, 1fr)" : "280px minmax(0, 1fr)", height: "100%" }}>
      <div className="list-col">
        <div className="toolbar">
          <label className="search grow"><Search size={13} /><input placeholder={`Filter ${rows ? rows.total : "…"} types…`} value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
        </div>
        {rows && rows.total > list.length && <div className="faint" style={{ padding: "2px 10px", fontSize: 11 }}>showing {list.length} of {rows.total}, narrow the filter</div>}
        <VList count={list.length} row={(i) => {
          const t = list[i];
          return (
            <div className="fn-row" data-selected={sel?.index === t.index && sel.name === t.name} onClick={() => setSel(t)} title={t.target ? `typedef ${t.target}` : undefined}>
              <span className="grow ellipsis">{t.name}</span>
              <span className="faint">{t.kind === "typedef" ? "td" : t.kind}</span>
              <span className="faint">{t.size ? `0x${t.size.toString(16)}` : ""}</span>
            </div>
          );
        }} />
      </div>
      <div className="list-col" style={{ borderRight: "none" }}>
        <div className="toolbar">
          <span className="panel-title grow ellipsis">{sel ? `${sel.name}${layout ? ` · ${layout.kind} · 0x${layout.size.toString(16)} bytes${layout.nested?.length ? ` · ${layout.nested.length} nested` : ""}` : ""}` : "Pick a type"}</span>
          <label className="row" title="also add every struct/union it embeds by value"><input type="checkbox" checked={nested} onChange={(e) => setNested(e.target.checked)} />nested</label>
          <button className="btn small primary" disabled={!layout || layout.kind === "enum"} onClick={() => void doImport()} title="add to the Structs catalog: embedded structs are flattened (pos.x), float triples become vec3, bitfields share their storage field">Import to Structs</button>
          <button className="btn small" disabled={!decl} onClick={() => void copy(decl)}>Copy C</button>
        </div>
        {err ? <div className="panel-section danger">{err}</div> : layout ? <pre className="code-block" style={{ flex: 1 }}>{decl}</pre> : <div className="empty"><div className="empty-hint">Structs, classes, unions and enums of {entry.pdb}. Pick one to see its layout with offsets; typedefs resolve to what they name.</div></div>}
      </div>
    </div>
  );
}
