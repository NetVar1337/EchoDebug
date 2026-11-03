// Structs → "Import from PDB": the type browser of a loaded PDB; importing adds the type (and the
// structs it embeds) to the catalog and opens it in the editor.
import { useState } from "react";
import { X } from "lucide-react";
import { useSymbols } from "@/store/symbols";
import { useUi } from "@/store/ui";
import { IconButton } from "../../ui";
import TypeBrowser from "../symbols/TypeBrowser";

export default function PdbImport({ onImported, onClose }: { onImported: (id: string) => void; onClose: () => void }) {
  const ui = useUi();
  const entries = useSymbols((s) => s.entries);
  const loaded = Object.values(entries).filter((e) => e.status === "loaded" && e.counts?.types);
  const [pick, setPick] = useState("");
  const e = loaded.find((x) => x.id === pick) ?? loaded[0];
  return (
    <div style={{ borderBottom: "1px solid var(--border-soft)" }}>
      <div className="toolbar">
        <span className="panel-title">Import from PDB</span>
        {loaded.length > 0 && (
          <select className="select" value={e?.id ?? ""} onChange={(ev) => setPick(ev.target.value)}>
            {loaded.map((x) => <option key={x.id} value={x.id}>{x.module} · {x.pdb}</option>)}
          </select>
        )}
        <span className="grow" />
        <IconButton tip="Close" onClick={onClose}><X size={14} /></IconButton>
      </div>
      {e ? (
        <div style={{ height: 300 }}><TypeBrowser entry={e} compact onImported={onImported} /></div>
      ) : (
        <div className="panel-section faint">
          No PDB with type information is loaded. <button className="row-action" onClick={() => ui.setTab("symbols")}>Open Symbols →</button>
        </div>
      )}
    </div>
  );
}
