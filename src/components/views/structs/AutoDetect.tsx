// Struct auto-detect: dump the object, read a little at every pointer, classify each slot.
import { useState } from "react";
import { X } from "lucide-react";
import { request } from "@/lib/client";
import { readMany } from "@/lib/batch";
import { fmtAddr, toBig, type Module } from "@/lib/hex";
import { readBytes } from "@/lib/memory";
import type { Field } from "@/lib/analysis/struct";
import { guessFields, placeField, pointerTargets, type Guess, type GuessContext, type MapRegion } from "@/lib/analysis/structguess";
import { log } from "@/store/output";
import { CommitInput, IconButton } from "../../ui";

let regionCache: { at: number; regions: MapRegion[] } | null = null;
async function regions(): Promise<MapRegion[]> {
  // the region walk is the slow part; a few seconds of staleness is fine for classification
  if (regionCache && Date.now() - regionCache.at < 5000) return regionCache.regions;
  const r = await request<{ regions: MapRegion[] }>("regions", { max: 20000 }).then((x) => x.regions ?? []).catch(() => []);
  regionCache = { at: Date.now(), regions: r };
  return r;
}

export default function AutoDetect({ base, modules, fields, onApply, onClose }: {
  base: string; modules: Module[]; fields: Field[]; onApply: (f: Field[]) => void; onClose: () => void;
}) {
  const [size, setSize] = useState("0x200");
  const [busy, setBusy] = useState(false);
  const [guesses, setGuesses] = useState<Guess[] | null>(null);

  const run = async () => {
    const n = Number(size);
    if (!Number.isInteger(n) || n < 8 || n > 0x1000) return log("warn", "struct", "auto-detect size must be 8..0x1000");
    setBusy(true);
    try {
      const buf = await readBytes(toBig(base), n & ~7);
      if (!buf) return log("warn", "struct", `cannot read ${base}`);
      const ctx: GuessContext = { modules, regions: await regions() };
      const targets = pointerTargets(buf, ctx);
      const deref = await readMany(targets.map((address) => ({ address, size: 32 }))).catch(() => targets.map(() => null));
      ctx.deref = new Map(targets.flatMap((t, i) => (deref[i] ? [[t, deref[i]!] as const] : [])));
      let g = guessFields(buf, ctx);
      // RTTI resolves the object a vtable pointer sits in (Windows agent only; Linux answers an error)
      const vt = g.filter((x) => x.kind === "vtable");
      if (vt.length) {
        const r = await request<{ results: { success: boolean; name: string }[] }>("rtti_resolve_batch", { addresses: vt.map((x) => fmtAddr(toBig(base) + BigInt(x.offset))) }, true).catch(() => null);
        if (r?.results) {
          ctx.rtti = new Map(vt.flatMap((x, i) => (r.results[i]?.success ? [[x.offset, r.results[i].name] as const] : [])));
          g = guessFields(buf, ctx);
        }
      }
      setGuesses(g);
    } finally {
      setBusy(false);
    }
  };

  const accept = (gs: Guess[]) => {
    let f = fields;
    for (const g of gs) f = placeField(f, g.offset, { type: g.type, name: g.name });
    onApply(f);
  };

  return (
    <div style={{ borderBottom: "1px solid var(--border-soft)" }}>
      <div className="toolbar">
        <span className="panel-title">Auto-detect</span>
        <span className="faint">bytes</span>
        <CommitInput value={size} onCommit={setSize} width={70} />
        <button className="btn small primary" onClick={() => void run()} disabled={busy}>{busy ? "Reading…" : "Analyze"}</button>
        <span className="grow" />
        {guesses && <button className="btn small" onClick={() => accept(guesses.filter((g) => g.kind !== "unknown"))}>Accept all</button>}
        <IconButton tip="Close" onClick={onClose}><X size={14} /></IconButton>
      </div>
      {guesses && (
        <div style={{ maxHeight: 260, overflow: "auto" }}>
          <table className="table mono">
            <colgroup><col style={{ width: 64 }} /><col style={{ width: 70 }} /><col style={{ width: 100 }} /><col /><col style={{ width: 70 }} /></colgroup>
            <thead><tr><th>Offset</th><th>Type</th><th>Kind</th><th>Evidence</th><th /></tr></thead>
            <tbody>
              {guesses.map((g) => (
                <tr key={g.offset}>
                  <td className="faint">{g.offset.toString(16).toUpperCase().padStart(4, "0")}</td>
                  <td>{g.type}</td>
                  <td className={g.kind === "unknown" || g.kind === "zero" ? "faint" : "accent"}>{g.kind}</td>
                  <td className="ellipsis">{g.label}</td>
                  <td><button className="row-action" onClick={() => accept([g])}>accept</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
