// Game tab — one-click offset recovery for Apex Legends / Respawn-Source builds.
//
// Everything here is signature-free: after an update the code (and so every byte pattern)
// moves, but member-name strings and descriptor-table structures survive. The pipeline
// re-derives the full netvar dump from those anchors, then locates the globals that have no
// name to anchor on (entity list, view matrix) with structural scans. The last scan is kept
// per module so a build change is flagged and canaries show what moved.
import { useEffect, useState } from "react";
import { fmtAddr, toBig, type Module } from "@/lib/hex";
import { loadImage, readBytes } from "@/lib/memory";
import { readMany } from "@/lib/batch";
import { parsePe } from "@/lib/analysis/pe";
import { enumerateNetvars, findEntityList, findViewMatrix, offsetMap, type ApexTable, type EntityListHit } from "@/lib/analysis/engines/apex";
import { kRespawnPresetFields } from "@/lib/analysis/engines/respawn";
import { saveText } from "@/lib/save";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { NeedsAgent, Progress } from "../ui";

type Scan = {
  build: number;
  ts: number;
  tables: ApexTable[];
  entries: number;
  confirmed: number;
  canaries: Record<string, number | null>;
  entityList: EntityListHit[];
  viewMatrix: bigint | null;
};

const storeKey = (m: Module) => `echodebug.game.${m.name}`;

function loadStored(m: Module): Scan | null {
  try {
    const raw = localStorage.getItem(storeKey(m));
    return raw ? (JSON.parse(raw) as Scan) : null;
  } catch {
    return null;
  }
}

export default function GameView() {
  const modules = useConn((s) => s.modules);
  const target = useConn((s) => s.target);
  const main = modules.find((m) => m.base === target?.base) ?? [...modules].sort((a, b) => b.size - a.size)[0];
  const [busy, setBusy] = useState("");
  const [progress, setProgress] = useState(1);
  const [scan, setScan] = useState<Scan | null>(main ? loadStored(main) : null);
  const [filter, setFilter] = useState("");
  const [budget, setBudget] = useState("32");

  useEffect(() => {
    setScan(main ? loadStored(main) : null);
  }, [main?.name, main?.size]); // eslint-disable-line react-hooks/exhaustive-deps

  const stored = main ? loadStored(main) : null;
  const buildChanged = !!main && stored !== null && scan !== null && stored.build !== main.size;
  const read = (addr: bigint, size: number) => readBytes(addr, size);
  const batch = (reads: { addr: bigint; size: number }[]) => readMany(reads.map((r) => ({ address: fmtAddr(r.addr), size: r.size })));

  const runScan = async (what: "netvars" | "entitylist" | "viewmatrix" | "all") => {
    if (!main) return;
    setBusy(what);
    setProgress(0);
    const prev = loadStored(main);
    const result = await attempt(`game ${what}`, (async () => {
      const img = await loadImage(main);
      const pe = parsePe(img);
      const base = toBig(main.base);
      const next: Scan = {
        build: main.size,
        ts: Date.now(),
        tables: scan?.tables ?? [],
        entries: scan?.entries ?? 0,
        confirmed: scan?.confirmed ?? 0,
        canaries: scan?.canaries ?? {},
        entityList: scan?.entityList ?? [],
        viewMatrix: scan?.viewMatrix ?? null,
      };
      if (what === "netvars" || what === "all") {
        const s = enumerateNetvars(img, base, pe);
        const map = offsetMap(s);
        next.tables = s.tables;
        next.entries = s.entries;
        next.confirmed = s.confirmed;
        next.canaries = Object.fromEntries(kRespawnPresetFields.map((n) => [n, map.get(n) ?? null]));
        log("info", "game", `${s.tables.length} tables, ${s.entries} entries (${s.confirmed} confirmed) in ${main.name}`);
      }
      const wsects = pe.sections.filter((s) => s.w && !s.x && s.vsize > 0).map((s) => ({ addr: base + BigInt(s.rva), size: s.vsize }));
      const rsects = pe.sections.filter((s) => !s.x && !s.w && s.vsize > 0).map((s) => ({ addr: base + BigInt(s.rva), size: s.vsize }));
      const mb = Number(budget) || 32;
      if (what === "entitylist" || what === "all") {
        next.entityList = await findEntityList(read, batch, wsects, rsects, { budgetBytes: mb * 1024 * 1024 });
        log("info", "game", next.entityList.length ? `entity list: ${fmtAddr(next.entityList[0].address)} (score ${next.entityList[0].score})` : "entity list: no candidate");
      }
      if (what === "viewmatrix" || what === "all") {
        setProgress(0.2);
        next.viewMatrix = (await findViewMatrix(read, wsects, { budgetBytes: Math.min(mb, 64) * 1024 * 1024, onProgress: (d, t) => setProgress(0.2 + 0.8 * (d / t)) }))?.address ?? null;
        log("info", "game", next.viewMatrix ? `view matrix: ${fmtAddr(next.viewMatrix)}` : "view matrix: not found in budget (raise it)");
      }
      localStorage.setItem(storeKey(main), JSON.stringify(next));
      return next;
    })());
    setBusy("");
    setProgress(1);
    if (result) {
      setScan(result);
      if (prev && prev.build !== main.size) log("warn", "game", `build changed (${prev.build} → ${main.size}); canaries below show what moved`);
    }
  };

  const exportJson = () => {
    if (!scan || !main) return;
    const j = {
      module: main.name,
      build_size: scan.build,
      scanned: new Date(scan.ts).toISOString(),
      canaries: scan.canaries,
      view_matrix: scan.viewMatrix ? fmtAddr(scan.viewMatrix) : null,
      entity_list: scan.entityList.map((h) => ({ address: fmtAddr(h.address), score: h.score })),
      tables: scan.tables.map((t) => ({ address: fmtAddr(t.address), anchors: t.anchors, entries: Object.fromEntries(t.entries.map((e) => [e.name, e.offset])) })),
    };
    void saveText("offsets.json", JSON.stringify(j, null, 1), { name: "JSON", extensions: ["json"] });
  };
  const exportCpp = () => {
    if (!scan || !main) return;
    const lines = [
      `// ${main.name} — build size ${scan.build}, scanned ${new Date(scan.ts).toISOString()}`,
      ...Object.entries(scan.canaries).map(([n, o]) => {
        const suffix = o !== null ? `  0x${o.toString(16).toUpperCase()}` : "  0x0 // NOT FOUND";
        return `#define OFF_${n.replace(/[^A-Za-z0-9]/g, "_").toUpperCase()}${suffix}`;
      }),
    ];
    if (scan.viewMatrix) lines.push(`#define ADDR_VIEW_MATRIX  0x${(scan.viewMatrix - toBig(main.base)).toString(16).toUpperCase()} // ${fmtAddr(scan.viewMatrix)}`);
    if (scan.entityList[0]) lines.push(`#define ADDR_ENTITY_LIST  0x${(scan.entityList[0].address - toBig(main.base)).toString(16).toUpperCase()} // ${fmtAddr(scan.entityList[0].address)}, score ${scan.entityList[0].score}`);
    void saveText("offsets.h", lines.join("\n") + "\n", { name: "C++ header", extensions: ["h"] });
  };

  const shownTables = scan ? scan.tables.filter((t) => !filter || t.entries.some((e) => e.name.toLowerCase().includes(filter.toLowerCase())) || t.anchors.some((a) => a.toLowerCase().includes(filter.toLowerCase()))) : [];
  const canaryMoved = (n: string) => stored !== null && scan !== null && stored.build !== scan.build && stored.canaries[n] !== undefined && scan.canaries[n] !== stored.canaries[n];

  return (
    <NeedsAgent>
      <div className="vlist">
        {busy && <Progress value={progress} />}
        <div className="panel-section">
          <div className="label">Game — Apex Legends / Respawn Source</div>
          <div className="faint">
            {main ? (<span>Module <span className="mono">{main.name}</span> · build fingerprint <span className="mono">{main.size.toLocaleString()} bytes</span></span>) : "No module — attach to the game first."}
            {" "}(signature-free: offsets re-derive from member-name strings and descriptor tables, not byte patterns)
          </div>
          {buildChanged && scan && main && (
            <div className="faint" style={{ color: "var(--warn, #d8a657)" }}>
              Build changed since the stored scan ({stored!.build.toLocaleString()} → {main.size.toLocaleString()}). Canary offsets that moved:
              {" "}{kRespawnPresetFields.filter(canaryMoved).join(", ") || "none in the preset"}
            </div>
          )}
          <div className="row">
            <button className="btn primary small" disabled={!!busy || !main} onClick={() => void runScan("all")}>Scan everything</button>
            <button className="btn small" disabled={!!busy || !main} onClick={() => void runScan("netvars")}>Netvars (all tables)</button>
            <button className="btn small" disabled={!!busy || !main} onClick={() => void runScan("entitylist")}>Entity list</button>
            <button className="btn small" disabled={!!busy || !main} onClick={() => void runScan("viewmatrix")}>View matrix</button>
            <span className="faint">scan budget</span>
            <input className="input mono" value={budget} onChange={(e) => setBudget(e.target.value)} style={{ width: 52 }} title="MiB of writable memory to scan for globals" />
            <span className="faint">MiB</span>
            {scan && <button className="btn small" onClick={exportJson}>offsets.json</button>}
            {scan && <button className="btn small" onClick={exportCpp}>offsets.h</button>}
          </div>
        </div>

        {scan && (
          <div className="panel-section">
            <div className="label">Canaries</div>
            <table className="table mono">
              <tbody>
                {kRespawnPresetFields.map((n) => (
                  <tr key={n}>
                    <td style={{ width: 220 }}>{n}</td>
                    <td style={{ width: 90 }} className={scan.canaries[n] === null ? "faint" : canaryMoved(n) ? "" : "dim"}>
                      {scan.canaries[n] !== null ? `0x${scan.canaries[n]!.toString(16).toUpperCase()}` : "—"}
                    </td>
                    <td className="faint">{canaryMoved(n) ? `was 0x${stored!.canaries[n]!.toString(16)}` : ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {scan && scan.entityList.length > 0 && (
          <div className="panel-section">
            <div className="label">Globals</div>
            <table className="table mono">
              <tbody>
                {scan.entityList.slice(0, 5).map((h, i) => (
                  <tr key={String(h.address)}>
                    <td style={{ width: 180 }}>{i === 0 ? "entity list" : "candidate"}</td>
                    <td style={{ width: 130 }} className="dim">{fmtAddr(h.address)}</td>
                    <td className="faint">score {h.score}{i === 0 ? " (best)" : ""}</td>
                  </tr>
                ))}
                {scan.viewMatrix !== null && (
                  <tr><td style={{ width: 180 }}>view matrix</td><td style={{ width: 130 }} className="dim">{fmtAddr(scan.viewMatrix)}</td><td className="faint">4x4 float, frame-differed</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {scan && scan.tables.length > 0 && (
          <div className="panel-section">
            <div className="label">Netvar tables — {scan.tables.length} tables, {scan.entries} entries ({scan.confirmed} cross-confirmed)</div>
            <div className="row">
              <input className="input grow" placeholder="filter by member or anchor name" value={filter} onChange={(e) => setFilter(e.target.value)} />
              <span className="faint">{shownTables.length} shown</span>
            </div>
            <div style={{ maxHeight: 420, overflowY: "auto" }}>
              <table className="table mono">
                <thead><tr><th style={{ width: 120 }}>Table</th><th style={{ width: 60 }}>Count</th><th>Anchors</th></tr></thead>
                <tbody>
                  {shownTables.slice(0, 500).map((t) => (
                    <tr key={String(t.address)}>
                      <td className="dim">{fmtAddr(t.address)}</td>
                      <td className="faint">{t.entries.length}{t.entries.some((e) => e.confirmed) ? ` (${t.entries.filter((e) => e.confirmed).length}✓)` : ""}</td>
                      <td className="ellipsis">{t.anchors.join(", ") || t.entries.slice(0, 4).map((e) => e.name).join(", ") + ", …"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </NeedsAgent>
  );
}
