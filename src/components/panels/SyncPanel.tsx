// Sync panel: IDA / Ghidra / Binary Ninja connected to the relay's /sync hub, the module map,
// per-direction toggles, pushes (names, struct types) and the sync log with conflicts.
import { useEffect, useMemo } from "react";
import { RefreshCw, Upload } from "lucide-react";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { pushAllNames, pushTypes, useSync, type Direction } from "@/store/sync";
import { useUi } from "@/store/ui";
import { fromModuleRva } from "@/lib/sync";
import { fmtAddr } from "@/lib/hex";
import { CopyChip, IconButton, Panel, useCopy } from "../ui";

const kRows: { label: string; inKey?: Direction; outKey: Direction }[] = [
  { label: "Cursor", inKey: "cursor_in", outKey: "cursor_out" },
  { label: "Names", inKey: "names_in", outKey: "names_out" },
  { label: "Comments", inKey: "comments_in", outKey: "comments_out" },
  { label: "Struct types", outKey: "types_out" },
];

export default function SyncPanel() {
  const s = useSync();
  const c = useConn();
  const ui = useUi();
  const [copied, copy] = useCopy();
  useEffect(() => {
    if (!c.relay) return;
    void s.refresh();
    const t = setInterval(() => void s.refresh(), 5000);
    return () => clearInterval(t);
  }, [c.relay]);
  const log2 = useMemo(() => s.log.slice().reverse(), [s.log]);
  const url = `ws://127.0.0.1:${c.port}/sync`;

  const go = (module: string, rva: string | null) => {
    if (!rva) return;
    const a = fromModuleRva(module, rva, c.modules);
    if (a !== null) ui.goDisasm(fmtAddr(a));
  };

  return (
    <Panel
      title={<>Sync <span className="faint">IDA · Ghidra · Binary Ninja</span></>}
      actions={<IconButton tip="Refresh" onClick={() => void s.refresh()}><RefreshCw size={14} /></IconButton>}
    >
      <div className="panel-section">
        <div className="label">Connected tools ({s.peers.length})</div>
        {s.peers.length === 0 && (
          <div className="faint" style={{ fontSize: 12 }}>
            No disassembler connected. Install a plugin from <span className="mono">integrations/</span> (see its README) and start it in IDA, Ghidra or Binary Ninja: it connects to the endpoint below with the relay token.
          </div>
        )}
        {s.peers.map((p) => (
          <div key={p.id} className="sync-peer">
            <div className="row">
              <span className="dot" data-state="ok" />
              <span className="mono">{p.tool}</span>
              <span className="faint ellipsis grow">{p.version} {p.file && `· ${p.file}`}</span>
              <span className="faint" style={{ fontSize: 11 }}>since {new Date(p.connected_at).toLocaleTimeString()}</span>
            </div>
            {p.modules.map((m) => {
              const loaded = c.modules.some((x) => x.name.toLowerCase() === m.live.toLowerCase());
              return (
                <div key={m.name} className="row" style={{ fontSize: 12, paddingLeft: 16 }}>
                  <span className="mono ellipsis" title={m.base ? `image base ${m.base}` : undefined} style={{ width: 120 }}>{m.name}</span>
                  <span className="faint">→</span>
                  <select className="select grow" value={s.map[m.name.toLowerCase()] ?? ""} onChange={(e) => s.setMapping(m.name, e.target.value)} title="Live module this database stands for (by name when unset)">
                    <option value="">{loaded ? `${m.name} (same name)` : `${m.name} (not loaded)`}</option>
                    {c.modules.filter((x) => x.name.toLowerCase() !== m.name.toLowerCase()).map((x) => <option key={x.base} value={x.name}>{x.name}</option>)}
                  </select>
                  <span className={loaded ? "ok" : "warn"} style={{ fontSize: 11 }}>{loaded ? "mapped" : "no match"}</span>
                </div>
              );
            })}
          </div>
        ))}
        <div className="label" style={{ marginTop: 6 }}>Endpoint</div>
        <CopyChip text={url} copied={copied} onCopy={copy} />
        <div className="faint" style={{ fontSize: 12 }}>
          Plugins read the token from the config folder (<span className="mono">relay-token</span>) or <span className="mono">ECHODEBUG_TOKEN</span>. Locations travel as module + RVA, so a rebased database still lines up with the live module.
        </div>
      </div>

      <div className="panel-section">
        <div className="label">Directions</div>
        <table className="table">
          <colgroup><col /><col style={{ width: 96 }} /><col style={{ width: 96 }} /></colgroup>
          <thead><tr><th /><th>Tool → app</th><th>App → tool</th></tr></thead>
          <tbody>
            {kRows.map((r) => (
              <tr key={r.label}>
                <td>{r.label}</td>
                <td>{r.inKey ? <input type="checkbox" aria-label={`${r.label} from the disassembler`} checked={s.directions[r.inKey]} onChange={(e) => s.setDirection(r.inKey!, e.target.checked)} /> : <span className="faint">—</span>}</td>
                <td><input type="checkbox" aria-label={`${r.label} to the disassembler`} checked={s.directions[r.outKey]} onChange={(e) => s.setDirection(r.outKey, e.target.checked)} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="faint" style={{ fontSize: 12 }}>Names and comments: the last writer wins; an overwritten value shows up as a conflict in the log below.</div>
        <div className="row wrap" style={{ marginTop: 6 }}>
          <button className="btn small" disabled={!s.peers.length || !s.directions.names_out} onClick={() => void attempt("sync", pushAllNames()).then((n) => n !== undefined && log("info", "sync", `${n} names and comments sent`))}>
            <Upload size={12} /> Push names & comments
          </button>
          <button className="btn small" disabled={!s.peers.length || !s.directions.types_out} title="The struct catalog as C declarations" onClick={() => void attempt("sync", pushTypes()).then((n) => n !== undefined && log("info", "sync", `struct types sent to ${n} tool(s)`))}>
            <Upload size={12} /> Push struct types
          </button>
        </div>
        {s.cursor && (
          <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>
            Cursor: <span className="mono link" onClick={() => go(s.cursor!.module, s.cursor!.rva)}>{s.cursor.module}+{s.cursor.rva}</span> from {s.cursor.from}
          </div>
        )}
      </div>

      <div className="panel-body">
        <div className="panel-section" style={{ paddingBottom: 0 }}><div className="label">Sync log <span className="faint">({s.log.length})</span></div></div>
        {log2.length === 0 ? (
          <div className="panel-section faint" style={{ fontSize: 12 }}>Nothing synced yet.</div>
        ) : (
          <table className="table">
            <colgroup><col style={{ width: 64 }} /><col style={{ width: 58 }} /><col /></colgroup>
            <tbody>
              {log2.map((e) => (
                <tr key={e.seq} data-dir={e.dir} title={e.text} onDoubleClick={() => go(e.module, e.rva)}>
                  <td className="mono dim">{new Date(e.ts).toLocaleTimeString()}</td>
                  <td className={e.dir === "conflict" ? "warn" : "faint"}>{e.dir === "in" ? `${e.from} →` : e.dir === "out" ? "→ tools" : e.dir}</td>
                  <td className={e.dir === "conflict" ? "warn ellipsis" : "ellipsis"}>{e.module && <span className="mono dim">{e.module}{e.rva ? `+${e.rva}` : ""} </span>}{e.text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
}
