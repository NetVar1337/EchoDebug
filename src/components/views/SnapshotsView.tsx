// Memory snapshots: capture a window of process memory, then diff two captures
// to see exactly which bytes changed (integrity checks, animated values).
import { useMemo, useState } from "react";
import { Pencil, Trash2 } from "lucide-react";
import { readBytes } from "@/lib/memory";
import { fmtAddr, labelAddr, parseAddress } from "@/lib/hex";
import { diffRange, type DiffEntry } from "@/lib/analysis/snapshot";
import { decodeBytes, encodeBytes, useSnapshots, type Snapshot } from "@/store/snapshots";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, IconButton, NeedsAgent } from "../ui";

const kSizes = [0x100, 0x400, 0x1000, 0x10000];

export default function SnapshotsView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const snaps = useSnapshots();
  const [at, setAt] = useState(ui.memoryAt ?? "");
  const [size, setSize] = useState(0x100);
  const [a, setA] = useState<string | null>(null);
  const [b, setB] = useState<string | null>(null);
  const [rows, setRows] = useState<DiffEntry[]>([]);

  const capture = async () => {
    const addr = parseAddress(at, modules);
    if (addr === null) return log("warn", "snapshot", `cannot parse ${at}`);
    const bytes = await attempt("snapshot", readBytes(addr, size));
    if (!bytes) return;
    const s: Snapshot = {
      id: Math.random().toString(36).slice(2, 10),
      name: `${labelAddr(fmtAddr(addr), modules)} +${bytes.length}`,
      address: fmtAddr(addr),
      size: bytes.length,
      data: encodeBytes(bytes),
      created: Date.now(),
    };
    snaps.add(s);
    log("info", "snapshot", `captured ${bytes.length} bytes at ${s.address}`);
  };

  const diff = () => {
    const sa = snaps.snapshots.find((s) => s.id === a);
    const sb = snaps.snapshots.find((s) => s.id === b);
    if (!sa || !sb) return;
    const out = diffRange(decodeBytes(sa.data), decodeBytes(sb.data), sa.address);
    setRows(out);
    log("info", "snapshot", `${out.length} differing bytes`);
  };

  const list = useMemo(() => snaps.snapshots, [snaps.snapshots]);

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "360px" }}>
        <div className="list-col vlist">
          <div className="panel-section">
            <div className="label">Capture</div>
            <div className="row">
              <CommitInput value={at} placeholder="address · module+0x…" onCommit={setAt} width={200} />
              <select className="select" value={size} onChange={(e) => setSize(Number(e.target.value))}>
                {kSizes.map((s) => <option key={s} value={s}>0x{s.toString(16)}</option>)}
              </select>
              <button className="btn primary" onClick={() => void capture()}>Capture</button>
            </div>
          </div>
          <div className="panel-section">
            <div className="label">Compare</div>
            <div className="row">
              <select className="select grow" value={a ?? ""} onChange={(e) => setA(e.target.value || null)}>
                <option value="">A…</option>
                {list.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
              <select className="select grow" value={b ?? ""} onChange={(e) => setB(e.target.value || null)}>
                <option value="">B…</option>
                {list.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
              <button className="btn" disabled={!a || !b} onClick={diff}>Diff</button>
            </div>
            <div className="row">
              <button className="btn small" disabled={!list.length} onClick={() => { setRows([]); snaps.clear(); }}>Clear all</button>
              <span className="grow faint" style={{ fontSize: 12 }}>{list.length} snapshots</span>
            </div>
          </div>
          <div className="panel-section">
            <div className="label">Captured</div>
            {list.length === 0 && <div className="faint">No snapshots yet.</div>}
            {list.map((s) => (
              <div key={s.id} className="row" data-selected={a === s.id || b === s.id}>
                <span className="mono grow ellipsis" title={s.address}>{s.name}</span>
                <span className="faint">{s.size}</span>
                <IconButton tip="Rename" onClick={() => {
                  const n = window.prompt("Name", s.name);
                  if (n !== null) snaps.rename(s.id, n);
                }}><Pencil size={12} /></IconButton>
                <IconButton tip="Delete" onClick={() => snaps.remove(s.id)}><Trash2 size={12} /></IconButton>
              </div>
            ))}
          </div>
        </div>
        <div className="list-col vlist" style={{ borderRight: "none" }}>
          {rows.length === 0 ? (
            <div className="empty">
              <div className="empty-title">No differences loaded.</div>
              <div className="empty-hint">Capture two snapshots of the same address and press Diff to list every byte that changed.</div>
            </div>
          ) : (
            <table className="table mono">
              <colgroup><col /><col style={{ width: 90 }} /><col style={{ width: 90 }} /></colgroup>
              <thead><tr><th>Address</th><th>Before</th><th>After</th></tr></thead>
              <tbody>
                {rows.slice(0, 5000).map((r) => (
                  <tr key={r.offset} onClick={() => ui.goMemory(r.address)}>
                    <td className="link">{labelAddr(r.address, modules)}</td>
                    <td className="danger">{r.before.toString(16).padStart(2, "0")}</td>
                    <td className="ok">{r.after.toString(16).padStart(2, "0")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
