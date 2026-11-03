// Memory snapshots: capture a window of process memory, then diff two captures
// to see exactly which bytes changed (integrity checks, animated values).
import { useMemo, useState } from "react";
import { Pencil, Trash2 } from "lucide-react";
import { readRange } from "@/lib/memory";
import { saveText } from "@/lib/save";
import { fmtAddr, labelAddr, parseAddress } from "@/lib/hex";
import { diffRange, type DiffEntry } from "@/lib/analysis/snapshot";
import { encodeBytes, snapshotBytes, storeSnapshot, useSnapshots, type SnapshotFile } from "@/store/snapshots";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, IconButton, NeedsAgent } from "../ui";

const kSizes = [0x100, 0x400, 0x1000, 0x10000, 0x100000, 0x1000000];

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
    const bytes = await attempt("snapshot", readRange(addr, size));
    if (!bytes) return;
    const id = Math.random().toString(36).slice(2, 10);
    const s = await attempt("snapshot", storeSnapshot({ id, name: `${labelAddr(fmtAddr(addr), modules)} +${bytes.length}`, address: fmtAddr(addr), size: bytes.length, created: Date.now() }, bytes));
    if (!s) return;
    snaps.add(s);
    log("info", "snapshot", `captured ${bytes.length} bytes at ${s.address}`);
  };

  const diff = async () => {
    const sa = snaps.snapshots.find((s) => s.id === a);
    const sb = snaps.snapshots.find((s) => s.id === b);
    if (!sa || !sb) return;
    const [ba, bb] = await Promise.all([snapshotBytes(sa), snapshotBytes(sb)]).catch((e) => { log("error", "snapshot", String(e)); return [null, null]; });
    if (!ba || !bb) return;
    const out = diffRange(ba, bb, sa.address);
    setRows(out);
    log("info", "snapshot", `${out.length} differing bytes`);
  };

  const list = useMemo(() => snaps.snapshots, [snaps.snapshots]);
  const exportAll = async () => {
    const out: SnapshotFile = { format: "echodebug.snapshots", version: 1, snapshots: [] };
    for (const s of snaps.snapshots) {
      const bytes = await snapshotBytes(s).catch(() => null);
      if (bytes) out.snapshots.push({ id: s.id, name: s.name, address: s.address, size: s.size, created: s.created, data: encodeBytes(bytes) });
    }
    await saveText("echodebug-snapshots.json", JSON.stringify(out));
  };
  const importFile = async () => {
    const input = Object.assign(document.createElement("input"), { type: "file", accept: ".json" });
    const { promise, resolve } = Promise.withResolvers<File | null>();
    input.onchange = () => resolve(input.files?.[0] ?? null);
    input.click();
    const f = await promise;
    if (!f) return;
    try {
      const file = JSON.parse(await f.text()) as SnapshotFile;
      if (file.format !== "echodebug.snapshots") throw new Error("not an EchoDebug snapshot file");
      const { decodeBytes } = await import("@/store/snapshots");
      for (const s of file.snapshots) snaps.add(await storeSnapshot({ ...s, id: Math.random().toString(36).slice(2, 10) }, decodeBytes(s.data)));
      log("info", "snapshot", `imported ${file.snapshots.length} snapshots`);
    } catch (e) {
      log("error", "snapshot", String(e instanceof Error ? e.message : e));
    }
  };

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
              <button className="btn small" disabled={!snaps.snapshots.length} onClick={() => void exportAll()}>Export</button>
              <button className="btn small" onClick={() => void importFile()}>Import</button>
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
              <button className="btn" disabled={!a || !b} onClick={() => void diff()}>Diff</button>
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
                <IconButton tip="Delete" onClick={() => { snaps.remove(s.id); if (s.stored === "idb") void import("@/lib/idb").then((m) => m.idbDel(`snap:${s.id}`)).catch(() => undefined); }}><Trash2 size={12} /></IconButton>
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
