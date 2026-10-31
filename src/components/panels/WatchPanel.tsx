import { useEffect, useState } from "react";
import { Lock, LockOpen, Plus, X } from "lucide-react";
import { request } from "@/lib/client";
import { readMany } from "@/lib/batch";
import { bytesToHex, fmtAddr, labelAddr, parseAddress, toBig } from "@/lib/hex";
import { decode, encode, kSizes, type ValueType } from "@/lib/analysis/values";
import { readBytes } from "@/lib/memory";
import { useConn } from "@/store/conn";
import { usePatches } from "@/store/patches";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch, type WatchEntry } from "@/store/watch";
import { CommitInput, IconButton, Panel } from "../ui";

const kTypes: ValueType[] = ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "ptr", "ascii", "utf16"];

export default function WatchPanel() {
  const w = useWatch();
  const { agent, modules } = useConn();
  const patches = usePatches();
  const ui = useUi();
  const [values, setValues] = useState<Record<string, Uint8Array | null>>({});
  const [newAddr, setNewAddr] = useState("");

  useEffect(() => {
    if (!agent || w.watches.length === 0) return;
    let live = true;
    const tick = async () => {
      const rs = await readMany(w.watches.map((x) => ({ address: x.address, size: kSizes[x.type] }))).catch(() => null);
      if (live && rs) setValues(Object.fromEntries(w.watches.map((x, i) => [x.id, rs[i]])));
    };
    void tick();
    const t = setInterval(() => void tick(), 500);
    return () => { live = false; clearInterval(t); };
  }, [agent, w.watches]);

  const add = () => {
    const a = parseAddress(newAddr, modules);
    if (a === null) return log("warn", "watch", `cannot parse ${newAddr}`);
    w.addWatch(fmtAddr(a));
    setNewAddr("");
  };

  const write = async (e: WatchEntry, text: string) => {
    try {
      const bytes = encode(text, e.type);
      const data = bytesToHex(bytes);
      const before = await readBytes(toBig(e.address), bytes.length).catch(() => null);
      await request("write", { address: e.address, data });
      if (before) {
        patches.add({
          id: Math.random().toString(36).slice(2, 10),
          address: e.address,
          written: data,
          before: bytesToHex(before),
          note: "watchlist",
          created: Date.now(),
          reverted: false,
        });
      }
      if (e.frozen) await request("freeze", { address: e.address, data, enabled: true });
    } catch (err) {
      log("error", "write", String(err));
    }
  };

  const toggleFreeze = async (e: WatchEntry) => {
    const cur = values[e.id];
    if (!e.frozen && !cur) return log("warn", "freeze", "no value to freeze yet");
    const ok = await attempt("freeze", request("freeze", { address: e.address, data: cur ? bytesToHex(cur) : "", enabled: !e.frozen }));
    if (ok) w.updateWatch(e.id, { frozen: !e.frozen });
  };

  return (
    <Panel title="Watchlist & Bookmarks">
      <div className="panel-section">
        <div className="row">
          <input className="input mono grow" placeholder="address or module+0x…" value={newAddr} onChange={(e) => setNewAddr(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} />
          <IconButton tip="Add watch" onClick={add}><Plus size={14} /></IconButton>
        </div>
      </div>
      <div className="panel-body">
        <table className="table">
          <colgroup><col /><col style={{ width: 62 }} /><col style={{ width: 96 }} /><col style={{ width: 48 }} /></colgroup>
          <thead><tr><th>Address</th><th>Type</th><th>Value</th><th /></tr></thead>
          <tbody>
            {w.watches.map((e) => (
              <tr key={e.id}>
                <td title={labelAddr(e.address, modules)}>
                  <CommitInput className="input mono" value={e.label || labelAddr(e.address, modules)} onCommit={(v) => {
                    const a = parseAddress(v, modules);
                    if (a !== null) w.updateWatch(e.id, { address: fmtAddr(a), label: "" });
                    else w.updateWatch(e.id, { label: v });
                  }} />
                </td>
                <td>
                  <select className="select" value={e.type} onChange={(ev) => w.updateWatch(e.id, { type: ev.target.value as ValueType })}>
                    {kTypes.map((t) => <option key={t}>{t}</option>)}
                  </select>
                </td>
                <td><CommitInput value={values[e.id] ? decode(values[e.id]!, 0, e.type) : "??"} onCommit={(v) => void write(e, v)} /></td>
                <td>
                  <IconButton tip={e.frozen ? "Unfreeze" : "Freeze"} onClick={() => void toggleFreeze(e)}>{e.frozen ? <Lock size={12} className="accent" /> : <LockOpen size={12} />}</IconButton>
                  <IconButton tip="Remove" onClick={() => w.removeWatch(e.id)}><X size={12} /></IconButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {w.watches.length === 0 && <div className="panel-section faint">No watches. Add one above or from the scanner / inspector.</div>}
        <div className="panel-head"><div className="panel-title">Bookmarks</div></div>
        <table className="table">
          <tbody>
            {w.bookmarks.map((b) => (
              <tr key={b.id}>
                <td><span className="link mono" onClick={() => ui.goDisasm(b.address)}>{labelAddr(b.address, modules)}</span></td>
                <td style={{ width: 90 }}>
                  <button className="row-action" onClick={() => ui.goMemory(b.address)}>mem</button>
                  <IconButton tip="Remove" onClick={() => w.removeBookmark(b.id)}><X size={12} /></IconButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {w.bookmarks.length === 0 && <div className="panel-section faint">No bookmarks.</div>}
      </div>
    </Panel>
  );
}
