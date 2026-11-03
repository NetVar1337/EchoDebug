import { useCallback, useEffect, useState } from "react";
import { LineChart, Lock, LockOpen, Plus, X } from "lucide-react";
import { request } from "@/lib/client";
import { readMany } from "@/lib/batch";
import { bytesToHex, fmtAddr, labelAddr, parseAddress, toBig } from "@/lib/hex";
import { decode, encode, kSizes, type ValueType } from "@/lib/analysis/values";
import { readBytes } from "@/lib/memory";
import { onAgentEvent, useConn } from "@/store/conn";
import { usePatches } from "@/store/patches";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { useWatch, type WatchEntry } from "@/store/watch";
import { useGraphs } from "@/store/graphs";
import { graphTypeOf } from "@/lib/graphs";
import { CommitInput, IconButton, Panel, useContextMenu } from "../ui";
import { accessMenuItems } from "../accessMenu";

const kTypes: ValueType[] = ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "ptr", "ascii", "utf16"];
const kAlertTypes = ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "bytes", "string", "wstring"];
const kConds = ["changed", "equals", "not_equals", "greater", "less"];

/** A conditional alert as the Echo agent's alert_list reports it. */
type Alert = { alert_id: number; address: string; value_type: string; condition: string; value: string; label: string; once: boolean; fired: number };

export default function WatchPanel() {
  const w = useWatch();
  const { mem: agent, ext, modules, target } = useConn();
  const patches = usePatches();
  const ui = useUi();
  const [values, setValues] = useState<Record<string, Uint8Array | null>>({});
  const [newAddr, setNewAddr] = useState("");
  // conditional alerts live in the Echo agent; fired ones are logged to Output by the conn store
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [al, setAl] = useState({ address: "", type: "i32", cond: "changed", value: "", once: false });
  const [openMenu, menu] = useContextMenu();
  const rowMenu = (ev: React.MouseEvent, e: WatchEntry) => openMenu(ev, [
    ...accessMenuItems(e.address, kSizes[e.type]),
    "sep",
    { label: "Graph this", onClick: () => graph(e) },
    { label: "Browse memory", onClick: () => ui.goMemory(e.address) },
    { label: "Disassemble here", onClick: () => ui.goDisasm(e.address) },
    { label: e.frozen ? "Unfreeze" : "Freeze", onClick: () => void toggleFreeze(e) },
    { label: "Remove", onClick: () => w.removeWatch(e.id) },
  ]);

  /** Plots the watch in the Value Graphs view. */
  const graph = (e: WatchEntry) => {
    const t = graphTypeOf(e.type);
    if (!t) return log("warn", "graph", `${e.type} values cannot be graphed; pick a number type`);
    useGraphs.getState().add(e.address, t, e.label);
    ui.setTab("values");
  };

  const refreshAlerts = useCallback(async () => {
    if (!ext) return setAlerts([]);
    const r = await request<{ entries: Alert[] }>("alert_list").catch(() => null);
    if (r) setAlerts(r.entries);
  }, [ext]);

  // the agent clears alerts on attach/detach; a fired one-shot alert removes itself
  useEffect(() => { void refreshAlerts(); }, [refreshAlerts, target?.pid]);
  useEffect(() => onAgentEvent((f) => {
    if (f.event === "alert_event" || f.event === "attached" || f.event === "detached") void refreshAlerts();
  }), [refreshAlerts]);

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

  const addAlert = async () => {
    const a = parseAddress(al.address, modules);
    if (a === null) return log("warn", "alert", `cannot parse ${al.address}`);
    const r = await attempt("alert", request<{ alert_id: number }>("alert_add", {
      address: fmtAddr(a),
      value_type: al.type,
      condition: al.cond,
      ...(al.cond !== "changed" ? { value: al.value } : {}),
      once: al.once,
      label: labelAddr(a, modules),
    }));
    if (r) {
      log("info", "alert", `#${r.alert_id} armed: ${labelAddr(a, modules)} ${al.cond}${al.cond !== "changed" ? ` ${al.value}` : ""}`);
      void refreshAlerts();
    }
  };

  const removeAlert = async (id: number) => {
    if (await attempt("alert", request("alert_remove", { alert_id: id }))) void refreshAlerts();
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
          <colgroup><col /><col style={{ width: 62 }} /><col style={{ width: 96 }} /><col style={{ width: 80 }} /></colgroup>
          <thead><tr><th>Address</th><th>Type</th><th>Value</th><th /></tr></thead>
          <tbody>
            {w.watches.map((e) => (
              <tr key={e.id} onContextMenu={(ev) => rowMenu(ev, e)} title="right-click: graph it, find what writes / accesses it">
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
                  <IconButton tip="Graph this" onClick={() => graph(e)}><LineChart size={12} /></IconButton>
                  <IconButton tip={e.frozen ? "Unfreeze" : "Freeze"} onClick={() => void toggleFreeze(e)}>{e.frozen ? <Lock size={12} className="accent" /> : <LockOpen size={12} />}</IconButton>
                  <IconButton tip="Remove" onClick={() => w.removeWatch(e.id)}><X size={12} /></IconButton>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {w.watches.length === 0 && <div className="panel-section faint">No watches. Add one above or from the scanner / inspector.</div>}
        <div className="panel-head"><div className="panel-title">Alerts</div></div>
        <div className="panel-section">
          <div className="row">
            <input className="input mono grow" placeholder="address or module+0x…" value={al.address} onChange={(e) => setAl({ ...al, address: e.target.value })} />
            <select className="select" value={al.type} onChange={(e) => setAl({ ...al, type: e.target.value })}>
              {kAlertTypes.map((t) => <option key={t}>{t}</option>)}
            </select>
          </div>
          <div className="row">
            <select className="select" value={al.cond} onChange={(e) => setAl({ ...al, cond: e.target.value })}>
              {kConds.map((c) => <option key={c}>{c}</option>)}
            </select>
            {al.cond !== "changed" && <input className="input mono grow" placeholder="value" value={al.value} onChange={(e) => setAl({ ...al, value: e.target.value })} onKeyDown={(e) => e.key === "Enter" && void addAlert()} />}
            {al.cond === "changed" && <span className="grow" />}
            <label className="row" title="Remove the alert after it fires once"><input type="checkbox" checked={al.once} onChange={(e) => setAl({ ...al, once: e.target.checked })} />once</label>
            <IconButton tip="Add alert" disabled={!ext} onClick={() => void addAlert()}><Plus size={14} /></IconButton>
          </div>
        </div>
        <table className="table">
          <tbody>
            {alerts.map((a) => (
              <tr key={a.alert_id}>
                <td><span className="link mono" onClick={() => ui.goMemory(a.address)}>{a.label || labelAddr(a.address, modules)}</span></td>
                <td className="mono">{a.value_type} {a.condition}{a.value ? ` ${a.value}` : ""}{a.once ? " · once" : ""}</td>
                <td style={{ width: 70 }} className={a.fired ? "warn" : "faint"}>{a.fired} fired</td>
                <td style={{ width: 28 }}><IconButton tip="Remove alert" onClick={() => void removeAlert(a.alert_id)}><X size={12} /></IconButton></td>
              </tr>
            ))}
          </tbody>
        </table>
        {alerts.length === 0 && <div className="panel-section faint">{ext ? "No alerts. Fired alerts are logged to Output with a memory snapshot." : "Alerts need the Echo agent (Windows)."}</div>}
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
      {menu}
    </Panel>
  );
}
