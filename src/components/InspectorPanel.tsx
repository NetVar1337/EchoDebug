import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { request } from "@/lib/client";
import { toBig } from "@/lib/hex";
import { symAddr } from "@/lib/pdb";
import { readBytes } from "@/lib/memory";
import { decode, type ValueType } from "@/lib/analysis/values";
import { useConn } from "@/store/conn";
import { useUi } from "@/store/ui";
import { useWatch } from "@/store/watch";
import { IconButton, Panel } from "./ui";

type Region = { base: string; size: number; present: boolean; writable: boolean; executable: boolean };
const kTypes: ValueType[] = ["u8", "u16", "u32", "u64", "i32", "i64", "f32", "f64", "ptr", "ascii", "utf16"];

export default function InspectorPanel() {
  const { target, modules, mem: agent, extOk: ext } = useConn();
  const ui = useUi();
  const { addWatch, addBookmark } = useWatch();
  const sel = ui.selected;
  const [bytes, setBytes] = useState<Uint8Array | null>(null);
  const [region, setRegion] = useState<Region | null>(null);
  const [rtti, setRtti] = useState("");
  const [tick, setTick] = useState(0);

  useEffect(() => {
    setBytes(null);
    setRegion(null);
    setRtti("");
    if (!sel || !agent) return;
    let live = true;
    void readBytes(toBig(sel), 64).then((b) => live && setBytes(b)).catch(() => undefined);
    void request<{ name: string }>("rtti_resolve", { address: sel }, true).then((r) => live && setRtti(r.success ? r.name : "")).catch(() => undefined);
    if (ext) void request<{ region: Region }>("query", { address: sel }).then((r) => live && setRegion(r.region)).catch(() => undefined);
    return () => { live = false; };
  }, [sel, agent, ext, tick]);

  return (
    <Panel title="Inspector" actions={<IconButton tip="Refresh" onClick={() => setTick(tick + 1)}><RefreshCw size={13} /></IconButton>}>
      <div className="panel-body">
        <div className="kv">
          <span>process</span><span>{target?.name ?? "—"}</span>
          <span>pid</span><span>{target?.pid ?? "—"}</span>
          <span>base</span><span>{target?.base ?? "—"}</span>
          <span>peb</span><span>{target?.peb ?? "—"}</span>
          <span>modules</span><span>{modules.length || "—"}</span>
        </div>
        {sel ? (
          <>
            <div className="panel-section">
              <div className="label">Selection</div>
              <div className="mono selectable">{sel}</div>
              <div className="mono dim ellipsis">{symAddr(sel, modules)}</div>
              {rtti && <div className="pill accent ellipsis" title={rtti}>{rtti}</div>}
              {region && (
                <div className="mono faint">
                  region {region.base} +0x{region.size.toString(16)} {region.present ? "" : "unmapped "}
                  {region.writable ? "RW" : "R-"}{region.executable ? "X" : "-"}
                </div>
              )}
              <div className="row wrap">
                <button className="btn small" onClick={() => ui.goDisasm(sel)}>Disasm</button>
                <button className="btn small" onClick={() => ui.goMemory(sel)}>Memory</button>
                <button className="btn small" onClick={() => ui.goStruct(sel)}>Struct</button>
                <button className="btn small" onClick={() => ui.goSig(sel)}>Signature</button>
                <button className="btn small" onClick={() => addWatch(sel)}>Watch</button>
                <button className="btn small" onClick={() => addBookmark(sel)}>Bookmark</button>
              </div>
            </div>
            <div className="kv">
              {kTypes.map((t) => (
                <KV key={t} k={t} v={bytes ? decode(bytes, 0, t) : "??"} />
              ))}
            </div>
          </>
        ) : (
          <div className="panel-section faint">Select an address in any view to inspect it.</div>
        )}
      </div>
    </Panel>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <>
      <span>{k}</span>
      <span title={v}>{v}</span>
    </>
  );
}
