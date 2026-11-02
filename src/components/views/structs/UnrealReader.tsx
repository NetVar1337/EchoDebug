// GNames / GObjects reader for Unreal targets: decode FNames by index and page through GUObjectArray.
import { useMemo, useRef, useState } from "react";
import { X } from "lucide-react";
import { request } from "@/lib/client";
import { readMany } from "@/lib/batch";
import { fmtAddr, parseAddress, toBig, type Module } from "@/lib/hex";
import { readBytes, readU64 } from "@/lib/memory";
import { kLegacyNames, kNamePool, kObjectArray, kUnrealSigs, readNames, readObjects, ripTarget, type NameSource, type ObjRow, type Reader } from "@/lib/analysis/unreal";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, IconButton } from "../../ui";

const reader: Reader = (reads) => readMany(reads.map((r) => ({ address: fmtAddr(r.address), size: r.size })));
const kPage = 100;

type Sig = (typeof kUnrealSigs)[number];

/** Scans `module` for the pattern and resolves its RIP-relative operand. */
async function findBySig(sig: Sig, pattern: string, module: string): Promise<bigint | null> {
  const r = await request<{ results: string[] }>("sig_scan_ida", { pattern, module, find_all: false }, true);
  const hit = r.results?.[0];
  if (!hit) return null;
  const disp = await readBytes(toBig(hit) + BigInt(sig.disp), 4);
  if (!disp || disp.length < 4) return null;
  const at = ripTarget(toBig(hit), disp, sig.len) - BigInt(sig.adjust);
  return sig.deref ? readU64(at) : at;
}

export default function UnrealReader({ modules, onClose }: { modules: Module[]; onClose: () => void }) {
  const ui = useUi();
  const target = useConn((s) => s.target);
  const [module, setModule] = useState(target?.name ?? modules[0]?.name ?? "");
  const [kind, setKind] = useState<"pool" | "legacy">("pool");
  const [namesAt, setNamesAt] = useState("");
  const [objectsAt, setObjectsAt] = useState("");
  const [pats, setPats] = useState<Record<string, string>>(Object.fromEntries(kUnrealSigs.map((s) => [s.id, s.pattern])));
  const [index, setIndex] = useState("");
  const [decoded, setDecoded] = useState("");
  const [itemSize, setItemSize] = useState("0x" + kObjectArray.itemSize.toString(16));
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(0);
  const [rows, setRows] = useState<ObjRow[]>([]);
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState("");
  const cache = useRef(new Map<number, string>());

  const names = useMemo<NameSource | null>(() => {
    const a = parseAddress(namesAt, modules);
    cache.current = new Map(); // a different table means different names
    if (a === null) return null;
    return kind === "pool" ? { kind, address: a, layout: kNamePool } : { kind, address: a, layout: kLegacyNames };
  }, [namesAt, kind, modules]);

  const find = async (id: Sig["id"]) => {
    const sig = kUnrealSigs.find((s) => s.id === id)!;
    setBusy(`scanning ${module}`);
    try {
      const a = await findBySig(sig, pats[id], module);
      if (a === null) return log("warn", "unreal", `pattern not found in ${module}: ${pats[id]}`);
      log("info", "unreal", `${sig.label.split(":")[0]} at ${fmtAddr(a)}`);
      if (id === "objects") setObjectsAt(fmtAddr(a));
      else setNamesAt(fmtAddr(a));
    } catch (e) {
      log("error", "unreal", String(e));
    } finally {
      setBusy("");
    }
  };

  const decode = async () => {
    if (!names) return log("warn", "unreal", "set the name table address first");
    const i = Number(index);
    if (!Number.isInteger(i) || i < 0) return log("warn", "unreal", "index must be a non-negative integer");
    const m = await readNames(reader, names, [i], cache.current).catch((e) => (log("error", "unreal", String(e)), null));
    setDecoded(m?.get(i) ?? "");
  };

  const objOpts = () => ({ array: { ...kObjectArray, itemSize: Number(itemSize) || kObjectArray.itemSize }, cache: cache.current });
  const objectsAddr = () => {
    const a = parseAddress(objectsAt, modules);
    if (a === null || !names) log("warn", "unreal", "set both the name table and GUObjectArray addresses");
    return names && a !== null ? a : null;
  };

  const load = async (p: number) => {
    const a = objectsAddr();
    if (a === null) return;
    setBusy("reading objects");
    try {
      const r = await readObjects(reader, a, names!, p * kPage, kPage, objOpts());
      setTotal(r.total);
      setRows(r.rows);
      setPage(p);
    } catch (e) {
      log("error", "unreal", String(e));
    } finally {
      setBusy("");
    }
  };

  /** Walks the whole array in pages and keeps the first 1000 rows whose name or class match. */
  const scanAll = async () => {
    const a = objectsAddr();
    if (a === null || !filter) return;
    const needle = filter.toLowerCase();
    const hits: ObjRow[] = [];
    try {
      for (let start = 0, n = Infinity; start < n && hits.length < 1000; start += 1000) {
        setBusy(`filtering ${start}/${n === Infinity ? "?" : n}`);
        const r = await readObjects(reader, a, names!, start, 1000, objOpts());
        n = r.total;
        setTotal(n);
        hits.push(...r.rows.filter((x) => x.name.toLowerCase().includes(needle) || x.className.toLowerCase().includes(needle)));
      }
      setRows(hits.slice(0, 1000));
    } catch (e) {
      log("error", "unreal", String(e));
    } finally {
      setBusy("");
    }
  };

  const shown = filter ? rows.filter((x) => (x.name + " " + x.className).toLowerCase().includes(filter.toLowerCase())) : rows;
  const sigRow = (id: Sig["id"]) => (
    <input className="input mono grow" value={pats[id]} spellCheck={false} title={kUnrealSigs.find((s) => s.id === id)!.label} onChange={(e) => setPats({ ...pats, [id]: e.target.value })} />
  );

  return (
    <div className="list-col" style={{ flex: 1, minHeight: 0, borderRight: "none" }}>
      <div className="toolbar">
        <span className="panel-title">Unreal names &amp; objects</span>
        <span className="faint">module</span>
        <select className="select" value={module} onChange={(e) => setModule(e.target.value)}>{modules.map((m) => <option key={m.base}>{m.name}</option>)}</select>
        <span className="grow faint">{busy}</span>
        <IconButton tip="Close" onClick={onClose}><X size={14} /></IconButton>
      </div>
      <div className="toolbar">
        <div className="segmented">
          <button data-active={kind === "pool"} onClick={() => setKind("pool")}>FNamePool (4.23+)</button>
          <button data-active={kind === "legacy"} onClick={() => setKind("legacy")}>GNames (≤4.22)</button>
        </div>
        <CommitInput value={namesAt} placeholder={kind === "pool" ? "NamePoolData address" : "TNameEntryArray address"} onCommit={setNamesAt} width={170} />
        {sigRow(kind)}
        <button className="btn small" onClick={() => void find(kind)} disabled={!!busy}>Find</button>
      </div>
      <div className="toolbar">
        <span className="faint">name index</span>
        <CommitInput value={index} placeholder="ComparisonIndex" onCommit={setIndex} width={110} />
        <button className="btn small" onClick={() => void decode()}>Decode</button>
        <span className="mono accent ellipsis grow">{decoded}</span>
      </div>
      <div className="toolbar">
        <CommitInput value={objectsAt} placeholder="GUObjectArray address" onCommit={setObjectsAt} width={170} />
        {sigRow("objects")}
        <button className="btn small" onClick={() => void find("objects")} disabled={!!busy}>Find</button>
        <span className="faint" title="sizeof(FUObjectItem)">item</span>
        <CommitInput value={itemSize} onCommit={setItemSize} width={50} />
      </div>
      <div className="toolbar">
        <button className="btn small primary" onClick={() => void load(0)} disabled={!!busy}>List objects</button>
        <button className="btn small" onClick={() => void load(page - 1)} disabled={!!busy || page === 0}>‹</button>
        <span className="mono faint">{total ? `${page * kPage}–${Math.min(total, (page + 1) * kPage) - 1} of ${total}` : ""}</span>
        <button className="btn small" onClick={() => void load(page + 1)} disabled={!!busy || (page + 1) * kPage >= total}>›</button>
        <input className="input" placeholder="filter name / class" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 180 }} />
        <button className="btn small" onClick={() => void scanAll()} disabled={!!busy || !filter} title="read every object and keep the matches (max 1000)">Search all</button>
      </div>
      <div className="vlist">
        {shown.length === 0 ? (
          <div className="empty"><div className="empty-title">No objects listed.</div><div className="empty-hint">Set the name table and GUObjectArray (type them or use Find with the editable patterns), then List objects. Layout defaults are the UE4.20+/UE5 typical ones.</div></div>
        ) : (
          <table className="table mono">
            <colgroup><col style={{ width: 80 }} /><col style={{ width: 150 }} /><col /><col style={{ width: 220 }} /><col style={{ width: 70 }} /></colgroup>
            <thead><tr><th>Index</th><th>Address</th><th>Name</th><th>Class</th><th /></tr></thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.index}>
                  <td className="faint">{r.index}</td>
                  <td className="dim">{r.address.toString(16).toUpperCase()}</td>
                  <td className="ellipsis">{r.name}</td>
                  <td className="ellipsis accent">{r.className}</td>
                  <td><button className="row-action" onClick={() => ui.goStruct(fmtAddr(r.address))}>struct →</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

