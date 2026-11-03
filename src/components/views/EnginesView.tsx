// Engine dumpers: Unreal (GNames/GObjects → objects and an SDK header), Unity IL2CPP
// (global-metadata.dat → types, methods and RVAs) and Source (ClientClass → netvars).
import { useState } from "react";
import { fmtAddr, parseAddress } from "@/lib/hex";
import { guessEngine, il2cppDump, sourceNetvars, unrealFindBySig, unrealOpen, unrealSdk, unrealTables, type UnrealSession } from "@/lib/enginelive";
import { dumpCs, scriptJson, type Il2CppMetadata } from "@/lib/analysis/engines/il2cpp";
import { netvarText, type NetvarDump } from "@/lib/analysis/engines/source";
import { fullName, kDefaultOffsets, kUnrealSigs, listObjects, type UObjectInfo, type UnrealSig } from "@/lib/analysis/engines/unreal";
import { saveText } from "@/lib/save";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";

export default function EnginesView() {
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [busy, setBusy] = useState("");
  const [progress, setProgress] = useState(1);
  // Unreal
  const [namesAt, setNamesAt] = useState("");
  const [objectsAt, setObjectsAt] = useState("");
  const [ue, setUe] = useState<UnrealSession | null>(null);
  const [ueFilter, setUeFilter] = useState("");
  const [legacy, setLegacy] = useState(false);
  const [itemSize, setItemSize] = useState("0x" + kDefaultOffsets.itemSize.toString(16));
  const [pats, setPats] = useState<Record<string, string>>(Object.fromEntries(kUnrealSigs.map((s) => [s.id, s.pattern])));
  const [nameIndex, setNameIndex] = useState("");
  const [decoded, setDecoded] = useState("");
  // paged GUObjectArray browser (reads one page at a time, no full dump needed)
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(0);
  const [rows, setRows] = useState<UObjectInfo[]>([]);
  const [rowFilter, setRowFilter] = useState("");
  // IL2CPP
  const [metaPath, setMetaPath] = useState("");
  const [il, setIl] = useState<{ md: Il2CppMetadata; source: string; withRva: string[] } | null>(null);
  const [ilFilter, setIlFilter] = useState("");
  // Source
  const [nv, setNv] = useState<(NetvarDump & { module: string }) | null>(null);
  const guess = guessEngine();

  const run = async <T,>(label: string, f: () => Promise<T>): Promise<T | undefined> => {
    setBusy(label);
    setProgress(0);
    const r = await attempt(label, f());
    setBusy("");
    setProgress(1);
    return r;
  };
  const addr = (s: string) => (s.trim() ? parseAddress(s, modules) ?? undefined : undefined);

  const offsets = () => ({ ...kDefaultOffsets, itemSize: Number(itemSize) || kDefaultOffsets.itemSize });
  const openUnreal = async () => {
    const r = await run("unreal", () => unrealOpen({ names: addr(namesAt), legacyNames: legacy, objects: addr(objectsAt), offsets: offsets(), onProgress: (d, t) => setProgress(d / t) }));
    if (r) {
      setUe(r);
      setNamesAt(fmtAddr(r.namesAddr));
      setObjectsAt(fmtAddr(r.objectsAddr));
      log("info", "unreal", `${r.dump.objects.length} objects (GNames ${fmtAddr(r.namesAddr)}, GObjects ${fmtAddr(r.objectsAddr)})`);
    }
  };
  /** Fills the GNames / GObjects address from an (editable) AOB pattern. */
  const findSig = async (id: UnrealSig["id"]) => {
    const sig = kUnrealSigs.find((s) => s.id === id)!;
    const a = await run("unreal pattern", () => unrealFindBySig(sig, pats[id]));
    if (a === undefined) return;
    if (a === null) return log("warn", "unreal", `pattern not found: ${pats[id]}`);
    log("info", "unreal", `${sig.label.split(":")[0]} at ${fmtAddr(a)}`);
    if (id === "objects") setObjectsAt(fmtAddr(a));
    else setNamesAt(fmtAddr(a));
  };
  const tables = (withObjects: boolean) => {
    const n = addr(namesAt), o = addr(objectsAt);
    if (n === undefined || (withObjects && o === undefined)) throw new Error(withObjects ? "set both the name table and GUObjectArray addresses" : "set the name table address first");
    return unrealTables({ names: n, legacyNames: legacy, objects: withObjects ? o : undefined, offsets: offsets() });
  };
  const decodeName = async () => {
    const i = Number(nameIndex);
    if (!Number.isInteger(i) || i < 0) return log("warn", "unreal", "name index must be a non-negative integer");
    const r = await run("unreal name", async () => (await tables(false)).names.name(i));
    setDecoded(r ?? "");
  };
  const kPage = 100;
  const loadPage = async (p: number) => {
    const r = await run("unreal objects", async () => {
      const t = await tables(true);
      return { total: t.objects!.num, rows: await listObjects(t.names, t.objects!, p * kPage, kPage) };
    });
    if (!r) return;
    setTotal(r.total);
    setRows(r.rows);
    setPage(p);
  };
  /** Walks the whole array in pages and keeps the first 1000 objects whose name or class match. */
  const searchAll = async () => {
    const needle = rowFilter.toLowerCase();
    if (!needle) return;
    const r = await run("unreal search", async () => {
      const t = await tables(true);
      const n = t.objects!.num;
      const hits: UObjectInfo[] = [];
      for (let start = 0; start < n && hits.length < 1000; start += 1000) {
        hits.push(...(await listObjects(t.names, t.objects!, start, 1000)).filter((x) => `${x.name} ${x.className}`.toLowerCase().includes(needle)));
        setProgress(Math.min(1, (start + 1000) / n));
      }
      return { total: n, rows: hits.slice(0, 1000) };
    });
    if (r) { setTotal(r.total); setRows(r.rows); }
  };
  const saveSdk = async () => {
    if (!ue) return;
    const r = await run("unreal sdk", () => unrealSdk(ue, { filter: ueFilter || undefined, max: 20000, onProgress: (d, t) => setProgress(d / t) }));
    if (r) {
      const p = await saveText("SDK.hpp", r.text, { name: "C++ header", extensions: ["hpp", "h"] });
      if (p) log("info", "unreal", `${r.structs.length} classes/structs written to ${p}`);
    }
  };
  const saveObjects = async () => {
    if (!ue) return;
    const text = ue.dump.objects.map((o) => `[${o.index}] ${fmtAddr(o.address)} ${o.className} ${fullName(o, ue.dump)}`).join("\n") + "\n";
    const p = await saveText("ObjectsDump.txt", text);
    if (p) log("info", "unreal", `objects written to ${p}`);
  };
  const openIl = async () => {
    const r = await run("il2cpp", () => il2cppDump({ path: metaPath.trim() || undefined }));
    if (r) {
      setIl(r);
      const types = r.md.images.reduce((a, i) => a + i.types.length, 0);
      log("info", "il2cpp", `metadata v${r.md.version} from ${r.source}: ${r.md.images.length} images, ${types} types; RVAs for ${r.withRva.length} images`);
    }
  };
  const openNv = async () => {
    const r = await run("netvars", () => sourceNetvars());
    if (r) {
      setNv(r);
      log("info", "netvars", `${r.classes.length} client classes, ${Object.keys(r.tables).length} tables in ${r.module}`);
    }
  };

  const ueShown = ue ? ue.dump.objects.filter((o) => (o.className === "Class" || o.className === "ScriptStruct") && (!ueFilter || o.name.toLowerCase().includes(ueFilter.toLowerCase()))).slice(0, 300) : [];
  const ilShown = il ? il.md.images.flatMap((im) => im.types.map((t) => ({ im: im.name, t }))).filter((x) => !ilFilter || `${x.t.namespace}.${x.t.name}`.toLowerCase().includes(ilFilter.toLowerCase())).slice(0, 200) : [];

  return (
    <NeedsAgent>
      <div className="vlist">
        {busy && <Progress value={progress} />}
        <div className="panel-section">
          <div className="faint">Detected: <span className="mono">{guess.engine}</span>{guess.module ? ` (${guess.module})` : ""}. Dumps read the target's memory only.</div>
        </div>

        <div className="panel-section">
          <div className="label">Unreal Engine 4.x / 5 — GNames, GObjects, SDK</div>
          <div className="row">
            <div className="segmented">
              <button data-active={!legacy} onClick={() => setLegacy(false)}>FNamePool (4.23+)</button>
              <button data-active={legacy} onClick={() => setLegacy(true)}>GNames (≤4.22)</button>
            </div>
            <input className="input mono grow" placeholder={legacy ? "GNames (TNameEntryArray) address" : "GNames (FNamePool) — empty: find"} value={namesAt} onChange={(e) => setNamesAt(e.target.value)} />
            <input className="input mono grow" placeholder="GObjects (FUObjectArray) — empty: find" value={objectsAt} onChange={(e) => setObjectsAt(e.target.value)} />
            <span className="faint" title="sizeof(FUObjectItem): 0x18 typical, 0x10 when the serial number is compiled out">item</span>
            <input className="input mono" value={itemSize} onChange={(e) => setItemSize(e.target.value)} style={{ width: 56 }} />
            <button className="btn primary small" disabled={!!busy} onClick={() => void openUnreal()}>Dump objects</button>
          </div>
          <div className="row">
            <span className="faint" style={{ width: 70 }}>{legacy ? "GNames" : "FNamePool"}</span>
            <input className="input mono grow" spellCheck={false} value={pats[legacy ? "legacy" : "pool"]} title={kUnrealSigs.find((s) => s.id === (legacy ? "legacy" : "pool"))!.label} onChange={(e) => setPats({ ...pats, [legacy ? "legacy" : "pool"]: e.target.value })} />
            <button className="btn small" disabled={!!busy} onClick={() => void findSig(legacy ? "legacy" : "pool")}>Find</button>
          </div>
          <div className="row">
            <span className="faint" style={{ width: 70 }}>GObjects</span>
            <input className="input mono grow" spellCheck={false} value={pats.objects} title={kUnrealSigs.find((s) => s.id === "objects")!.label} onChange={(e) => setPats({ ...pats, objects: e.target.value })} />
            <button className="btn small" disabled={!!busy} onClick={() => void findSig("objects")}>Find</button>
          </div>
          <div className="row">
            <span className="faint">name index</span>
            <input className="input mono" placeholder="ComparisonIndex" value={nameIndex} onChange={(e) => setNameIndex(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void decodeName()} style={{ width: 130 }} />
            <button className="btn small" disabled={!!busy} onClick={() => void decodeName()}>Decode</button>
            <span className="mono accent ellipsis grow">{decoded}</span>
          </div>
          <div className="row">
            <button className="btn small" disabled={!!busy} onClick={() => void loadPage(0)} title="read GUObjectArray one page at a time (no full dump)">List objects</button>
            <button className="btn small" disabled={!!busy || page === 0} onClick={() => void loadPage(page - 1)}>‹</button>
            <span className="mono faint">{total ? `${page * kPage}–${Math.min(total, (page + 1) * kPage) - 1} of ${total}` : ""}</span>
            <button className="btn small" disabled={!!busy || (page + 1) * kPage >= total} onClick={() => void loadPage(page + 1)}>›</button>
            <input className="input grow" placeholder="filter name / class" value={rowFilter} onChange={(e) => setRowFilter(e.target.value)} />
            <button className="btn small" disabled={!!busy || !rowFilter} onClick={() => void searchAll()} title="read every object and keep the matches (max 1000)">Search all</button>
          </div>
          {rows.length > 0 && (
            <table className="table mono">
              <thead><tr><th style={{ width: 80 }}>Index</th><th style={{ width: 150 }}>Address</th><th>Name</th><th style={{ width: 200 }}>Class</th><th style={{ width: 70 }} /></tr></thead>
              <tbody>{rows.filter((r) => !rowFilter || `${r.name} ${r.className}`.toLowerCase().includes(rowFilter.toLowerCase())).map((r) => (
                <tr key={r.index}>
                  <td className="faint">{r.index}</td>
                  <td className="dim">{r.address.toString(16).toUpperCase()}</td>
                  <td className="ellipsis">{r.name}</td>
                  <td className="ellipsis accent">{r.className}</td>
                  <td><button className="row-action" onClick={() => ui.goStruct(fmtAddr(r.address))}>struct →</button></td>
                </tr>
              ))}</tbody>
            </table>
          )}
          {ue && (
            <>
              <div className="row">
                <input className="input grow" placeholder="filter classes / structs" value={ueFilter} onChange={(e) => setUeFilter(e.target.value)} />
                <button className="btn small" disabled={!!busy} onClick={() => void saveSdk()}>Save SDK.hpp{ueFilter ? " (filtered)" : ""}</button>
                <button className="btn small" onClick={() => void saveObjects()}>Save object list</button>
              </div>
              <div className="faint" style={{ fontSize: 12 }}>{ue.dump.objects.length} objects in {ue.module}</div>
              <table className="table mono"><tbody>{ueShown.map((o) => <tr key={String(o.address)}><td className="faint" style={{ width: 90 }}>{o.className}</td><td className="link" onClick={() => ui.goStruct(fmtAddr(o.address))}>{fullName(o, ue.dump)}</td></tr>)}</tbody></table>
            </>
          )}
        </div>

        <div className="panel-section">
          <div className="label">Unity IL2CPP — global-metadata.dat (v24–31) + GameAssembly method RVAs</div>
          <div className="row">
            <input className="input mono grow" placeholder="path to global-metadata.dat — empty: find it in memory (works when the file is encrypted on disk)" value={metaPath} onChange={(e) => setMetaPath(e.target.value)} />
            <button className="btn primary small" disabled={!!busy} onClick={() => void openIl()}>Dump</button>
          </div>
          {il && (
            <>
              <div className="row">
                <input className="input grow" placeholder="filter types" value={ilFilter} onChange={(e) => setIlFilter(e.target.value)} />
                <button className="btn small" onClick={() => void saveText("dump.cs", dumpCs(il.md))}>Save dump.cs</button>
                <button className="btn small" onClick={() => void saveText("script.json", JSON.stringify(scriptJson(il.md), null, 1), { name: "JSON", extensions: ["json"] })}>Save script.json</button>
              </div>
              <table className="table mono"><tbody>{ilShown.map(({ im, t }) => (
                <tr key={im + t.token}><td className="faint" style={{ width: 160 }}>{im}</td><td>{t.namespace ? `${t.namespace}.` : ""}{t.name}</td><td className="faint">{t.methods.length} methods · {t.fields.length} fields</td></tr>
              ))}</tbody></table>
            </>
          )}
        </div>

        <div className="panel-section">
          <div className="label">Source engine — netvars (ClientClass / RecvTable)</div>
          <div className="row">
            <button className="btn primary small" disabled={!!busy} onClick={() => void openNv()}>Dump netvars</button>
            {nv && <button className="btn small" onClick={() => void saveText("netvars.txt", netvarText(nv))}>Save netvars.txt</button>}
            {nv && <span className="faint">{nv.classes.length} classes · head {fmtAddr(nv.head)}</span>}
          </div>
          {nv && <pre className="mcp-result" style={{ maxHeight: 360 }}>{netvarText(nv).slice(0, 20000)}</pre>}
        </div>
      </div>
    </NeedsAgent>
  );
}
