// Engine dumpers: Unreal (GNames/GObjects → objects and an SDK header), Unity IL2CPP
// (global-metadata.dat → types, methods and RVAs) and Source (ClientClass → netvars).
import { useState } from "react";
import { fmtAddr, parseAddress } from "@/lib/hex";
import { guessEngine, il2cppDump, sourceNetvars, unrealOpen, unrealSdk, type UnrealSession } from "@/lib/enginelive";
import { dumpCs, scriptJson, type Il2CppMetadata } from "@/lib/analysis/engines/il2cpp";
import { netvarText, type NetvarDump } from "@/lib/analysis/engines/source";
import { fullName } from "@/lib/analysis/engines/unreal";
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

  const openUnreal = async () => {
    const r = await run("unreal", () => unrealOpen({ names: addr(namesAt), objects: addr(objectsAt), onProgress: (d, t) => setProgress(d / t) }));
    if (r) {
      setUe(r);
      setNamesAt(fmtAddr(r.namesAddr));
      setObjectsAt(fmtAddr(r.objectsAddr));
      log("info", "unreal", `${r.dump.objects.length} objects (GNames ${fmtAddr(r.namesAddr)}, GObjects ${fmtAddr(r.objectsAddr)})`);
    }
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
          <div className="label">Unreal Engine 4.23+ / 5 — GNames, GObjects, SDK</div>
          <div className="row">
            <input className="input mono grow" placeholder="GNames (FNamePool) — empty: find" value={namesAt} onChange={(e) => setNamesAt(e.target.value)} />
            <input className="input mono grow" placeholder="GObjects (FUObjectArray) — empty: find" value={objectsAt} onChange={(e) => setObjectsAt(e.target.value)} />
            <button className="btn primary small" disabled={!!busy} onClick={() => void openUnreal()}>Dump objects</button>
          </div>
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
