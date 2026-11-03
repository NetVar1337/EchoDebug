// Binary diff: match the functions of the live module against an older build of it (a PE file
// on disk), see what changed, and carry names over.
import { useMemo, useRef, useState } from "react";
import { Upload } from "lucide-react";
import { labelAddr, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { functionsFromImage } from "@/lib/diffinput";
import { moduleFunctions } from "@/lib/flirtlive";
import { pickBinaryFile } from "@/lib/tauri";
import { saveText } from "@/lib/save";
import { mapPeFile, parsePe, parseRuntimeFunctions } from "@/lib/analysis/pe";
import { diffFunctions, type DiffResult } from "@/lib/analysis/bindiff";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

const kMax = 6000;

async function pickFile(): Promise<{ bytes: Uint8Array; name: string } | null> {
  const native = await pickBinaryFile(["exe", "dll", "sys", "bin", "dmp"], "Older build").catch(() => null);
  if (native) return native;
  const input = Object.assign(document.createElement("input"), { type: "file" });
  const { promise, resolve } = Promise.withResolvers<File | null>();
  input.onchange = () => resolve(input.files?.[0] ?? null);
  input.click();
  const f = await promise;
  return f ? { bytes: new Uint8Array(await f.arrayBuffer()), name: f.name } : null;
}

export default function BinDiffView() {
  const m = useFocusedModule();
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const names = useNames();
  const [oldName, setOldName] = useState("");
  const [oldBase, setOldBase] = useState(0n);
  const [result, setResult] = useState<DiffResult | null>(null);
  const [progress, setProgress] = useState(1);
  const [filter, setFilter] = useState<"all" | "changed" | "added" | "removed">("changed");
  const abort = useRef({ aborted: false });

  const run = async () => {
    if (!m) return;
    const file = await pickFile();
    if (!file) return;
    abort.current = { aborted: false };
    setProgress(0);
    try {
      const oldImg = file.bytes[0] === 0x4d && file.bytes[1] === 0x5a && file.bytes.length !== m.size ? mapPeFile(file.bytes) : file.bytes;
      const oldPe = parsePe(oldImg);
      const ob = oldPe.imageBase;
      const oldFns = parseRuntimeFunctions(oldImg, oldPe).filter((f) => !f.chained).slice(0, kMax).map((f) => ({ rva: f.begin, size: f.end - f.begin, name: names.nameOf("0x" + (ob + BigInt(f.begin)).toString(16)) }));
      if (!oldFns.length) throw new Error("the older build has no .pdata function table (x64 PE needed)");
      const newImg = await loadImage(m);
      const nb = toBig(m.base);
      const newFns = (await moduleFunctions(m)).slice(0, kMax).map((f) => ({ rva: Number(toBig(f.address) - nb), size: f.size, name: names.nameOf(f.address) }));
      const total = oldFns.length + newFns.length;
      const a = await functionsFromImage(oldImg, ob, oldFns, (d) => setProgress(d / total), abort.current);
      const b = await functionsFromImage(newImg, nb, newFns, (d) => setProgress((oldFns.length + d) / total), abort.current);
      const r = diffFunctions(a, b, Number(ob & 0xffffffffffffn), Number(nb & 0xffffffffffffn));
      setResult(r);
      setOldName(file.name);
      setOldBase(ob);
      log("info", "bindiff", `${r.pairs.length} matched (${r.pairs.filter((p) => p.changed).length} changed), ${r.onlyOld.length} removed, ${r.onlyNew.length} added`);
    } catch (e) {
      log("error", "bindiff", String(e instanceof Error ? e.message : e));
    }
    setProgress(1);
  };

  const rows = useMemo(() => {
    if (!result) return [];
    if (filter === "added") return result.onlyNew.map((f) => ({ key: `n${f.rva}`, oldRva: null, newRva: f.rva, kind: "added", sim: 0 }));
    if (filter === "removed") return result.onlyOld.map((f) => ({ key: `o${f.rva}`, oldRva: f.rva, newRva: null, kind: "removed", sim: 0 }));
    return result.pairs.filter((p) => filter === "all" || p.changed).map((p) => ({ key: `p${p.new.rva}`, oldRva: p.old.rva, newRva: p.new.rva, kind: p.kind, sim: p.similarity }));
  }, [result, filter]);

  const portNames = () => {
    if (!result || !m) return;
    const nb = toBig(m.base);
    let n = 0;
    for (const p of result.pairs) {
      const from = names.nameOf("0x" + (oldBase + BigInt(p.old.rva)).toString(16)) || p.old.name;
      const to = "0x" + (nb + BigInt(p.new.rva)).toString(16);
      if (from && !names.nameOf(to)) { names.rename(to, from); n++; }
    }
    log("info", "bindiff", `${n} names carried over to ${m.name}`);
  };
  const exportMap = async () => {
    if (!result) return;
    const lines = ["old_rva,new_rva,kind,similarity,changed", ...result.pairs.map((p) => `0x${p.old.rva.toString(16)},0x${p.new.rva.toString(16)},${p.kind},${p.similarity.toFixed(3)},${p.changed}`)];
    await saveText(`${m?.name ?? "module"}-diff.csv`, lines.join("\n"));
  };

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <ModulePicker />
          <button className="btn small primary" disabled={!m || progress < 1} onClick={() => void run()}><Upload size={12} /> Diff against an older build…</button>
          {progress < 1 && <button className="btn small" onClick={() => { abort.current.aborted = true; }}>Stop</button>}
          <span className="grow" />
          {result && <>
            <select className="select" value={filter} onChange={(e) => setFilter(e.target.value as typeof filter)}>
              <option value="changed">changed ({result.pairs.filter((p) => p.changed).length})</option>
              <option value="all">all matched ({result.pairs.length})</option>
              <option value="added">added ({result.onlyNew.length})</option>
              <option value="removed">removed ({result.onlyOld.length})</option>
            </select>
            <button className="btn small" onClick={portNames}>Carry names over</button>
            <button className="btn small" onClick={() => void exportMap()}>Export .csv</button>
          </>}
        </div>
        {progress < 1 && <Progress value={progress} />}
        {!result ? (
          <div className="empty"><div className="empty-title">Pick an older build of {m?.name ?? "the module"}.</div><div className="empty-hint">Functions come from the .pdata tables; matching uses names, exact and structural hashes, the call graph and mnemonic similarity. Names on the old build's addresses (or its own function names) can be carried over.</div></div>
        ) : (
          <div className="vlist">
            <div className="faint" style={{ padding: "4px 10px", fontSize: 12 }}>{oldName} (base {"0x" + oldBase.toString(16)}) → {m?.name}</div>
            <table className="table mono">
              <thead><tr><th>Old</th><th>New</th><th>Match</th><th>Similarity</th></tr></thead>
              <tbody>
                {rows.slice(0, 5000).map((r) => {
                  const na = r.newRva !== null && m ? "0x" + (toBig(m.base) + BigInt(r.newRva)).toString(16) : null;
                  return (
                    <tr key={r.key} onClick={() => na && ui.goDisasm(na)}>
                      <td className="faint">{r.oldRva !== null ? `0x${r.oldRva.toString(16)}` : "—"}</td>
                      <td className={na ? "link" : "faint"}>{na ? labelAddr(na, modules) : "—"}{na && names.nameOf(na) ? ` ${names.nameOf(na)}` : ""}</td>
                      <td>{r.kind}</td>
                      <td className="faint">{r.sim ? `${(r.sim * 100).toFixed(0)}%` : ""}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </NeedsAgent>
  );
}
