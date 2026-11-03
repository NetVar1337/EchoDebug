// Unpacking: find the original entry point with the emulator, recover the IAT from the live
// (unpacked) image, and save a rebuilt PE with a fresh import table.
import { useState } from "react";
import { fmtAddr, labelAddr, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { saveBinary } from "@/lib/save";
import { exportIndex, oepCandidates } from "@/lib/unpacklive";
import { parsePe } from "@/lib/analysis/pe";
import { detectPacker } from "@/lib/analysis/entropy";
import { buildDumpPe, findIat, type IatBlock, type OepCandidate } from "@/lib/analysis/unpack";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

export default function UnpackView() {
  const m = useFocusedModule();
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const [oep, setOep] = useState("");
  const [cands, setCands] = useState<OepCandidate[] | null>(null);
  const [note, setNote] = useState("");
  const [blocks, setBlocks] = useState<IatBlock[] | null>(null);
  const [busy, setBusy] = useState(0);
  const [verdict, setVerdict] = useState("");

  const findOepRun = async () => {
    if (!m) return;
    setBusy(0.5);
    const img = await attempt("unpack", loadImage(m));
    if (img) {
      try {
        const v = detectPacker(img, parsePe(img));
        setVerdict(v.packed ? `packed (${Math.round(v.confidence * 100)}%): ${v.reasons.join("; ")}` : "no packer signs (entropy and section names look normal)");
      } catch { /* not PE */ }
    }
    const r = await attempt("unpack", oepCandidates(m));
    setBusy(0);
    if (!r) return;
    setCands(r.candidates);
    setNote(`${r.instructions.toLocaleString()} instructions emulated, stopped with ${r.stop}`);
    if (r.candidates[0]) setOep(fmtAddr(r.candidates[0].address));
  };
  const recover = async () => {
    if (!m) return;
    setBusy(0.01);
    const idx = await attempt("unpack", exportIndex(modules, m, (d, t) => setBusy(d / t)));
    const img = await attempt("unpack", loadImage(m));
    setBusy(0);
    if (!idx || !img) return;
    const b = findIat(img, idx);
    setBlocks(b);
    log("info", "unpack", `${b.length} IAT blocks, ${b.reduce((n, x) => n + x.thunks.length, 0)} imports recovered from ${idx.size.toLocaleString()} exports`);
  };
  const save = async () => {
    if (!m || !blocks) return;
    const img = await loadImage(m);
    const o = oep ? toBig(oep) - toBig(m.base) : BigInt(parsePe(img).entryRva);
    try {
      const out = buildDumpPe(img, toBig(m.base), Number(o), blocks);
      await saveBinary(m.name.replace(/(\.\w+)?$/, "_unpacked$1"), out);
    } catch (e) {
      log("error", "unpack", String(e instanceof Error ? e.message : e));
    }
  };

  return (
    <NeedsAgent ext>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar"><ModulePicker /><span className="faint" style={{ fontSize: 12 }}>{verdict}</span></div>
        {busy > 0 && <Progress value={busy} />}
        <div className="vlist">
          <div className="panel-section">
            <div className="label">1 · Original entry point</div>
            <div className="row">
              <button className="btn small primary" disabled={!m || busy > 0} onClick={() => void findOepRun()}>Emulate from the entry point</button>
              <span className="faint" style={{ fontSize: 12 }}>{note}</span>
            </div>
            {cands?.length === 0 && <div className="faint">No candidate: the stub never jumped into code it wrote or into another section within the budget.</div>}
            {cands?.map((c) => (
              <div key={String(c.address)} className="row">
                <span className="mono link" onClick={() => ui.goDisasm(fmtAddr(c.address))}>{labelAddr(c.address, modules)}</span>
                <span className="faint">after {c.step.toLocaleString()} instructions · {c.reason === "written-then-executed" ? "runs code the stub wrote" : "first jump into another section"}</span>
                <button className="row-action" onClick={() => setOep(fmtAddr(c.address))}>use</button>
              </div>
            ))}
            <div className="row"><span className="faint">OEP</span><CommitInput value={oep} placeholder="address of the original entry point" onCommit={setOep} width={240} /></div>
          </div>
          <div className="panel-section">
            <div className="label">2 · Imports</div>
            <div className="faint" style={{ fontSize: 12 }}>Let the target run past its unpacking stub first (the live image is dumped). The IAT is found as runs of pointers into the exports of the other loaded modules.</div>
            <button className="btn small" disabled={!m || busy > 0} onClick={() => void recover()}>Recover the import table</button>
            {blocks && (
              <table className="table mono"><tbody>
                {blocks.map((b) => <tr key={b.rva}><td>{b.dll}</td><td className="faint">rva 0x{b.rva.toString(16)}</td><td className="faint ellipsis">{b.thunks.length} · {b.thunks.slice(0, 6).map((t) => t.name || `#${t.ordinal}`).join(", ")}{b.thunks.length > 6 ? " …" : ""}</td></tr>)}
              </tbody></table>
            )}
          </div>
          <div className="panel-section">
            <div className="label">3 · Rebuilt file</div>
            <button className="btn small primary" disabled={!blocks?.length} onClick={() => void save()}>Save the unpacked PE…</button>
            <div className="faint" style={{ fontSize: 12 }}>Raw layout = virtual layout, entry point = OEP, a new .edimp section with the import descriptors; FirstThunk points at the original IAT so the code's references stay valid.</div>
          </div>
        </div>
      </div>
    </NeedsAgent>
  );
}
