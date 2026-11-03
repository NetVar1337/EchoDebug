// Binary map: the module's section layout as a proportional bar, plus the
// live region map of the attached process.
import { useEffect, useMemo, useState } from "react";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { parsePe } from "@/lib/analysis/pe";
import { useConn } from "@/store/conn";
import { attempt } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

type Region = { base: string; size: number; present: boolean; writable: boolean; executable: boolean };

export default function BinaryMapView() {
  const m = useFocusedModule();
  const modules = useConn((s) => s.modules);
  const ext = useConn((s) => s.extOk);
  const ui = useUi();
  const [sections, setSections] = useState<{ name: string; rva: number; vsize: number; r: boolean; w: boolean; x: boolean }[]>([]);
  const [sizeOfImage, setSizeOfImage] = useState(0);
  const [regions, setRegions] = useState<Region[]>([]);
  const [progress, setProgress] = useState(1);

  useEffect(() => {
    if (!m) return;
    let live = true;
    setProgress(0);
    void attempt("map", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      try {
        const pe = parsePe(img);
        setSections(pe.sections.map((s) => ({ name: s.name, rva: s.rva, vsize: s.vsize, r: s.r, w: s.w, x: s.x })));
        setSizeOfImage(pe.sizeOfImage);
      } catch {
        setSections([]);
      }
    });
    return () => { live = false; };
  }, [m?.name, m?.base]);

  useEffect(() => {
    if (!ext) return;
    void attempt("regions", request<{ regions: Region[] }>("regions", { max: 20000 })).then((r) => r && setRegions(r.regions));
  }, [ext]);

  const bar = useMemo(() => {
    if (!sizeOfImage) return [];
    return sections
      .filter((s) => s.vsize > 0)
      .map((s) => ({ ...s, pct: Math.max(0.4, (s.vsize / sizeOfImage) * 100) }));
  }, [sections, sizeOfImage]);

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <ModulePicker />
          <span className="grow faint" style={{ fontSize: 12 }}>
            {m ? `${m.name} · image 0x${sizeOfImage.toString(16)} · ${sections.length} sections` : "no module"}
          </span>
        </div>
        {progress < 1 && <Progress value={progress} />}
        <div className="vlist">
          <div className="panel-section">
            <div className="label">Module layout</div>
            {bar.length === 0 ? (
              <div className="faint">No sections parsed.</div>
            ) : (
              <>
                <div className="map-bar">
                  {bar.map((s) => (
                    <div
                      key={s.name + s.rva}
                      className="map-seg"
                      style={{ width: `${s.pct}%` }}
                      data-x={s.x}
                      data-w={s.w}
                      title={`${s.name} rva 0x${s.rva.toString(16)} size 0x${s.vsize.toString(16)}`}
                      onClick={() => m && ui.goMemory(fmtAddr(toBig(m.base) + BigInt(s.rva)))}
                    >
                      <span>{s.name.trim()}</span>
                    </div>
                  ))}
                </div>
                <table className="table mono">
                  <thead><tr><th>Section</th><th>RVA</th><th>Size</th><th>Prot</th></tr></thead>
                  <tbody>
                    {sections.map((s) => (
                      <tr key={s.name + s.rva} onClick={() => m && ui.goMemory(fmtAddr(toBig(m.base) + BigInt(s.rva)))}>
                        <td>{s.name.trim()}</td>
                        <td className="dim">0x{s.rva.toString(16)}</td>
                        <td className="faint">0x{s.vsize.toString(16)}</td>
                        <td className="dim">{s.r ? "R" : "-"}{s.w ? "W" : "-"}{s.x ? "X" : "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>

          <div className="panel-section">
            <div className="label">Process regions {ext ? "" : "(needs the EchoDebug agent)"}</div>
            {regions.length === 0 ? (
              <div className="faint">No region data.</div>
            ) : (
              <table className="table mono">
                <colgroup><col /><col style={{ width: 90 }} /><col style={{ width: 50 }} /></colgroup>
                <thead><tr><th>Base</th><th>Size</th><th>Prot</th></tr></thead>
                <tbody>
                  {regions.slice(0, 2000).map((r) => (
                    <tr key={r.base} onClick={() => ui.goMemory(r.base)} title={labelAddr(r.base, modules)}>
                      <td className="mono">{r.base.replace(/^0x/, "")}</td>
                      <td className="faint">{r.size >= 1048576 ? `${(r.size / 1048576).toFixed(1)}M` : `${(r.size / 1024).toFixed(0)}K`}</td>
                      <td className="dim">{r.present ? (r.writable ? "RW" : "R-") : "--"}{r.executable ? "X" : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </NeedsAgent>
  );
}
