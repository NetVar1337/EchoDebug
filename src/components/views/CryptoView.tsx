// Crypto scanner: finds well-known crypto constant tables (AES S-box, SHA-256
// K, MD5 T, CRC32, ChaCha sigma, TEA delta, ...) inside a module image.
import { useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { labelAddr, toBig } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { scanCrypto, type CryptoHit } from "@/lib/analysis/crypto";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

export default function CryptoView() {
  const m = useFocusedModule();
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [hits, setHits] = useState<CryptoHit[]>([]);
  const [progress, setProgress] = useState(1);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    if (!m) return;
    let live = true;
    setHits([]);
    setProgress(0);
    void attempt("crypto", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      const found = scanCrypto(img, toBig(m.base));
      setHits(found);
      log("info", "crypto", `${found.length} crypto constant hits in ${m.name}`);
    });
    return () => { live = false; };
  }, [m?.name, m?.base]);

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return hits.filter((h) => !f || h.name.toLowerCase().includes(f) || h.kind.includes(f) || h.note.toLowerCase().includes(f));
  }, [hits, filter]);

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <ModulePicker />
          <label className="search grow"><Search size={13} /><input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
          <span className="faint" style={{ fontSize: 12 }}>{shown.length} hits</span>
        </div>
        {progress < 1 && <Progress value={progress} />}
        <div className="vlist">
          {shown.length === 0 && progress >= 1 && (
            <div className="empty">
              <div className="empty-title">No known crypto constants found.</div>
              <div className="empty-hint">The scanner matches fixed tables (AES S-box, SHA-256 K, MD5 T, CRC32, ChaCha sigma, TEA delta…). Obfuscated or generated tables are not detected.</div>
            </div>
          )}
          {shown.length > 0 && (
            <table className="table mono">
              <colgroup><col style={{ width: 150 }} /><col style={{ width: 180 }} /><col style={{ width: 70 }} /><col /></colgroup>
              <thead><tr><th>Constant</th><th>Address</th><th>Confidence</th><th>Note</th></tr></thead>
              <tbody>
                {shown.map((h) => (
                  <tr key={h.kind + h.rva} onClick={() => ui.select(h.address)} onDoubleClick={() => ui.goMemory(h.address)}>
                    <td>{h.name}</td>
                    <td className="link">{labelAddr(h.address, modules)}</td>
                    <td className="faint">{Math.round(h.confidence * 100)}%</td>
                    <td className="dim ellipsis" title={h.note}>{h.note}</td>
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
