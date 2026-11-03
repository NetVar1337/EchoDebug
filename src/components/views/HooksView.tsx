// Hook / tamper scanner: code that differs from the file on disk, exports that jump out of the
// module, and IAT slots that point at unbacked memory or an unexpected module.
import { useState } from "react";
import { fmtAddr, labelAddr } from "@/lib/hex";
import { scanModuleHooks, type HookReport } from "@/lib/hooklive";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

type Row = HookReport & { error?: string };

export default function HooksView() {
  const m = useFocusedModule();
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [reports, setReports] = useState<Row[]>([]);
  const [busy, setBusy] = useState("");
  const [showInfo, setShowInfo] = useState(false);
  const [useFile, setUseFile] = useState(true);

  const scan = async (all: boolean) => {
    const list = all ? modules : m ? [m] : [];
    const out: Row[] = [];
    for (const [i, x] of list.entries()) {
      setBusy(`${x.name} (${i + 1}/${list.length})`);
      try {
        out.push(await scanModuleHooks(x, { file: useFile }));
      } catch (e) {
        if (!all) log("error", "hooks", `${x.name}: ${e instanceof Error ? e.message : String(e)}`);
        else out.push({ module: x.name, base: 0n, file: "", fileError: "", patches: [], inline: [], iat: [], error: e instanceof Error ? e.message : String(e) });
      }
    }
    setBusy("");
    setReports(out);
    const n = out.reduce((a, r) => a + r.patches.length + r.inline.length + r.iat.filter((x) => x.severity === "high").length, 0);
    log(n ? "warn" : "info", "hooks", `${n} findings in ${out.length} module(s)`);
  };
  const hit = (r: Row) => r.patches.length + r.inline.length + r.iat.filter((x) => showInfo || x.severity === "high").length > 0;

  return (
    <NeedsAgent>
      <div className="vlist">
        <div className="toolbar">
          <ModulePicker />
          <button className="btn primary small" disabled={!!busy || !m} onClick={() => void attempt("hooks", scan(false))}>Scan module</button>
          <button className="btn small" disabled={!!busy} onClick={() => void attempt("hooks", scan(true))}>Scan all modules</button>
          <label className="row small-label" title="Compare executable sections with the file on disk (rebased with its relocations)"><input type="checkbox" checked={useFile} onChange={(e) => setUseFile(e.target.checked)} />compare with file</label>
          <label className="row small-label" title="Also list imports resolved into a different module (usually API forwarding)"><input type="checkbox" checked={showInfo} onChange={(e) => setShowInfo(e.target.checked)} />forwarded imports</label>
          {busy && <span className="faint">scanning {busy}…</span>}
        </div>
        {reports.length === 0 && !busy && <div className="empty"><div className="empty-title">No scan yet.</div><div className="empty-hint">Finds inline hooks (jmp/push-ret/int3 at exports), patched code (memory vs the file on disk) and IAT entries redirected outside their DLL. PE modules only.</div></div>}
        {reports.filter((r) => r.error).length > 0 && <div className="faint" style={{ padding: 8, fontSize: 12 }}>skipped: {reports.filter((r) => r.error).map((r) => `${r.module} (${r.error})`).join(", ")}</div>}
        {reports.filter((r) => !r.error && !hit(r)).length > 0 && <div className="ok" style={{ padding: 8 }}>clean: {reports.filter((r) => !r.error && !hit(r)).map((r) => r.module).join(", ")}</div>}
        {reports.filter((r) => !r.error && hit(r)).map((r) => (
          <div key={r.module} className="panel-section">
            <div className="label">{r.module} <span className="faint">{r.file || (r.fileError ? `file not compared: ${r.fileError}` : "")}</span></div>
            {r.inline.length > 0 && (
              <table className="table mono"><thead><tr><th>Inline hook</th><th>stub</th><th>target</th></tr></thead><tbody>
                {r.inline.map((h) => <tr key={h.rva}><td className="link" onClick={() => ui.goDisasm(fmtAddr(r.base + BigInt(h.rva)))}>{h.name}</td><td>{h.kind}</td><td className="link danger" onClick={() => ui.goDisasm(fmtAddr(h.target))}>{labelAddr(h.target, modules)}{h.targetModule ? "" : " (unbacked)"}</td></tr>)}
              </tbody></table>
            )}
            {r.patches.length > 0 && (
              <table className="table mono"><thead><tr><th>Patched code ({r.patches.length})</th><th>kind</th><th>file → memory</th></tr></thead><tbody>
                {r.patches.slice(0, 500).map((p) => (
                  <tr key={p.rva}>
                    <td className="link" onClick={() => ui.goDisasm(fmtAddr(r.base + BigInt(p.rva)))}>{p.symbol || `${p.section}+0x${p.rva.toString(16)}`} <span className="faint">{p.size}b</span></td>
                    <td>{p.kind}{p.target !== undefined ? ` → ${labelAddr(p.target, modules)}` : ""}</td>
                    <td className="ellipsis" title={`${p.file}\n${p.memory}`}><span className="faint">{p.file.slice(0, 24)}</span> → <span className="warn">{p.memory.slice(0, 24)}</span></td>
                  </tr>
                ))}
              </tbody></table>
            )}
            {r.iat.filter((x) => showInfo || x.severity === "high").length > 0 && (
              <table className="table mono"><thead><tr><th>Import</th><th>slot</th><th>points to</th></tr></thead><tbody>
                {r.iat.filter((x) => showInfo || x.severity === "high").map((h) => (
                  <tr key={h.iatRva}><td>{h.dll}!{h.func}</td><td className="faint">+0x{h.iatRva.toString(16)}</td><td className={h.severity === "high" ? "danger link" : "link"} onClick={() => ui.goDisasm(fmtAddr(h.pointer))}>{labelAddr(h.pointer, modules)}{h.module ? "" : " (unbacked)"}</td></tr>
                ))}
              </tbody></table>
            )}
          </div>
        ))}
      </div>
    </NeedsAgent>
  );
}
