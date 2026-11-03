// Dump view: full process dump, kernel/crash dump file browser, and .sys driver analyser.
//
// Three panels in a tabbed layout:
//   1. Process Dump  – dump the attached (or any) process to a .dmp file.
//   2. Open Dump     – open a .dmp/.edmp file, list modules, extract PEs.
//   3. Driver Info   – static analysis of a .sys (or any PE) from disk.
import { useState } from "react";
import { Archive, ChevronDown, ChevronRight, Download, FolderOpen, HardDrive, RefreshCw } from "lucide-react";
import { fmtAddr } from "@/lib/hex";
import { request } from "@/lib/client";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function fmtBytes(n: number) {
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GiB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MiB`;
  if (n >= 1 << 10) return `${(n / 1024).toFixed(1)} KiB`;
  return `${n} B`;
}

function errText(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

type PanelName = "process" | "kdump" | "driver";

// ---------------------------------------------------------------------------
// Types from backend
// ---------------------------------------------------------------------------

interface KdumpModule {
  name: string;
  base: number;
  size: number;
  timestamp: number;
}
interface KdumpInfo {
  format: string;
  arch: string;
  os_version: string;
  bug_check?: number;
  modules: KdumpModule[];
  path: string;
}

interface IoctlCode {
  code: number;
  device_type: number;
  function: number;
  method: string;
  access: string;
}
interface DriverInfo {
  name: string;
  is64: boolean;
  image_base: number;
  driver_entry_rva: number;
  driver_entry_va: number;
  exports: { name: string; rva: number }[];
  driver_imports: string[];
  ioctl_codes: IoctlCode[];
  irp_note: string;
}

// ---------------------------------------------------------------------------
// Sub-panels
// ---------------------------------------------------------------------------

function ProcessDumpPanel() {
  const pid = useConn((s) => s.target?.pid);
  const [pidInput, setPidInput] = useState(String(pid ?? ""));
  const [pathInput, setPathInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ path: string; bytes: number } | null>(null);

  async function run() {
    const p = parseInt(pidInput, 10);
    if (!p || !pathInput.trim()) return;
    setBusy(true);
    setResult(null);
    try {
      const r = await request("dump_process_full", { pid: p, path: pathInput.trim() });
      if (r.type === "error") { log("error", "dump", r.message as string); return; }
      setResult({ path: r.path as string, bytes: r.bytes as number });
      log("info", "dump", `wrote ${fmtBytes(r.bytes as number)} → ${r.path}`);
    } catch (e) {
      log("error", "dump", errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dump-panel">
      <p className="dump-blurb">
        Write a full process dump to disk. On Windows this produces a MINIDUMP with full memory,
        thread info and handles (via <code>MiniDumpWriteDump</code>). On Linux it writes an
        EchoDebug raw-segment archive from <code>/proc/&lt;pid&gt;/mem</code>.
        The output can be opened with <b>Open Dump</b> below, WinDbg, or GDB.
      </p>
      <div className="dump-form">
        <label>PID</label>
        <input
          className="dump-input"
          value={pidInput}
          onChange={(e) => setPidInput(e.target.value)}
          placeholder="process id"
          style={{ width: 100 }}
        />
        <label>Output path</label>
        <input
          className="dump-input dump-input-wide"
          value={pathInput}
          onChange={(e) => setPathInput(e.target.value)}
          placeholder={navigator.platform.startsWith("Win") ? "C:\\dumps\\game.dmp" : "/tmp/game.edmp"}
        />
        <button className="dump-btn" onClick={run} disabled={busy || !pidInput || !pathInput.trim()}>
          {busy ? <RefreshCw size={13} className="spin" /> : <Archive size={13} />}
          {busy ? "Dumping…" : "Dump"}
        </button>
      </div>
      {result && (
        <div className="dump-result ok">
          Saved {fmtBytes(result.bytes)} → <code>{result.path}</code>
        </div>
      )}
    </div>
  );
}

function KdumpPanel() {
  const [pathInput, setPathInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [info, setInfo] = useState<KdumpInfo | null>(null);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [extractPath, setExtractPath] = useState<Record<number, string>>({});
  const [extracting, setExtracting] = useState<Set<number>>(new Set());

  async function open() {
    if (!pathInput.trim()) return;
    setBusy(true);
    setInfo(null);
    try {
      const r = await request("kdump_open", { path: pathInput.trim() });
      if (r.type === "error") { log("error", "kdump", r.message as string); return; }
      setInfo(r as unknown as KdumpInfo);
      log("info", "kdump", `${r.format}: ${(r.modules as KdumpModule[]).length} modules`);
    } catch (e) {
      log("error", "kdump", errText(e));
    } finally {
      setBusy(false);
    }
  }

  async function extract(mod: KdumpModule, i: number) {
    const outPath = extractPath[i]?.trim();
    if (!outPath || !info) return;
    setExtracting((prev) => new Set(prev).add(i));
    try {
      const r = await request("kdump_extract", { path: info.path, base: mod.base, out: outPath });
      if (r.type === "error") { log("error", "kdump_extract", r.message as string); return; }
      log("info", "kdump_extract", `${mod.name} → ${outPath} (${fmtBytes(r.bytes as number)})`);
    } catch (e) {
      log("error", "kdump_extract", errText(e));
    } finally {
      setExtracting((prev) => { const s = new Set(prev); s.delete(i); return s; });
    }
  }

  function toggleExpand(i: number) {
    setExpanded((prev) => {
      const s = new Set(prev);
      if (s.has(i)) s.delete(i); else s.add(i);
      return s;
    });
  }

  return (
    <div className="dump-panel">
      <p className="dump-blurb">
        Open a <code>.dmp</code> or <code>.edmp</code> file: Windows MINIDUMP (Task Manager, ProcDump,
        WinDbg), Windows kernel crash dump (complete / kernel / small memory), or an EchoDebug raw dump.
        Lists modules and lets you extract each driver's PE image.
      </p>
      <div className="dump-form">
        <label>Dump file</label>
        <input
          className="dump-input dump-input-wide"
          value={pathInput}
          onChange={(e) => setPathInput(e.target.value)}
          placeholder="/path/to/memory.dmp"
        />
        <button className="dump-btn" onClick={open} disabled={busy || !pathInput.trim()}>
          {busy ? <RefreshCw size={13} className="spin" /> : <FolderOpen size={13} />}
          {busy ? "Opening…" : "Open"}
        </button>
      </div>

      {info && (
        <>
          <div className="dump-meta">
            <span className="dump-badge">{info.format}</span>
            <span className="dump-badge">{info.arch}</span>
            {info.os_version && <span className="dump-badge">Windows {info.os_version}</span>}
            {info.bug_check != null && (
              <span className="dump-badge warn">BugCheck 0x{info.bug_check.toString(16).toUpperCase().padStart(8, "0")}</span>
            )}
            <span className="dump-badge faint">{info.modules.length} modules</span>
          </div>

          <table className="table mono dump-modules">
            <thead>
              <tr>
                <th></th>
                <th>Name</th>
                <th>Base</th>
                <th>Size</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {info.modules.map((m, i) => (
                <>
                  <tr key={i} className="dump-mod-row" onClick={() => toggleExpand(i)}>
                    <td style={{ width: 20 }}>
                      {expanded.has(i) ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    </td>
                    <td className="ellipsis">{m.name || "<unknown>"}</td>
                    <td>{fmtAddr(m.base)}</td>
                    <td>{fmtBytes(m.size)}</td>
                    <td className="faint">{m.timestamp ? new Date(m.timestamp * 1000).toISOString().slice(0, 10) : "—"}</td>
                  </tr>
                  {expanded.has(i) && (
                    <tr key={`x${i}`}>
                      <td />
                      <td colSpan={4}>
                        <div className="dump-extract-row">
                          <input
                            className="dump-input dump-input-wide"
                            value={extractPath[i] ?? ""}
                            onChange={(e) => setExtractPath((prev) => ({ ...prev, [i]: e.target.value }))}
                            placeholder={`/tmp/${m.name || "module.exe"}`}
                          />
                          <button
                            className="dump-btn"
                            onClick={() => extract(m, i)}
                            disabled={extracting.has(i) || !extractPath[i]?.trim()}
                          >
                            {extracting.has(i) ? <RefreshCw size={12} className="spin" /> : <Download size={12} />}
                            Extract
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function DriverInfoPanel() {
  const [pathInput, setPathInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [info, setInfo] = useState<DriverInfo | null>(null);

  async function analyse() {
    if (!pathInput.trim()) return;
    setBusy(true);
    setInfo(null);
    try {
      const r = await request("driver_info", { path: pathInput.trim() });
      if (r.type === "error") { log("error", "driver_info", r.message as string); return; }
      setInfo(r as unknown as DriverInfo);
    } catch (e) {
      log("error", "driver_info", errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dump-panel">
      <p className="dump-blurb">
        Static analysis of a Windows kernel driver (<code>.sys</code>) or any PE on disk:
        DriverEntry offset, exports, key driver imports, and IOCTL codes decoded from code sections.
        No process attachment or kernel access required.
      </p>
      <div className="dump-form">
        <label>File path</label>
        <input
          className="dump-input dump-input-wide"
          value={pathInput}
          onChange={(e) => setPathInput(e.target.value)}
          placeholder="C:\Windows\System32\drivers\example.sys"
        />
        <button className="dump-btn" onClick={analyse} disabled={busy || !pathInput.trim()}>
          {busy ? <RefreshCw size={13} className="spin" /> : <HardDrive size={13} />}
          {busy ? "Analysing…" : "Analyse"}
        </button>
      </div>

      {info && (
        <div className="dump-driver-info">
          <div className="dump-meta">
            <span className="dump-badge">{info.name}</span>
            <span className="dump-badge">{info.is64 ? "64-bit" : "32-bit"}</span>
            <span className="dump-badge">Base 0x{info.image_base.toString(16)}</span>
          </div>

          <section className="dump-section">
            <h4>DriverEntry</h4>
            <p>
              RVA <code>0x{info.driver_entry_rva.toString(16)}</code>&ensp;
              VA <code>{fmtAddr(info.driver_entry_va)}</code>
            </p>
          </section>

          {info.driver_imports.length > 0 && (
            <section className="dump-section">
              <h4>Driver imports</h4>
              <div className="dump-tag-list">
                {info.driver_imports.map((n) => <span key={n} className="dump-badge ok">{n}</span>)}
              </div>
            </section>
          )}

          {info.exports.length > 0 && (
            <section className="dump-section">
              <h4>Exports ({info.exports.length})</h4>
              <table className="table mono">
                <thead><tr><th>Name</th><th>RVA</th></tr></thead>
                <tbody>
                  {info.exports.slice(0, 128).map((e, i) => (
                    <tr key={i}>
                      <td>{e.name}</td>
                      <td>0x{e.rva.toString(16)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {info.ioctl_codes.length > 0 && (
            <section className="dump-section">
              <h4>IOCTL codes ({info.ioctl_codes.length})</h4>
              <p className="faint small">{info.irp_note}</p>
              <table className="table mono">
                <thead>
                  <tr>
                    <th>Code</th>
                    <th>DevType</th>
                    <th>Fn</th>
                    <th>Method</th>
                    <th>Access</th>
                  </tr>
                </thead>
                <tbody>
                  {info.ioctl_codes.map((c) => (
                    <tr key={c.code}>
                      <td>0x{c.code.toString(16).padStart(8, "0")}</td>
                      <td>0x{c.device_type.toString(16)}</td>
                      <td>0x{c.function.toString(16)}</td>
                      <td className="faint">{c.method}</td>
                      <td className="faint">{c.access}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          )}

          {info.ioctl_codes.length === 0 && (
            <section className="dump-section">
              <p className="faint">{info.irp_note}</p>
            </section>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main view
// ---------------------------------------------------------------------------

export default function DumpView() {
  const [panel, setPanel] = useState<PanelName>("process");

  return (
    <div className="dump-view">
      <div className="dump-tabs">
        {(["process", "kdump", "driver"] as PanelName[]).map((p) => {
          const labels: Record<PanelName, string> = {
            process: "Process Dump",
            kdump: "Open Dump",
            driver: "Driver Info",
          };
          return (
            <button
              key={p}
              className={`dump-tab${panel === p ? " active" : ""}`}
              onClick={() => setPanel(p)}
            >
              {labels[p]}
            </button>
          );
        })}
      </div>
      <div className="dump-body">
        {panel === "process" && <ProcessDumpPanel />}
        {panel === "kdump" && <KdumpPanel />}
        {panel === "driver" && <DriverInfoPanel />}
      </div>
    </div>
  );
}
