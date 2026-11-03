// Runtime dumps through the attached backend's reads (Echo, the local /proc backend, …): a module
// rebuilt into a loadable PE (x64dbg / Scylla style), images the module list does not show,
// kernel drivers, and the whole target as a MINIDUMP / ELF core streamed to disk.
import { useEffect, useMemo, useRef, useState } from "react";
import { Archive, HardDrive, RefreshCw, Search, Square } from "lucide-react";
import { fmtAddr, parseAddress, toBig, type Module } from "@/lib/hex";
import { saveBinary } from "@/lib/save";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { Progress } from "../../ui";
import {
  defaultFormat, dumpImage, dumpName, dumpTarget, findHiddenImages, kernelModules, pickSink,
  type Cancel, type KernelModule, type ModuleDump, type ModuleDumpOptions, type TargetDumpReport,
} from "@/lib/dumplive";
import type { FoundImage } from "@/lib/analysis/dumper";

export function fmtBytes(n: number): string {
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GiB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MiB`;
  if (n >= 1 << 10) return `${(n / 1024).toFixed(1)} KiB`;
  return `${n} B`;
}
const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));

function DumpOptionsForm({ o, set, allowImports = true }: { o: Omit<ModuleDumpOptions, "onProgress" | "cancel">; set: (o: Omit<ModuleDumpOptions, "onProgress" | "cancel">) => void; allowImports?: boolean }) {
  return (
    <div className="dump-form">
      <label title="file: sections packed at FileAlignment (IDA, disk tools); virtual: raw = virtual, maps 1:1 (Scylla's dump)">Layout</label>
      <select className="select" value={o.rebuildImports ? "virtual" : o.layout} disabled={o.rebuildImports} onChange={(e) => set({ ...o, layout: e.target.value as "file" | "virtual" })}>
        <option value="file">file (unmapped)</option>
        <option value="virtual">virtual (raw = virtual)</option>
      </select>
      <label title="anti-dump code wipes or corrupts the PE headers in memory">Headers</label>
      <select className="select" value={o.headers} onChange={(e) => set({ ...o, headers: e.target.value as ModuleDumpOptions["headers"] })}>
        <option value="auto">memory, disk if broken</option>
        <option value="memory">memory</option>
        <option value="disk">file on disk</option>
      </select>
      {allowImports && (
        <label className="row" title="rebuild the import table from the live IAT (PE32+; forces the virtual layout)">
          <input type="checkbox" checked={!!o.rebuildImports} onChange={(e) => set({ ...o, rebuildImports: e.target.checked })} />rebuild imports
        </label>
      )}
      <label title="new entry point (RVA, hex), e.g. the OEP from the Unpack tab">OEP</label>
      <input className="dump-input" style={{ width: 90 }} placeholder="RVA" value={o.oepRva === undefined ? "" : o.oepRva.toString(16)}
        onChange={(e) => { const v = e.target.value.trim().replace(/^0x/i, ""); set({ ...o, oepRva: v && /^[0-9a-f]+$/i.test(v) ? parseInt(v, 16) : undefined }); }} />
    </div>
  );
}

function Report({ d, path }: { d: ModuleDump; path: string | null }) {
  const r = d.report;
  return (
    <div className="dump-section">
      <div className="dump-meta">
        <span className="dump-badge ok">{r.layout} layout</span>
        <span className="dump-badge">{fmtBytes(r.size)}</span>
        <span className="dump-badge">ImageBase {r.imageBase}</span>
        <span className="dump-badge">entry +0x{r.entryRva.toString(16)}</span>
        <span className="dump-badge">checksum 0x{r.checksum.toString(16)}</span>
        <span className={`dump-badge ${r.headerSource === "disk" ? "warn" : ""}`}>headers from {r.headerSource}</span>
        {r.imports !== undefined && <span className="dump-badge ok">{r.imports} imports rebuilt</span>}
        <span className={`dump-badge ${r.badPages ? "warn" : "faint"}`}>{r.badPages} unreadable pages</span>
      </div>
      {path && <div className="dump-result ok">Saved → <code>{path}</code></div>}
      {r.warnings.map((w) => <div key={w} className="warn" style={{ fontSize: 12 }}>{w}</div>)}
      <table className="table mono" style={{ fontSize: 12 }}>
        <thead><tr><th>section</th><th>rva</th><th>vsize</th><th>raw ptr</th><th>raw size</th><th>bad pages</th></tr></thead>
        <tbody>
          {r.sections.map((s) => (
            <tr key={`${s.name}${s.rva}`}>
              <td>{s.name}</td><td>0x{s.rva.toString(16)}</td><td>0x{s.vsize.toString(16)}</td><td>0x{s.rawPtr.toString(16)}</td><td>0x{s.rawSize.toString(16)}</td>
              <td className={s.badPages ? "warn" : "faint"}>{s.badPages}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Runs one image dump with progress and saves it; shared by the module, hidden-image and driver panels. */
function useImageDump() {
  const modules = useConn((s) => s.modules);
  const [busy, setBusy] = useState<string | null>(null);
  const [prog, setProg] = useState(0);
  const [last, setLast] = useState<{ d: ModuleDump; path: string | null } | null>(null);
  const run = async (t: Parameters<typeof dumpImage>[0], o: Omit<ModuleDumpOptions, "onProgress" | "cancel">) => {
    setBusy(t.name || fmtAddr(t.base));
    setProg(0);
    try {
      const d = await dumpImage(t, modules, { ...o, onProgress: (a, b) => setProg(a / b) });
      const path = await saveBinary(dumpName(d.name, t.base), d.bytes);
      setLast({ d, path });
      log(d.report.warnings.length ? "warn" : "info", "dump", `${d.name || fmtAddr(t.base)}: ${fmtBytes(d.bytes.length)} ${d.report.layout} layout${d.report.badPages ? `, ${d.report.badPages} unreadable pages` : ""}${path ? ` → ${path}` : ""}`);
    } catch (e) {
      log("error", "dump", errText(e));
    } finally {
      setBusy(null);
    }
  };
  return { busy, prog, last, run };
}

const kDefaults: Omit<ModuleDumpOptions, "onProgress" | "cancel"> = { layout: "file", headers: "auto" };

export function ModuleDumpPanel() {
  const { modules, target } = useConn();
  const focused = useUi((s) => s.module);
  const [name, setName] = useState<string>(focused ?? "");
  const [o, setO] = useState(kDefaults);
  const [addr, setAddr] = useState("");
  const { busy, prog, last, run } = useImageDump();
  const m = modules.find((x) => x.name === name) ?? modules.find((x) => x.base === target?.base) ?? modules[0];
  const dumpAt = () => {
    const a = parseAddress(addr, modules);
    if (a === null) return log("warn", "dump", `cannot parse ${addr}`);
    void run({ name: "", base: a }, o);
  };
  return (
    <div className="dump-panel">
      <p className="dump-blurb">
        Dump a loaded module from memory into a PE that loads and disassembles (x64dbg / Scylla style): every readable page (a page that is not resident costs 4 KiB, not the whole read), ImageBase set to where it was dumped, the section table rewritten for the layout, debug-directory offsets fixed,
        the signature table dropped, the checksum recomputed; headers wiped by anti-dump code come from the file on disk. Reads go through the
        attached backend, so nothing touches the target.
      </p>
      <div className="dump-form">
        <label>Module</label>
        <select className="select" style={{ minWidth: 220 }} value={m?.name ?? ""} onChange={(e) => setName(e.target.value)}>
          {modules.map((x) => <option key={x.base} value={x.name}>{x.name} · {x.base}</option>)}
        </select>
        <button className="dump-btn" disabled={!m || !!busy} onClick={() => m && void run({ name: m.name, base: toBig(m.base), size: m.size, module: m }, o)}>
          {busy ? <RefreshCw size={13} className="spin" /> : <Archive size={13} />} Dump module
        </button>
      </div>
      <DumpOptionsForm o={o} set={setO} />
      <div className="dump-form">
        <label title="a PE image anywhere in memory: a manually mapped DLL, an unpacked payload (size from its headers)">Image at address</label>
        <input className="dump-input" style={{ width: 200 }} placeholder="0x… · module+0x…" value={addr} onChange={(e) => setAddr(e.target.value)} onKeyDown={(e) => e.key === "Enter" && dumpAt()} />
        <button className="dump-btn" disabled={!addr.trim() || !!busy} onClick={dumpAt}><Archive size={13} /> Dump image</button>
      </div>
      {busy && <div className="row"><span className="faint" style={{ fontSize: 12 }}>reading {busy}…</span><Progress value={prog} /></div>}
      {last && <Report d={last.d} path={last.path} />}
    </div>
  );
}

export function HiddenImagesPanel() {
  const modules = useConn((s) => s.modules);
  const [found, setFound] = useState<FoundImage[] | null>(null);
  const [scanning, setScanning] = useState(false);
  const [prog, setProg] = useState(0);
  const [all, setAll] = useState(false);
  const [o, setO] = useState(kDefaults);
  const { busy, prog: dprog, last, run } = useImageDump();
  const scan = async () => {
    setScanning(true);
    try {
      const f = await findHiddenImages(modules, (a, b) => setProg(a / b));
      setFound(f);
      const hidden = f.filter((x) => !x.listed).length;
      log(hidden ? "warn" : "info", "dump", `${hidden} image(s) or code region(s) outside the module list`);
    } catch (e) {
      log("error", "dump", errText(e));
    } finally {
      setScanning(false);
    }
  };
  const shown = (found ?? []).filter((f) => all || !f.listed);
  return (
    <div className="dump-panel">
      <p className="dump-blurb">
        Walks every region and looks for PE headers the loader's module list does not account for (manually mapped DLLs, unpacked or injected
        images), and for executable memory outside every module with no headers at all (code copied without them, or headers wiped).
        Dump any PE found as a module.
      </p>
      <div className="dump-form">
        <button className="dump-btn" disabled={scanning} onClick={() => void scan()}>{scanning ? <RefreshCw size={13} className="spin" /> : <Search size={13} />} Scan memory</button>
        <label className="row"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />show listed modules too</label>
        {scanning && <Progress value={prog} />}
      </div>
      <DumpOptionsForm o={o} set={setO} allowImports={false} />
      {found && (
        <table className="table mono" style={{ fontSize: 12 }}>
          <thead><tr><th>base</th><th>size</th><th>kind</th><th></th><th></th></tr></thead>
          <tbody>
            {shown.length === 0 && <tr><td colSpan={5} className="faint">nothing outside the module list</td></tr>}
            {shown.map((f) => (
              <tr key={f.base.toString()}>
                <td>{fmtAddr(f.base)}</td>
                <td>{fmtBytes(f.size)}</td>
                <td className={f.listed ? "faint" : "warn"}>{f.kind === "pe" ? `${f.listed ? "module" : "unlisted PE"}${f.is64 === false ? " (PE32)" : ""}` : "code, no headers"}</td>
                <td className="faint ellipsis">{f.reason ?? (f.timestamp ? new Date(f.timestamp * 1000).toISOString().slice(0, 10) : "")}</td>
                <td>{f.kind === "pe" && <button className="row-action" disabled={!!busy} onClick={() => void run({ name: "", base: f.base, size: f.size }, o)}>dump</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {busy && <div className="row"><span className="faint" style={{ fontSize: 12 }}>reading {busy}…</span><Progress value={dprog} /></div>}
      {last && <Report d={last.d} path={last.path} />}
    </div>
  );
}

export function DriversPanel() {
  const [list, setList] = useState<{ modules: KernelModule[]; source: string; note?: string } | null>(null);
  const [filter, setFilter] = useState("");
  const [o, setO] = useState<Omit<ModuleDumpOptions, "onProgress" | "cancel">>({ layout: "file", headers: "memory" });
  const { busy, prog, last, run } = useImageDump();
  const load = async () => {
    try {
      setList(await kernelModules());
    } catch (e) {
      log("error", "dump", errText(e));
    }
  };
  useEffect(() => { void load(); }, []);
  const shown = useMemo(() => (list?.modules ?? []).filter((m) => !filter || `${m.name} ${m.path}`.toLowerCase().includes(filter.toLowerCase())), [list, filter]);
  return (
    <div className="dump-panel">
      <p className="dump-blurb">
        The machine's kernel drivers (Windows: <code>NtQuerySystemInformation</code>, which reports image bases only to an elevated EchoDebug;
        Linux: <code>/proc/modules</code>), dumped through the attached backend's reads like a module: INIT and other discarded sections come back
        as unreadable pages, the checksum is recomputed so the image is valid again. Reading kernel addresses is not part of Echo's documented
        API (its reads go through the attached process's address space), so whether this works depends on your Echo build and system; the
        local /proc backend cannot. If no page reads, it says so.
      </p>
      <div className="dump-form">
        <button className="dump-btn" onClick={() => void load()}><RefreshCw size={13} /> Reload</button>
        <input className="dump-input dump-input-wide" placeholder="filter drivers…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        {list && <span className="faint">{list.modules.length} from {list.source}</span>}
      </div>
      {list?.note && <div className="warn" style={{ fontSize: 12 }}>{list.note}</div>}
      <DumpOptionsForm o={o} set={setO} allowImports={false} />
      <table className="table mono" style={{ fontSize: 12 }}>
        <thead><tr><th>driver</th><th>base</th><th>size</th><th>path</th><th></th></tr></thead>
        <tbody>
          {shown.slice(0, 1000).map((m) => (
            <tr key={`${m.name}${m.base}`}>
              <td>{m.name}</td><td>{m.base}</td><td>{fmtBytes(m.size)}</td><td className="faint ellipsis">{m.path}</td>
              <td><button className="row-action" disabled={!!busy || toBig(m.base) === 0n} title={toBig(m.base) === 0n ? "the kernel did not report its base" : undefined}
                onClick={() => void run({ name: m.name, base: toBig(m.base), size: m.size }, o)}>dump</button></td>
            </tr>
          ))}
        </tbody>
      </table>
      {busy && <div className="row"><span className="faint" style={{ fontSize: 12 }}>reading {busy}…</span><Progress value={prog} /></div>}
      {last && <Report d={last.d} path={last.path} />}
    </div>
  );
}

export function TargetDumpPanel() {
  const { modules, target } = useConn();
  const [format, setFormat] = useState<"minidump" | "elf">("minidump");
  const [include, setInclude] = useState<"all" | "writable+images">("all");
  const [maxMiB, setMaxMiB] = useState(0);
  const [prog, setProg] = useState<{ done: number; total: number; phase: string } | null>(null);
  const [res, setRes] = useState<TargetDumpReport | null>(null);
  const cancel = useRef<Cancel>({ aborted: false });
  useEffect(() => { void defaultFormat(modules as Module[], target?.base).then(setFormat).catch(() => {}); }, [target?.base, modules.length]);
  const run = async () => {
    const base = (target?.name ?? modules[0]?.name ?? "target").replace(/\.[^.]+$/, "");
    const sink = await pickSink(format === "minidump" ? `${base}.dmp` : `${base}.core`);
    if (!sink) return;
    cancel.current = { aborted: false };
    setRes(null);
    setProg({ done: 0, total: 1, phase: "starting" });
    try {
      const r = await dumpTarget(modules, { pid: target?.pid, name: target?.name, arch: target?.arch }, { format, include, maxRegionMiB: maxMiB, sink, cancel: cancel.current, onProgress: (done, total, phase) => setProg({ done, total, phase }) });
      setRes(r);
      log(r.badPages ? "warn" : "info", "dump", `${r.format}: ${r.regions} regions, ${fmtBytes(r.bytes)}${r.badPages ? `, ${r.badPages} unreadable pages zero-filled` : ""} → ${r.path}`);
    } catch (e) {
      log("error", "dump", errText(e));
    } finally {
      setProg(null);
    }
  };
  return (
    <div className="dump-panel">
      <p className="dump-blurb">
        The whole target from memory through the attached backend (no OpenProcess, nothing the target can notice): every present region,
        streamed to disk region by region, as a full-memory <b>MINIDUMP</b> (WinDbg, x64dbg, the Open Dump tab; the module list carries
        CodeView records so WinDbg finds the symbols) or an <b>ELF core</b> (gdb). Thread contexts are not part of it — memory reads cannot see them.
      </p>
      <div className="dump-form">
        <label>Format</label>
        <select className="select" value={format} onChange={(e) => setFormat(e.target.value as "minidump" | "elf")}>
          <option value="minidump">MINIDUMP (.dmp)</option>
          <option value="elf">ELF core</option>
        </select>
        <label>Regions</label>
        <select className="select" value={include} onChange={(e) => setInclude(e.target.value as "all" | "writable+images")}>
          <option value="all">every readable region</option>
          <option value="writable+images">writable, executable and module regions</option>
        </select>
        <label title="0: no limit">Skip regions over</label>
        <input className="dump-input" style={{ width: 70 }} value={maxMiB} onChange={(e) => setMaxMiB(Math.max(0, Number(e.target.value) || 0))} /> MiB
        {prog
          ? <button className="dump-btn" onClick={() => { cancel.current.aborted = true; }}><Square size={13} /> Cancel</button>
          : <button className="dump-btn" disabled={!target} onClick={() => void run()}><HardDrive size={13} /> Dump target</button>}
      </div>
      {prog && <div className="row"><span className="faint" style={{ fontSize: 12 }}>{prog.phase} · {fmtBytes(prog.done)} / {fmtBytes(prog.total)}</span><Progress value={prog.done / Math.max(1, prog.total)} /></div>}
      {res && (
        <div className="dump-section">
          <div className="dump-result ok">Saved {fmtBytes(res.bytes)} → <code>{res.path}</code></div>
          <div className="dump-meta">
            <span className="dump-badge ok">{res.format}</span>
            <span className="dump-badge">{res.regions} regions</span>
            <span className="dump-badge">{res.modules} modules</span>
            <span className={`dump-badge ${res.badPages ? "warn" : "faint"}`}>{res.badPages} unreadable pages</span>
            {res.skipped > 0 && <span className="dump-badge faint">{res.skipped} regions skipped</span>}
          </div>
        </div>
      )}
    </div>
  );
}
