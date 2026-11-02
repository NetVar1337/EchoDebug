import { useState } from "react";
import { Copy, Download, HeartPulse, Save, Search, Trash2, Upload, X } from "lucide-react";
import { request } from "@/lib/client";
import { fmtAddr, hexToBytes, labelAddr, moduleOf, parseAddress, toBig } from "@/lib/hex";
import { loadImage, readBytes } from "@/lib/memory";
import { makeSignature, toByteArray, toCode, toIda, trim, type Insn, type Pattern } from "@/lib/analysis/sigmaker";
import { flirtArchName, matchFlirt, parseFlirtFile } from "@/lib/analysis/flirt";
import { executableRanges } from "@/lib/analysis/xrefindex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useFlirt } from "@/store/flirt";
import { useSigs, toYara } from "@/store/sigs";
import { sigHits as hits } from "@/store/projects";
import { classify, findModule, type ScanStatus } from "@/lib/projects";
import { saveTextFile } from "@/lib/session";
import { useUi } from "@/store/ui";
import { isTauri, pickBinaryFile } from "@/lib/tauri";
import { CommitInput, IconButton, NeedsAgent, copy } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

type Health = { id: string; name: string; module: string; oldRva: string | null; newRva?: string; hits: number; status: ScanStatus | "unloaded" };

const kHealthLabel: Record<Health["status"], string> = { same: "OK", moved: "moved", multiple: "multiple", broken: "broken", unloaded: "module not loaded" };

export default function SignaturesView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const catalog = useSigs();
  const flirt = useFlirt();
  const focused = useFocusedModule();
  const [mode, setMode] = useState<"code" | "raw">("code");
  const [pattern, setPattern] = useState<Pattern>([]);
  const [orig, setOrig] = useState<number[]>([]); // un-wildcarded bytes, so toggles can restore them
  const [found, setFound] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [scanQ, setScanQ] = useState("");
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  const [catalogFilter, setCatalogFilter] = useState("");
  const [health, setHealth] = useState<Health[] | null>(null);
  const addr = ui.sigAt ? parseAddress(ui.sigAt, modules) : null;
  const mod = addr !== null ? moduleOf(addr, modules) : undefined;

  const generate = async () => {
    if (addr === null || !mod) return log("warn", "sig", "pick an address inside a module");
    setBusy(true);
    setFound(null);
    let insns: Insn[] = [];
    if (mode === "code") {
      const r = await attempt("sig", request<{ results: Insn[] }>("disassemble", { address: fmtAddr(addr), size: 0x200 }));
      insns = r?.results ?? [];
    } else {
      const b = await attempt("sig", readBytes(addr, 128));
      insns = b ? Array.from(b, (x, i) => ({ address: fmtAddr(addr + BigInt(i)), length: 1, bytes: x.toString(16).padStart(2, "0"), text: "" })) : [];
    }
    const r = await attempt("sig", makeSignature(insns, async (p) => (await hits(p, mod.name)).length));
    setBusy(false);
    if (!r) return log("warn", "sig", "no unique signature within the scanned range");
    setPattern(r.pattern);
    setOrig(Array.from(hexToBytes(insns.map((i) => i.bytes).join(""))));
    setFound([fmtAddr(addr)]);
    log("info", "sig", `unique ${r.pattern.length}-byte signature for ${labelAddr(fmtAddr(addr), modules)}`);
  };

  const test = async (p: string) => {
    const m = mod?.name ?? modules[0]?.name;
    if (!m) return;
    const r = await attempt("sig", hits(p, m));
    if (r) { setFound(r); log("info", "sig", `${r.length} hits in ${m}`); }
  };

  const save = () => {
    if (!pattern.length) return log("warn", "sig", "generate a signature first");
    catalog.add({
      name: name.trim() || `sig_${pattern.length}`,
      address: ui.sigAt ?? "",
      module: mod?.name ?? "",
      pattern: trim(pattern),
      note: note.trim(),
      hits: found?.length ?? 0,
    });
    log("info", "sig", `saved "${name.trim() || `sig_${pattern.length}`}" to the catalog`);
    setName("");
    setNote("");
  };

  /** Re-scans every saved signature in its module and compares the match with the RVA it was saved at. */
  const checkAll = async () => {
    setBusy(true);
    const out: Health[] = [];
    for (const s of catalog.sigs) {
      const module = s.anchor?.module ?? s.module;
      const m = findModule(module, modules);
      const row: Health = { id: s.id, name: s.name, module, oldRva: s.anchor?.rva ?? null, hits: 0, status: "unloaded" };
      if (m) {
        const at = row.oldRva === null ? parseAddress(s.address, modules) : null;
        if (at !== null && moduleOf(at, modules) === m) row.oldRva = fmtAddr(at - toBig(m.base));
        const found = (await attempt("sig", hits(s.ida, m.name))) ?? [];
        const c = classify(row.oldRva === null ? null : toBig(row.oldRva), found.map((h) => toBig(h) - toBig(m.base)));
        Object.assign(row, { hits: found.length, status: c.status, newRva: c.newRva === undefined ? undefined : fmtAddr(c.newRva) });
        catalog.update(s.id, { hits: found.length });
      }
      out.push(row);
    }
    setBusy(false);
    setHealth(out);
    const n = (k: Health["status"]) => out.filter((r) => r.status === k).length;
    log("info", "sig", `health: ${n("same")} OK, ${n("moved")} moved, ${n("multiple")} multiple, ${n("broken")} broken${n("unloaded") ? `, ${n("unloaded")} not loaded` : ""}`);
  };

  /** Points every moved signature at its new match; the anchor follows the address. */
  const updateMoved = () => {
    if (!health) return;
    for (const r of health) {
      const m = findModule(r.module, modules);
      if (r.status === "moved" && r.newRva && m) catalog.update(r.id, { address: fmtAddr(toBig(m.base) + toBig(r.newRva)) });
    }
    setHealth(health.map((r) => (r.status === "moved" ? { ...r, status: "same", oldRva: r.newRva ?? r.oldRva } : r)));
  };

  const exportHealth = () => {
    if (health) void attempt("sig", saveTextFile("echodebug-signature-health.json", JSON.stringify({ checkedAt: new Date().toISOString(), signatures: health }, null, 2), "Signature health report"));
  };

  const ida = toIda(trim(pattern));
  const code = toCode(trim(pattern));
  const formats: [string, string][] = pattern.length ? [["IDA", ida], ["Bytes", code.bytes], ["Mask", code.mask], ["Array", toByteArray(trim(pattern))]] : [];
  const shown = catalog.sigs.filter((s) => {
    const f = catalogFilter.toLowerCase();
    return !f || s.name.toLowerCase().includes(f) || s.note.toLowerCase().includes(f) || s.module.toLowerCase().includes(f);
  });

  /** Loads a FLIRT signature file and matches it against the focused module. */
  const loadFlirt = async (bytes: Uint8Array, fileName: string) => {
    try {
      const sig = await parseFlirtFile(bytes);
      flirt.set(fileName, sig);
      log("info", "flirt", `${fileName}: ${sig.libraryName || "signature set"} (${flirtArchName(sig.arch)})`);
      await applyFlirt();
    } catch (e) {
      flirt.clear();
      log("error", "flirt", `${fileName}: ${(e as Error).message}`);
    }
  };

  /** Matches the loaded signature set against the focused module image. */
  const applyFlirt = async () => {
    if (!flirt.signature || !focused) return;
    const img = await attempt("flirt", loadImage(focused));
    if (!img) return;
    const matches = matchFlirt(flirt.signature, img, BigInt(focused.base), executableRanges(img));
    flirt.setMatches(matches);
    const verified = matches.filter((m) => m.crcVerified).length;
    log("info", "flirt", `${matches.length} matches in ${focused.name}${verified ? ` (${verified} CRC verified)` : ""}`);
  };

  const pickFlirt = async () => {
    if (isTauri()) {
      const picked = await pickBinaryFile(["sig"], "FLIRT signature file");
      if (picked) await loadFlirt(picked.bytes, picked.name);
      return;
    }
    // Browser fallback: a file input.
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".sig";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      await loadFlirt(new Uint8Array(await file.arrayBuffer()), file.name);
    };
    input.click();
  };

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "300px" }}>
        <div className="list-col">
          <div className="toolbar">
            <span className="panel-title grow">Catalog</span>
            <span className="faint" style={{ fontSize: 12 }}>{catalog.sigs.length}</span>
            <IconButton tip="Check all: re-scan every saved signature in the loaded modules" disabled={busy || !catalog.sigs.length} onClick={() => void checkAll()}><HeartPulse size={13} /></IconButton>
          </div>
          <div className="toolbar">
            <label className="search grow"><Search size={13} /><input placeholder="Filter…" value={catalogFilter} onChange={(e) => setCatalogFilter(e.target.value)} /></label>
          </div>
          <div className="vlist">
            {shown.length === 0 && <div className="panel-section faint">No saved signatures. Generate one and press Save.</div>}
            {shown.map((s) => (
              <div key={s.id} className="fn-row" onClick={() => { setPattern(s.pattern); setFound(null); }} onDoubleClick={() => void test(s.ida)}>
                <span className="grow ellipsis">{s.name}</span>
                {s.hits > 1 && <span className="warn">{s.hits}</span>}
                <IconButton tip="Delete" onClick={(e) => { e.stopPropagation(); catalog.remove(s.id); }}><Trash2 size={12} /></IconButton>
              </div>
            ))}
          </div>
        </div>
        <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
          <div className="toolbar">
            <CommitInput value={ui.sigAt ?? ""} placeholder="address to sign" onCommit={(v) => ui.goSig(v)} width={230} />
            <select className="select" value={mode} onChange={(e) => setMode(e.target.value as "code" | "raw")}><option value="code">Code</option><option value="raw">Raw bytes</option></select>
            <button className="btn primary" disabled={busy || addr === null} onClick={() => void generate()}>{busy ? "Searching…" : "Generate unique"}</button>
            <span className="mono faint ellipsis grow">{addr !== null ? labelAddr(fmtAddr(addr), modules) : ""}</span>
          </div>
          <div className="vlist">
            {health && (
              <div className="panel-section">
                <div className="row">
                  <span className="label grow">Signature health · {health.length} checked</span>
                  <button className="btn small" disabled={!health.some((r) => r.status === "moved")} onClick={updateMoved}>Update {health.filter((r) => r.status === "moved").length} moved</button>
                  <button className="btn small" onClick={exportHealth}><Download size={12} /> Report</button>
                  <IconButton tip="Close report" onClick={() => setHealth(null)}><X size={12} /></IconButton>
                </div>
                <table className="table mono">
                  <thead><tr><th>Signature</th><th>Status</th><th>RVA</th><th>Hits</th></tr></thead>
                  <tbody>
                    {health.map((r) => (
                      <tr key={r.id}>
                        <td className="ellipsis">{r.name} <span className="faint">{r.module}</span></td>
                        <td className={r.status === "same" ? "" : "warn"}>{kHealthLabel[r.status]}</td>
                        <td className="dim">{r.status === "moved" ? `${r.oldRva ?? "?"} → ${r.newRva}` : r.oldRva ?? "—"}</td>
                        <td className="dim">{r.status === "unloaded" ? "—" : r.hits}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {pattern.length > 0 && (
              <div className="panel-section">
                <div className="label">Pattern · click a byte to toggle wildcard</div>
                <div className="row wrap mono">
                  {pattern.map((b, i) => (
                    <button key={i} className="pill" style={{ minWidth: 26, color: b === null ? "var(--text-faint)" : "var(--text)" }}
                      onClick={() => setPattern(pattern.map((x, j) => (j === i ? (x === null ? orig[i] ?? 0 : null) : x)))}>
                      {b === null ? "??" : b.toString(16).toUpperCase().padStart(2, "0")}
                    </button>
                  ))}
                </div>
                {formats.map(([k, v]) => (
                  <div key={k} className="row">
                    <span className="label" style={{ width: 50 }}>{k}</span>
                    <span className="mono selectable grow ellipsis" title={v}>{v}</span>
                    <IconButton tip={`Copy ${k}`} onClick={() => void copy(v)}><Copy size={13} /></IconButton>
                  </div>
                ))}
                <div className="row wrap">
                  <input className="input" style={{ width: 160 }} value={name} onChange={(e) => setName(e.target.value)} placeholder="name" />
                  <input className="input grow" value={note} onChange={(e) => setNote(e.target.value)} placeholder="note" />
                  <button className="btn" onClick={() => void copy(toYara(name || "sig", trim(pattern)))}>YARA</button>
                  <button className="btn" onClick={save}><Save size={12} /> Save</button>
                </div>
                <div className="row">
                  <button className="btn" onClick={() => void test(ida)}>Test in {mod?.name ?? "module"}</button>
                </div>
              </div>
            )}
            <div className="panel-section">
              <div className="label">Scan an existing pattern</div>
              <div className="row">
                <input className="input mono grow" placeholder="48 8B 05 ? ? ? ? 48 85 C0" value={scanQ} onChange={(e) => setScanQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void test(scanQ)} />
                <button className="btn" onClick={() => void test(scanQ)}>Scan</button>
              </div>
            </div>
            {found && (
              <table className="table mono">
                <thead><tr><th>{found.length} hit{found.length === 1 ? "" : "s"}</th></tr></thead>
                <tbody>{found.map((a) => <tr key={a} onClick={() => ui.select(a)} onDoubleClick={() => ui.goDisasm(a)}><td className="link">{labelAddr(a, modules)}</td></tr>)}</tbody>
              </table>
            )}
            <div className="panel-section">
              <div className="label">FLIRT signature set</div>
              <div className="row">
                <ModulePicker />
                <button className="btn" onClick={() => void pickFlirt()}><Upload size={12} /> Load .sig</button>
                {flirt.fileName && <button className="btn" onClick={() => void applyFlirt()}>Re-scan</button>}
                <span className="faint mono ellipsis grow">
                  {flirt.fileName ? `${flirt.fileName} · ${flirt.signature?.libraryName || "?"} · ${flirt.matches.length} matches` : "no signature set loaded"}
                </span>
              </div>
              {flirt.matches.length > 0 && (
                <table className="table mono">
                  <thead><tr><th>Address</th><th>Function</th><th>Size</th></tr></thead>
                  <tbody>
                    {flirt.matches.map((m) => (
                      <tr key={`${m.rva}-${m.name}`} onClick={() => ui.goDisasm(m.address)}>
                        <td className="link">{labelAddr(m.address, modules)}</td>
                        <td>{m.name}{m.crcVerified ? <span className="faint"> ✓</span> : null}</td>
                        <td className="dim">{m.functionLength ? "0x" + m.functionLength.toString(16) : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </NeedsAgent>
  );
}
