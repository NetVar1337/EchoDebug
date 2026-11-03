// Patch journal: every write EchoDebug made to the target, with the bytes
// that were there before, and a one-click revert.
import { useState } from "react";
import { Download, Trash2, Undo2 } from "lucide-react";
import { request } from "@/lib/client";
import { bytesToHex, fmtAddr, labelAddr, parseAddress } from "@/lib/hex";
import { readBytes } from "@/lib/memory";
import { useConn } from "@/store/conn";
import { usePatches } from "@/store/patches";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, IconButton, NeedsAgent } from "../ui";
import { applyPatchSet, toPatchSet, useAutoPatches, type PatchSet } from "@/lib/patchsets";
import { saveBinary, saveText } from "@/lib/save";
import { apply1337, journalBytePatches, patchedModuleFile } from "@/lib/patchfilelive";
import { parse1337, to1337 } from "@/lib/analysis/patchfile";

async function pickText(accept: string): Promise<string | null> {
  const input = Object.assign(document.createElement("input"), { type: "file", accept });
  const { promise, resolve } = Promise.withResolvers<File | null>();
  input.onchange = () => resolve(input.files?.[0] ?? null);
  input.click();
  const f = await promise;
  return f ? f.text() : null;
}

async function pickSet(): Promise<PatchSet | null> {
  const input = Object.assign(document.createElement("input"), { type: "file", accept: ".json,.edpatch" });
  const { promise, resolve } = Promise.withResolvers<File | null>();
  input.onchange = () => resolve(input.files?.[0] ?? null);
  input.click();
  const f = await promise;
  return f ? (JSON.parse(await f.text()) as PatchSet) : null;
}

export default function PatchesView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const patches = usePatches();
  const [at, setAt] = useState(ui.selected ?? "");
  const [hex, setHex] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const auto = useAutoPatches();
  const [setName, setSetName] = useState("my-patches");
  const [report, setReport] = useState("");

  const saveSet = async () => {
    const s = await toPatchSet(setName, patches.pending(), modules);
    if (!s.entries.length) return log("warn", "patches", "no active patches inside a module (heap patches cannot be replayed)");
    await saveText(`${setName}.edpatch`, JSON.stringify(s, null, 1));
  };
  const keepSet = async () => {
    const s = await toPatchSet(setName, patches.pending(), modules);
    if (!s.entries.length) return log("warn", "patches", "no active patches inside a module");
    auto.add(s);
    log("info", "patches", `${setName}: ${s.entries.length} patches re-applied on every attach of these builds`);
  };
  const importSet = async (force = false) => {
    const s = await pickSet().catch((e) => { log("error", "patches", String(e)); return null; });
    if (!s) return;
    const r = await attempt("patches", applyPatchSet(s, modules, { force }));
    if (!r) return;
    const text = `${s.name}: ${r.applied} applied, ${r.already} already in place, ${r.conflicts.length} conflicts${r.missing.length ? `, ${r.missing.length} for modules not loaded` : ""}${r.otherBuild ? `, ${r.otherBuild} on a different build` : ""}`;
    setReport(text + (r.conflicts.length ? ` — conflicts at ${r.conflicts.slice(0, 4).map((c) => `${c.entry.module}+0x${c.entry.rva.toString(16)} (found ${c.found || "unreadable"})`).join(", ")}` : ""));
    log(r.conflicts.length ? "warn" : "info", "patches", text);
  };

  // x64dbg: .1337 patch files and Patch file
  const bytes = journalBytePatches(patches.pending(), modules);
  const patchedMods = [...new Set(bytes.patches.map((p) => p.module))];
  const [fileMod, setFileMod] = useState("");
  const export1337 = async () => {
    if (!bytes.patches.length) return log("warn", "patches", "no active patches inside a module");
    const name = (patchedMods[0] ?? "patches").replace(/\.[^.]+$/, "");
    await saveText(`${name}.1337`, to1337(bytes.patches), { name: "x64dbg patch", extensions: ["1337"] });
    if (bytes.outside) log("warn", "patches", `${bytes.outside} patch(es) outside every module left out (a .1337 file is module + RVA)`);
  };
  const import1337 = async (force = false) => {
    const text = await pickText(".1337,.txt");
    if (text === null) return;
    const { patches: list, errors } = parse1337(text);
    if (errors.length) log("warn", "patches", `.1337: ${errors.slice(0, 5).join("; ")}${errors.length > 5 ? ` (+${errors.length - 5})` : ""}`);
    const r = await attempt("patches", apply1337(list, modules, force));
    if (!r) return;
    const msg = `.1337: ${r.applied} bytes patched, ${r.already} already in place, ${r.conflicts.length} conflicts${r.missing.length ? `, modules not loaded: ${r.missing.join(", ")}` : ""}`;
    setReport(msg + (r.conflicts.length ? ` — e.g. ${r.conflicts.slice(0, 3).map((c) => `${c.module}+0x${c.rva.toString(16)} has ${c.found === null ? "??" : c.found.toString(16).padStart(2, "0")}, expected ${c.expected.toString(16).padStart(2, "0")}`).join(", ")}` : ""));
    log(r.conflicts.length ? "warn" : "info", "patches", msg);
  };
  const patchFileOnDisk = async () => {
    const m = modules.find((x) => x.name === (fileMod || patchedMods[0]));
    if (!m) return;
    const r = await attempt("patch file", patchedModuleFile(m, bytes.patches));
    if (!r) return;
    const path = await saveBinary(m.name.replace(/(\.[^.]+)?$/, "_patched$1"), r.bytes);
    const rep = r.report;
    const msg = `${m.name}: ${rep.applied} bytes written into a copy of ${r.path}${path ? ` → ${path}` : ""}${rep.outside.length ? `; ${rep.outside.length} not in the file (no raw data there)` : ""}${rep.differed.length ? `; ${rep.differed.length} where the file differs from memory (relocated addresses: check them)` : ""}`;
    setReport(msg);
    log(rep.differed.length || rep.outside.length ? "warn" : "info", "patches", msg);
  };

  /** Writes bytes and records the previous content so the write can be undone. */
  const apply = async () => {
    const addr = parseAddress(at, modules);
    if (addr === null) return log("warn", "patch", `cannot parse ${at}`);
    const clean = hex.replace(/[^0-9a-f]/gi, "").toLowerCase();
    if (!clean || clean.length % 2 !== 0) return log("warn", "patch", "need an even number of hex digits");
    const before = await attempt("patch", readBytes(addr, clean.length / 2));
    if (!before) return log("error", "patch", "could not read the current bytes");
    setBusy(true);
    const ok = await attempt("patch", request("write", { address: fmtAddr(addr), data: clean }));
    setBusy(false);
    if (!ok) return;
    patches.add({
      id: Math.random().toString(36).slice(2, 10),
      address: fmtAddr(addr),
      written: clean,
      before: bytesToHex(before),
      note,
      created: Date.now(),
      reverted: false,
    });
    log("info", "patch", `wrote ${clean.length / 2} bytes at ${fmtAddr(addr)}`);
    setHex("");
    setNote("");
  };

  const revert = async (id: string) => {
    const p = patches.patches.find((x) => x.id === id);
    if (!p) return;
    const ok = await attempt("patch", request("write", { address: p.address, data: p.before }));
    if (!ok) return;
    patches.revert(id);
    log("info", "patch", `reverted the write at ${p.address}`);
  };

  const exportJson = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(patches.patches, null, 2)], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "echodebug-patches.json" });
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <NeedsAgent ext>
      <div className="split-h" style={{ ["--fn-w" as string]: "400px" }}>
        <div className="list-col vlist">
          <div className="panel-section">
            <div className="label">Write bytes</div>
            <div className="row">
              <CommitInput value={at} placeholder="address · module+0x…" onCommit={setAt} width={200} />
            </div>
            <textarea className="textarea" rows={3} value={hex} onChange={(e) => setHex(e.target.value)} placeholder="bytes to write, hex" />
            <div className="row">
              <input className="input grow" value={note} onChange={(e) => setNote(e.target.value)} placeholder="note (optional)" />
              <button className="btn primary" disabled={busy} onClick={() => void apply()}>{busy ? "Writing…" : "Write"}</button>
            </div>
            <div className="faint" style={{ fontSize: 12 }}>
              The bytes that are there now are recorded first, so every write can be reverted.
            </div>
          </div>
          <div className="panel-section">
            <div className="label">Patch sets</div>
            <div className="row">
              <input className="input grow" value={setName} onChange={(e) => setSetName(e.target.value.replace(/[^\w.-]/g, "_"))} placeholder="set name" />
              <button className="btn small" disabled={!patches.pending().length} onClick={() => void saveSet()}>Save set…</button>
              <button className="btn small" disabled={!patches.pending().length} onClick={() => void keepSet()} title="re-apply on every attach of the same builds">Auto-apply</button>
            </div>
            <div className="row">
              <button className="btn small" onClick={() => void importSet(false)}>Import & apply…</button>
              <button className="btn small" onClick={() => void importSet(true)} title="write even where the original bytes differ">Force…</button>
            </div>
            {report && <div className="faint" style={{ fontSize: 12 }}>{report}</div>}
            {auto.sets.map((s) => (
              <div key={s.name} className="row">
                <span className="mono grow">{s.name}</span>
                <span className="faint">{s.entries.length} patches · {[...new Set(s.entries.map((e) => e.module))].join(", ")}</span>
                <button className="row-action" onClick={() => auto.remove(s.name)}>stop</button>
              </div>
            ))}
            <div className="faint" style={{ fontSize: 12 }}>A set stores each patch as module + RVA with the bytes it replaces; applying checks those bytes first.</div>
          </div>
          <div className="panel-section">
            <div className="label">x64dbg</div>
            <div className="row wrap">
              <button className="btn small" disabled={!bytes.patches.length} onClick={() => void export1337()} title="x64dbg's patch file: >module, then RVA:OLD->NEW per byte">Export .1337</button>
              <button className="btn small" onClick={() => void import1337(false)} title="apply where the original byte is still there">Import .1337…</button>
              <button className="btn small" onClick={() => void import1337(true)} title="write even where the original byte differs">Force…</button>
            </div>
            <div className="row">
              <select className="select grow" value={fileMod || patchedMods[0] || ""} onChange={(e) => setFileMod(e.target.value)} disabled={!patchedMods.length}>
                {patchedMods.length === 0 && <option value="">no patched module</option>}
                {patchedMods.map((m) => <option key={m}>{m}</option>)}
              </select>
              <button className="btn small" disabled={!patchedMods.length} onClick={() => void patchFileOnDisk()} title="write the patches into a copy of the module's file on disk">Patch file…</button>
            </div>
            <div className="faint" style={{ fontSize: 12 }}>{bytes.patches.length} patched bytes in {patchedMods.length} module(s). Patch file maps each RVA to its file offset; bytes the loader relocated are reported.</div>
          </div>
          <div className="panel-section">
            <div className="label">Journal</div>
            <div className="row">
              <span className="faint grow" style={{ fontSize: 12 }}>{patches.patches.length} patches · {patches.pending().length} active</span>
              <button className="btn small" disabled={!patches.patches.length} onClick={exportJson}><Download size={12} /> JSON</button>
              <button className="btn small" disabled={!patches.patches.length} onClick={() => patches.clear()}>clear</button>
            </div>
          </div>
        </div>
        <div className="list-col vlist" style={{ borderRight: "none" }}>
          {patches.patches.length === 0 ? (
            <div className="empty">
              <div className="empty-title">No patches yet.</div>
              <div className="empty-hint">Writes made from the memory view, the watchlist or here are recorded here with their original bytes.</div>
            </div>
          ) : (
            <table className="table mono">
              <colgroup><col style={{ width: 150 }} /><col /><col style={{ width: 90 }} /></colgroup>
              <thead><tr><th>Address</th><th>Change</th><th /></tr></thead>
              <tbody>
                {patches.patches.map((p) => (
                  <tr key={p.id} data-selected={ui.selected === p.address} onClick={() => ui.select(p.address)}>
                    <td className="link">{labelAddr(p.address, modules)}</td>
                    <td>
                      <div className="danger">{p.written}</div>
                      <div className="faint">{p.reverted ? "reverted · was " + p.before : p.before}</div>
                      {p.note && <div className="faint">{p.note}</div>}
                    </td>
                    <td>
                      <IconButton tip={p.reverted ? "Already reverted" : "Revert"} disabled={p.reverted} onClick={() => void revert(p.id)}>
                        <Undo2 size={12} />
                      </IconButton>
                      <IconButton tip="Forget" onClick={() => patches.remove(p.id)}><Trash2 size={12} /></IconButton>
                    </td>
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
