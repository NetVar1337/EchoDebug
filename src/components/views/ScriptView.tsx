// Script console: async JavaScript against the `ed` API, with saved scripts and captured output.
import { useRef, useState } from "react";
import { BookOpen, Play, Plus, Save, Square, Trash2 } from "lucide-react";
import { runScript, show } from "@/lib/scripting";
import { useScripts, type Script } from "@/store/scripts";
import { log } from "@/store/output";
import { IconButton } from "../ui";

const kRef = `ed.request(verb, args)      any relay verb (read, write, sig_scan_ida, …)
ed.ui(verb, args)           app analyses: ui_strings, ui_xrefs_to, ui_cfg, …
ed.read(addr, n)            Uint8Array | null
ed.readU32 / readU64(addr)
ed.write(addr, bytes|hex, note)   journaled (revertable)
ed.disasm(addr, size)       [{address, text, bytes, length}]
ed.modules() / ed.module(name?)
ed.addr("game.exe+0x10")    → bigint
ed.hex(n) / ed.label(addr)
ed.names.get / set / comment / all
ed.toHex / fromHex / big
ed.sleep(ms)
ed.print(...values)
return value                 shown when the script ends`;

export default function ScriptView() {
  const store = useScripts();
  const [cur, setCur] = useState<Script>(store.scripts[0] ?? { id: "new", name: "untitled", code: "" });
  const [out, setOut] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [showRef, setShowRef] = useState(() => { try { return localStorage.getItem("echodebug.script.ref") === "1"; } catch { return false; } });
  const toggleRef = () => { setShowRef(!showRef); try { localStorage.setItem("echodebug.script.ref", showRef ? "0" : "1"); } catch { /* private mode */ } };
  const signal = useRef({ aborted: false });

  const run = async () => {
    signal.current = { aborted: false };
    setRunning(true);
    const lines: string[] = [];
    const print = (...a: unknown[]) => {
      lines.push(a.map(show).join(" "));
      setOut([...lines]);
    };
    const t0 = performance.now();
    try {
      const r = await runScript(cur.code, print, signal.current);
      if (r !== undefined) print("⇒", r);
      print(`— done in ${((performance.now() - t0) / 1000).toFixed(2)} s`);
    } catch (e) {
      print(`✗ ${e instanceof Error ? e.stack ?? e.message : String(e)}`);
    }
    setRunning(false);
  };
  const save = () => {
    store.save(cur);
    log("info", "script", `saved ${cur.name}`);
  };
  const create = () => setCur({ id: Math.random().toString(36).slice(2, 10), name: "untitled", code: "// ed.print(ed.module().name)\n" });

  return (
    <div className="split-h" style={{ gridTemplateColumns: showRef ? "minmax(120px, 170px) minmax(280px, 1fr) minmax(220px, 300px)" : "minmax(120px, 170px) minmax(280px, 1fr)" }}>
      <div className="list-col">
        <div className="toolbar"><span className="panel-title grow">Scripts</span><IconButton tip="New script" onClick={create}><Plus size={14} /></IconButton></div>
        <div className="vlist">
          {store.scripts.map((s) => (
            <div key={s.id} className="fn-row" data-selected={cur.id === s.id} onClick={() => setCur(s)}>
              <span className="grow ellipsis">{s.name}</span>
              <button className="row-action" onClick={(e) => { e.stopPropagation(); store.remove(s.id); }}><Trash2 size={11} /></button>
            </div>
          ))}
        </div>
      </div>
      <div className="list-col">
        <div className="toolbar">
          <input className="input" style={{ width: 180, minWidth: 80, flexShrink: 1 }} value={cur.name} onChange={(e) => setCur({ ...cur, name: e.target.value })} />
          <IconButton tip="Run (Ctrl+Enter)" onClick={() => void run()} disabled={running}><Play size={14} /></IconButton>
          <IconButton tip="Stop" onClick={() => { signal.current.aborted = true; }} disabled={!running}><Square size={14} /></IconButton>
          <IconButton tip="Save" onClick={save}><Save size={14} /></IconButton>
          <span className="grow" />
          <span className="faint ellipsis" style={{ fontSize: 12, minWidth: 0 }} title="Scripts run in the app with full access to the target">full access to the target</span>
          <IconButton tip={showRef ? "Hide the API reference" : "Show the API reference"} onClick={toggleRef}><BookOpen size={14} /></IconButton>
        </div>
        <textarea className="textarea mono" style={{ flex: "1 1 60%", resize: "none", border: "none", borderRadius: 0 }} spellCheck={false} value={cur.code}
          onChange={(e) => setCur({ ...cur, code: e.target.value })}
          onKeyDown={(e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); void run(); }
            if (e.key === "Tab") { e.preventDefault(); const t = e.currentTarget; const p = t.selectionStart; setCur({ ...cur, code: cur.code.slice(0, p) + "  " + cur.code.slice(t.selectionEnd) }); requestAnimationFrame(() => t.setSelectionRange(p + 2, p + 2)); }
          }} />
        <div className="toolbar"><span className="panel-title grow">Output</span><button className="row-action" onClick={() => setOut([])}>clear</button></div>
        <pre className="mcp-result" style={{ flex: "1 1 40%", margin: 0, overflow: "auto", maxHeight: "none" }}>{out.join("\n")}</pre>
      </div>
      {showRef && <div className="list-col" style={{ borderRight: "none" }}>
        <div className="toolbar"><span className="panel-title">API</span></div>
        <pre className="mcp-result" style={{ margin: 0, maxHeight: "none", whiteSpace: "pre-wrap" }}>{kRef}</pre>
      </div>}
    </div>
  );
}
