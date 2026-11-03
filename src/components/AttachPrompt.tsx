// Shown by views that need a process when none is attached: quick re-attach to recent targets,
// a jump to the process list, and (Windows without the agent) the steps to load it.
import { useEffect, useState } from "react";
import { PlugZap, Target } from "lucide-react";
import { request } from "@/lib/client";
import { useConn } from "@/store/conn";
import { attempt } from "@/store/output";
import { useUi } from "@/store/ui";
import { togglePanel, useVisiblePanels } from "@/lib/layout";

type Proc = { pid: number; name: string };

export default function AttachPrompt() {
  const c = useConn();
  const recent = useUi((s) => s.recentTargets);
  const vis = useVisiblePanels();
  const [running, setRunning] = useState<Proc[]>([]);
  const [busy, setBusy] = useState("");
  const canAttach = c.ext || c.localAvailable;
  useEffect(() => {
    if (!canAttach || !recent.length) return;
    void request<{ processes: Proc[] }>("processes", {}, true).then((r) => {
      const want = new Set(recent.map((n) => n.toLowerCase()));
      setRunning(r.processes.filter((p) => want.has(p.name.toLowerCase())));
    }).catch(() => undefined);
  }, [canAttach, recent.join("|")]);

  const showTargets = () => {
    useUi.getState().setRail("targets");
    if (!vis.left) togglePanel("left");
    setTimeout(() => document.querySelector<HTMLInputElement>('input[placeholder="Filter processes…"]')?.focus(), 50);
  };
  const attach = async (p: Proc) => {
    setBusy(p.name);
    await attempt("attach", c.attach({ pid: p.pid, name: p.name }));
    setBusy("");
  };

  if (c.target) {
    return (
      <div className="empty">
        <div className="empty-glyph"><PlugZap size={26} strokeWidth={1.5} /></div>
        <div className="empty-title">Attached to {c.target.name ?? c.target.pid}; waiting for Echo's memory server</div>
        <div className="empty-hint">The agent re-opens it automatically. If it stays offline, detach and attach again.</div>
      </div>
    );
  }
  if (!canAttach) {
    return (
      <div className="empty">
        <div className="empty-glyph"><PlugZap size={26} strokeWidth={1.5} /></div>
        <div className="empty-title">Echo agent not loaded</div>
        <ol className="steps">
          <li>Start Echo and open its script manager.</li>
          <li>Load <span className="mono">echo_debug.as</span> (the app installs it to <span className="mono">%APPDATA%\scripts</span>).</li>
          <li>Pick your process in <button className="link-button" onClick={showTargets}>Targets</button> and press Attach.</li>
        </ol>
      </div>
    );
  }
  return (
    <div className="empty">
      <div className="empty-glyph"><Target size={26} strokeWidth={1.5} /></div>
      <div className="empty-title">No process attached</div>
      <div className="empty-hint">{c.os === "linux" || c.localAvailable && !c.ext ? "The relay reads the process through /proc (same user, or ptrace_scope=0)." : "Pick the process Echo should open."}</div>
      {running.length > 0 && (
        <div className="row wrap" style={{ justifyContent: "center" }}>
          {running.slice(0, 5).map((p) => (
            <button key={p.pid} className="btn primary small" disabled={!!busy} onClick={() => void attach(p)}>{busy === p.name ? "Attaching…" : `Attach ${p.name} (${p.pid})`}</button>
          ))}
        </div>
      )}
      <button className={`btn small${running.length ? "" : " primary"}`} onClick={showTargets}>Choose a process…</button>
    </div>
  );
}
