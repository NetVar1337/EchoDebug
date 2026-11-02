import { SunMoon } from "lucide-react";
import { useConn } from "@/store/conn";
import { useMotion, kMotionPrefs } from "@/store/motion";
import { useUi } from "@/store/ui";
import UpdatePill from "./UpdatePill";

type DotState = "ok" | "busy" | "bad" | "idle";

function Pill({ state, label }: { state: DotState; label: string }) {
  return (
    <span className="status-pill">
      <span className="dot" data-state={state} />
      {label}
    </span>
  );
}

export default function StatusBar() {
  const c = useConn();
  const selected = useUi((s) => s.selected);
  const theme = useUi((s) => s.theme);
  const setUi = useUi((s) => s.set);
  const motion = useMotion((s) => s.pref);
  const setMotion = useMotion((s) => s.setPref);
  const mismatch = c.ext && c.extVersion && c.extVersion !== c.appVersion;

  const cycleTheme = () => {
    const ids = ["obsidian", "nord", "blood-orange"] as const;
    setUi({ theme: ids[(ids.indexOf(theme) + 1) % ids.length] });
  };
  const cycleMotion = () => {
    const i = kMotionPrefs.findIndex((p) => p.id === motion);
    setMotion(kMotionPrefs[(i + 1) % kMotionPrefs.length].id);
  };

  return (
    <footer className="statusbar">
      <span className="ellipsis">{c.target ? `${c.target.name ?? "target"} (${c.target.pid})` : "no target"}</span>
      {selected && <span className="mono faint">{selected}</span>}
      <div className="grow" />
      {c.progress && c.progress.done < c.progress.total && (
        <Pill state="busy" label={`${c.progress.job} ${Math.round((c.progress.done / Math.max(1, c.progress.total)) * 100)}%`} />
      )}
      <UpdatePill />
      <Pill state={c.relay ? "ok" : "bad"} label={`Relay :${c.port}`} />
      <Pill state={c.mem ? "ok" : "idle"} label={c.agent ? "Memory: ready" : c.mem ? "Memory: local /proc" : "Memory: idle"} />
      <Pill state={c.modules.length ? "ok" : "idle"} label={c.modules.length ? `Modules: ${c.modules.length}` : "Modules: none"} />
      <Pill state={c.ext ? (mismatch ? "busy" : "ok") : "bad"} label={c.ext ? `Agent v${c.extVersion}${mismatch ? ` ≠ app v${c.appVersion}` : ""}` : "Agent: offline"} />
      <button className="icon-button" data-tip={`Theme: ${theme}`} onClick={cycleTheme}><SunMoon size={13} /></button>
      <button className="icon-button" data-tip={`Motion: ${motion}`} onClick={cycleMotion}><SunMoon size={13} /></button>
      <span className="faint">v{c.appVersion}</span>
    </footer>
  );
}
