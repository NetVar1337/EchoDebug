import { useConn } from "@/store/conn";
import { useUpdate } from "@/store/update";
import { useUi } from "@/store/ui";

function Pill({ state, label }: { state: "ok" | "busy" | "bad" | "off"; label: string }) {
  return (
    <span className="status-pill">
      <span className="dot" data-state={state} />
      {label}
    </span>
  );
}

export default function StatusBar() {
  const c = useConn();
  const update = useUpdate((s) => s.status);
  const selected = useUi((s) => s.selected);
  const mismatch = c.ext && c.extVersion && c.extVersion !== c.appVersion;
  return (
    <footer className="statusbar">
      <span className="ellipsis">{c.target ? `${c.target.name ?? "target"} (${c.target.pid})` : "no target"}</span>
      {selected && <span className="mono faint">{selected}</span>}
      <div className="grow" />
      {c.progress && c.progress.done < c.progress.total && <Pill state="busy" label={`${c.progress.job} ${Math.round((c.progress.done / Math.max(1, c.progress.total)) * 100)}%`} />}
      {update && <Pill state="busy" label={update} />}
      <Pill state={c.relay ? "ok" : "bad"} label={`Relay :${c.port}`} />
      <Pill state={c.agent ? "ok" : "bad"} label={`Memory server: ${c.agent ? "connected" : "offline"}`} />
      <Pill state={c.ext ? (mismatch ? "busy" : "ok") : "bad"} label={c.ext ? `Agent v${c.extVersion}${mismatch ? ` ≠ app v${c.appVersion}` : ""}` : "Agent: offline"} />
      <span className="faint">v{c.appVersion}</span>
    </footer>
  );
}
