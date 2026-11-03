// Boot checklist: shows what the app is waiting for so a missing Echo agent
// or an un-attached target does not look like a hang.
import iconUrl from "@/assets/icon.png";
import { useConn } from "@/store/conn";
import { useOutput } from "@/store/output";

const kStages = [
  "relay listener",
  "Echo memory server",
  "EchoDebug agent",
  "target attached",
  "module list",
];

export default function Splash() {
  const conn = useConn();
  const entries = useOutput((s) => s.entries);
  const tail = entries.slice(-4);

  const done = [
    conn.relay,
    conn.agent,
    conn.ext,
    Boolean(conn.target),
    conn.modules.length > 0,
  ];
  const stage = done.findIndex((d) => !d);

  return (
    <div className="splash">
      <div className="splash-card">
        <img className="splash-logo" src={iconUrl} alt="" draggable={false} />
        <div className="splash-title">EchoDebug</div>
        <div className="faint" style={{ fontSize: "var(--type-small)" }}>
          windows reverse-engineering workbench on Echo&apos;s hypervisor backend
        </div>
        <div className="splash-rows">
          {kStages.map((label, i) => {
            const status = done[i] ? "ok" : i === stage ? "run" : "wait";
            const marker = status === "ok" ? "[ ok ]" : status === "run" ? "[ .. ]" : "[    ]";
            return (
              <div className="splash-row" data-status={status} key={label}>
                {marker} {label}
              </div>
            );
          })}
        </div>
        {tail.length > 0 && (
          <div className="log" style={{ padding: 0, marginBottom: "var(--pad-md)" }}>
            {tail.map((l) => (
              <div className="log-row faint" key={l.id}>
                <span className="log-time">{l.time}</span>
                <span className="log-msg">{l.msg}</span>
              </div>
            ))}
          </div>
        )}
        <div className="progress">
          <div className="progress-fill" style={{ width: `${Math.round((done.filter(Boolean).length / kStages.length) * 100)}%` }} />
        </div>
        <div className="empty-hint" style={{ marginTop: "var(--pad-sm)" }}>
          {!conn.relay
            ? "waiting for the relay to accept connections…"
            : !conn.ext
              ? "load echo_debug.as in Echo — the app installed it into %APPDATA%\\scripts"
              : !conn.agent
                ? "attach to a process from the Targets panel"
                : "ready"}
        </div>
        <button className="btn" style={{ marginTop: "var(--pad-md)" }} onClick={() => useConn.getState().dismissSplash()}>
          Continue to the workbench
        </button>
      </div>
    </div>
  );
}
