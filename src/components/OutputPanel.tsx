import { useEffect, useRef, useState } from "react";
import { ArrowDownToLine, Trash2 } from "lucide-react";
import { useOutput } from "@/store/output";
import { IconButton, Panel, Tabs } from "./ui";

export default function OutputPanel() {
  const { entries, clear } = useOutput();
  const [tab, setTab] = useState<"output" | "errors">("output");
  const [follow, setFollow] = useState(true);
  const [open, setOpen] = useState<number | null>(null);
  const end = useRef<HTMLDivElement>(null);

  const shown = tab === "output" ? entries : entries.filter((e) => e.level !== "info");
  useEffect(() => {
    if (follow) end.current?.scrollIntoView({ block: "end" });
  }, [shown.length, follow]);

  const save = () => {
    const text = shown.map((e) => `${e.time} [${e.level}] ${e.tag}: ${e.msg}${e.detail ? "\n" + e.detail : ""}`).join("\n");
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: "echodebug-output.log" });
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Panel
      title={
        <Tabs
          tabs={[
            { id: "output", label: "Output" },
            { id: "errors", label: `Errors ${entries.filter((e) => e.level !== "info").length}` },
          ]}
          active={tab}
          onSelect={setTab}
        />
      }
      actions={
        <>
          <IconButton tip={follow ? "Follow tail" : "Follow tail (off)"} onClick={() => setFollow(!follow)}><ArrowDownToLine size={13} /></IconButton>
          <IconButton tip="Save log" onClick={save}><ArrowDownToLine size={13} /></IconButton>
          <IconButton tip="Clear" onClick={clear}><Trash2 size={13} /></IconButton>
        </>
      }
    >
      <div className="panel-body">
        <div className="log">
          {shown.length === 0 && <div className="panel-section faint">No output yet.</div>}
          {shown.map((e) => (
            <div key={e.id}>
              <div className="log-row" data-level={e.level} title={e.detail ? "Click to show details" : undefined} style={e.detail ? { cursor: "pointer" } : undefined}
                onClick={e.detail ? () => setOpen(open === e.id ? null : e.id) : undefined}>
                <span className="log-time">{e.time}</span>
                <span className="log-tag">{e.tag}</span>
                <span className="log-msg">{e.msg}{e.detail ? (open === e.id ? " ▾" : " ▸") : ""}</span>
              </div>
              {open === e.id && <pre className="log-msg mono selectable" style={{ margin: "0 0 4px 0", padding: "0 var(--pad-md)" }}>{e.detail}</pre>}
            </div>
          ))}
          <div ref={end} />
        </div>
      </div>
    </Panel>
  );
}
