import { useEffect, useRef } from "react";
import { Trash2 } from "lucide-react";
import { useOutput } from "@/store/output";
import { IconButton, Panel } from "./ui";

export default function OutputPanel() {
  const { entries, clear } = useOutput();
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [entries.length]);
  return (
    <Panel title="Output" actions={<IconButton tip="Clear" onClick={clear}><Trash2 size={14} /></IconButton>}>
      <div className="panel-body">
        <div className="log">
          {entries.map((e) => (
            <div key={e.id} className="log-row" data-level={e.level}>
              <span className="log-time">{e.time}</span>
              <span className="log-tag">{e.tag}</span>
              <span className="log-msg">{e.msg}</span>
            </div>
          ))}
          <div ref={end} />
        </div>
      </div>
    </Panel>
  );
}
