// Warnings and errors from the output log, shown briefly in the corner, so they are not missed
// while the output panel is hidden or scrolled. Click one to open the output panel.
import { useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import { useOutput, type LogEntry } from "@/store/output";
import { togglePanel, useVisiblePanels } from "@/lib/layout";

const kLife = 5000;
const kMax = 4;

export default function Toasts() {
  const [shown, setShown] = useState<(LogEntry & { at: number })[]>([]);
  const last = useRef(-1);
  const vis = useVisiblePanels();
  const visRef = useRef(vis);
  visRef.current = vis;
  useEffect(() => {
    last.current = useOutput.getState().entries.at(-1)?.id ?? -1;
    return useOutput.subscribe((s) => {
      const fresh = s.entries.filter((e) => e.id > last.current);
      if (!fresh.length) return;
      last.current = fresh[fresh.length - 1].id;
      // errors always; warnings only when the output panel is not on screen
      const pick = fresh.filter((e) => e.level === "error" || (e.level === "warn" && !visRef.current.output));
      if (pick.length) setShown((cur) => [...cur, ...pick.map((e) => ({ ...e, at: Date.now() }))].slice(-kMax));
    });
  }, []);
  useEffect(() => {
    if (!shown.length) return;
    const t = setTimeout(() => setShown((cur) => cur.filter((x) => Date.now() - x.at < kLife)), 500);
    return () => clearTimeout(t);
  }, [shown]);
  if (!shown.length) return null;
  return (
    <div className="toasts" aria-live="polite">
      {shown.map((t) => (
        <div key={t.id} className="toast" data-level={t.level} onClick={() => { if (!visRef.current.output) togglePanel("output"); setShown((c) => c.filter((x) => x.id !== t.id)); }}>
          <span className="toast-tag">{t.tag}</span>
          <span className="toast-msg">{t.msg}</span>
          <button className="icon-button" aria-label="Dismiss" onClick={(e) => { e.stopPropagation(); setShown((c) => c.filter((x) => x.id !== t.id)); }}><X size={12} /></button>
        </div>
      ))}
    </div>
  );
}
