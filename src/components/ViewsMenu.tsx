// "All views" picker: every workspace view grouped by what it is for, searchable, with a one-line
// description. Opening a view adds it to the tab strip.
import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import { kTabHints, kTabs, kViewGroups, useUi, type TabId, type ViewGroup } from "@/store/ui";

export default function ViewsMenu() {
  const ui = useUi();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const label = (t: TabId) => kTabs.find((x) => x.id === t)?.label ?? t;
  const groups = useMemo(() => {
    const f = q.toLowerCase();
    return (Object.entries(kViewGroups) as [ViewGroup, { blurb: string; tabs: TabId[] }][])
      .map(([g, v]) => ({ g, blurb: v.blurb, tabs: v.tabs.filter((t) => !f || label(t).toLowerCase().includes(f) || (kTabHints[t] ?? "").toLowerCase().includes(f)) }))
      .filter((x) => x.tabs.length);
  }, [q]);
  const flat = groups.flatMap((g) => g.tabs);
  useEffect(() => setSel(0), [q]);
  useEffect(() => {
    const close = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) ui.set({ viewsOpen: false }); };
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, []);
  const open = (t: TabId) => {
    ui.setTab(t);
    ui.set({ viewsOpen: false });
  };
  return (
    <div className="views-menu" ref={ref} role="dialog" aria-label="All views">
      <label className="search">
        <Search size={13} />
        <input
          autoFocus
          placeholder="Find a view…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Escape") ui.set({ viewsOpen: false });
            else if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(flat.length - 1, s + 1)); }
            else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
            else if (e.key === "Enter" && flat[sel]) open(flat[sel]);
          }}
        />
      </label>
      <div className="views-grid">
        {groups.map((g) => (
          <div key={g.g} className="views-group">
            <div className="label">{g.g} <span className="faint">· {g.blurb}</span></div>
            {g.tabs.map((t) => (
              <button key={t} className="views-item" data-active={ui.tab === t} data-sel={flat[sel] === t} data-open={ui.openTabs.includes(t)} onClick={() => open(t)}>
                <span>{label(t)}</span>
                <span className="faint ellipsis">{kTabHints[t]}</span>
              </button>
            ))}
          </div>
        ))}
        {!groups.length && <div className="faint" style={{ padding: 12 }}>No view matches “{q}”.</div>}
      </div>
    </div>
  );
}
