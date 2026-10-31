import { Bookmark, Boxes, Settings, Sparkles, Tag, Target } from "lucide-react";
import { useUi, type RailView } from "@/store/ui";

const kItems: { id: RailView; label: string; Icon: typeof Target }[] = [
  { id: "targets", label: "Targets", Icon: Target },
  { id: "modules", label: "Modules", Icon: Boxes },
  { id: "watch", label: "Watchlist & Bookmarks", Icon: Bookmark },
  { id: "names", label: "Names & Comments", Icon: Tag },
  { id: "ai", label: "AI Assistant", Icon: Sparkles },
];

export default function ActivityRail() {
  const { rail, setRail, set } = useUi();
  return (
    <nav className="rail" aria-label="Panels">
      {kItems.map(({ id, label, Icon }) => (
        <button key={id} className="rail-button" data-active={rail === id} data-tip={label} aria-label={label} onClick={() => setRail(id)}>
          <Icon size={18} strokeWidth={1.75} />
        </button>
      ))}
      <div className="rail-spacer" />
      <button className="rail-button" data-tip="Settings" aria-label="Settings" onClick={() => set({ settingsOpen: true })}>
        <Settings size={18} strokeWidth={1.75} />
      </button>
    </nav>
  );
}
