import { Bookmark, Boxes, Network, Settings, Tag, Target } from "lucide-react";
import { useUi, type RailView } from "@/store/ui";
import { togglePanel, useVisiblePanels } from "@/lib/layout";

const kItems: { id: RailView; label: string; Icon: typeof Target }[] = [
  { id: "targets", label: "Targets", Icon: Target },
  { id: "modules", label: "Modules", Icon: Boxes },
  { id: "watch", label: "Watchlist & Bookmarks", Icon: Bookmark },
  { id: "names", label: "Names & Comments", Icon: Tag },
  { id: "mcp", label: "MCP Server", Icon: Network },
];

export default function ActivityRail() {
  const { rail, setRail, set } = useUi();
  const vis = useVisiblePanels();
  // the active button folds the side panel away (and back), like an editor's activity bar
  const pick = (id: RailView) => {
    if (id === rail) return togglePanel("left");
    setRail(id);
    if (!vis.left) togglePanel("left");
  };
  return (
    <nav className="rail" aria-label="Panels">
      {kItems.map(({ id, label, Icon }) => (
        <button key={id} className="rail-button" data-active={rail === id && vis.left} data-tip={rail === id && vis.left ? `${label} (click to hide · Ctrl+B)` : label} aria-label={label} onClick={() => pick(id)}>
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
