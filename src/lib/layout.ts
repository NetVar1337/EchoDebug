// Which panels are visible: the user's toggles, plus auto-hiding the scanner and inspector in
// narrow windows so the workspace keeps a usable width. Showing an auto-hidden panel explicitly
// keeps it until the window is wide again.
import { useEffect, useState } from "react";
import { create } from "zustand";
import { useUi, type PanelId } from "@/store/ui";

export const kNarrowScanner = 1440;
export const kNarrowInspector = 1200;

type LayoutStore = { width: number; forced: Partial<Record<PanelId, boolean>> };
export const useLayout = create<LayoutStore>(() => ({ width: typeof window === "undefined" ? 1600 : window.innerWidth, forced: {} }));

export function autoHidden(p: PanelId, width: number): boolean {
  return (p === "scanner" && width < kNarrowScanner) || (p === "inspector" && width < kNarrowInspector);
}

export function visiblePanels(panels: Record<PanelId, boolean>, width: number, forced: Partial<Record<PanelId, boolean>>): Record<PanelId, boolean> {
  const v = { ...panels };
  for (const p of Object.keys(v) as PanelId[]) if (v[p] && autoHidden(p, width) && !forced[p]) v[p] = false;
  return v;
}

export function useVisiblePanels(): Record<PanelId, boolean> {
  const panels = useUi((s) => s.panels);
  const { width, forced } = useLayout();
  return visiblePanels(panels, width, forced);
}

/** The toggle every UI entry point uses (menu, status bar, shortcuts). */
export function togglePanel(p: PanelId): void {
  const { width, forced } = useLayout.getState();
  const ui = useUi.getState();
  const shown = visiblePanels(ui.panels, width, forced)[p];
  if (!shown && autoHidden(p, width)) {
    useLayout.setState({ forced: { ...forced, [p]: true } });
    if (!ui.panels[p]) ui.togglePanel(p);
    return;
  }
  if (shown && forced[p]) useLayout.setState({ forced: { ...forced, [p]: false } });
  ui.togglePanel(p);
}

export function useWindowWidth(): void {
  const [, force] = useState(0);
  useEffect(() => {
    const on = () => {
      const width = window.innerWidth;
      const f = useLayout.getState().forced;
      // a forced panel returns to automatic once the window is wide enough again
      const forced = Object.fromEntries(Object.entries(f).filter(([p]) => autoHidden(p as PanelId, width)));
      useLayout.setState({ width, forced });
      force((n) => n + 1);
    };
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  }, []);
}
