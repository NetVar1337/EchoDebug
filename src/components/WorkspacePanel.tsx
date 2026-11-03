import { lazy, useEffect, useRef, type ComponentType } from "react";
import { LayoutGrid, X } from "lucide-react";
import { useUi, kTabs, type TabId } from "@/store/ui";
import { Boundary, Lazy, Panel } from "./ui";
import ViewsMenu from "./ViewsMenu";

// Views load on first open (own chunk each) to keep startup small; add new ones the same way.
const kViews: Record<TabId, ComponentType> = {
  disassembly: lazy(() => import("./views/DisassemblyView")),
  memory: lazy(() => import("./views/MemoryView")),
  structs: lazy(() => import("./views/StructsView")),
  strings: lazy(() => import("./views/StringsView")),
  pe: lazy(() => import("./views/PeView")),
  signatures: lazy(() => import("./views/SignaturesView")),
  pointers: lazy(() => import("./views/PointersView")),
  emulator: lazy(() => import("./views/EmulatorView")),
  emudbg: lazy(() => import("./views/EmuDebugView")),
  trace: lazy(() => import("./views/TraceView")),
  hooks: lazy(() => import("./views/HooksView")),
  monitors: lazy(() => import("./views/MonitorsView")),
  engines: lazy(() => import("./views/EnginesView")),
  lifter: lazy(() => import("./views/LifterView")),
  graph: lazy(() => import("./views/GraphView")),
  dotnet: lazy(() => import("./views/DotnetView")),
  crypto: lazy(() => import("./views/CryptoView")),
  caves: lazy(() => import("./views/CavesView")),
  snapshots: lazy(() => import("./views/SnapshotsView")),
  map: lazy(() => import("./views/BinaryMapView")),
  patches: lazy(() => import("./views/PatchesView")),
  triage: lazy(() => import("./views/TriageView")),
  rtti: lazy(() => import("./views/RttiView")),
  xrefs: lazy(() => import("./views/XrefView")),
  antidebug: lazy(() => import("./views/AntiDebugView")),
  debugger: lazy(() => import("./views/DebuggerView")),
  cfg: lazy(() => import("./views/CfgView")),
  sigtools: lazy(() => import("./views/SigToolsView")),
  yara: lazy(() => import("./views/YaraView")),
  bindiff: lazy(() => import("./views/BinDiffView")),
  unpack: lazy(() => import("./views/UnpackView")),
  decrypt: lazy(() => import("./views/DecryptView")),
  script: lazy(() => import("./views/ScriptView")),
};

export default function WorkspacePanel() {
  const { tab, setTab, openTabs, closeTab, viewsOpen, set } = useUi();
  const View = kViews[tab] ?? kViews.disassembly;
  const strip = useRef<HTMLDivElement>(null);
  const shown = openTabs.includes(tab) ? openTabs : [...openTabs, tab];
  const label = (t: TabId) => kTabs.find((x) => x.id === t)?.label ?? t;
  // keep the active tab in view
  useEffect(() => {
    strip.current?.querySelector<HTMLElement>(`[data-tab="${tab}"]`)?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [tab]);
  return (
    <Panel>
      <div className="tabs-wrap">
        <div
          className="tabs"
          role="tablist"
          ref={strip}
          onWheel={(e) => { if (strip.current && Math.abs(e.deltaY) > Math.abs(e.deltaX)) strip.current.scrollLeft += e.deltaY; }}
        >
          {shown.map((t) => (
            <div
              key={t}
              role="tab"
              tabIndex={0}
              aria-selected={tab === t}
              data-tab={t}
              className="tab closable"
              data-active={tab === t}
              onClick={() => setTab(t)}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") setTab(t); }}
              onAuxClick={(e) => { if (e.button === 1) { e.preventDefault(); closeTab(t); } }}
              title="Middle-click or × to close"
            >
              {label(t)}
              {shown.length > 1 && (
                <button className="tab-close" aria-label={`Close ${label(t)}`} onClick={(e) => { e.stopPropagation(); closeTab(t); }}><X size={11} /></button>
              )}
            </div>
          ))}
        </div>
        <button className="tab-more" aria-label="All views" data-tip="All views (Ctrl+Shift+V)" data-active={viewsOpen} onMouseDown={(e) => e.stopPropagation()} onClick={() => set({ viewsOpen: !viewsOpen })}>
          <LayoutGrid size={13} /> <span>Views</span>
        </button>
        {viewsOpen && <ViewsMenu />}
      </div>
      <div className="panel-body" style={{ overflow: "hidden" }}>
        <Boundary key={tab}><Lazy><View /></Lazy></Boundary>
      </div>
    </Panel>
  );
}
