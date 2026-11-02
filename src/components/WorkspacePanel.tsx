import { useEffect, useRef } from "react";
import { LayoutGrid, X } from "lucide-react";
import { useUi, kTabs, type TabId } from "@/store/ui";
import { Boundary, Panel } from "./ui";
import ViewsMenu from "./ViewsMenu";
import DisassemblyView from "./views/DisassemblyView";
import MemoryView from "./views/MemoryView";
import StructsView from "./views/StructsView";
import StringsView from "./views/StringsView";
import PeView from "./views/PeView";
import SignaturesView from "./views/SignaturesView";
import PointersView from "./views/PointersView";
import EmulatorView from "./views/EmulatorView";
import EmuDebugView from "./views/EmuDebugView";
import HooksView from "./views/HooksView";
import MonitorsView from "./views/MonitorsView";
import EnginesView from "./views/EnginesView";
import GraphView from "./views/GraphView";
import DotnetView from "./views/DotnetView";
import CryptoView from "./views/CryptoView";
import CavesView from "./views/CavesView";
import SnapshotsView from "./views/SnapshotsView";
import BinaryMapView from "./views/BinaryMapView";
import PatchesView from "./views/PatchesView";
import TriageView from "./views/TriageView";
import RttiView from "./views/RttiView";
import XrefView from "./views/XrefView";
import AntiDebugView from "./views/AntiDebugView";
import DebuggerView from "./views/DebuggerView";
import CfgView from "./views/CfgView";
import SigToolsView from "./views/SigToolsView";
import YaraView from "./views/YaraView";
import BinDiffView from "./views/BinDiffView";
import UnpackView from "./views/UnpackView";
import DecryptView from "./views/DecryptView";
import ScriptView from "./views/ScriptView";

const kViews: Record<TabId, () => JSX.Element> = {
  disassembly: DisassemblyView,
  memory: MemoryView,
  structs: StructsView,
  strings: StringsView,
  pe: PeView,
  signatures: SignaturesView,
  pointers: PointersView,
  emulator: EmulatorView,
  emudbg: EmuDebugView,
  hooks: HooksView,
  monitors: MonitorsView,
  engines: EnginesView,
  graph: GraphView,
  dotnet: DotnetView,
  crypto: CryptoView,
  caves: CavesView,
  snapshots: SnapshotsView,
  map: BinaryMapView,
  patches: PatchesView,
  triage: TriageView,
  rtti: RttiView,
  xrefs: XrefView,
  antidebug: AntiDebugView,
  debugger: DebuggerView,
  cfg: CfgView,
  sigtools: SigToolsView,
  yara: YaraView,
  bindiff: BinDiffView,
  unpack: UnpackView,
  decrypt: DecryptView,
  script: ScriptView,
};

export default function WorkspacePanel() {
  const { tab, setTab, openTabs, closeTab, viewsOpen, set } = useUi();
  const View = kViews[tab] ?? DisassemblyView;
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
        <Boundary key={tab}><View /></Boundary>
      </div>
    </Panel>
  );
}
