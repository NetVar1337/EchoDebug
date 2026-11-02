import { lazy, type ComponentType } from "react";
import { useUi, kTabs, type TabId } from "@/store/ui";
import { Boundary, Lazy, Panel, Tabs } from "./ui";

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
};

export default function WorkspacePanel() {
  const { tab, setTab } = useUi();
  const View = kViews[tab] ?? kViews.disassembly;
  return (
    <Panel>
      <Tabs tabs={kTabs} active={tab} onSelect={setTab} />
      <div className="panel-body" style={{ overflow: "hidden" }}>
        <Boundary key={tab}><Lazy><View /></Lazy></Boundary>
      </div>
    </Panel>
  );
}
