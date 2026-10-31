import { useUi, kTabs, type TabId } from "@/store/ui";
import { Boundary, Panel, Tabs } from "./ui";
import DisassemblyView from "./views/DisassemblyView";
import MemoryView from "./views/MemoryView";
import StructsView from "./views/StructsView";
import StringsView from "./views/StringsView";
import PeView from "./views/PeView";
import SignaturesView from "./views/SignaturesView";
import PointersView from "./views/PointersView";
import EmulatorView from "./views/EmulatorView";
import GraphView from "./views/GraphView";
import DotnetView from "./views/DotnetView";
import CryptoView from "./views/CryptoView";
import CavesView from "./views/CavesView";
import SnapshotsView from "./views/SnapshotsView";
import BinaryMapView from "./views/BinaryMapView";
import PatchesView from "./views/PatchesView";
import TriageView from "./views/TriageView";

const kViews: Record<TabId, () => JSX.Element> = {
  disassembly: DisassemblyView,
  memory: MemoryView,
  structs: StructsView,
  strings: StringsView,
  pe: PeView,
  signatures: SignaturesView,
  pointers: PointersView,
  emulator: EmulatorView,
  graph: GraphView,
  dotnet: DotnetView,
  crypto: CryptoView,
  caves: CavesView,
  snapshots: SnapshotsView,
  map: BinaryMapView,
  patches: PatchesView,
  triage: TriageView,
};

export default function WorkspacePanel() {
  const { tab, setTab } = useUi();
  const View = kViews[tab] ?? DisassemblyView;
  return (
    <Panel>
      <Tabs tabs={kTabs} active={tab} onSelect={setTab} />
      <div className="panel-body" style={{ overflow: "hidden" }}>
        <Boundary key={tab}><View /></Boundary>
      </div>
    </Panel>
  );
}
