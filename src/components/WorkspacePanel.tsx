import { useUi, type TabId } from "@/store/ui";
import { Boundary, Panel, Tabs } from "./ui";
import DisassemblyView from "./views/DisassemblyView";
import MemoryView from "./views/MemoryView";
import StructsView from "./views/StructsView";
import StringsView from "./views/StringsView";
import PeView from "./views/PeView";
import SignaturesView from "./views/SignaturesView";
import PointersView from "./views/PointersView";
import EmulatorView from "./views/EmulatorView";

const kTabs: { id: TabId; label: string }[] = [
  { id: "disassembly", label: "Disassembly" },
  { id: "memory", label: "Memory" },
  { id: "structs", label: "Structs" },
  { id: "strings", label: "Strings" },
  { id: "pe", label: "PE Browser" },
  { id: "signatures", label: "Signatures" },
  { id: "pointers", label: "Pointers" },
  { id: "emulator", label: "Emulator" },
];

const kViews: Record<TabId, () => JSX.Element> = {
  disassembly: DisassemblyView,
  memory: MemoryView,
  structs: StructsView,
  strings: StringsView,
  pe: PeView,
  signatures: SignaturesView,
  pointers: PointersView,
  emulator: EmulatorView,
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
