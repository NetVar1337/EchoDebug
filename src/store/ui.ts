// shell state + navigation between views; settings persisted under echodebug.*
import { create } from "zustand";
import { persist } from "zustand/middleware";

export type RailView = "targets" | "modules" | "watch" | "names" | "mcp";
export type TabId =
  | "disassembly" | "memory" | "structs" | "strings" | "pe" | "signatures" | "pointers" | "emulator"
  | "graph" | "dotnet" | "crypto" | "caves" | "snapshots" | "map" | "patches" | "triage" | "rtti" | "xrefs" | "antidebug"
  | "debugger" | "cfg" | "sigtools" | "yara" | "bindiff" | "unpack" | "decrypt" | "script";
export type Theme = "obsidian" | "nord" | "blood-orange";

export const kTabs: { id: TabId; label: string }[] = [
  { id: "disassembly", label: "Disassembly" },
  { id: "cfg", label: "CFG" },
  { id: "memory", label: "Memory" },
  { id: "structs", label: "Structs" },
  { id: "strings", label: "Strings" },
  { id: "pe", label: "PE Browser" },
  { id: "signatures", label: "Signatures" },
  { id: "sigtools", label: "Sig Tools" },
  { id: "yara", label: "YARA" },
  { id: "pointers", label: "Pointers" },
  { id: "emulator", label: "Emulator" },
  { id: "graph", label: "Graph" },
  { id: "dotnet", label: ".NET" },
  { id: "crypto", label: "Crypto" },
  { id: "caves", label: "Code Caves" },
  { id: "snapshots", label: "Snapshots" },
  { id: "map", label: "Binary Map" },
  { id: "patches", label: "Patches" },
  { id: "triage", label: "Triage" },
  { id: "rtti", label: "RTTI" },
  { id: "xrefs", label: "Xrefs" },
  { id: "antidebug", label: "Anti-Debug" },
  { id: "bindiff", label: "BinDiff" },
  { id: "unpack", label: "Unpack" },
  { id: "decrypt", label: "Decrypt" },
  { id: "script", label: "Script" },
  { id: "debugger", label: "Debugger" },
];

type UiStore = {
  rail: RailView;
  tab: TabId;
  settingsOpen: boolean;
  gotoOpen: boolean;
  paletteOpen: boolean;
  sessionExportOpen: boolean;
  sessionImportOpen: boolean;
  theme: Theme;
  accent: string;
  autoUpdate: boolean;
  /** last address the user focused anywhere; drives the inspector */
  selected: string | null;
  disasmAt: string | null;
  memoryAt: string | null;
  structAt: string | null;
  sigAt: string | null;
  chainAt: { base: string; offsets: number[] } | null;
  module: string | null; // module focused for PE / strings
  /** splitter sizes (CSS variables on the app root), restored on start */
  layout: Record<string, string>;
  /** last place per view, module-relative so it survives ASLR */
  places: Partial<Record<"disasm" | "memory" | "struct", { module: string; rva: number }>>;
  /** reattach to the last target by name when the app starts */
  reattach: boolean;
  lastTarget: string | null;
  /** recently attached process names, most recent first (target switcher) */
  recentTargets: string[];
  setRail: (r: RailView) => void;
  setTab: (t: TabId) => void;
  set: (p: Partial<UiStore>) => void;
  select: (a: string) => void;
  goDisasm: (a: string) => void;
  goMemory: (a: string) => void;
  goStruct: (a: string) => void;
  goSig: (a: string) => void;
  goModule: (name: string, tab: "pe" | "strings") => void;
};

export const useUi = create<UiStore>()(
  persist(
    (set) => ({
      rail: "targets",
      tab: "disassembly",
      settingsOpen: false,
      gotoOpen: false,
      paletteOpen: false,
      sessionExportOpen: false,
      sessionImportOpen: false,
      theme: "obsidian",
      accent: "",
      autoUpdate: true,
      selected: null,
      disasmAt: null,
      memoryAt: null,
      structAt: null,
      sigAt: null,
      chainAt: null,
      module: null,
      layout: {},
      places: {},
      reattach: false,
      lastTarget: null,
      recentTargets: [],
      setRail: (rail) => set({ rail }),
      setTab: (tab) => set({ tab }),
      set: (p) => set(p),
      select: (selected) => set({ selected }),
      goDisasm: (a) => set({ disasmAt: a, selected: a, tab: "disassembly" }),
      goMemory: (a) => set({ memoryAt: a, selected: a, tab: "memory" }),
      goStruct: (a) => set({ structAt: a, selected: a, tab: "structs" }),
      goSig: (a) => set({ sigAt: a, selected: a, tab: "signatures" }),
      goModule: (module, tab) => set({ module, tab }),
    }),
    {
      name: "echodebug.ui",
      partialize: (s) => ({ rail: s.rail, tab: s.tab, theme: s.theme, accent: s.accent, autoUpdate: s.autoUpdate, module: s.module, layout: s.layout, places: s.places, reattach: s.reattach, lastTarget: s.lastTarget, recentTargets: s.recentTargets }),
    },
  ),
);
