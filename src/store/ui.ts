// shell state + navigation between views; settings persisted under echodebug.*
import { create } from "zustand";
import { persist } from "zustand/middleware";

export type RailView = "targets" | "modules" | "watch" | "names" | "ai";
export type TabId =
  | "disassembly" | "memory" | "structs" | "strings" | "pe" | "signatures" | "pointers" | "emulator"
  | "graph" | "dotnet" | "crypto" | "caves" | "snapshots" | "map" | "patches" | "triage";
export type Theme = "obsidian" | "nord" | "blood-orange";
export type AiProvider = "anthropic" | "openai";

export type AiSettings = { provider: AiProvider; apiKey: string; model: string; baseUrl: string };

export const kTabs: { id: TabId; label: string }[] = [
  { id: "disassembly", label: "Disassembly" },
  { id: "memory", label: "Memory" },
  { id: "structs", label: "Structs" },
  { id: "strings", label: "Strings" },
  { id: "pe", label: "PE Browser" },
  { id: "signatures", label: "Signatures" },
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
  ai: AiSettings;
  /** last address the user focused anywhere; drives the inspector */
  selected: string | null;
  disasmAt: string | null;
  memoryAt: string | null;
  structAt: string | null;
  sigAt: string | null;
  chainAt: { base: string; offsets: number[] } | null;
  module: string | null; // module focused for PE / strings
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

export const kDefaultAi: AiSettings = { provider: "anthropic", apiKey: "", model: "claude-sonnet-5-5", baseUrl: "https://api.openai.com/v1" };

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
      ai: kDefaultAi,
      selected: null,
      disasmAt: null,
      memoryAt: null,
      structAt: null,
      sigAt: null,
      chainAt: null,
      module: null,
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
      partialize: (s) => ({ rail: s.rail, tab: s.tab, theme: s.theme, accent: s.accent, autoUpdate: s.autoUpdate, ai: s.ai }),
    },
  ),
);
