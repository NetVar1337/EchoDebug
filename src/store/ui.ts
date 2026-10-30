// shell state + navigation between views; settings persisted under echodebug.*
import { create } from "zustand";
import { persist } from "zustand/middleware";

export type RailView = "targets" | "modules" | "watch" | "ai";
export type TabId = "disassembly" | "memory" | "structs" | "strings" | "pe" | "signatures" | "pointers" | "emulator";
export type Theme = "obsidian" | "nord" | "blood-orange";
export type AiProvider = "anthropic" | "openai";

export type AiSettings = { provider: AiProvider; apiKey: string; model: string; baseUrl: string };

type UiStore = {
  rail: RailView;
  tab: TabId;
  settingsOpen: boolean;
  gotoOpen: boolean;
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
