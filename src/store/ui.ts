// shell state + navigation between views; settings persisted under echodebug.*
import { create } from "zustand";
import { persist } from "zustand/middleware";

export type RailView = "targets" | "modules" | "watch" | "names" | "mcp" | "assistant" | "sync";
export type TabId =
  | "disassembly" | "memory" | "structs" | "strings" | "pe" | "signatures" | "pointers" | "emulator"
  | "graph" | "dotnet" | "crypto" | "caves" | "snapshots" | "map" | "patches" | "triage" | "rtti" | "xrefs" | "antidebug"
  | "debugger" | "cfg" | "sigtools" | "yara" | "bindiff" | "unpack" | "decrypt" | "script" | "emudbg" | "hooks" | "monitors" | "engines" | "lifter" | "symbols" | "values" | "plugins";
export type Theme = "obsidian" | "nord" | "blood-orange";

export const kTabs: { id: TabId; label: string }[] = [
  { id: "disassembly", label: "Disassembly" },
  { id: "cfg", label: "CFG" },
  { id: "memory", label: "Memory" },
  { id: "structs", label: "Structs" },
  { id: "strings", label: "Strings" },
  { id: "pe", label: "PE Browser" },
  { id: "symbols", label: "Symbols" },
  { id: "signatures", label: "Signatures" },
  { id: "sigtools", label: "Sig Tools" },
  { id: "yara", label: "YARA" },
  { id: "pointers", label: "Pointers" },
  { id: "emulator", label: "Emulator" },
  { id: "emudbg", label: "Emu Debugger" },
  { id: "lifter", label: "Lifter" },
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
  { id: "hooks", label: "Hooks" },
  { id: "monitors", label: "Monitors" },
  { id: "values", label: "Value Graphs" },
  { id: "engines", label: "Engines" },
  { id: "bindiff", label: "BinDiff" },
  { id: "unpack", label: "Unpack" },
  { id: "decrypt", label: "Decrypt" },
  { id: "script", label: "Script" },
  { id: "debugger", label: "Debugger" },
  { id: "plugins", label: "Plugins" },
];

/** Views grouped for the "All views" menu and the command palette. */
export type ViewGroup = "Code" | "Memory" | "Binary" | "Dynamic";
export const kViewGroups: Record<ViewGroup, { blurb: string; tabs: TabId[] }> = {
  Code: { blurb: "disassembly, graphs, references, signatures", tabs: ["disassembly", "cfg", "graph", "xrefs", "strings", "signatures", "sigtools", "yara"] },
  Memory: { blurb: "bytes, structures, pointers, snapshots, patches", tabs: ["memory", "structs", "pointers", "snapshots", "map", "patches"] },
  Binary: { blurb: "PE, .NET, RTTI, triage, unpacking, engines", tabs: ["pe", "symbols", "dotnet", "rtti", "triage", "crypto", "caves", "antidebug", "hooks", "bindiff", "unpack", "decrypt", "engines"] },
  Dynamic: { blurb: "debuggers, emulation, lifting, devirtualization", tabs: ["debugger", "emudbg", "lifter", "emulator", "monitors", "values", "script", "plugins"] },
};
export const kTabHints: Partial<Record<TabId, string>> = {
  disassembly: "functions and instructions", cfg: "control-flow graph of a function", graph: "call graph", xrefs: "who references an address",
  strings: "ASCII / UTF-16 strings of a module", signatures: "make and test byte patterns", sigtools: "signature catalog, health and repair", yara: "YARA rules over memory",
  memory: "hex view with find and edit", structs: "typed structure view", pointers: "pointer scanner and chains", snapshots: "diff memory over time", map: "module layout and entropy", patches: "every byte you changed, with undo",
  pe: "headers, sections, imports, exports, resources", symbols: "PDBs: symbol servers, functions, types, source lines", dotnet: ".NET metadata and IL", rtti: "C++ classes and vtables", triage: "suspicious imports", crypto: "crypto constants", caves: "free space in code sections", antidebug: "anti-debugging tricks", hooks: "inline / IAT hooks and patched code", bindiff: "compare with an older build", unpack: "find the OEP, rebuild imports", decrypt: "run string decryptors in the emulator", engines: "Unreal / Unity IL2CPP / Source dumps",
  debugger: "breakpoints on the live process", lifter: "lift, deobfuscate traces, devirtualize VMs", emudbg: "step code in an emulator", emulator: "run a routine once", monitors: "module loads, page changes", values: "plot watched values over time", script: "automate with JavaScript", plugins: "views and analyses from plugins",
};
export const kDefaultOpenTabs: TabId[] = ["disassembly", "memory", "structs", "strings", "pe", "xrefs", "emudbg", "script"];
export type PanelId = "left" | "scanner" | "inspector" | "output";

type UiStore = {
  rail: RailView;
  tab: TabId;
  /** tabs shown in the workspace strip, in order */
  openTabs: TabId[];
  /** panel visibility (narrow windows also auto-hide the scanner and inspector) */
  panels: Record<PanelId, boolean>;
  viewsOpen: boolean;
  shortcutsOpen: boolean;
  closeTab: (t: TabId) => void;
  togglePanel: (p: PanelId) => void;
  settingsOpen: boolean;
  gotoOpen: boolean;
  paletteOpen: boolean;
  /** Ctrl+Shift+F search-everything dialog */
  searchOpen: boolean;
  /** struct type the Structs view should open (set by search, cleared by the view) */
  structType: string | null;
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
  /** catalog type the Structs view should open (set by the PDB type importer) */
  structTypeId: string | null;
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

/** Activating a tab opens it in the strip (after the active one) when it is not there yet. */
function withTab(s: { tab: TabId; openTabs: TabId[] }, tab: TabId): { tab: TabId; openTabs: TabId[] } {
  if (s.openTabs.includes(tab)) return { tab, openTabs: s.openTabs };
  const at = s.openTabs.indexOf(s.tab);
  const open = [...s.openTabs];
  open.splice(at < 0 ? open.length : at + 1, 0, tab);
  return { tab, openTabs: open };
}

export const useUi = create<UiStore>()(
  persist(
    (set) => ({
      rail: "targets",
      tab: "disassembly",
      openTabs: kDefaultOpenTabs,
      panels: { left: true, scanner: true, inspector: true, output: true },
      viewsOpen: false,
      shortcutsOpen: false,
      closeTab: (t) => set((s) => {
        const open = s.openTabs.filter((x) => x !== t);
        if (!open.length) return {};
        const i = s.openTabs.indexOf(t);
        return { openTabs: open, tab: s.tab === t ? open[Math.min(i, open.length - 1)] : s.tab };
      }),
      togglePanel: (p) => set((s) => ({ panels: { ...s.panels, [p]: !s.panels[p] } })),
      settingsOpen: false,
      gotoOpen: false,
      paletteOpen: false,
      searchOpen: false,
      structType: null,
      sessionExportOpen: false,
      sessionImportOpen: false,
      theme: "obsidian",
      accent: "",
      autoUpdate: true,
      selected: null,
      disasmAt: null,
      memoryAt: null,
      structAt: null,
      structTypeId: null,
      sigAt: null,
      chainAt: null,
      module: null,
      layout: {},
      places: {},
      reattach: false,
      lastTarget: null,
      recentTargets: [],
      setRail: (rail) => set({ rail }),
      setTab: (tab) => set((s) => withTab(s, tab)),
      set: (p) => set(p),
      select: (selected) => set({ selected }),
      goDisasm: (a) => set((s) => ({ disasmAt: a, selected: a, ...withTab(s, "disassembly") })),
      goMemory: (a) => set((s) => ({ memoryAt: a, selected: a, ...withTab(s, "memory") })),
      goStruct: (a) => set((s) => ({ structAt: a, selected: a, ...withTab(s, "structs") })),
      goSig: (a) => set((s) => ({ sigAt: a, selected: a, ...withTab(s, "signatures") })),
      goModule: (module, tab) => set((s) => ({ module, ...withTab(s, tab) })),
    }),
    {
      name: "echodebug.ui",
      partialize: (s) => ({ rail: s.rail, tab: s.tab, openTabs: s.openTabs, panels: s.panels, theme: s.theme, accent: s.accent, autoUpdate: s.autoUpdate, module: s.module, layout: s.layout, places: s.places, reattach: s.reattach, lastTarget: s.lastTarget, recentTargets: s.recentTargets }),
    },
  ),
);
