// The FLIRT signature set the user loaded, and the functions it matched in the
// current module.
import { create } from "zustand";
import type { FlirtMatch, FlirtSignature } from "@/lib/analysis/flirt";

export type FlirtState = {
  /** the file the signature set came from */
  fileName: string;
  /** the parsed signature set, null when none is loaded */
  signature: FlirtSignature | null;
  /** the matches in the current module */
  matches: FlirtMatch[];
  set: (fileName: string, signature: FlirtSignature) => void;
  setMatches: (m: FlirtMatch[]) => void;
  clear: () => void;
};

export const useFlirt = create<FlirtState>((set) => ({
  fileName: "",
  signature: null,
  matches: [],
  set: (fileName, signature) => set({ fileName, signature, matches: [] }),
  setMatches: (matches) => set({ matches }),
  clear: () => set({ fileName: "", signature: null, matches: [] }),
}));
