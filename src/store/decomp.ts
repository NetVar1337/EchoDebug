// Decompiler settings the user makes per function: which variables point to
// which Structs type (so field accesses get the type's field names), and the
// view toggles of the CFG / Pseudocode view. Persisted locally.
import { create } from "zustand";
import { persist } from "zustand/middleware";

type DecompStore = {
  /** function address (0x hex) -> variable name -> struct type name */
  varTypes: Record<string, Record<string, string>>;
  setVarType: (func: string, variable: string, type: string | null) => void;
  raw: boolean;
  unflatten: boolean;
  setRaw: (v: boolean) => void;
  setUnflatten: (v: boolean) => void;
};

const key = (a: string) => "0x" + BigInt(a).toString(16);

export const useDecomp = create<DecompStore>()(
  persist(
    (set) => ({
      varTypes: {},
      setVarType: (func, variable, type) =>
        set((s) => {
          const f = { ...(s.varTypes[key(func)] ?? {}) };
          if (type) f[variable] = type;
          else delete f[variable];
          const all = { ...s.varTypes, [key(func)]: f };
          if (!Object.keys(f).length) delete all[key(func)];
          return { varTypes: all };
        }),
      raw: false,
      unflatten: false,
      setRaw: (raw) => set({ raw }),
      setUnflatten: (unflatten) => set({ unflatten }),
    }),
    { name: "echodebug.decomp" },
  ),
);

export function varTypesOf(all: Record<string, Record<string, string>>, func: string | null): Record<string, string> | undefined {
  return func ? all[key(func)] : undefined;
}
