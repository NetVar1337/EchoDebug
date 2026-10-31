// A catalog of user-defined struct templates. Each entry is a named list of
// fields with a ReClass-style cumulative layout. Persisted locally.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Field } from "@/lib/analysis/struct";

export type TypeDef = {
  id: string;
  name: string;
  fields: Field[];
};

type TypesStore = {
  types: TypeDef[];
  add: (name: string, fields?: Field[]) => string;
  update: (id: string, p: Partial<TypeDef>) => void;
  remove: (id: string) => void;
  /** returns the id of the type with that name, creating it when missing */
  ensure: (name: string) => string;
  find: (name: string) => TypeDef | undefined;
  /** replaces the whole list, used by the session importer */
  setTypes: (types: TypeDef[]) => void;
};

const uid = () => Math.random().toString(36).slice(2, 10);

export const useTypes = create<TypesStore>()(
  persist(
    (set, get) => ({
      types: [],
      add: (name, fields = []) => {
        const id = uid();
        set((s) => ({ types: [...s.types, { id, name, fields }] }));
        return id;
      },
      update: (id, p) => set((s) => ({ types: s.types.map((t) => (t.id === id ? { ...t, ...p } : t)) })),
      remove: (id) => set((s) => ({ types: s.types.filter((t) => t.id !== id) })),
      ensure: (name) => {
        const hit = get().types.find((t) => t.name.toLowerCase() === name.toLowerCase());
        if (hit) return hit.id;
        return get().add(name);
      },
      find: (name) => get().types.find((t) => t.name.toLowerCase() === name.toLowerCase()),
      setTypes: (types) => set({ types }),
    }),
    { name: "echodebug.types" },
  ),
);
