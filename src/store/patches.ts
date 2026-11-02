// Patch journal: every write EchoDebug makes is recorded with the bytes that
// were there before, so it can be reverted. Patches are stored per session
// and are never applied automatically.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { migrateAnchored, type Anchor } from "@/lib/projects";

export type Patch = {
  id: string;
  address: string;
  /** hex bytes that were written */
  written: string;
  /** hex bytes that were read before the write */
  before: string;
  note: string;
  created: number;
  reverted: boolean;
  anchor?: Anchor;
};

type PatchStore = {
  patches: Patch[];
  add: (p: Patch) => void;
  revert: (id: string) => Patch | null;
  remove: (id: string) => void;
  clear: () => void;
  pending: () => Patch[];
};

const uid = () => Math.random().toString(36).slice(2, 10);

export const usePatches = create<PatchStore>()(
  persist(
    (set, get) => ({
      patches: [],
      add: (p) => set((s) => ({ patches: [p, ...s.patches] })),
      revert: (id) => {
        const p = get().patches.find((x) => x.id === id);
        if (!p || p.reverted) return null;
        set((s) => ({ patches: s.patches.map((x) => (x.id === id ? { ...x, reverted: true } : x)) }));
        return p;
      },
      remove: (id) => set((s) => ({ patches: s.patches.filter((x) => x.id !== id) })),
      clear: () => set({ patches: [] }),
      pending: () => get().patches.filter((p) => !p.reverted),
    }),
    { name: "echodebug.patches", version: 1, migrate: migrateAnchored("patches") },
  ),
);

export const kNewPatchId = uid;
