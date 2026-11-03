// Automation rules (alert/event → verb/command/log), persisted locally and exported with bundles.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { validateRules, type Rule } from "@/lib/automation";

type RulesStore = {
  rules: Rule[];
  add: (r: Rule) => void;
  update: (id: string, p: Partial<Rule>) => void;
  remove: (id: string) => void;
  setRules: (rules: Rule[]) => void;
  importJson: (text: string) => string | null; // error message, or null on success
};

const uid = () => Math.random().toString(36).slice(2, 10);

export const useRules = create<RulesStore>()(
  persist(
    (set) => ({
      rules: [],
      add: (r) => set((s) => ({ rules: [...s.rules.filter((x) => x.id !== r.id), { ...r, id: r.id || uid() }] })),
      update: (id, p) => set((s) => ({ rules: s.rules.map((x) => (x.id === id ? { ...x, ...p } : x)) })),
      remove: (id) => set((s) => ({ rules: s.rules.filter((x) => x.id !== id) })),
      setRules: (rules) => set({ rules }),
      importJson: (text) => {
        const v = validateRules(text);
        if (!v.ok) return v.errors.join("\n");
        set({ rules: v.rules });
        return null;
      },
    }),
    { name: "echodebug.rules" },
  ),
);
