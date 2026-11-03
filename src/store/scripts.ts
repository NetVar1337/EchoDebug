// Saved scripts for the Script tab.
import { create } from "zustand";
import { persist } from "zustand/middleware";

export type Script = { id: string; name: string; code: string };

export const kExampleScript = `// Scripts are async JavaScript with an \`ed\` object (see the reference on the right).
// Example: name every function that references a string containing "error".
const m = ed.module();                          // the main module
const strs = await ed.ui("ui_strings", { module: m.name, filter: "error", limit: 50 });
for (const s of strs.results.slice(0, 10)) {
  const refs = await ed.ui("ui_xrefs_to", { address: s.address });
  ed.print(s.text, "→", refs.count, "references");
  for (const r of refs.results) ed.names.comment(r.address, "uses " + JSON.stringify(s.text));
}
`;

type ScriptStore = { scripts: Script[]; save: (s: Script) => void; remove: (id: string) => void };

export const useScripts = create<ScriptStore>()(
  persist(
    (set) => ({
      scripts: [{ id: "example", name: "example: strings → comments", code: kExampleScript }],
      save: (s) => set((st) => ({ scripts: st.scripts.some((x) => x.id === s.id) ? st.scripts.map((x) => (x.id === s.id ? s : x)) : [...st.scripts, s] })),
      remove: (id) => set((st) => ({ scripts: st.scripts.filter((x) => x.id !== id) })),
    }),
    { name: "echodebug.scripts" },
  ),
);
