// A catalog of signatures the user has saved. Each entry keeps the pattern
// in every format the app can produce, so it can be pasted into IDA,
// x64dbg, YARA or a C array without re-deriving anything.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { toByteArray, toCode, toIda, type Pattern } from "@/lib/analysis/sigmaker";

export type Signature = {
  id: string;
  name: string;
  /** the address the signature was made from */
  address: string;
  /** the module it was made from, if any */
  module: string;
  /** IDA-style pattern, e.g. "48 8B 05 ? ? ? ?" */
  ida: string;
  /** the raw pattern, one byte per entry, null for a wildcard */
  pattern: Pattern;
  note: string;
  created: number;
  /** how many hits the last scan found */
  hits: number;
};

type SigStore = {
  sigs: Signature[];
  add: (s: Omit<Signature, "id" | "ida" | "pattern" | "created"> & { pattern: Pattern }) => void;
  update: (id: string, p: Partial<Signature>) => void;
  remove: (id: string) => void;
  clear: () => void;
};

const uid = () => Math.random().toString(36).slice(2, 10);

export const useSigs = create<SigStore>()(
  persist(
    (set) => ({
      sigs: [],
      add: (s) =>
        set((st) => ({
          sigs: [{ ...s, id: uid(), ida: toIda(s.pattern), created: Date.now() }, ...st.sigs],
        })),
      update: (id, p) =>
        set((st) => ({
          sigs: st.sigs.map((s) => {
            if (s.id !== id) return s;
            const next = { ...s, ...p };
            // The IDA rendering follows the pattern when it changes.
            if (p.pattern) next.ida = toIda(p.pattern);
            return next;
          }),
        })),
      remove: (id) => set((st) => ({ sigs: st.sigs.filter((s) => s.id !== id) })),
      clear: () => set({ sigs: [] }),
    }),
    { name: "echodebug.sigs" },
  ),
);

/** Every format a saved signature can be exported in. */
export function signatureFormats(pattern: Pattern): { id: string; label: string; value: string }[] {
  const code = toCode(pattern);
  return [
    { id: "ida", label: "IDA", value: toIda(pattern) },
    { id: "bytes", label: "Bytes", value: code.bytes },
    { id: "mask", label: "Mask", value: code.mask },
    { id: "array", label: "Array", value: toByteArray(pattern) },
    { id: "x64dbg", label: "x64dbg", value: toIda(pattern) },
  ];
}

/** A YARA rule that matches the pattern. */
export function toYara(name: string, pattern: Pattern): string {
  const bytes = pattern.map((x) => (x === null ? "??" : x.toString(16).padStart(2, "0"))).join(" ");
  const hex = pattern.map((x) => (x === null ? "??" : x.toString(16))).join(" ");
  return [
    `rule ${name.replace(/[^A-Za-z0-9_]/g, "_") || "sig"} {`,
    "  strings:",
    `    $a = { ${bytes} }`,
    "  condition:",
    "    $a",
    "}",
    "",
    `// hex: ${hex}`,
  ].join("\n");
}
