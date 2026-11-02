// User names and comments for addresses, plus per-function labels.
// Persisted locally; the disassembly view renders them and the exporter
// writes an IDC-style script for IDA and a .json sidecar.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { migrateAnchored, type Anchor } from "@/lib/projects";

export type NameEntry = { address: string; name: string; comment: string; anchor?: Anchor };

type NamesStore = {
  names: NameEntry[];
  /** address -> user name */
  rename: (address: string, name: string) => void;
  /** address -> comment (empty string removes it) */
  comment: (address: string, text: string) => void;
  remove: (address: string) => void;
  /** replaces the whole list, used by the session importer */
  setNames: (entries: NameEntry[]) => void;
  nameOf: (address: string) => string;
  commentOf: (address: string) => string;
  /** every entry, for the names panel and the exporter */
  list: () => NameEntry[];
};

export const norm = (a: string) => a.toLowerCase().replace(/^0x/, "").padStart(16, "0");

export const useNames = create<NamesStore>()(
  persist(
    (set, get) => ({
      names: [],
      rename: (address, name) =>
        set((s) => {
          const key = norm(address);
          const rest = s.names.filter((n) => norm(n.address) !== key);
          if (!name.trim()) return { names: rest };
          const prev = s.names.find((n) => norm(n.address) === key);
          return { names: [...rest, { ...prev, address: key, name: name.trim(), comment: prev?.comment ?? "" }] };
        }),
      comment: (address, text) =>
        set((s) => {
          const key = norm(address);
          const prev = s.names.find((n) => norm(n.address) === key);
          if (!text.trim() && !prev?.name) return { names: s.names.filter((n) => norm(n.address) !== key) };
          return {
            names: [
              ...s.names.filter((n) => norm(n.address) !== key),
              { ...prev, address: key, name: prev?.name ?? "", comment: text.trim() },
            ],
          };
        }),
      remove: (address) => set((s) => ({ names: s.names.filter((n) => norm(n.address) !== norm(address)) })),
      setNames: (entries) => set({ names: entries }),
      nameOf: (address) => get().names.find((n) => norm(n.address) === norm(address))?.name ?? "",
      commentOf: (address) => get().names.find((n) => norm(n.address) === norm(address))?.comment ?? "",
      list: () => get().names,
    }),
    { name: "echodebug.names", version: 1, migrate: migrateAnchored("names") },
  ),
);

/** IDA-style script: renames and comments for the addresses the user marked. */
export function toIdc(entries: readonly NameEntry[]): string {
  const lines = ["// EchoDebug export", ""];
  for (const e of entries) {
    if (e.name) lines.push(`MakeName(${e.address}, "${e.name.replace(/"/g, '\\"')}", SN_NOWARN);`);
    if (e.comment) lines.push(`auto_cmt = "${e.comment.replace(/"/g, '\\"')}";\nSetComment(${e.address}, auto_cmt);`);
  }
  return lines.join("\n");
}

/** Ghidra script: renames and comments applied by a script the user runs. */
export function toGhidra(entries: readonly NameEntry[]): string {
  const lines = ["// EchoDebug export", "// @category EchoDebug", ""];
  for (const e of entries) {
    if (e.name) lines.push(`renameFunction(toAddr("${e.address}"), "${e.name.replace(/"/g, '\\"')}");`);
    if (e.comment) lines.push(`setComment(toAddr("${e.address}"), "${e.comment.replace(/"/g, '\\"')}");`);
  }
  return lines.join("\n");
}
