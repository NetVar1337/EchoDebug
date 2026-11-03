// Memory snapshots: a captured window of process memory that can be compared
// with a later capture to see what changed (integrity checks, animated values).
import { create } from "zustand";
import { persist } from "zustand/middleware";

export type Snapshot = {
  id: string;
  name: string;
  address: string;
  size: number;
  /** base64 of the captured bytes; empty when the bytes live in IndexedDB (large captures) */
  data: string;
  /** "idb" when the bytes are stored in IndexedDB under snap:<id> */
  stored?: "idb";
  created: number;
};

type SnapshotStore = {
  snapshots: Snapshot[];
  add: (s: Snapshot) => void;
  remove: (id: string) => void;
  rename: (id: string, name: string) => void;
  clear: () => void;
};

export const kMaxSnapshots = 24;
const kMaxBytes = 64 * 1024;

export const useSnapshots = create<SnapshotStore>()(
  persist(
    (set) => ({
      snapshots: [],
      add: (s) => set((st) => ({ snapshots: [s, ...st.snapshots].slice(0, kMaxSnapshots) })),
      remove: (id) => set((st) => ({ snapshots: st.snapshots.filter((x) => x.id !== id) })),
      rename: (id, name) => set((st) => ({ snapshots: st.snapshots.map((x) => (x.id === id ? { ...x, name } : x)) })),
      clear: () => set({ snapshots: [] }),
    }),
    { name: "echodebug.snapshots" },
  ),
);

/** Captured bytes are stored base64 so the persisted state stays JSON-safe. */
export function encodeBytes(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

export function decodeBytes(s: string): Uint8Array {
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

export const kSnapshotMaxBytes = kMaxBytes;

/** The captured bytes, wherever they are stored. */
export async function snapshotBytes(s: Snapshot): Promise<Uint8Array> {
  if (s.stored !== "idb") return decodeBytes(s.data);
  const { idbGet } = await import("@/lib/idb");
  const b = await idbGet(`snap:${s.id}`);
  if (!b) throw new Error(`the bytes of ${s.name} are gone from IndexedDB`);
  return b;
}

/** Keeps small captures inline (localStorage), large ones in IndexedDB. */
export async function storeSnapshot(meta: Omit<Snapshot, "data" | "stored">, bytes: Uint8Array): Promise<Snapshot> {
  if (bytes.length <= kMaxBytes) return { ...meta, data: encodeBytes(bytes) };
  const { idbSet } = await import("@/lib/idb");
  await idbSet(`snap:${meta.id}`, bytes);
  return { ...meta, data: "", stored: "idb" };
}

export type SnapshotFile = { format: "echodebug.snapshots"; version: 1; snapshots: (Omit<Snapshot, "stored"> & { data: string })[] };
