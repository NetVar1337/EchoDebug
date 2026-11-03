// watchlist + bookmarks, persisted locally
import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { ValueType } from "@/lib/analysis/values";

export type WatchEntry = { id: string; address: string; label: string; type: ValueType; frozen: boolean };
export type Bookmark = { id: string; address: string; label: string };

type WatchStore = {
  watches: WatchEntry[];
  bookmarks: Bookmark[];
  addWatch: (address: string, type?: ValueType, label?: string) => void;
  updateWatch: (id: string, p: Partial<WatchEntry>) => void;
  removeWatch: (id: string) => void;
  addBookmark: (address: string, label?: string) => void;
  removeBookmark: (id: string) => void;
  /** replaces the whole list, used by the session importer */
  setWatches: (watches: WatchEntry[], bookmarks: Bookmark[]) => void;
};

const uid = () => Math.random().toString(36).slice(2, 10);

export const useWatch = create<WatchStore>()(
  persist(
    (set) => ({
      watches: [],
      bookmarks: [],
      addWatch: (address, type = "i32", label = "") =>
        set((s) => ({ watches: [...s.watches, { id: uid(), address, type, label, frozen: false }] })),
      updateWatch: (id, p) => set((s) => ({ watches: s.watches.map((w) => (w.id === id ? { ...w, ...p } : w)) })),
      removeWatch: (id) => set((s) => ({ watches: s.watches.filter((w) => w.id !== id) })),
      addBookmark: (address, label = "") =>
        set((s) => (s.bookmarks.some((b) => b.address === address) ? s : { bookmarks: [...s.bookmarks, { id: uid(), address, label }] })),
      removeBookmark: (id) => set((s) => ({ bookmarks: s.bookmarks.filter((b) => b.id !== id) })),
      setWatches: (watches, bookmarks) => set({ watches, bookmarks }),
    }),
    { name: "echodebug.watch" },
  ),
);
