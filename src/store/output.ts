import { create } from "zustand";

export type Level = "info" | "warn" | "error";
/** `detail` is extra text (e.g. an alert's memory snapshot) the Output panel shows on click. */
export type LogEntry = { id: number; time: string; level: Level; tag: string; msg: string; detail?: string };

type OutputStore = { entries: LogEntry[]; push: (level: Level, tag: string, msg: string, detail?: string) => void; clear: () => void };

let seq = 0;
const kMax = 2000;

export const useOutput = create<OutputStore>((set) => ({
  entries: [],
  push: (level, tag, msg, detail) =>
    set((s) => {
      const e = { id: seq++, time: new Date().toTimeString().slice(0, 8), level, tag, msg, detail };
      const next = s.entries.length >= kMax ? s.entries.slice(-kMax + 1) : s.entries.slice();
      next.push(e);
      return { entries: next };
    }),
  clear: () => set({ entries: [] }),
}));

export const log = (level: Level, tag: string, msg: string, detail?: string) => useOutput.getState().push(level, tag, msg, detail);

/** Await a promise, logging failures to the output panel; returns undefined on failure. */
export async function attempt<T>(tag: string, p: Promise<T>): Promise<T | undefined> {
  try {
    return await p;
  } catch (e) {
    log("error", tag, e instanceof Error ? e.message : String(e));
    return undefined;
  }
}
