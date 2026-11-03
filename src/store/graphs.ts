// Value graphs: which addresses are plotted (persisted) and their sample history (in memory).
// One sampler reads every series in a batch at the chosen rate; `watch_event`s from the agent
// (watch_add) are folded in too, so changes between two polls are not lost.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { readMany } from "@/lib/batch";
import { hexToBytes } from "@/lib/hex";
import { RingBuffer, decodeNumber, kGraphSizes, type GraphType } from "@/lib/graphs";
import { onAgentEvent, useConn } from "./conn";

export type GraphSeries = { id: string; address: string; type: GraphType; label: string; color: string; visible: boolean };

const kPalette = ["#4ea1ff", "#f2a33a", "#5ccf8a", "#e8607a", "#b48cf2", "#40c4c4", "#d4c14a", "#f07f4f"];

type GraphStore = {
  series: GraphSeries[];
  /** samples kept per series */
  capacity: number;
  /** poll interval */
  intervalMs: number;
  paused: boolean;
  /** bumped whenever new samples arrive, so views redraw */
  tick: number;
  add: (address: string, type: GraphType, label?: string) => string;
  update: (id: string, p: Partial<GraphSeries>) => void;
  remove: (id: string) => void;
  clearSamples: () => void;
  set: (p: Partial<Pick<GraphStore, "capacity" | "intervalMs" | "paused">>) => void;
};

const buffers = new Map<string, RingBuffer>();
const uid = () => Math.random().toString(36).slice(2, 10);
const norm = (a: string) => a.toLowerCase().replace(/^0x0*/, "");

/** the history of one series (created on first use) */
export function bufferOf(id: string): RingBuffer {
  let b = buffers.get(id);
  const cap = useGraphs.getState().capacity;
  if (!b) buffers.set(id, (b = new RingBuffer(cap)));
  else if (b.capacity !== cap) buffers.set(id, (b = b.resized(cap)));
  return b;
}

export const useGraphs = create<GraphStore>()(
  persist(
    (set, get) => ({
      series: [],
      capacity: 6000,
      intervalMs: 100,
      paused: false,
      tick: 0,
      add: (address, type, label = "") => {
        const hit = get().series.find((s) => norm(s.address) === norm(address) && s.type === type);
        if (hit) return hit.id;
        const id = uid();
        const color = kPalette[get().series.length % kPalette.length];
        set((s) => ({ series: [...s.series, { id, address, type, label, color, visible: true }] }));
        return id;
      },
      update: (id, p) => {
        if (p.type || p.address) buffers.get(id)?.clear();
        set((s) => ({ series: s.series.map((x) => (x.id === id ? { ...x, ...p } : x)) }));
      },
      remove: (id) => {
        buffers.delete(id);
        set((s) => ({ series: s.series.filter((x) => x.id !== id) }));
      },
      clearSamples: () => {
        for (const b of buffers.values()) b.clear();
        set((s) => ({ tick: s.tick + 1 }));
      },
      set: (p) => {
        const capacity = p.capacity !== undefined ? Math.min(1_000_000, Math.max(100, Math.floor(p.capacity))) : undefined;
        const intervalMs = p.intervalMs !== undefined ? Math.min(10_000, Math.max(20, Math.floor(p.intervalMs))) : undefined;
        set({ ...p, ...(capacity !== undefined ? { capacity } : {}), ...(intervalMs !== undefined ? { intervalMs } : {}) });
      },
    }),
    { name: "echodebug.graphs", partialize: (s) => ({ series: s.series, capacity: s.capacity, intervalMs: s.intervalMs }) },
  ),
);

let started = false;

/** Starts the sampler once; it idles while nothing is plotted, the graphs are paused or no target is attached. */
export function startGraphs(): void {
  if (started) return;
  started = true;
  let busy = false;
  const bump = () => useGraphs.setState((s) => ({ tick: s.tick + 1 }));
  const loop = async () => {
    const g = useGraphs.getState();
    const c = useConn.getState();
    if (!busy && !g.paused && g.series.length && c.mem && c.target) {
      busy = true;
      const list = g.series;
      const rs = await readMany(list.map((s) => ({ address: s.address, size: kGraphSizes[s.type] }))).catch(() => null);
      busy = false;
      if (rs) {
        const now = Date.now();
        let any = false;
        list.forEach((s, i) => {
          const v = decodeNumber(rs[i], s.type);
          if (v !== null) {
            bufferOf(s.id).push(now, v);
            any = true;
          }
        });
        if (any) bump();
      }
    }
    setTimeout(() => void loop(), useGraphs.getState().intervalMs);
  };
  void loop();
  // the agent's watch stream reports changes as they happen (old/new hex bytes)
  onAgentEvent((f) => {
    if (f.event !== "watch_event" || typeof f.new !== "string" || typeof f.address !== "string") return;
    const g = useGraphs.getState();
    if (g.paused) return;
    const bytes = hexToBytes(f.new);
    const now = Date.now();
    let any = false;
    for (const s of g.series) {
      if (norm(s.address) !== norm(String(f.address))) continue;
      const v = decodeNumber(bytes, s.type);
      if (v === null) continue;
      const b = bufferOf(s.id);
      const last = b.last();
      // keep time order; drop duplicates of a poll in the same millisecond
      if (last && last.t >= now) continue;
      b.push(now, v);
      any = true;
    }
    if (any) bump();
  });
  // a new target means new memory: start the history over
  useConn.subscribe((s, prev) => {
    if (s.target?.pid !== prev.target?.pid) useGraphs.getState().clearSamples();
  });
}
