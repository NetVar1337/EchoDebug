// App-wide undo/redo for edits to names, comments and struct types (Ctrl+Z / Ctrl+Shift+Z / Ctrl+Y).
// Stores record a snapshot pair per action; undo restores the "before" state.

type Entry = { label: string; undo: () => void; redo: () => void };

const past: Entry[] = [];
const future: Entry[] = [];
let applying = false;
const listeners = new Set<() => void>();
const kMax = 300;

/** True while an undo/redo is being applied, so stores do not record it again. */
export function isApplying(): boolean {
  return applying;
}

export function record(e: Entry): void {
  if (applying) return;
  past.push(e);
  if (past.length > kMax) past.shift();
  future.length = 0;
  for (const l of listeners) l();
}

function run(from: Entry[], to: Entry[], which: "undo" | "redo"): string | null {
  const e = from.pop();
  if (!e) return null;
  applying = true;
  try {
    e[which]();
  } finally {
    applying = false;
  }
  to.push(e);
  for (const l of listeners) l();
  return e.label;
}

export const undo = () => run(past, future, "undo");
export const redo = () => run(future, past, "redo");
export const canUndo = () => past.length > 0;
export const canRedo = () => future.length > 0;
export function onHistory(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}
export function clearHistory(): void {
  past.length = 0;
  future.length = 0;
}
