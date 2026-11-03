// Session resume (#39): after a relay restart or re-attach, restore the per-target state that
// was persisted with the session — watches, alerts, frozen values, the scanner checkpoint and
// pending patches. Pure functions over plain data so they are unit-testable without a target.

export type PersistedWatch = { address: string; type: string; label: string; frozen?: boolean };
export type PersistedAlert = { id?: string; kind: string; address?: string; value?: string; label?: string; enabled?: boolean };
export type PersistedScan = { id: string; value: string; vtype: string; scanType: string; regionsDone: number; totalRegions: number; results: string[]; done: boolean };
export type PersistedPatch = { address: string; original: string; current: string; note?: string };

export type PersistedTargetState = {
  pid?: number;
  name?: string;
  savedAt?: number;
  watches?: PersistedWatch[];
  alerts?: PersistedAlert[];
  frozen?: string[];
  scanner?: PersistedScan | null;
  patches?: PersistedPatch[];
};

export type RestoreAction =
  | { kind: "attach"; pid?: number; name?: string }
  | { kind: "watch"; address: string; type: string; label: string }
  | { kind: "freeze"; address: string }
  | { kind: "alert"; alert: PersistedAlert }
  | { kind: "scan"; scan: PersistedScan }
  | { kind: "note"; message: string };

/**
 * Builds the ordered list of actions to replay for a persisted state against the process now
 * attached. Watches that were frozen are re-added and re-frozen; a finished scanner is skipped
 * (its results are kept in the checkpoint), an unfinished one is resumed.
 */
export function restorePlan(state: PersistedTargetState, attached: { pid?: number; name?: string } | null): RestoreAction[] {
  const out: RestoreAction[] = [];
  if (!attached) {
    if (state.name || state.pid) out.push({ kind: "attach", pid: state.pid, name: state.name });
  } else {
    const nameChanged = state.name && attached.name && state.name.toLowerCase() !== attached.name.toLowerCase();
    if (nameChanged) out.push({ kind: "note", message: `session was saved on ${state.name}, now attached to ${attached.name}` });
  }
  for (const w of state.watches ?? []) {
    out.push({ kind: "watch", address: w.address, type: w.type, label: w.label ?? "" });
    if (w.frozen || (state.frozen ?? []).includes(w.address)) out.push({ kind: "freeze", address: w.address });
  }
  for (const a of state.alerts ?? []) if (a.enabled !== false) out.push({ kind: "alert", alert: a });
  if (state.scanner && !state.scanner.done) out.push({ kind: "scan", scan: state.scanner });
  return out;
}

/** True when the scanner checkpoint can be resumed (regions left to scan). */
export function scannerResumable(s: PersistedScan | null | undefined): s is PersistedScan {
  return !!s && !s.done && s.regionsDone < s.totalRegions && s.totalRegions > 0;
}

/** Progress of a persisted scanner, 0..1. */
export function scanProgress(s: PersistedScan): number {
  if (s.totalRegions <= 0) return s.done ? 1 : 0;
  return Math.min(1, s.regionsDone / s.totalRegions);
}

/** Merges results found since the checkpoint into it (dedup by address, cap the list). */
export function mergeScanResults(s: PersistedScan, found: string[], cap = 100_000): PersistedScan {
  const seen = new Set(s.results);
  const results = s.results.slice();
  for (const a of found) {
    if (!seen.has(a) && results.length < cap) {
      seen.add(a);
      results.push(a);
    }
  }
  return { ...s, results };
}
