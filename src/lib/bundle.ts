// Portable config + annotation bundle (#35, #26): one JSON file that carries the workspace
// (session) plus signatures, patches, FLIRT databases and automation rules, so a whole setup —
// including an annotated module ready to push to IDA/Ghidra/Binary Ninja — moves between machines.
import { validateRules, type Rule } from "./automation";

export type BundleState = {
  ui?: { theme?: string; accent?: string };
  watches?: unknown[];
  bookmarks?: unknown[];
  names?: unknown[];
  comments?: unknown[];
  types?: unknown[];
  signatures?: unknown[];
  patches?: { address: string; original: string; current: string; note?: string }[];
  flirt?: { name: string; path?: string }[];
  rules?: Rule[];
};

export type Bundle = {
  format: "echodebug.bundle";
  version: 1;
  savedAt: string;
  app: { name: string; version: string };
  target?: { name?: string; module?: string };
  state: BundleState;
};

export function buildBundle(app: { name: string; version: string }, state: BundleState, target?: { name?: string; module?: string }): Bundle {
  return {
    format: "echodebug.bundle",
    version: 1,
    savedAt: new Date().toISOString(),
    app,
    ...(target ? { target } : {}),
    state,
  };
}

export function validateBundle(raw: unknown): { ok: true; bundle: Bundle } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  let v = raw;
  if (typeof v === "string") {
    try { v = JSON.parse(v); } catch (e) { return { ok: false, errors: [`not valid JSON: ${e instanceof Error ? e.message : e}`] }; }
  }
  const b = v as Bundle;
  if (!v || typeof v !== "object") return { ok: false, errors: ["bundle must be an object"] };
  if (b.format !== "echodebug.bundle") errors.push('"format" must be "echodebug.bundle"');
  if (b.version !== 1) errors.push('"version" must be 1');
  if (!b.app || typeof b.app.name !== "string" || typeof b.app.version !== "string") errors.push('"app" needs name and version');
  if (!b.state || typeof b.state !== "object") errors.push('"state" must be an object');
  for (const k of ["watches", "bookmarks", "names", "comments", "types", "signatures", "flirt"] as const) {
    if (b.state?.[k] !== undefined && !Array.isArray(b.state[k])) errors.push(`state.${k} must be an array`);
  }
  if (b.state?.rules !== undefined) {
    const r = validateRules({ format: "echodebug.rules", version: 1, rules: b.state.rules });
    if (!r.ok) errors.push(...r.errors.map((e) => `state.rules: ${e}`));
  }
  return errors.length ? { ok: false, errors } : { ok: true, bundle: b };
}

export type BundleDiff = {
  added: string[];
  removed: string[];
  changed: string[];
};

/** Section-level diff between two bundles (counts + rule/patch ids), for "what changed?". */
export function diffBundles(a: Bundle, b: Bundle): Record<string, BundleDiff> {
  const out: Record<string, BundleDiff> = {};
  const idOf = (x: unknown): string => (x && typeof x === "object" ? String((x as Record<string, unknown>).id ?? (x as Record<string, unknown>).address ?? JSON.stringify(x)) : String(x));
  for (const k of ["watches", "bookmarks", "names", "comments", "types", "signatures", "flirt", "rules"] as const) {
    const A = new Set((a.state[k] ?? []).map(idOf));
    const B = new Set((b.state[k] ?? []).map(idOf));
    out[k] = {
      added: [...B].filter((x) => !A.has(x)),
      removed: [...A].filter((x) => !B.has(x)),
      changed: [],
    };
  }
  const pa = new Set((a.state.patches ?? []).map((p) => p.address));
  const pb = new Set((b.state.patches ?? []).map((p) => p.address));
  out.patches = {
    added: [...pb].filter((x) => !pa.has(x)),
    removed: [...pa].filter((x) => !pb.has(x)),
    changed: (a.state.patches ?? []).filter((p) => pb.has(p.address) && (b.state.patches ?? []).find((q) => q.address === p.address)?.current !== p.current).map((p) => p.address),
  };
  return out;
}
