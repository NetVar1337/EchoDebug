// Signature health and repair (Signature-Doctor style): a saved pattern that no longer matches
// exactly once is shortened from the end until it finds the function again; when that leaves a
// single candidate, a fresh unique signature is derived at it.
import { toIda, type Pattern } from "./sigmaker";

export type Health = "ok" | "missing" | "ambiguous";
export type Repair = { status: "repaired" | "ambiguous" | "lost"; at?: string; candidates: string[]; prefix: number };

export function health(hits: number): Health {
  return hits === 1 ? "ok" : hits === 0 ? "missing" : "ambiguous";
}

/**
 * Finds where a broken pattern's function went: tries ever shorter prefixes (dropping bytes from
 * the end, never below `minFixed` fixed bytes) until something matches. `find(ida)` returns the
 * hit addresses.
 */
export async function locate(p: Pattern, find: (ida: string) => Promise<string[]>, minFixed = 6): Promise<Repair> {
  for (let n = p.length; n > 0; n--) {
    const cut = p.slice(0, n);
    while (cut.length && cut[cut.length - 1] === null) cut.pop();
    if (cut.filter((x) => x !== null).length < minFixed) break;
    const hits = await find(toIda(cut));
    if (hits.length === 1) return { status: "repaired", at: hits[0], candidates: hits, prefix: cut.length };
    if (hits.length > 1) return { status: "ambiguous", candidates: hits.slice(0, 32), prefix: cut.length };
  }
  return { status: "lost", candidates: [], prefix: 0 };
}

/** A unique match is "moved" when it is not at the RVA the signature (or a relocated item) was saved at. */
export type Located = { status: Health | "moved"; rva?: bigint };

/** Where a pattern that used to match at `savedRva` matches now (`savedRva` unknown: a unique match is "ok"). */
export function classify(savedRva: bigint | null | undefined, hitRvas: readonly bigint[]): Located {
  if (hitRvas.length === 0) return { status: "missing" };
  if (hitRvas.length > 1) return { status: "ambiguous" };
  return { status: savedRva != null && hitRvas[0] !== savedRva ? "moved" : "ok", rva: hitRvas[0] };
}

/** Relocation summary: matched = same RVA, moved = unique new RVA, lost = no signature, no match or ambiguous. */
export function countRelocation(statuses: readonly (Located["status"] | "nosig")[]): { matched: number; moved: number; lost: number } {
  const c = { matched: 0, moved: 0, lost: 0 };
  for (const s of statuses) {
    if (s === "ok") c.matched++;
    else if (s === "moved") c.moved++;
    else c.lost++;
  }
  return c;
}
