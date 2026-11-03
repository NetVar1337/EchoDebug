// "Search everything": a fuzzy matcher and a grouped ranking over names, comments, bookmarks,
// saved signatures, struct types, module exports and already-extracted strings. Pure, so the
// ranking is unit-tested; the dialog (components/SearchDialog.tsx) collects the items.

export type SearchKind = "name" | "comment" | "bookmark" | "signature" | "type" | "field" | "export" | "string" | "module";

export const kKindLabels: Record<SearchKind, string> = {
  name: "Names", comment: "Comments", bookmark: "Bookmarks", signature: "Signatures", type: "Struct types",
  field: "Struct fields", export: "Exports", string: "Strings", module: "Modules",
};

/** Order of groups when their best scores tie. */
const kKindOrder: SearchKind[] = ["name", "export", "bookmark", "comment", "signature", "type", "field", "module", "string"];

export type SearchItem = {
  kind: SearchKind;
  /** the text matched and shown */
  text: string;
  /** shown dimmed after the text (module, address, pattern, …) */
  detail?: string;
  address?: string;
  /** kind-specific payload for the jump (type id, module name, …) */
  ref?: string;
  /** the address is outside every loaded module (an older base): ranked below live items */
  stale?: boolean;
};

export type Match = { score: number; /** indices of matched characters in the text */ hits: number[] };

const isBoundary = (text: string, i: number): boolean => {
  if (i === 0) return true;
  const p = text[i - 1];
  const c = text[i];
  if (/[\s_.:\-/\\!@?$<>()[\],]/.test(p)) return true;
  // camelCase hump: aB
  return p >= "a" && p <= "z" && c >= "A" && c <= "Z";
};

/**
 * Subsequence match of `query` in `text`, case-insensitive. Scores contiguous runs, word starts
 * (after `_ . : -`, camelCase humps), prefixes and exact matches higher, and penalises gaps and
 * long texts. Returns null when not every character occurs in order.
 */
export function fuzzyMatch(query: string, text: string): Match | null {
  const q = query.toLowerCase();
  if (!q) return { score: 0, hits: [] };
  const t = text.toLowerCase();
  // contiguous substring: the best case, scored by where it sits
  const at = t.indexOf(q);
  if (at >= 0) {
    let score = 100 + q.length * 6;
    if (t === q) score += 120;
    else if (at === 0) score += 60;
    else if (isBoundary(text, at)) score += 35;
    score -= Math.min(30, at * 0.5) + Math.min(25, (t.length - q.length) * 0.15);
    return { score, hits: Array.from({ length: q.length }, (_, k) => at + k) };
  }
  // scattered subsequence, preferring word starts (greedy with a look for a boundary)
  const hits: number[] = [];
  let ti = 0;
  let score = 0;
  let prev = -2;
  for (const ch of q) {
    let found = -1;
    let boundary = -1;
    for (let k = ti; k < t.length; k++) {
      if (t[k] !== ch) continue;
      if (found < 0) found = k;
      if (k === prev + 1) { boundary = k; break; }
      if (isBoundary(text, k)) { boundary = k; break; }
    }
    const k = boundary >= 0 ? boundary : found;
    if (k < 0) return null;
    if (k === prev + 1) score += 8;
    else if (isBoundary(text, k)) score += 7;
    else score += 1;
    score -= Math.min(6, (k - ti) * 0.2);
    hits.push(k);
    prev = k;
    ti = k + 1;
  }
  score -= Math.min(20, (t.length - q.length) * 0.1);
  return { score, hits };
}

/** Matches every space-separated token of `query` (AND); hits are merged. */
export function matchAll(query: string, item: SearchItem): Match | null {
  const tokens = query.trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) return null;
  let score = 0;
  const hits = new Set<number>();
  for (const tok of tokens) {
    // an address-looking token also matches the item's address
    if (/^(0x)?[0-9a-f]{4,}$/i.test(tok) && item.address) {
      const a = item.address.toLowerCase().replace(/^0x0*/, "");
      const n = tok.toLowerCase().replace(/^0x0*/, "");
      if (a === n) { score += 300; continue; }
      if (a.startsWith(n)) { score += 120; continue; }
    }
    const m = fuzzyMatch(tok, item.text) ?? (item.detail ? scaled(fuzzyMatch(tok, item.detail), 0.4) : null);
    if (!m) return null;
    score += m.score;
    if (m.hits.length && fuzzyMatch(tok, item.text)) for (const h of m.hits) hits.add(h);
  }
  if (item.stale) score -= 25;
  return { score, hits: [...hits].sort((a, b) => a - b) };
}

function scaled(m: Match | null, f: number): Match | null {
  return m ? { score: m.score * f, hits: [] } : null;
}

export type Ranked = { item: SearchItem; score: number; hits: number[] };
export type Group = { kind: SearchKind; label: string; results: Ranked[]; total: number };

/**
 * Ranks `items` against `query` and groups them by kind. Groups are ordered by their best score;
 * each keeps at most `perGroup` results (total says how many matched).
 */
export function searchAll(items: Iterable<SearchItem>, query: string, perGroup = 8, minScore = 0): Group[] {
  const byKind = new Map<SearchKind, Ranked[]>();
  if (!query.trim()) return [];
  for (const item of items) {
    const m = matchAll(query, item);
    if (!m || m.score < minScore) continue;
    let list = byKind.get(item.kind);
    if (!list) byKind.set(item.kind, (list = []));
    list.push({ item, score: m.score, hits: m.hits });
  }
  const groups: Group[] = [];
  for (const [kind, list] of byKind) {
    list.sort((a, b) => b.score - a.score || a.item.text.length - b.item.text.length || a.item.text.localeCompare(b.item.text));
    groups.push({ kind, label: kKindLabels[kind], results: list.slice(0, perGroup), total: list.length });
  }
  groups.sort((a, b) => b.results[0].score - a.results[0].score || kKindOrder.indexOf(a.kind) - kKindOrder.indexOf(b.kind));
  return groups;
}

/** Results in display order, for keyboard navigation across groups. */
export function flatten(groups: Group[]): Ranked[] {
  return groups.flatMap((g) => g.results);
}

/** Splits `text` into [plain, matched] runs for highlighting. */
export function highlight(text: string, hits: number[]): { s: string; hit: boolean }[] {
  const set = new Set(hits);
  const out: { s: string; hit: boolean }[] = [];
  for (let i = 0; i < text.length; i++) {
    const hit = set.has(i);
    const last = out[out.length - 1];
    if (last && last.hit === hit) last.s += text[i];
    else out.push({ s: text[i], hit });
  }
  return out;
}
