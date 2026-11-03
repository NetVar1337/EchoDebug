// String-decryption campaign planner (#16): given the listing of a function that calls several
// routines, rank the call targets as candidate string-decryptors (xor/rotate loops with an
// immediate key, touching data) so the campaign emulates the most promising ones first and
// collects the decrypted strings into one table.
import type { ListingLine } from "./analysis/listing";

export type DecryptCandidate = {
  callSite: string;
  target: string;
  score: number;
  reasons: string[];
};

export type Campaign = {
  functionStart: string;
  candidates: DecryptCandidate[];
  /** call order to emulate first */
  plan: string[];
};

type LinesByAddr = Map<string, ListingLine[]>;

/** Heuristic score of a routine's body as a decryptor. `lines` are the target's instructions. */
export function decryptScore(lines: readonly ListingLine[]): { score: number; reasons: string[] } {
  let score = 0;
  const reasons: string[] = [];
  let xorLoop = 0;
  let rot = 0;
  let immKey = 0;
  let memTouch = 0;
  for (const l of lines) {
    const t = l.text.toLowerCase();
    if (/\bxor\s+/.test(t)) xorLoop++;
    if (/\b(r[oa]r|rol)\s+/.test(t)) rot++;
    if (/,\s*0x[0-9a-f]{2,}\b/.test(t)) immKey++;
    if (/\[(?:r|e|0x)/.test(t)) memTouch++;
  }
  if (xorLoop >= 1) {
    score += 3;
    reasons.push(`${xorLoop} xor op(s) (decryption loop)`);
  }
  if (rot > 0) {
    score += 2;
    reasons.push(`${rot} rotate op(s)`);
  }
  if (immKey > 0) {
    score += 2;
    reasons.push("immediate key material");
  }
  if (memTouch > 0) {
    score += 1;
    reasons.push("memory operands (in-place buffer)");
  }
  if (lines.some((l) => /\b(ret|retn)\b/i.test(l.text))) {
    score += 1;
    reasons.push("returns normally");
  }
  return { score, reasons };
}

const kCall = /\bcall\s+(?:qword\s+\[\s*)?(?:0x([0-9a-fA-F]+)|([A-Za-z_][\w.]*))/i;

export type DisasmOf = (addr: string, size: number) => Promise<ListingLine[]>;

/**
 * Auto-detects the decryption routine called from a function: disassembles the function, plans a
 * campaign (fetching each call target's body through `disasmOf`, bounded), and returns the
 * best-scoring target — or null when nothing looks like a decryptor.
 */
export async function detectDecryptRoutine(
  funcLines: readonly ListingLine[],
  disasmOf: DisasmOf,
  opts: { maxTargets?: number; bodySize?: number; minScore?: number } = {},
): Promise<DecryptCandidate | null> {
  const maxTargets = opts.maxTargets ?? 24;
  const bodySize = opts.bodySize ?? 0x400;
  const direct = funcLines
    .map((l) => l.text.match(kCall))
    .filter((m): m is RegExpMatchArray => !!m && !!m[1])
    .map((m) => `0x${m[1]!.toLowerCase()}`)
    .filter((v, i, a) => a.indexOf(v) === i)
    .slice(0, maxTargets);
  const bodies = new Map<string, ListingLine[]>();
  await Promise.all(
    direct.map(async (t) => {
      bodies.set(t.toLowerCase(), await disasmOf(t, bodySize).catch(() => []));
    }),
  );
  const campaign = planDecryptionCampaign(funcLines, bodies);
  const top = campaign.candidates[0];
  if (!top || top.score < (opts.minScore ?? 5)) return null;
  return top;
}

/**
 * Plans a decryption campaign for a function: every direct `call 0x…` target that has a body in
 * `bodies` (addr → lines) is scored; indirect calls (`call rax` etc.) are listed separately.
 */
export function planDecryptionCampaign(funcLines: readonly ListingLine[], bodies: LinesByAddr = new Map()): Campaign {
  const candidates: DecryptCandidate[] = [];
  const indirect: string[] = [];
  for (const l of funcLines) {
    const m = l.text.match(kCall);
    if (!m) continue;
    const target = m[1] ? `0x${m[1].toLowerCase()}` : null;
    if (!target) {
      indirect.push(l.address);
      continue;
    }
    const body = bodies.get(target.toLowerCase()) ?? bodies.get(target);
    if (!body) {
      candidates.push({ callSite: l.address, target, score: 1, reasons: ["external/unknown body"] });
      continue;
    }
    const { score, reasons } = decryptScore(body);
    candidates.push({ callSite: l.address, target, score, reasons });
  }
  candidates.sort((a, b) => b.score - a.score);
  return {
    functionStart: funcLines[0]?.address ?? "",
    candidates,
    plan: candidates.map((c) => c.target),
  };
}
