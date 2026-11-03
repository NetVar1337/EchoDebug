// Pointer-path ranking (#17): a pointer scan returns many candidate chains for a value; rank them
// so the shortest, still-valid, stable-across-snapshots chain is tried first.

export type PtrChain = {
  /** addresses followed, base first, final value last */
  path: string[];
};

export type RankedChain = PtrChain & {
  score: number;
  reasons: string[];
};

/**
 * `valid(addr)` should resolve whether an address is currently readable/dereferenceable.
 * `seenInSnapshots` counts in how many previous snapshots the chain's final value appeared at the
 * same address — stability bonus.
 */
export function rankPointerChains(
  chains: readonly PtrChain[],
  opts: {
    valid?: (addr: string) => boolean;
    stability?: Map<string, number>;
    maxDepth?: number;
  } = {},
): RankedChain[] {
  const maxDepth = opts.maxDepth ?? 12;
  return chains
    .map((c) => {
      const reasons: string[] = [];
      let score = 0;
      const depth = c.path.length - 1;
      if (depth > maxDepth) {
        reasons.push(`depth ${depth} > ${maxDepth}, penalized`);
      }
      score -= Math.min(depth, maxDepth) * 2; // shorter chains first
      if (depth <= maxDepth) reasons.push(`depth ${depth}`);
      let validCount = 0;
      if (opts.valid) {
        for (const a of c.path) if (opts.valid(a)) validCount++;
        const ratio = validCount / c.path.length;
        score += Math.round(ratio * 10);
        if (ratio < 1) reasons.push(`${c.path.length - validCount} hop(s) currently unreadable`);
        else reasons.push("all hops readable");
      }
      const final = c.path[c.path.length - 1];
      const stab = opts.stability?.get(final.toLowerCase()) ?? 0;
      if (stab > 1) {
        score += Math.min(stab, 5);
        reasons.push(`stable in ${stab} snapshots`);
      }
      return { ...c, score, reasons };
    })
    .sort((a, b) => b.score - a.score);
}
