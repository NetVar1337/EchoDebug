// Target-side function fuzzing (#15): drive the emulator (`emulate` verb) over one function with
// mutated register/argument and memory inputs, and collect the distinct ways it can fault — without
// ever touching the live process. Inputs are generated with fast-check; every run is bounded by
// an instruction cap and the whole campaign by a time budget (same FUZZ_BUDGET_MS discipline as the
// parser fuzzers).
import fc from "fast-check";
import type { EmuReply } from "./emucall";

export type EmulateFn = (args: {
  start: string;
  end: string;
  regs: Record<string, string>;
  write: { address: string; data: string }[];
  max_insns: number;
  timeout_us: number;
}) => Promise<EmuReply>;

export type CrashFinding = {
  /** the faulting stop reason, e.g. "unmapped-memory" / error_name */
  stop: string;
  faultAddress?: string;
  regs: Record<string, string>;
  write: { address: string; data: string }[];
  instructions: number;
};

export type FuzzResult = {
  runs: number;
  findings: CrashFinding[];
  /** findings deduped by stop reason */
  distinctStops: string[];
  budgetMs: number;
  timedOut: boolean;
};

/** One mutated input: random argument registers plus random scratch writes near a buffer. */
const inputArb = fc.record({
  regs: fc.record({
    rcx: fc.bigUintN(64).map((v) => `0x${v.toString(16)}`),
    rdx: fc.bigUintN(64).map((v) => `0x${v.toString(16)}`),
    r8: fc.bigUintN(64).map((v) => `0x${v.toString(16)}`),
    r9: fc.bigUintN(64).map((v) => `0x${v.toString(16)}`),
  }),
  write: fc.array(
    fc.record({
      address: fc.nat({ max: 0x10000 }).map((v) => `0x${(0x10000000 + v).toString(16)}`),
      data: fc.hexaString({ minLength: 2, maxLength: 64 }).map((h) => (h.length % 2 ? h + "0" : h)),
    }),
    { maxLength: 4 },
  ),
});

/**
 * Fuzzes [start, end) of the target. `emulate` is injectable for tests. A run "crashes" when it
 * stops without reaching the end (fault) — `reached_end` with error_name "ok" is a clean run.
 */
export async function fuzzFunction(
  start: bigint,
  end: bigint,
  emulate: EmulateFn,
  opts: { runs?: number; budgetMs?: number; maxInsns?: number; timeoutUs?: number; seed?: number } = {},
): Promise<FuzzResult> {
  const runs = opts.runs ?? 64;
  const budgetMs = opts.budgetMs ?? 200;
  const maxInsns = opts.maxInsns ?? 100_000;
  const timeoutUs = opts.timeoutUs ?? 500_000;
  const started = Date.now();
  const findings: CrashFinding[] = [];
  const stops = new Set<string>();
  let timedOut = false;
  let n = 0;
  await fc.assert(
    fc.asyncProperty(inputArb, async (input) => {
      if (n >= runs || Date.now() - started > budgetMs) {
        timedOut = Date.now() - started > budgetMs;
        return true; // over budget: skip the run (returning false would fail the property)
      }
      n++;
      const r = await emulate({
        start: `0x${start.toString(16)}`,
        end: `0x${end.toString(16)}`,
        regs: input.regs,
        write: input.write,
        max_insns: maxInsns,
        timeout_us: timeoutUs,
      }).catch((e) => ({ error_name: `request-failed: ${e instanceof Error ? e.message : e}`, reached_end: false, instructions: 0, regs: {} }) as EmuReply);
      if (!r.reached_end || r.error_name !== "ok") {
        const stop = r.error_name || "unknown";
        stops.add(stop);
        const fault = (r as EmuReply & { fault_address?: string }).fault_address;
        findings.push({ stop, ...(fault ? { faultAddress: fault } : {}), regs: r.regs ?? {}, write: input.write, instructions: r.instructions ?? 0 });
      }
      return true;
    }),
    { numRuns: runs, seed: opts.seed },
  );
  return { runs: n, findings, distinctStops: [...stops], budgetMs, timedOut };
}
