// Test-only fuzz harness for the byte parsers: fast-check arbitraries (random bytes and
// structure-aware mutations of real fixtures) and the robustness property every parser must keep:
//
//   - it returns, or throws a deliberate error (Error or a parser's own subclass): never a
//     non-Error and never an engine fault such as a RangeError (DataView bounds, typed array
//     length, stack overflow), a TypeError (undefined access) or a SyntaxError (unchecked RegExp);
//   - it finishes inside a time budget per input (FUZZ_BUDGET_MS, default 200 ms).
//
// FUZZ_CASES sets the number of cases per property (default 40, CI-friendly) and FUZZ_SEED replays
// a failing run. `FUZZ_CASES=100000 npm run test:fuzz` is the long run.
import fc from "fast-check";

const env = (k: string): string | undefined => (typeof process !== "undefined" ? process.env[k] : undefined);

export const kCases = Math.max(1, Number(env("FUZZ_CASES") ?? 40) || 40);
export const kBudgetMs = Math.max(1, Number(env("FUZZ_BUDGET_MS") ?? 200) || 200);
const kSeed = env("FUZZ_SEED");

/** fast-check parameters for one property. */
export function params<T>(extra: fc.Parameters<T> = {}): fc.Parameters<T> {
  return { numRuns: kCases, ...(kSeed ? { seed: Number(kSeed) } : {}), ...extra };
}

/** vitest timeout for one property: generous for the default run, scaled for long runs. */
export const kTimeout = Math.max(60_000, kCases * 60);

const kFaults: unknown[] = [RangeError, TypeError, SyntaxError, ReferenceError, EvalError, URIError];

/** Throws unless `e` is a deliberate parser error. */
export function assertCleanError(e: unknown): void {
  if (!(e instanceof Error)) throw new Error(`threw a non-Error: ${String(e)}`);
  if (kFaults.includes(e.constructor)) {
    const at = (e.stack ?? "").split("\n").find((l) => /\/src\/lib\//.test(l) && !/\/fuzz\//.test(l))?.trim() ?? "";
    throw new Error(`engine fault instead of a parse error: ${e.name}: ${e.message} ${at}`);
  }
}

function once<T>(f: () => T): { out: T | undefined; ms: number } {
  const t0 = performance.now();
  let out: T | undefined;
  try {
    out = f();
  } catch (e) {
    assertCleanError(e);
  }
  return { out, ms: performance.now() - t0 };
}

async function onceAsync<T>(f: () => Promise<T>): Promise<{ out: T | undefined; ms: number }> {
  const t0 = performance.now();
  let out: T | undefined;
  try {
    out = await f();
  } catch (e) {
    assertCleanError(e);
  }
  return { out, ms: performance.now() - t0 };
}

const slow = (ms: number, budgetMs: number) => new Error(`took ${ms.toFixed(0)} ms (budget ${budgetMs} ms)`);

/**
 * Runs `f` under the robustness property; returns its result, or undefined when it threw cleanly.
 * An input over budget is timed a second time, so a GC pause or a JIT tier-up does not fail a run.
 */
export function clean<T>(f: () => T, budgetMs = kBudgetMs): T | undefined {
  const r = once(f);
  if (r.ms <= budgetMs) return r.out;
  const again = once(f);
  if (again.ms > budgetMs) throw slow(Math.min(r.ms, again.ms), budgetMs);
  return again.out;
}

export async function cleanAsync<T>(f: () => Promise<T>, budgetMs = kBudgetMs): Promise<T | undefined> {
  const r = await onceAsync(f);
  if (r.ms <= budgetMs) return r.out;
  const again = await onceAsync(f);
  if (again.ms > budgetMs) throw slow(Math.min(r.ms, again.ms), budgetMs);
  return again.out;
}

/** Random bytes. */
export const randomBytes = (max = 4096) => fc.uint8Array({ maxLength: max });

/** Values that break offset / size / count arithmetic. */
const kExtremes = [
  0, 1, 2, 3, 4, 7, 8, 0x10, 0x7f, 0x80, 0xff, 0x100, 0x1000, 0x7fff, 0x8000, 0xffff, 0x10000,
  0x7fffffff, 0x80000000, 0x80000001, 0x80000010, 0xfffffff0, 0xfffffffe, 0xffffffff,
];

type Value = number | "len" | "self" | "back";
type Mutation =
  | { k: "u32" | "u16" | "u8"; at: number; v: Value }
  | { k: "flip"; at: number; bit: number }
  | { k: "trunc"; at: number }
  | { k: "copy"; from: number; to: number; n: number }
  | { k: "fill"; at: number; n: number; v: number };

/** Byte ranges [start, end) holding headers or directory entries: most mutations land inside one. */
export type Regions = readonly (readonly [number, number])[];

function mutationArb(len: number, regions: Regions): fc.Arbitrary<Mutation> {
  const anywhere = fc.nat({ max: Math.max(0, len - 1) });
  const usable = regions.filter(([s, e]) => s >= 0 && s < len && e > s);
  const inRegion = usable.length
    ? fc.constantFrom(...usable).chain(([s, e]) => fc.integer({ min: s, max: Math.min(len, e) - 1 }))
    : anywhere;
  const at = fc.oneof(
    { weight: 4, arbitrary: inRegion.map((o) => o & ~3) },
    { weight: 2, arbitrary: inRegion },
    { weight: 1, arbitrary: anywhere },
  );
  const value: fc.Arbitrary<Value> = fc.oneof(
    { weight: 4, arbitrary: fc.constantFrom(...kExtremes) },
    { weight: 1, arbitrary: fc.constantFrom("len" as const, "self" as const, "back" as const) },
    { weight: 1, arbitrary: fc.nat({ max: Math.max(1, len) }) },
    { weight: 1, arbitrary: fc.integer({ min: 0, max: 0xffffffff }) },
  );
  return fc.oneof(
    { weight: 6, arbitrary: fc.record({ k: fc.constant("u32" as const), at, v: value }) },
    { weight: 3, arbitrary: fc.record({ k: fc.constant("u16" as const), at, v: value }) },
    { weight: 2, arbitrary: fc.record({ k: fc.constant("u8" as const), at, v: value }) },
    { weight: 2, arbitrary: fc.record({ k: fc.constant("flip" as const), at: anywhere, bit: fc.nat({ max: 7 }) }) },
    { weight: 1, arbitrary: fc.record({ k: fc.constant("trunc" as const), at: anywhere }) },
    { weight: 1, arbitrary: fc.record({ k: fc.constant("copy" as const), from: anywhere, to: at, n: fc.integer({ min: 1, max: 64 }) }) },
    { weight: 1, arbitrary: fc.record({ k: fc.constant("fill" as const), at, n: fc.integer({ min: 1, max: 256 }), v: fc.constantFrom(0, 0xff, 0x41, 0x80) }) },
  );
}

/** Applies mutations to a copy of `seed`. */
export function applyMutations(seed: Uint8Array, muts: readonly Mutation[]): Uint8Array {
  let b = seed.slice();
  for (const m of muts) {
    if (m.k === "trunc") {
      b = b.slice(0, Math.min(m.at, b.length));
    } else if (m.k === "flip") {
      if (m.at < b.length) b[m.at] ^= 1 << m.bit;
    } else if (m.k === "copy") {
      const n = Math.min(m.n, b.length - m.from, b.length - m.to);
      if (n > 0) b.copyWithin(m.to, m.from, m.from + n);
    } else if (m.k === "fill") {
      if (m.at < b.length) b.fill(m.v, m.at, Math.min(b.length, m.at + m.n));
    } else {
      const v = m.v === "len" ? b.length : m.v === "self" ? m.at : m.v === "back" ? Math.max(0, m.at - 16) : m.v;
      const w = m.k === "u32" ? 4 : m.k === "u16" ? 2 : 1;
      if (m.at + w > b.length) continue;
      const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
      if (w === 4) dv.setUint32(m.at, v >>> 0, true);
      else if (w === 2) dv.setUint16(m.at, v & 0xffff, true);
      else dv.setUint8(m.at, v & 0xff);
    }
  }
  return b;
}

/** Mutated copies of `seed`, 0–`max` structure-aware mutations each. */
export function mutated(seed: Uint8Array, regions: Regions = [], max = 8): fc.Arbitrary<Uint8Array> {
  return fc.array(mutationArb(seed.length, regions), { minLength: 0, maxLength: max }).map((ms) => applyMutations(seed, ms));
}

/** Mutations of any of several seeds. */
export function mutatedAny(seeds: readonly { bytes: Uint8Array; regions?: Regions }[], max = 8): fc.Arbitrary<Uint8Array> {
  return fc.oneof(...seeds.map((s) => mutated(s.bytes, s.regions ?? [], max)));
}

/** Random bytes or a mutated seed. */
export function inputs(seeds: readonly { bytes: Uint8Array; regions?: Regions }[], maxRandom = 4096): fc.Arbitrary<Uint8Array> {
  return fc.oneof({ weight: 1, arbitrary: randomBytes(maxRandom) }, { weight: 4, arbitrary: mutatedAny(seeds) });
}

/**
 * Header regions of a PE image (`mapped`, indexed by RVA) or file: DOS and NT headers, the
 * section table, and the first bytes of every data directory.
 */
export function peRegions(b: Uint8Array, mapped: boolean): [number, number][] {
  if (b.length < 0x40) return [];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out: [number, number][] = [[0, 0x40]];
  const nt = dv.getUint32(0x3c, true);
  if (nt + 24 + 240 > b.length) return out;
  const oh = nt + 24;
  const is64 = dv.getUint16(oh, true) === 0x20b;
  const optSize = dv.getUint16(nt + 20, true);
  const nsec = dv.getUint16(nt + 6, true);
  out.push([nt, oh + optSize + nsec * 40]);
  const secs: { rva: number; raw: number; size: number }[] = [];
  for (let i = 0; i < nsec; i++) {
    const s = oh + optSize + i * 40;
    if (s + 40 > b.length) break;
    secs.push({ rva: dv.getUint32(s + 12, true), size: dv.getUint32(s + 16, true), raw: dv.getUint32(s + 20, true) });
  }
  const toOff = (rva: number) => {
    if (mapped) return rva;
    const s = secs.find((x) => rva >= x.rva && rva < x.rva + x.size);
    return s ? rva - s.rva + s.raw : rva;
  };
  const dd = oh + (is64 ? 112 : 96);
  for (let i = 0; i < 16; i++) {
    const rva = dv.getUint32(dd + i * 8, true);
    const size = dv.getUint32(dd + i * 8 + 4, true);
    if (!rva || !size) continue;
    const o = i === 4 ? rva : toOff(rva); // the Security directory holds a file offset
    if (o < b.length) out.push([o, Math.min(b.length, o + Math.min(size, 512))]);
  }
  return out;
}

export { fc };
