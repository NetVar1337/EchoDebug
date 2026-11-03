// BinDiff-style function matching between two builds of a module.
//
// Each function is reduced to: its bytes with relocated operands wildcarded (exact hash), its
// mnemonic sequence (structure hash), its mnemonic 3-grams (fuzzy similarity), its direct callees
// and its name. Matching runs in passes, most certain first:
//   1. same non-generated name   2. unique exact hash   3. unique structure hash
//   4. call-graph propagation (the i-th callee of a matched pair, when both have the same shape)
//   5. fuzzy: best 3-gram Jaccard similarity ≥ 0.6 between functions of similar size
import { insnPattern } from "./sigmaker";

export type DiffInsn = { address: string; length: number; bytes: string; text: string };
export type DiffFunction = { rva: number; size: number; name: string; insns: DiffInsn[] };
export type MatchKind = "name" | "identical" | "structure" | "callgraph" | "fuzzy";
export type DiffPair = { old: DiffFunction; new: DiffFunction; kind: MatchKind; similarity: number; changed: boolean };
export type DiffResult = { pairs: DiffPair[]; onlyOld: DiffFunction[]; onlyNew: DiffFunction[] };

type Prepared = { f: DiffFunction; exact: string; shape: string; grams: Set<string>; callees: number[] };

const generated = (n: string) => !n || /^(sub|loc|fn|func|nullsub|j)_[0-9a-f]+$/i.test(n);

function hashStr(s: string): string {
  // FNV-1a 64 as hex: stable, cheap, collisions irrelevant at this scale (it only buckets)
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < s.length; i++) h = BigInt.asUintN(64, (h ^ BigInt(s.charCodeAt(i))) * 0x100000001b3n);
  return h.toString(16);
}

const mnemonic = (t: string) => t.trim().toLowerCase().replace(/^(?:(?:notrack|bnd|lock|rep[a-z]*) )+/, "").split(/\s/)[0];

function prepare(f: DiffFunction, base: number): Prepared {
  const exact = f.insns.map((i) => insnPattern(i.bytes, i.text).map((b) => (b === null ? "??" : b.toString(16).padStart(2, "0"))).join("")).join("");
  const mns = f.insns.map((i) => mnemonic(i.text));
  const grams = new Set<string>();
  for (let i = 0; i + 2 < mns.length; i++) grams.add(`${mns[i]} ${mns[i + 1]} ${mns[i + 2]}`);
  if (mns.length < 3) grams.add(mns.join(" "));
  const callees: number[] = [];
  for (const i of f.insns) {
    const m = /^call[a-z]*\s+(?:0x)?([0-9a-f]+)$/i.exec(i.text.trim());
    if (m) callees.push(Number(BigInt("0x" + m[1]) - BigInt(base)));
  }
  return { f, exact: hashStr(exact), shape: hashStr(mns.join(";")), grams, callees };
}

export function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size && !b.size) return 1;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}

/** `oldBase`/`newBase` turn call targets into RVAs so callees can be paired. */
export function diffFunctions(oldFns: readonly DiffFunction[], newFns: readonly DiffFunction[], oldBase = 0, newBase = 0, fuzzyMin = 0.6): DiffResult {
  const A = oldFns.map((f) => prepare(f, oldBase));
  const B = newFns.map((f) => prepare(f, newBase));
  const usedA = new Set<Prepared>();
  const usedB = new Set<Prepared>();
  const pairs: DiffPair[] = [];
  const byRvaA = new Map(A.map((p) => [p.f.rva, p]));
  const byRvaB = new Map(B.map((p) => [p.f.rva, p]));
  const add = (a: Prepared, b: Prepared, kind: MatchKind) => {
    usedA.add(a);
    usedB.add(b);
    const similarity = a.exact === b.exact ? 1 : jaccard(a.grams, b.grams);
    pairs.push({ old: a.f, new: b.f, kind, similarity, changed: a.exact !== b.exact });
  };
  /** pairs functions whose key is unique on both sides; a null key opts a function out */
  const uniqueBy = (key: (p: Prepared) => string | null, kind: MatchKind) => {
    const index = (list: Prepared[], used: Set<Prepared>) => {
      const m = new Map<string, Prepared[]>();
      for (const p of list) {
        const k = used.has(p) ? null : key(p);
        if (k !== null) m.set(k, [...(m.get(k) ?? []), p]);
      }
      return m;
    };
    const ia = index(A, usedA);
    const ib = index(B, usedB);
    for (const [k, la] of ia) {
      const lb = ib.get(k);
      if (la.length === 1 && lb?.length === 1) add(la[0], lb[0], kind);
    }
  };

  uniqueBy((p) => (generated(p.f.name) ? null : p.f.name), "name");
  uniqueBy((p) => (p.f.insns.length >= 3 ? p.exact : null), "identical");
  uniqueBy((p) => (p.f.insns.length >= 6 ? p.shape : null), "structure");

  // call-graph propagation until nothing changes
  for (let round = 0; round < 8; round++) {
    let grew = false;
    for (const pr of [...pairs]) {
      const a = byRvaA.get(pr.old.rva)!;
      const b = byRvaB.get(pr.new.rva)!;
      if (a.callees.length !== b.callees.length) continue;
      a.callees.forEach((ca, i) => {
        const x = byRvaA.get(ca);
        const y = byRvaB.get(b.callees[i]);
        if (x && y && !usedA.has(x) && !usedB.has(y) && Math.abs(x.f.size - y.f.size) <= Math.max(16, x.f.size * 0.5)) {
          add(x, y, "callgraph");
          grew = true;
        }
      });
    }
    if (!grew) break;
  }

  // fuzzy: best candidate per old function, greedy by similarity
  const cands: { a: Prepared; b: Prepared; s: number }[] = [];
  const restB = B.filter((p) => !usedB.has(p));
  for (const a of A) {
    if (usedA.has(a) || a.f.insns.length < 4) continue;
    for (const b of restB) {
      if (b.f.insns.length < 4) continue;
      const r = a.f.size / Math.max(1, b.f.size);
      if (r < 0.7 || r > 1.43) continue;
      const s = jaccard(a.grams, b.grams);
      if (s >= fuzzyMin) cands.push({ a, b, s });
    }
  }
  cands.sort((x, y) => y.s - x.s);
  for (const c of cands) if (!usedA.has(c.a) && !usedB.has(c.b)) add(c.a, c.b, "fuzzy");

  return {
    pairs: pairs.sort((x, y) => x.new.rva - y.new.rva),
    onlyOld: A.filter((p) => !usedA.has(p)).map((p) => p.f),
    onlyNew: B.filter((p) => !usedB.has(p)).map((p) => p.f),
  };
}
