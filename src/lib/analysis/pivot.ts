// Stack-pivot and CET/control-flow detection (#14): finds instructions that move the stack
// pointer to attacker-influenced memory (the classic `xchg rsp, rax` / `mov rsp, [mem]` pivot),
// and reports indirect branch targets that lack ENDBR64 (CET-IBT) so a landing-pad check can be
// suggested. Works on plain listing lines.
import type { ListingLine } from "./listing";

export type PivotFinding = {
  address: string;
  kind: "xchg-rsp" | "mov-rsp" | "pop-rsp" | "leave";
  severity: "high" | "medium";
  detail: string;
};

const kPivots: { re: RegExp; kind: PivotFinding["kind"]; severity: PivotFinding["severity"]; detail: string }[] = [
  { re: /\bxchg\s+(?:(?:e|r)sp\s*,\s*\w+|\w+\s*,\s*(?:e|r)sp)\b/i, kind: "xchg-rsp", severity: "high", detail: "stack pointer swapped with another register — classic stack pivot" },
  { re: /\bmov\s+(?:e|r)sp\s*,\s*(?:\[|r|i)/i, kind: "mov-rsp", severity: "high", detail: "stack pointer loaded from a register or memory — possible pivot" },
  { re: /\bpop\s+(?:e|r)sp\b/i, kind: "pop-rsp", severity: "medium", detail: "stack pointer popped from the stack" },
  { re: /\bleave\b/i, kind: "leave", severity: "medium", detail: "leave (mov rsp,rbp; pop rbp) — pivot when rbp was controlled" },
];

export function findStackPivots(lines: readonly ListingLine[]): PivotFinding[] {
  const out: PivotFinding[] = [];
  for (const l of lines) {
    for (const p of kPivots) {
      if (p.re.test(l.text)) {
        out.push({ address: l.address, kind: p.kind, severity: p.severity, detail: `${p.detail}: ${l.text}` });
        break;
      }
    }
  }
  return out;
}

/** Addresses in `indirectTargets` whose listing does not start with endbr64 (CET IBT missing). */
export function findMissingEndbr(lines: readonly ListingLine[], indirectTargets: readonly string[]): string[] {
  const byAddr = new Map(lines.map((l) => [l.address.toLowerCase(), l.text.toLowerCase()]));
  const out: string[] = [];
  for (const t of indirectTargets) {
    const text = byAddr.get(t.toLowerCase());
    if (text !== undefined && !text.startsWith("endbr64") && !text.startsWith("endbr32")) out.push(t);
  }
  return out;
}

export type CetReport = {
  pivots: PivotFinding[];
  /** indirect targets missing ENDBR64 */
  missingEndbr: string[];
  /** indirect targets present in the listing */
  checked: number;
};

export function analyzeControlFlow(lines: readonly ListingLine[], indirectTargets: readonly string[]): CetReport {
  return {
    pivots: findStackPivots(lines),
    missingEndbr: findMissingEndbr(lines, indirectTargets),
    checked: indirectTargets.length,
  };
}
