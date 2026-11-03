// Shared bits of the native-debugger views: the access finder ("find what writes / accesses this
// address") and the API call monitor. The relay's ptrace (Linux) and Win32 (Windows) debuggers
// serve the same dbg_* verbs; see PROTOCOL.md "Debugger".
import { request } from "./client";

export type TraceKind = "write" | "access";
export type TraceHit = { address: string; length: number; text: string; count: number; tid: number; regs: Record<string, string>; first: number; last: number };
export type Trace = {
  slot: number;
  address: string;
  size: number;
  kind: TraceKind;
  watch: { address: string; len: number };
  active: boolean;
  total: number;
  started: number;
  hits: TraceHit[];
};
export type ApiArg = { name: string; value: string; text: string };
export type ApiCall = { seq: number; t: number; tid: number; function: string; address: string; caller: string; args: ApiArg[]; ret: string | null; ret_text: string; returned: boolean };
export type ApiHook = { address: string; name: string; hits: number };
export type ApiLog = { active: boolean; entries: ApiCall[]; next: number; total: number; dropped: number; pending_returns: number; hooks: ApiHook[] };
export type ApiSignature = { name: string; args: { name: string; type: string }[]; ret: string };

/** Watch width for a value: debug registers cover 1, 2, 4 or 8 bytes. */
export function watchSize(bytes: number): number {
  if (!(bytes > 0)) return 4;
  return Math.min(8, Math.max(1, Math.round(bytes)));
}

/** Starts "find what writes / accesses" on an address; the relay attaches the debugger if needed. */
export function startTrace(address: string, size: number, kind: TraceKind): Promise<{ slot: number; watch: { address: string; len: number }; auto: boolean }> {
  return request("dbg_trace_start", { address, size: watchSize(size), kind });
}

/** Hits sorted the way the access-finder table shows them: most frequent first, then by address. */
export function sortHits(hits: TraceHit[]): TraceHit[] {
  return [...hits].sort((a, b) => b.count - a.count || (BigInt(a.address) < BigInt(b.address) ? -1 : BigInt(a.address) > BigInt(b.address) ? 1 : 0));
}

/** One line of arguments: `name=text, …`. */
export function formatArgs(c: ApiCall): string {
  return c.args.map((a) => `${a.name}=${a.text}`).join(", ");
}

/** Case-insensitive filter over function, arguments, return value, caller and thread id;
 * `!term` excludes, several space-separated terms must all match. */
export function filterCalls(calls: ApiCall[], query: string): ApiCall[] {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return calls;
  return calls.filter((c) => {
    const hay = `${c.function} ${formatArgs(c)} ${c.ret_text} ${c.caller} ${c.tid}`.toLowerCase();
    return terms.every((t) => (t.startsWith("!") && t.length > 1 ? !hay.includes(t.slice(1)) : hay.includes(t)));
  });
}

function csvCell(v: string | number): string {
  const s = String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** The call log as CSV: one row per call, arguments in one column. */
export function callsToCsv(calls: ApiCall[]): string {
  const head = ["seq", "time", "tid", "function", "address", "caller", "arguments", "return", "return_text"];
  const rows = calls.map((c) => [c.seq, new Date(c.t).toISOString(), c.tid, c.function, c.address, c.caller, formatArgs(c), c.ret ?? "", c.ret_text]);
  return [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\n") + "\n";
}

/** Function picks from free text: one per line or comma-separated, de-duplicated. */
export function parseFunctionList(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of text.split(/[\n,]/)) {
    const f = part.trim();
    if (f && !seen.has(f.toLowerCase())) {
      seen.add(f.toLowerCase());
      out.push(f);
    }
  }
  return out;
}

/** Imports grouped the way the picker offers them: `module!function`. */
export function importSpecs(imports: { dll: string; name: string }[]): string[] {
  const out = new Set<string>();
  for (const i of imports) if (i.name && !i.name.startsWith("#")) out.add(`${i.dll.toLowerCase()}!${i.name}`);
  return [...out].sort((a, b) => a.localeCompare(b));
}

// ---- x64dbg-style debugging: breakpoint options, stepping keys, the stack pane -------------------

/** A software breakpoint's options as the relay reports them (`breakpoint_info`). */
export type BpInfo = { address: string; condition: string; log: string; log_condition: string; once: boolean; hits: number };
export type StackEntry = {
  address: string;
  value: string;
  offset: number;
  kind?: "return" | "code" | "stack" | "string";
  text?: string;
  frame?: number;
  rsp?: boolean;
  rbp?: boolean;
};
export type DbgAction = "run" | "pause" | "stepInto" | "stepOver" | "stepOut" | "runToCursor" | "toggleBreakpoint" | "setOrigin";

/** x64dbg's keys: F9 run, F12 pause, F7 step into, F8 step over, Ctrl+F9 execute till return,
 * F4 run to the selected line, F2 toggle a breakpoint on it, Ctrl+* set rip to it. */
export function debuggerKey(e: { key: string; ctrlKey?: boolean; metaKey?: boolean; shiftKey?: boolean; altKey?: boolean }): DbgAction | null {
  if (e.altKey) return null;
  const mod = !!(e.ctrlKey || e.metaKey);
  if (e.key === "*" && mod) return "setOrigin";
  if (e.shiftKey) return null;
  if (e.key === "F9") return mod ? "stepOut" : "run";
  if (mod) return null;
  const plain: Record<string, DbgAction> = { F12: "pause", F7: "stepInto", F8: "stepOver", F4: "runToCursor", F2: "toggleBreakpoint" };
  return plain[e.key] ?? null;
}

/** One line for a breakpoint row: `break if … · log "…" if … · once · 3 hits`. */
export function bpSummary(b: BpInfo | undefined): string {
  if (!b) return "";
  const parts: string[] = [];
  if (b.condition) parts.push(`break if ${b.condition}`);
  if (b.log) parts.push(`log "${b.log}"${b.log_condition ? ` if ${b.log_condition}` : ""}`);
  if (b.once) parts.push("once");
  if (b.hits) parts.push(`${b.hits} hit${b.hits === 1 ? "" : "s"}`);
  return parts.join(" · ");
}

/** A stack slot's offset from rsp the way x64dbg labels it: `rsp`, `rsp+8`, `rsp-10` (hex). */
export function stackOffset(n: number): string {
  if (!n) return "rsp";
  return `rsp${n < 0 ? "-" : "+"}${Math.abs(n).toString(16).toUpperCase()}`;
}

/** The `dbg_break` fields that save a breakpoint's options. */
export function bpFields(address: string, o: { condition: string; log: string; log_condition: string; once: boolean }): Record<string, unknown> {
  return { address, enabled: true, condition: o.condition.trim(), log: o.log, log_condition: o.log_condition.trim(), once: o.once };
}
