// Audit log for every relay verb call, plus per-client ACLs on top of the MCP tool profiles.
//
// The relay already keeps a 200-entry ring buffer of MCP tools/call frames (echodebug://mcp/log);
// this module is the app-side equivalent for every verb the UI, scripts and plugins send, and the
// ACL layer lets one client be restricted further than the global "readonly / reverse / full" profiles.
import { isReadOnlyVerb, kAnnotate, kRawWrites, kStateful } from "./verbclass";

export type AuditClass = "read" | "write" | "stateful" | "annotate";

export type AuditEntry = {
  seq: number;
  ts: number;
  /** which client sent it: "ui", "mcp:<clientInfo>", "plugin:<id>", "script", … */
  client: string;
  verb: string;
  cls: AuditClass;
  /** arguments with byte payloads shrunk so the log stays readable */
  args: Record<string, unknown>;
  ok: boolean;
  ms: number;
  error?: string;
};

export function classifyVerb(verb: string): AuditClass {
  if (kRawWrites.has(verb)) return "write";
  if (kAnnotate.has(verb)) return "annotate";
  if (kStateful.has(verb)) return "stateful";
  return isReadOnlyVerb(verb) ? "read" : "stateful";
}

/** Shrinks long hex/base64 argument values so a dump's payload doesn't flood the log. */
export function shrinkArgs(args: Record<string, unknown>, max = 64): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === "string" && v.length > max && /^[0-9a-fA-F]+$/.test(v)) out[k] = `${v.slice(0, max)}… (+${v.length - max} hex chars)`;
    else if (v && typeof v === "object" && !Array.isArray(v)) out[k] = shrinkArgs(v as Record<string, unknown>, max);
    else out[k] = v;
  }
  return out;
}

export class AuditLog {
  private entries: AuditEntry[] = [];
  private nextSeq = 1;
  constructor(readonly max = 1000) {}

  record(e: Omit<AuditEntry, "seq" | "cls" | "args" | "ts"> & { args?: Record<string, unknown>; ts?: number }): AuditEntry {
    const entry: AuditEntry = {
      seq: this.nextSeq++,
      ts: e.ts ?? Date.now(),
      client: e.client,
      verb: e.verb,
      cls: classifyVerb(e.verb),
      args: shrinkArgs(e.args ?? {}),
      ok: e.ok,
      ms: e.ms,
      ...(e.error !== undefined ? { error: e.error } : {}),
    };
    this.entries.push(entry);
    if (this.entries.length > this.max) this.entries.splice(0, this.entries.length - this.max);
    return entry;
  }

  list(): readonly AuditEntry[] {
    return this.entries;
  }

  /** Entries with seq > `seq` (for incremental sync to a viewer). */
  since(seq: number): readonly AuditEntry[] {
    return this.entries.filter((e) => e.seq > seq);
  }

  filter(pred: (e: AuditEntry) => boolean): readonly AuditEntry[] {
    return this.entries.filter(pred);
  }

  clear(): void {
    this.entries = [];
  }
}

/** The shared log; client.ts records into it on every request. */
export const auditLog = new AuditLog();

// --- per-client ACL ------------------------------------------------------------

/** `*` matches any run of characters, so "dbg_*" matches dbg_attach, dbg_step, … */
export function globMatch(pattern: string, value: string): boolean {
  const rx = new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
  return rx.test(value);
}

export type AclRule = {
  /** client id or glob, e.g. "mcp:claude-code" or "plugin:*" */
  client: string;
  /** when present, only these verb globs are allowed */
  allow?: string[];
  /** these verb globs are always denied (deny wins over allow) */
  deny?: string[];
};

export class Acl {
  constructor(readonly rules: readonly AclRule[] = []) {}

  /** Rules whose client glob matches, most specific (longest pattern) first. */
  private matching(client: string): AclRule[] {
    return this.rules
      .filter((r) => globMatch(r.client, client))
      .sort((a, b) => b.client.length - a.client.length);
  }

  allowed(client: string, verb: string): boolean {
    for (const r of this.matching(client)) {
      if (r.deny?.some((p) => globMatch(p, verb))) return false;
      if (r.allow && !r.allow.some((p) => globMatch(p, verb))) return false;
    }
    return true;
  }

  /** Why a call was refused (for the error message), or null when allowed. */
  denyReason(client: string, verb: string): string | null {
    if (this.allowed(client, verb)) return null;
    const r = this.matching(client)[0];
    return `ACL: client '${client}' may not call '${verb}'${r?.allow ? ` (allowed: ${r.allow.join(", ")})` : ""}`;
  }
}
