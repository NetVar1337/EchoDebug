// Alert-triggered automation: rules that fire when a relay event arrives and run an action —
// call another verb, run a plugin command, or just log. Rules are plain JSON so they can be
// exported with a session/bundle and edited in any text editor.
//
//   { "id": "decrypt-on-hit", "when": { "event": "alert", "match": { "kind": "value" } },
//     "action": { "kind": "verb", "verb": "decrypt_strings", "args": { "address": "$event.address" } } }
//
// "$event.<field>" placeholders in args are substituted from the event frame.
import { globMatch } from "./audit";

export type TriggerEvent =
  | "alert" | "watch" | "page_changed" | "module_loaded" | "module_unloaded" | "scan_done" | "breakpoint"
  // relay event names as they arrive on /client
  | "alert_event" | "freeze_error" | "progress" | "log" | "hello" | "attached" | "detached";

export type Action =
  | { kind: "verb"; verb: string; args?: Record<string, unknown> }
  | { kind: "command"; command: string; args?: Record<string, unknown> }
  | { kind: "log"; message: string };

export type Rule = {
  id: string;
  enabled?: boolean;
  when: { event: TriggerEvent; /** field globs, e.g. { kind: "value", label: "health*" } */ match?: Record<string, string> };
  action: Action;
};

export type RuleFile = { format: "echodebug.rules"; version: 1; rules: Rule[] };

export function validateRules(raw: unknown): { ok: true; rules: Rule[] } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  let v = raw;
  if (typeof v === "string") {
    try { v = JSON.parse(v); } catch (e) { return { ok: false, errors: [`not valid JSON: ${e instanceof Error ? e.message : e}`] }; }
  }
  const f = v as RuleFile;
  if (!v || typeof v !== "object" || f.format !== "echodebug.rules") errors.push('"format" must be "echodebug.rules"');
  if (f.version !== 1) errors.push('"version" must be 1');
  if (!Array.isArray(f.rules)) return { ok: false, errors: [...errors, '"rules" must be an array'] };
  const seen = new Set<string>();
  f.rules.forEach((r, i) => {
    const at = `rules[${i}]`;
    if (!r || typeof r !== "object") return errors.push(`${at} must be an object`);
    if (typeof r.id !== "string" || !/^[a-z0-9][a-z0-9._-]{1,63}$/.test(r.id)) errors.push(`${at}.id must be 2-64 chars of a-z 0-9 . _ -`);
    else if (seen.has(r.id)) errors.push(`${at}.id "${r.id}" is duplicated`);
    else seen.add(r.id);
    if (!r.when || typeof r.when.event !== "string") errors.push(`${at}.when.event is required`);
    if (r.when?.match !== undefined && (typeof r.when.match !== "object" || Array.isArray(r.when.match))) errors.push(`${at}.when.match must be an object`);
    const a = r.action;
    if (!a || !["verb", "command", "log"].includes(a.kind)) return errors.push(`${at}.action.kind must be verb, command or log`);
    if (a.kind === "verb" && typeof a.verb !== "string") errors.push(`${at}.action.verb is required`);
    if (a.kind === "command" && typeof a.command !== "string") errors.push(`${at}.action.command is required`);
  });
  return errors.length ? { ok: false, errors } : { ok: true, rules: f.rules };
}

/** Does this rule fire for the event frame? `match` fields are globs matched against the frame's fields. */
export function matchRule(rule: Rule, event: { event?: string; [k: string]: unknown }): boolean {
  if (rule.enabled === false) return false;
  if (event.event !== rule.when.event) return false;
  for (const [k, pat] of Object.entries(rule.when.match ?? {})) {
    if (!globMatch(pat, String(event[k] ?? ""))) return false;
  }
  return true;
}

export function substitute(text: unknown, event: Record<string, unknown>): unknown {
  if (typeof text !== "string") return text;
  return text.replace(/\$event\.([A-Za-z0-9_.]+)/g, (_, path: string) => {
    let v: unknown = event;
    for (const k of path.split(".")) v = v && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined;
    return v === undefined || v === null ? "" : String(v);
  });
}

export function substituteArgs(args: Record<string, unknown> | undefined, event: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args ?? {})) {
    out[k] = v && typeof v === "object" && !Array.isArray(v) ? substituteArgs(v as Record<string, unknown>, event) : substitute(v, event);
  }
  return out;
}

export type Exec = {
  verb: (verb: string, args: Record<string, unknown>) => Promise<unknown>;
  command: (command: string, args: Record<string, unknown>) => Promise<unknown>;
  log: (message: string) => void;
};

export type RuleResult = { rule: string; ok: boolean; detail?: unknown; error?: string };

/** Runs every matching rule against the event. Never throws: a failing action is reported. */
export async function runRules(rules: readonly Rule[], event: Record<string, unknown>, exec: Exec): Promise<RuleResult[]> {
  const out: RuleResult[] = [];
  for (const rule of rules) {
    if (!matchRule(rule, event)) continue;
    try {
      const a = rule.action;
      if (a.kind === "verb") exec.log(`rule '${rule.id}': ${a.verb} ${JSON.stringify(substituteArgs(a.args, event))}`);
      const detail =
        a.kind === "verb" ? await exec.verb(a.verb, substituteArgs(a.args, event))
        : a.kind === "command" ? await exec.command(a.command, substituteArgs(a.args, event))
        : (exec.log(substitute(a.message, event) as string), undefined);
      out.push({ rule: rule.id, ok: true, detail });
    } catch (e) {
      const error = e instanceof Error ? e.message : String(e);
      exec.log(`rule '${rule.id}' failed: ${error}`);
      out.push({ rule: rule.id, ok: false, error });
    }
  }
  return out;
}
