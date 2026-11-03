// MCP tool profiles: one click sets the call policy (mode + allow/deny lists) the relay enforces.
// Tools a profile denies also disappear from tools/list, so a client sees only what it may use.
import tools from "@/lib/tools.json";
import { isGatedVerb, isReadOnlyVerb } from "@/lib/verbclass";

export type PolicyMode = "allow" | "ask" | "readonly";
export type PolicyShape = { mode: PolicyMode; allow: string[]; deny: string[] };
export type PresetId = "readonly" | "re" | "full";
export type Preset = { id: PresetId; label: string; hint: string; policy: PolicyShape };

type ToolDef = { name: string; verb: string };
const kTools = tools as ToolDef[];

/** Changes only EchoDebug's own connection, so read-only analysis keeps them. */
const kReadOnlyKeeps = new Set(["attach", "detach", "cancel"]);

/** Tools that change anything (target memory, EchoDebug state, names, files): denied by the read-only profile. */
export function changingTools(): string[] {
  return kTools.filter((t) => !isReadOnlyVerb(t.verb) && !kReadOnlyKeeps.has(t.verb)).map((t) => t.name).sort();
}

export const kPresets: Preset[] = [
  {
    id: "readonly",
    label: "Read-only analysis",
    hint: "Read memory, disassemble, analyse, attach and detach. Nothing that writes, freezes, dumps, renames, emulates or scans is offered.",
    policy: { mode: "readonly", allow: [], deny: changingTools() },
  },
  {
    id: "re",
    label: "Reverse engineering",
    hint: "Everything for analysis, scans, the emulator, naming and comments; writes, freezes and dumps need your approval.",
    policy: { mode: "ask", allow: [], deny: [] },
  },
  {
    id: "full",
    label: "Full control",
    hint: "Every tool, writes included, without asking. Use with clients you trust.",
    policy: { mode: "allow", allow: [], deny: [] },
  },
];

const same = (a: string[], b: string[]) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

/** The profile a policy equals, or null for a custom policy. */
export function matchPreset(p: PolicyShape): PresetId | null {
  return kPresets.find((x) => x.policy.mode === p.mode && same(x.policy.allow, p.allow) && same(x.policy.deny, p.deny))?.id ?? null;
}

/** Tool names a client may call under `p` (what the relay lists, the app window's ui_* tools included). */
export function allowedTools(p: PolicyShape): string[] {
  return kTools
    .filter((t) => !p.deny.includes(t.name))
    .filter((t) => !p.allow.length || p.allow.includes(t.name))
    .filter((t) => !(p.mode === "readonly" && isGatedVerb(t.verb)))
    .map((t) => t.name);
}
