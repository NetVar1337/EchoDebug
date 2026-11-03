// What enabled plugins contributed: views (tabs inside the Plugins view), command palette
// commands, context-menu actions on addresses and table analyses. Keys are "<plugin id>/<item id>".
// Nothing here is reachable over MCP: plugin analyses are not provider (ui_*) verbs.
import { create } from "zustand";

export type Cleanup = void | (() => void);
export type ViewSpec = { id: string; title: string; render: (container: HTMLElement) => Cleanup | Promise<Cleanup> };
export type CommandSpec = { id: string; label: string; run: () => unknown };
export type AddressActionSpec = { id: string; label: string; run: (address: string) => unknown; when?: (address: string) => boolean };
export type AnalysisParam = { name: string; label?: string; default?: string };
export type AnalysisResult = { columns: string[]; rows: (string | number | boolean | null)[][] };
export type AnalysisSpec = { id: string; title: string; description?: string; params?: AnalysisParam[]; run: (args: Record<string, string>) => AnalysisResult | Promise<AnalysisResult> };

export type Kind = "view" | "command" | "action" | "analysis";
type Spec = { view: ViewSpec; command: CommandSpec; action: AddressActionSpec; analysis: AnalysisSpec };
export type Registered<K extends Kind> = Spec[K] & { key: string; plugin: string; pluginName: string };

type RegistryStore = {
  views: Registered<"view">[];
  commands: Registered<"command">[];
  actions: Registered<"action">[];
  analyses: Registered<"analysis">[];
};

const kField: Record<Kind, keyof RegistryStore> = { view: "views", command: "commands", action: "actions", analysis: "analyses" };
const kItemId = /^[a-z0-9][a-z0-9._-]{0,63}$/i;

export const usePluginRegistry = create<RegistryStore>(() => ({ views: [], commands: [], actions: [], analyses: [] }));

function need(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}

/** Checks a registration's shape; throws with a message the plugin author can act on. */
export function checkSpec(kind: Kind, spec: unknown): void {
  need(spec && typeof spec === "object", `${kind}: expected an object`);
  const s = spec as Record<string, unknown>;
  need(typeof s.id === "string" && kItemId.test(s.id), `${kind}: "id" must be 1-64 characters of letters, digits, '.', '_' or '-'`);
  const text = kind === "command" || kind === "action" ? "label" : "title";
  need(typeof s[text] === "string" && (s[text] as string).trim() && (s[text] as string).length <= 120, `${kind} ${s.id}: "${text}" must be a non-empty string`);
  const fn = kind === "view" ? "render" : "run";
  need(typeof s[fn] === "function", `${kind} ${s.id}: "${fn}" must be a function`);
  if (kind === "action" && s.when !== undefined) need(typeof s.when === "function", `action ${s.id}: "when" must be a function`);
  if (kind === "analysis" && s.params !== undefined) {
    need(Array.isArray(s.params) && s.params.every((p) => p && typeof p === "object" && typeof (p as AnalysisParam).name === "string"), `analysis ${s.id}: "params" must be [{ name, label?, default? }]`);
  }
}

export function register<K extends Kind>(kind: K, plugin: { id: string; name: string }, spec: Spec[K]): () => void {
  checkSpec(kind, spec);
  const key = `${plugin.id}/${spec.id}`;
  const field = kField[kind];
  const list = usePluginRegistry.getState()[field] as unknown as Registered<K>[];
  if (list.some((x) => x.key === key)) throw new Error(`${kind} ${spec.id} is already registered by ${plugin.id}`);
  const entry = { ...spec, key, plugin: plugin.id, pluginName: plugin.name } as Registered<K>;
  usePluginRegistry.setState({ [field]: [...list, entry] } as Partial<RegistryStore>);
  return () => usePluginRegistry.setState((s) => ({ [field]: (s[field] as unknown as Registered<K>[]).filter((x) => x.key !== key) }) as Partial<RegistryStore>);
}

/** Removes everything a plugin registered (on disable or reload). */
export function unregisterPlugin(id: string): void {
  usePluginRegistry.setState((s) => ({
    views: s.views.filter((x) => x.plugin !== id),
    commands: s.commands.filter((x) => x.plugin !== id),
    actions: s.actions.filter((x) => x.plugin !== id),
    analyses: s.analyses.filter((x) => x.plugin !== id),
  }));
}

/** An analysis result checked before it is rendered as a table. */
export function checkResult(r: unknown): AnalysisResult {
  need(r && typeof r === "object", "analysis returned nothing (expected { columns, rows })");
  const { columns, rows } = r as AnalysisResult;
  need(Array.isArray(columns) && columns.every((c) => typeof c === "string"), "analysis result: columns must be an array of strings");
  need(Array.isArray(rows) && rows.every((row) => Array.isArray(row)), "analysis result: rows must be an array of arrays");
  return {
    columns,
    rows: rows.slice(0, 100_000).map((row) => row.slice(0, columns.length).map((c) => (c === null || ["string", "number", "boolean"].includes(typeof c) ? c : typeof c === "bigint" ? `0x${(c as bigint).toString(16)}` : JSON.stringify(c)))),
  };
}
