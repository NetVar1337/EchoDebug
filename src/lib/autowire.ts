// Wires automation rules to the relay's event stream: every `event` frame is matched against the
// user's rules (store/rules.ts) and matching actions run — a relay verb, a registered plugin
// command, or a log line. Firing is best-effort: a failing action is logged, never thrown.
import { request } from "./client";
import { runRules, type Exec, type Rule } from "./automation";
import { usePluginRegistry } from "./plugins/registry";
import { log } from "@/store/output";

/** The app-side executor: verbs go to the relay, commands to plugin-registered commands. */
export function automationExec(): Exec {
  return {
    verb: (verb, args) => request(verb, args),
    command: async (command, _args) => {
      const c = usePluginRegistry.getState().commands.find((x) => x.id === command || x.key === command);
      if (!c) throw new Error(`no plugin command '${command}' is registered`);
      return c.run();
    },
    log: (message) => log("info", "automation", message),
  };
}

/** Runs the rules against one event frame. Never rejects. */
export async function fireRules(frame: Record<string, unknown>, rules: readonly Rule[], exec: Exec = automationExec()) {
  if (!rules.length) return [];
  return runRules(rules, frame, exec);
}
