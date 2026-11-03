// Which of EchoDebug's MCP tools the in-app assistant may call, and their Messages API
// definitions. Only read-only analysis tools: never a write, freeze, dump, patch revert, name
// change, attach, scan session, alert, emulation or debugger control. The same rule is enforced
// again on the desktop side (relay/src/assistant.rs) for every provider before a request leaves the app, and the
// lists below are checked against relay/src/mcp.rs and assistant.rs by a unit test.
import kTools from "../tools.json";

export type ToolDef = { name: string; verb: string; description: string; input_schema: JsonSchema };
export type JsonSchema = { type?: string; properties?: Record<string, JsonSchema>; required?: string[]; items?: JsonSchema; enum?: unknown[]; description?: string };

/** relay/src/mcp.rs DESTRUCTIVE: verbs that change the target process. */
export const kDestructive = ["write", "freeze", "freeze_group", "ui_revert_patch"];
/** relay/src/mcp.rs STATEFUL: verbs that change state but not the target's memory. */
export const kStateful = [
  "attach", "detach", "dump", "reopen_socket", "watch", "unwatch", "scan_new", "scan_next", "scan_clear",
  "ui_load_symbols", "ui_import_pdb_type", "ui_guess_struct", "emu_start", "emu_step", "emu_run", "emu_set", "emu_break", "emu_close",
  "module_monitor", "page_monitor", "emu_watch", "emu_snapshot", "emu_restore", "mem_snapshot",
  "ptr_save", "cancel", "agent_config", "ui_set_name", "ui_set_comment",
];
/** relay/src/assistant.rs ASSISTANT_DENY: read-only by annotation, but they run code, change the agent's state or use the network. */
export const kAssistantDeny = [
  "emulate", "lift_trace", "devirt", "ui_find_oep", "ui_batch_decrypt", "ui_rebuild_imports",
  "ui_load_symbols", "alert_add", "alert_remove", "ui_flirt_pat", "ui_binary_diff",
];

/** Tools the assistant handles in the app: they only fill the review lists the user accepts from. */
export const kLocalTools: ToolDef[] = [
  {
    name: "submit_name_suggestions",
    verb: "",
    description: "Hand name suggestions to the user for review. Nothing is renamed until the user accepts each suggestion. Use for the function, its callees, globals it touches, and its stack locals / arguments (as comments at the function start).",
    input_schema: {
      type: "object",
      properties: {
        suggestions: {
          type: "array",
          items: {
            type: "object",
            properties: {
              address: { type: "string", description: "0x-prefixed address the name applies to (for a local or argument: the function's address)" },
              kind: { type: "string", enum: ["function", "callee", "global", "local", "argument"] },
              current: { type: "string", description: "Current label, register or stack slot (e.g. sub_1400010A0, [rbp-0x18], rcx)" },
              name: { type: "string", description: "Suggested identifier" },
              reason: { type: "string", description: "One sentence of evidence" },
            },
            required: ["address", "kind", "name", "reason"],
          },
        },
      },
      required: ["suggestions"],
    },
  },
  {
    name: "submit_struct_fields",
    verb: "",
    description: "Hand struct field suggestions to the user for review. Nothing changes until the user accepts each field.",
    input_schema: {
      type: "object",
      properties: {
        fields: {
          type: "array",
          items: {
            type: "object",
            properties: {
              offset: { type: "integer", description: "Byte offset in the struct" },
              type: { type: "string", enum: ["hex64", "hex32", "hex16", "hex8", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "ptr", "vec2", "vec3", "vec4", "ascii", "utf16"] },
              name: { type: "string" },
              reason: { type: "string" },
            },
            required: ["offset", "type", "name", "reason"],
          },
        },
      },
      required: ["fields"],
    },
  },
];

/** The assistant may call `verb`: read-only by the MCP annotations and not denied above. */
export function isReadOnlyVerb(verb: string): boolean {
  return !kDestructive.includes(verb) && !kStateful.includes(verb) && !kAssistantDeny.includes(verb) && !verb.startsWith("dbg_") && !verb.startsWith("emu_");
}

/** EchoDebug tools offered to the assistant, in tools.json order. */
export function assistantTools(all: readonly ToolDef[] = kTools as ToolDef[]): ToolDef[] {
  return all.filter((t) => isReadOnlyVerb(t.verb));
}

const kByName = new Map<string, ToolDef>([...assistantTools().map((t) => [t.name, t] as const), ...kLocalTools.map((t) => [t.name, t] as const)]);

/** The definition of a tool the assistant may call, or undefined (unknown or not read-only). */
export function allowedTool(name: string): ToolDef | undefined {
  return kByName.get(name);
}

/** Tool definitions for a request (the desktop side writes each provider's own format). */
export function apiTools(): { name: string; description: string; input_schema: JsonSchema }[] {
  return [...assistantTools(), ...kLocalTools].map((t) => ({
    name: t.name,
    description: t.description,
    input_schema: { type: "object", ...t.input_schema },
  }));
}

const typeOk = (v: unknown, t: string | undefined): boolean => {
  switch (t) {
    case undefined: return true;
    case "string": return typeof v === "string";
    case "integer": return typeof v === "number" && Number.isInteger(v);
    case "number": return typeof v === "number" && Number.isFinite(v);
    case "boolean": return typeof v === "boolean";
    case "array": return Array.isArray(v);
    case "object": return !!v && typeof v === "object" && !Array.isArray(v);
    default: return true;
  }
};

/** Checks a tool input against its schema (types, required, enums); returns the first problem. */
export function validateInput(schema: JsonSchema, input: unknown, path = "input"): string | null {
  if (!typeOk(input, schema.type)) return `${path} must be ${schema.type}`;
  if (schema.enum && !schema.enum.includes(input)) return `${path} must be one of ${schema.enum.join(", ")}`;
  if (schema.type === "object" && input && typeof input === "object") {
    const o = input as Record<string, unknown>;
    for (const r of schema.required ?? []) if (o[r] === undefined) return `${path}.${r} is required`;
    for (const [k, sub] of Object.entries(schema.properties ?? {})) {
      if (o[k] === undefined) continue;
      const e = validateInput(sub, o[k], `${path}.${k}`);
      if (e) return e;
    }
  }
  if (schema.type === "array" && Array.isArray(input) && schema.items) {
    for (let i = 0; i < input.length; i++) {
      const e = validateInput(schema.items, input[i], `${path}[${i}]`);
      if (e) return e;
    }
  }
  return null;
}
