// What each relay verb does to the target, mirroring the MCP annotations in
// src-tauri/relay/src/mcp.rs (a unit test in src/lib/plugins checks the lists cover mcp.rs).
// Used by the plugin permission checks and the MCP panel's tool profiles.

/** Verbs that write target memory directly (DESTRUCTIVE in mcp.rs). */
export const kRawWrites = new Set(["write", "freeze", "freeze_group", "ui_revert_patch"]);
/** Verbs that change state (STATEFUL in mcp.rs, plus alerts). */
export const kStateful = new Set([
  "attach", "detach", "dump", "reopen_socket", "watch", "unwatch", "scan_new", "scan_next", "scan_clear",
  "ui_load_symbols", "ui_guess_struct", "emu_start", "emu_step", "emu_run", "emu_set", "emu_break", "emu_close",
  "module_monitor", "page_monitor", "emu_watch", "emu_snapshot", "emu_restore", "mem_snapshot",
  "ptr_save", "cancel", "agent_config", "alert_add", "alert_remove", "trace_record",
  // dump tools: write files to disk
  "dump_process_full", "kdump_extract",
  // the native debuggers: attaching, int3s and debug registers, the access finder, the API monitor
  "dbg_attach", "dbg_detach", "dbg_break", "dbg_hwbreak", "dbg_continue", "dbg_step", "dbg_pause", "dbg_set_regs",
  "dbg_trace_start", "dbg_trace_stop", "dbg_api_start", "dbg_api_stop", "dbg_api_clear",
]);
/** Verbs that change names, comments and the struct catalog. */
export const kAnnotate = new Set(["ui_set_name", "ui_set_comment", "ui_import_pdb_type"]);

/** Read-only by the MCP annotations (nothing in EchoDebug or the target changes). */
export function isReadOnlyVerb(verb: string): boolean {
  return !kRawWrites.has(verb) && !kStateful.has(verb) && !kAnnotate.has(verb);
}

/** Stateful debugger verbs gated like writes (GATED in mcp.rs): int3s, debug registers, execution. */
export const kGatedDebugger = new Set(["dbg_attach", "dbg_break", "dbg_hwbreak", "dbg_set_regs", "dbg_step", "dbg_continue", "dbg_trace_start", "dbg_api_start"]);

/** What the "ask" and "readonly" policies gate (mcp.rs `is_gated`). */
export function isGatedVerb(verb: string): boolean {
  return kRawWrites.has(verb) || verb === "dump" || verb === "dump_process_full" || verb === "trace_record" || kGatedDebugger.has(verb);
}
