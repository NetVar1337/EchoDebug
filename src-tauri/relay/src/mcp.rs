//! MCP pieces beyond plain tool calls: tool annotations, the call policy (allow / ask / read-only,
//! allow and deny lists, the audit file), resource templates and argument completion.

use std::io::Write;

use serde_json::{json, Map, Value};

/// Verbs that change the target process (memory, threads, execution). `ui_revert_patch` writes the
/// journalled original bytes back through the app window.
const DESTRUCTIVE: &[&str] = &["write", "freeze", "freeze_group", "ui_revert_patch"];
/// Verbs that change state but not the target's memory: attach/detach, execution control, files.
const STATEFUL: &[&str] = &[
    "attach", "detach", "dump", "reopen_socket", "watch", "unwatch", "scan_new", "scan_next", "scan_clear",
    "ui_load_symbols", "ui_guess_struct", "emu_start", "emu_step", "emu_run", "emu_set", "emu_break", "emu_close",
    "module_monitor", "page_monitor", "emu_watch", "emu_snapshot", "emu_restore", "mem_snapshot",
    "ptr_save", "cancel", "agent_config", "ui_set_name", "ui_set_comment",
    // the native debuggers (ptrace / Win32): execution control, the access finder, the API monitor
    "dbg_attach", "dbg_detach", "dbg_break", "dbg_hwbreak", "dbg_continue", "dbg_step", "dbg_pause", "dbg_set_regs",
    "dbg_trace_start", "dbg_trace_stop", "dbg_api_start", "dbg_api_stop", "dbg_api_clear",
];
/// Stateful verbs the ask / read-only policies gate like `write`: they plant int3s in the target
/// (`dbg_break`, `dbg_api_start`) or change how it executes (attaching a debugger, debug
/// registers, registers, stepping).
const GATED: &[&str] = &[
    "dbg_attach", "dbg_break", "dbg_hwbreak", "dbg_set_regs", "dbg_step", "dbg_continue", "dbg_trace_start", "dbg_api_start",
];

/// MCP 2025-06-18 tool annotations, derived from the verb.
pub fn annotations(verb: &str, title: &str) -> Value {
    let destructive = DESTRUCTIVE.contains(&verb);
    let stateful = STATEFUL.contains(&verb);
    json!({
        "title": title,
        "readOnlyHint": !destructive && !stateful,
        "destructiveHint": destructive,
        // the same write twice leaves the same bytes; attach/detach twice too
        "idempotentHint": destructive || matches!(verb, "attach" | "detach" | "dbg_detach" | "dbg_trace_stop" | "dbg_api_stop" | "dbg_api_clear" | "watch" | "unwatch" | "ui_set_name" | "ui_set_comment"),
        "openWorldHint": verb == "ui_load_symbols",
    })
}

pub fn is_read_only(verb: &str) -> bool {
    !DESTRUCTIVE.contains(&verb) && !STATEFUL.contains(&verb)
}

/// What the ask / read-only policies gate: calls that change the target's memory, plus dumps
/// (they write files), plus the debugger verbs that plant int3s or change execution (`GATED`).
/// Attach, scans and the emulator change only EchoDebug's own state.
pub fn is_gated(verb: &str) -> bool {
    DESTRUCTIVE.contains(&verb) || verb == "dump" || GATED.contains(&verb)
}

/// What MCP clients may call. Set by the app (Settings → MCP), kept in memory by the relay.
#[derive(Clone, Debug)]
pub struct Policy {
    /// "allow": everything; "ask": the app window approves every gated call (`is_gated`);
    /// "readonly": gated calls are refused
    pub mode: String,
    /// when non-empty, only these tools may be called
    pub allow: Vec<String>,
    /// never callable
    pub deny: Vec<String>,
    /// append every call to <config>/EchoDebug/mcp-audit.jsonl
    pub audit: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { mode: "allow".into(), allow: Vec::new(), deny: Vec::new(), audit: false }
    }
}

impl Policy {
    pub fn to_json(&self) -> Value {
        json!({ "mode": self.mode, "allow": self.allow, "deny": self.deny, "audit": self.audit, "audit_path": audit_path().display().to_string() })
    }

    pub fn from_json(v: &Value, cur: &Policy) -> Result<Policy, String> {
        let list = |k: &str, d: &Vec<String>| -> Vec<String> {
            v.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()).unwrap_or_else(|| d.clone())
        };
        let mode = v.get("mode").and_then(Value::as_str).unwrap_or(&cur.mode).to_owned();
        if !matches!(mode.as_str(), "allow" | "ask" | "readonly") {
            return Err(format!("unknown policy mode '{mode}' (allow, ask, readonly)"));
        }
        Ok(Policy { mode, allow: list("allow", &cur.allow), deny: list("deny", &cur.deny), audit: v.get("audit").and_then(Value::as_bool).unwrap_or(cur.audit) })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Ask,
    Deny(String),
}

pub fn decide(p: &Policy, tool: &str, verb: &str) -> Decision {
    if p.deny.iter().any(|d| d == tool) {
        return Decision::Deny(format!("'{tool}' is on the deny list (EchoDebug → Settings → MCP)"));
    }
    if !p.allow.is_empty() && !p.allow.iter().any(|a| a == tool) {
        return Decision::Deny(format!("'{tool}' is not on the allow list (EchoDebug → Settings → MCP)"));
    }
    if !is_gated(verb) {
        return Decision::Allow;
    }
    match p.mode.as_str() {
        "readonly" => Decision::Deny(format!("'{tool}' changes the target and the MCP policy is read-only (EchoDebug → Settings → MCP)")),
        "ask" => Decision::Ask,
        _ => Decision::Allow,
    }
}

pub fn audit_path() -> std::path::PathBuf {
    crate::auth::config_dir().join("mcp-audit.jsonl")
}

pub fn append_audit(entry: &Value) {
    let path = audit_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{entry}");
    }
}

// ---- resource templates -------------------------------------------------------------------------

pub fn templates() -> Value {
    json!([
        { "uriTemplate": "echodebug://memory/{address}/{size}", "name": "Memory", "description": "size bytes (≤ 64 KiB) at a 0x address or module+0x offset, as hex", "mimeType": "application/json" },
        { "uriTemplate": "echodebug://disasm/{address}", "name": "Disassembly", "description": "the function at an address, disassembled", "mimeType": "application/json" },
        { "uriTemplate": "echodebug://module/{name}/pe", "name": "Module PE", "description": "headers, sections, imports, exports, entropy (app window)", "mimeType": "application/json" },
        { "uriTemplate": "echodebug://module/{name}/exports", "name": "Module exports", "description": "the export table (app window)", "mimeType": "application/json" },
        { "uriTemplate": "echodebug://module/{name}/strings", "name": "Module strings", "description": "ASCII/UTF-16 strings (app window)", "mimeType": "application/json" },
        { "uriTemplate": "echodebug://names", "name": "Names", "description": "every name and comment the user gave an address (app window)", "mimeType": "application/json" },
    ])
}

/// A templated resource URI turned into the relay request that answers it.
pub fn template_request(uri: &str) -> Option<Map<String, Value>> {
    let rest = uri.strip_prefix("echodebug://")?;
    let parts: Vec<&str> = rest.split('/').collect();
    let mut m = Map::new();
    let dec = |s: &str| s.replace("%2B", "+").replace("%2b", "+").replace("%20", " ");
    match parts.as_slice() {
        ["memory", addr, size] => {
            m.insert("type".into(), json!("ui_read_text"));
            m.insert("address".into(), json!(dec(addr)));
            m.insert("size".into(), json!(size.parse::<u64>().ok()?.min(0x10000)));
        }
        ["disasm", addr] => {
            m.insert("type".into(), json!("ui_disasm_text"));
            m.insert("address".into(), json!(dec(addr)));
            m.insert("size".into(), json!(256));
        }
        ["module", name, "pe"] => {
            m.insert("type".into(), json!("ui_pe_info"));
            m.insert("module".into(), json!(dec(name)));
        }
        ["module", name, "exports"] => {
            m.insert("type".into(), json!("ui_exports"));
            m.insert("module".into(), json!(dec(name)));
        }
        ["module", name, "strings"] => {
            m.insert("type".into(), json!("ui_strings"));
            m.insert("module".into(), json!(dec(name)));
            m.insert("limit".into(), json!(5000));
        }
        ["names"] => {
            m.insert("type".into(), json!("ui_names"));
        }
        _ => return None,
    }
    Some(m)
}

// ---- completion ---------------------------------------------------------------------------------

pub const VALUE_TYPES: &[&str] = &["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "bytes", "string", "wstring"];

/// Which suggestion source an argument uses.
pub fn completion_kind(arg: &str) -> Option<&'static str> {
    match arg {
        "module" | "name" => Some("module"),
        "address" | "target" | "start" | "end" | "from" | "routine" => Some("address"),
        "value_type" => Some("value_type"),
        "format" => Some("format"),
        _ => None,
    }
}

/// Up to 100 candidates starting with (else containing) `prefix`, case-insensitively.
pub fn rank(candidates: impl IntoIterator<Item = String>, prefix: &str) -> Value {
    let p = prefix.to_lowercase();
    let all: Vec<String> = candidates.into_iter().collect();
    let mut starts: Vec<String> = all.iter().filter(|c| c.to_lowercase().starts_with(&p)).cloned().collect();
    let mut contains: Vec<String> = all.iter().filter(|c| !c.to_lowercase().starts_with(&p) && c.to_lowercase().contains(&p)).cloned().collect();
    starts.sort();
    contains.sort();
    starts.dedup();
    contains.dedup();
    starts.extend(contains);
    let total = starts.len();
    starts.truncate(100);
    json!({ "completion": { "values": starts, "total": total, "hasMore": total > 100 } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn annotations_follow_the_verb() {
        assert_eq!(annotations("read", "r")["readOnlyHint"], true);
        assert_eq!(annotations("write", "w")["destructiveHint"], true);
        assert_eq!(annotations("write", "w")["readOnlyHint"], false);
        assert_eq!(annotations("attach", "a")["readOnlyHint"], false);
        assert_eq!(annotations("attach", "a")["destructiveHint"], false);
        assert_eq!(annotations("ui_load_symbols", "s")["openWorldHint"], true);
        // the app window's annotation tools
        assert_eq!(annotations("ui_list_names", "n")["readOnlyHint"], true);
        assert_eq!(annotations("ui_list_signatures", "s")["readOnlyHint"], true);
        let set = annotations("ui_set_name", "n");
        assert_eq!((set["readOnlyHint"].as_bool(), set["destructiveHint"].as_bool(), set["idempotentHint"].as_bool()), (Some(false), Some(false), Some(true)));
        assert_eq!(annotations("ui_set_comment", "c")["readOnlyHint"], false);
        assert_eq!(annotations("ui_revert_patch", "r")["destructiveHint"], true);
        // the debugger: reading results is read-only, starting / stopping monitors is stateful
        for v in ["dbg_trace_results", "dbg_api_log", "dbg_api_signatures", "dbg_status", "dbg_regs", "dbg_disasm"] {
            assert_eq!(annotations(v, "x")["readOnlyHint"], true, "{v}");
        }
        for v in ["dbg_trace_start", "dbg_trace_stop", "dbg_api_start", "dbg_api_stop", "dbg_api_clear", "dbg_break", "dbg_continue"] {
            assert_eq!(annotations(v, "x")["readOnlyHint"], false, "{v}");
            assert_eq!(annotations(v, "x")["destructiveHint"], false, "{v}");
        }
        assert_eq!(annotations("dbg_api_stop", "x")["idempotentHint"], true);
    }

    #[test]
    fn debugger_verbs_that_touch_the_target_are_gated() {
        let mut p = Policy { mode: "readonly".into(), ..Policy::default() };
        assert!(matches!(decide(&p, "api_monitor_start", "dbg_api_start"), Decision::Deny(_)));
        assert!(matches!(decide(&p, "find_accesses_start", "dbg_trace_start"), Decision::Deny(_)));
        assert!(matches!(decide(&p, "x", "dbg_break"), Decision::Deny(_)));
        // reading and stopping stay allowed: stopping restores the target
        assert_eq!(decide(&p, "api_monitor_log", "dbg_api_log"), Decision::Allow);
        assert_eq!(decide(&p, "api_monitor_stop", "dbg_api_stop"), Decision::Allow);
        assert_eq!(decide(&p, "find_accesses_stop", "dbg_trace_stop"), Decision::Allow);
        assert_eq!(decide(&p, "find_accesses_results", "dbg_trace_results"), Decision::Allow);
        p.mode = "ask".into();
        assert_eq!(decide(&p, "api_monitor_start", "dbg_api_start"), Decision::Ask);
        assert_eq!(decide(&p, "find_accesses_start", "dbg_trace_start"), Decision::Ask);
    }

    #[test]
    fn policy_decisions() {
        let mut p = Policy::default();
        assert_eq!(decide(&p, "write_memory", "write"), Decision::Allow);
        p.mode = "ask".into();
        assert_eq!(decide(&p, "write_memory", "write"), Decision::Ask);
        assert_eq!(decide(&p, "read_memory", "read"), Decision::Allow);
        p.mode = "readonly".into();
        assert!(matches!(decide(&p, "freeze_value", "freeze"), Decision::Deny(_)));
        assert_eq!(decide(&p, "disassemble", "disassemble"), Decision::Allow);
        assert_eq!(decide(&p, "emu_step", "emu_step"), Decision::Allow);
        assert!(matches!(decide(&p, "dump_module", "dump"), Decision::Deny(_)));
        // reverting a patch writes target memory; naming only touches EchoDebug's own stores
        assert!(matches!(decide(&p, "revert_patch", "ui_revert_patch"), Decision::Deny(_)));
        assert_eq!(decide(&p, "set_name", "ui_set_name"), Decision::Allow);
        p.mode = "ask".into();
        assert_eq!(decide(&p, "revert_patch", "ui_revert_patch"), Decision::Ask);
        p.mode = "allow".into();
        p.deny = vec!["dump_module".into()];
        assert!(matches!(decide(&p, "dump_module", "dump"), Decision::Deny(_)));
        p.allow = vec!["read_memory".into()];
        assert!(matches!(decide(&p, "disassemble", "disassemble"), Decision::Deny(_)));
        assert_eq!(decide(&p, "read_memory", "read"), Decision::Allow);
        assert!(Policy::from_json(&json!({ "mode": "yolo" }), &p).is_err());
        let q = Policy::from_json(&json!({ "mode": "ask", "audit": true }), &p).unwrap();
        assert_eq!((q.mode.as_str(), q.audit, q.allow.len()), ("ask", true, 1));
    }

    #[test]
    fn templates_and_completion() {
        let r = template_request("echodebug://memory/game.exe%2B0x10/32").unwrap();
        assert_eq!(r["address"], "game.exe+0x10");
        assert_eq!(r["size"], 32);
        assert_eq!(template_request("echodebug://module/ntdll.dll/exports").unwrap()["type"], "ui_exports");
        assert!(template_request("echodebug://memory/0x1/notanumber").is_none());
        assert!(template_request("echodebug://nope").is_none());
        let c = rank(["kernel32.dll", "KERNELBASE.dll", "ntdll.dll", "game.exe"].map(String::from), "ker");
        assert_eq!(c["completion"]["values"], json!(["KERNELBASE.dll", "kernel32.dll"]));
        let c = rank(["kernel32.dll", "ntdll.dll"].map(String::from), "dll");
        assert_eq!(c["completion"]["total"], 2);
        assert_eq!(completion_kind("module"), Some("module"));
    }
}
