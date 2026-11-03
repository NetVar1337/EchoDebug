//! One-click MCP client setup (the MCP panel's "Connect a client"): where each client keeps its MCP
//! servers on Windows, macOS and Linux, and how to add or remove EchoDebug there without touching
//! anything else.
//!
//! - JSON / JSONC files (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, Gemini CLI,
//!   Cline) are edited in place: only the `echodebug` member is inserted, replaced or removed, so
//!   comments, formatting and every other server stay as they are.
//! - Codex CLI's TOML gets its own `[mcp_servers.echodebug]` table.
//! - Continue gets its own block file (`~/.continue/mcpServers/echodebug.yaml`).
//!
//! [`plan`] computes the new file and a diff for the preview; [`apply`] refuses to write when the
//! file changed since the preview, keeps a backup of the old file next to it and writes atomically.
//! Paths only ever come from [`config_path`] (a fixed table), never from the caller.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// The name EchoDebug's entry has in every client's config.
pub const SERVER_NAME: &str = "echodebug";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Windows,
    Macos,
    Linux,
}

/// Where the user's files are (from the environment; tests build their own).
#[derive(Clone, Debug)]
pub struct Env {
    pub os: Os,
    pub home: PathBuf,
    /// `%APPDATA%` (Windows)
    pub appdata: Option<PathBuf>,
    /// `$XDG_CONFIG_HOME` (Linux)
    pub xdg_config: Option<PathBuf>,
    /// `$CODEX_HOME`
    pub codex_home: Option<PathBuf>,
}

impl Env {
    pub fn current() -> Env {
        let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        let os = if cfg!(windows) {
            Os::Windows
        } else if cfg!(target_os = "macos") {
            Os::Macos
        } else {
            Os::Linux
        };
        let home = var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).or_else(|| var("HOME")).unwrap_or_else(|| PathBuf::from("."));
        Env { os, home, appdata: var("APPDATA"), xdg_config: var("XDG_CONFIG_HOME"), codex_home: var("CODEX_HOME") }
    }

    fn appdata(&self) -> PathBuf {
        self.appdata.clone().unwrap_or_else(|| self.home.join("AppData").join("Roaming"))
    }

    fn xdg(&self) -> PathBuf {
        self.xdg_config.clone().unwrap_or_else(|| self.home.join(".config"))
    }

    /// `Code/User`, VS Code's user data folder.
    fn vscode_user(&self) -> PathBuf {
        match self.os {
            Os::Windows => self.appdata().join("Code").join("User"),
            Os::Macos => self.home.join("Library").join("Application Support").join("Code").join("User"),
            Os::Linux => self.xdg().join("Code").join("User"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Streamable HTTP to the running app, with the token header
    Http,
    /// the client launches `<EchoDebug> --mcp-stdio` (or `echodebug-relay --stdio`); no token
    Stdio,
}

impl Transport {
    pub fn parse(s: &str) -> Option<Transport> {
        match s {
            "http" => Some(Transport::Http),
            "stdio" => Some(Transport::Stdio),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::Stdio => "stdio",
        }
    }
}

/// What gets written: the endpoint and token for HTTP, the command for stdio.
#[derive(Clone, Debug)]
pub struct Server {
    pub url: String,
    pub token: Option<String>,
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    /// JSON (comments allowed) with the servers object at this key path
    Json(&'static [&'static str]),
    Toml,
    /// a file of its own
    Yaml,
}

pub struct Client {
    pub id: &'static str,
    pub name: &'static str,
    pub http: bool,
    pub stdio: bool,
    format: Format,
    pub docs: &'static str,
    pub note: &'static str,
}

pub const CLIENTS: &[Client] = &[
    Client { id: "claude-desktop", name: "Claude Desktop", http: false, stdio: true, format: Format::Json(&["mcpServers"]), docs: "https://modelcontextprotocol.io/docs/develop/connect-local-servers", note: "Its config file takes local (stdio) servers only. Quit and restart Claude Desktop afterwards." },
    Client { id: "claude-code", name: "Claude Code", http: true, stdio: true, format: Format::Json(&["mcpServers"]), docs: "https://code.claude.com/docs/en/mcp", note: "User scope in ~/.claude.json, which Claude Code also writes: close running sessions first, or run the `claude mcp add` command instead." },
    Client { id: "cursor", name: "Cursor", http: true, stdio: true, format: Format::Json(&["mcpServers"]), docs: "https://cursor.com/docs/context/mcp", note: "Global ~/.cursor/mcp.json." },
    Client { id: "vscode", name: "VS Code", http: true, stdio: true, format: Format::Json(&["servers"]), docs: "https://code.visualstudio.com/docs/copilot/reference/mcp-configuration", note: "User-profile mcp.json (MCP: Open User Configuration). For one workspace use .vscode/mcp.json with the same entry." },
    Client { id: "windsurf", name: "Windsurf", http: true, stdio: true, format: Format::Json(&["mcpServers"]), docs: "https://docs.windsurf.com/windsurf/cascade/mcp", note: "Cascade uses at most 100 tools across all servers and EchoDebug offers up to 140: trim them with an allow list in the call policy below." },
    Client { id: "zed", name: "Zed", http: true, stdio: true, format: Format::Json(&["context_servers"]), docs: "https://zed.dev/docs/ai/mcp", note: "Zed's settings.json (context_servers)." },
    Client { id: "codex", name: "Codex CLI", http: true, stdio: true, format: Format::Toml, docs: "https://developers.openai.com/codex/mcp", note: "~/.codex/config.toml ($CODEX_HOME if set)." },
    Client { id: "gemini", name: "Gemini CLI", http: true, stdio: true, format: Format::Json(&["mcpServers"]), docs: "https://geminicli.com/docs/tools/mcp-server/", note: "User settings ~/.gemini/settings.json." },
    Client { id: "continue", name: "Continue", http: true, stdio: true, format: Format::Yaml, docs: "https://docs.continue.dev/customize/deep-dives/mcp", note: "A block file of its own in ~/.continue/mcpServers (agent mode only)." },
    Client { id: "cline", name: "Cline", http: true, stdio: true, format: Format::Json(&["mcpServers"]), docs: "https://docs.cline.bot/mcp/configuring-mcp-servers", note: "cline_mcp_settings.json of the VS Code extension, or of the Cline CLI." },
];

pub fn client(id: &str) -> Option<&'static Client> {
    CLIENTS.iter().find(|c| c.id == id)
}

/// Config file candidates, the preferred one first.
fn candidates(c: &Client, env: &Env) -> Vec<PathBuf> {
    let h = &env.home;
    match c.id {
        "claude-desktop" => vec![match env.os {
            Os::Windows => env.appdata().join("Claude"),
            Os::Macos => h.join("Library").join("Application Support").join("Claude"),
            Os::Linux => env.xdg().join("Claude"),
        }
        .join("claude_desktop_config.json")],
        "claude-code" => vec![h.join(".claude.json")],
        "cursor" => vec![h.join(".cursor").join("mcp.json")],
        "vscode" => vec![env.vscode_user().join("mcp.json")],
        "windsurf" => vec![h.join(".codeium").join("windsurf").join("mcp_config.json")],
        "zed" => vec![match env.os {
            Os::Windows => env.appdata().join("Zed"),
            Os::Macos => h.join(".config").join("zed"),
            Os::Linux => env.xdg().join("zed"),
        }
        .join("settings.json")],
        "codex" => vec![env.codex_home.clone().unwrap_or_else(|| h.join(".codex")).join("config.toml")],
        "gemini" => vec![h.join(".gemini").join("settings.json")],
        "continue" => vec![h.join(".continue").join("mcpServers").join("echodebug.yaml")],
        "cline" => vec![
            env.vscode_user().join("globalStorage").join("saoudrizwan.claude-dev").join("settings").join("cline_mcp_settings.json"),
            h.join(".cline").join("data").join("settings").join("cline_mcp_settings.json"),
        ],
        _ => vec![],
    }
}

/// Folders whose presence means the client is installed (or was run once).
fn markers(c: &Client, env: &Env) -> Vec<PathBuf> {
    let h = &env.home;
    let parent = |p: PathBuf| p.parent().map(Path::to_path_buf).unwrap_or(p);
    match c.id {
        "claude-code" => vec![h.join(".claude.json"), h.join(".claude")],
        "continue" => vec![h.join(".continue")],
        "cline" => vec![env.vscode_user().join("globalStorage").join("saoudrizwan.claude-dev"), h.join(".cline")],
        "windsurf" => vec![h.join(".codeium").join("windsurf")],
        _ => candidates(c, env).into_iter().map(parent).collect(),
    }
}

/// The file EchoDebug edits for `c`: the first candidate that exists, else the first whose
/// client looks installed, else the preferred one.
pub fn config_path(c: &Client, env: &Env) -> PathBuf {
    let cands = candidates(c, env);
    if let Some(p) = cands.iter().find(|p| p.exists()) {
        return p.clone();
    }
    if c.id == "cline" {
        let m = markers(c, env);
        if let Some(i) = m.iter().position(|p| p.exists()) {
            return cands[i.min(cands.len() - 1)].clone();
        }
    }
    cands.into_iter().next().unwrap_or_default()
}

pub fn installed(c: &Client, env: &Env) -> bool {
    markers(c, env).iter().any(|p| p.exists())
}

fn headers(s: &Server) -> Option<Value> {
    s.token.as_ref().map(|t| json!({ "Authorization": format!("Bearer {t}") }))
}

/// EchoDebug's entry for a JSON-config client.
pub fn entry(c: &Client, t: Transport, s: &Server) -> Value {
    let mut e = match (c.id, t) {
        ("claude-code" | "vscode", Transport::Http) => json!({ "type": "http", "url": s.url }),
        ("windsurf", Transport::Http) => json!({ "serverUrl": s.url }),
        ("gemini", Transport::Http) => json!({ "httpUrl": s.url }),
        ("cline", Transport::Http) => json!({ "type": "streamableHttp", "url": s.url, "disabled": false }),
        (_, Transport::Http) => json!({ "url": s.url }),
        ("claude-code" | "cursor" | "vscode", Transport::Stdio) => json!({ "type": "stdio", "command": s.command, "args": s.args }),
        ("cline", Transport::Stdio) => json!({ "command": s.command, "args": s.args, "disabled": false }),
        (_, Transport::Stdio) => json!({ "command": s.command, "args": s.args }),
    };
    if t == Transport::Http {
        if let Some(h) = headers(s) {
            e["headers"] = h;
        }
    }
    e
}

fn toml_str(s: &str) -> String {
    let mut o = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04X}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn toml_block(t: Transport, s: &Server) -> String {
    let mut b = format!("[mcp_servers.{SERVER_NAME}]\n");
    match t {
        Transport::Http => {
            b.push_str(&format!("url = {}\n", toml_str(&s.url)));
            if let Some(tok) = &s.token {
                b.push_str(&format!("http_headers = {{ \"Authorization\" = {} }}\n", toml_str(&format!("Bearer {tok}"))));
            }
        }
        Transport::Stdio => {
            b.push_str(&format!("command = {}\n", toml_str(&s.command)));
            let args: Vec<String> = s.args.iter().map(|a| toml_str(a)).collect();
            b.push_str(&format!("args = [{}]\n", args.join(", ")));
        }
    }
    b
}

fn yaml_file(t: Transport, s: &Server) -> String {
    // double-quoted YAML scalars are JSON strings
    let q = |x: &str| serde_json::to_string(x).unwrap_or_default();
    let mut y = String::from("# Added by EchoDebug (MCP Server panel → Connect a client); remove it there or delete this file.\nname: EchoDebug\nversion: 0.0.1\nschema: v1\nmcpServers:\n  - name: EchoDebug\n");
    match t {
        Transport::Http => {
            y.push_str(&format!("    type: streamable-http\n    url: {}\n", q(&s.url)));
            if let Some(tok) = &s.token {
                y.push_str(&format!("    requestOptions:\n      headers:\n        Authorization: {}\n", q(&format!("Bearer {tok}"))));
            }
        }
        Transport::Stdio => {
            y.push_str(&format!("    type: stdio\n    command: {}\n    args:\n", q(&s.command)));
            for a in &s.args {
                y.push_str(&format!("      - {}\n", q(a)));
            }
        }
    }
    y
}

/// The text a user would paste for `c` (what one-click setup adds), for the "copy" buttons.
pub fn snippet(c: &Client, t: Transport, s: &Server) -> String {
    match c.format {
        Format::Json(keys) => {
            let mut v = json!({ SERVER_NAME: entry(c, t, s) });
            for k in keys.iter().rev() {
                v = json!({ *k: v });
            }
            jsonc::ordered_pretty(&v)
        }
        Format::Toml => toml_block(t, s),
        Format::Yaml => yaml_file(t, s),
    }
}

// ---- reading what is configured ---------------------------------------------------------------------

fn transport_of(v: &Value) -> &'static str {
    if v.get("command").is_some() {
        "stdio"
    } else if ["url", "serverUrl", "httpUrl"].iter().any(|k| v.get(*k).is_some()) {
        "http"
    } else {
        "other"
    }
}

/// How EchoDebug is configured in `text` (None: it is not).
pub fn configured_in(c: &Client, text: &str) -> Result<Option<&'static str>, String> {
    match c.format {
        Format::Json(keys) => Ok(jsonc::get(text, keys, SERVER_NAME)?.map(|v| transport_of(&v))),
        Format::Toml => {
            let lines: Vec<&str> = text.lines().collect();
            let regions = toml::regions(&lines);
            if regions.is_empty() {
                return Ok(toml::inline_entry(&lines).then_some("other"));
            }
            let body: Vec<&str> = regions.iter().flat_map(|(a, b)| lines[*a..*b].iter().copied()).collect();
            let has = |k: &str| body.iter().any(|l| l.trim_start().starts_with(k) && l.trim_start()[k.len()..].trim_start().starts_with('='));
            Ok(Some(if has("command") {
                "stdio"
            } else if has("url") {
                "http"
            } else {
                "other"
            }))
        }
        Format::Yaml => Ok(Some(if text.contains("type: stdio") { "stdio" } else { "http" })),
    }
}

/// The panel's row for `c`.
pub fn status(c: &Client, env: &Env) -> Value {
    let path = config_path(c, env);
    let (configured, error) = match fs::read_to_string(&path) {
        Ok(text) => match configured_in(c, &text) {
            Ok(t) => (json!(t), Value::Null),
            Err(e) => (Value::Null, json!(e)),
        },
        Err(_) => (Value::Null, Value::Null),
    };
    let mut transports = Vec::new();
    if c.http {
        transports.push("http");
    }
    if c.stdio {
        transports.push("stdio");
    }
    json!({
        "id": c.id,
        "name": c.name,
        "path": path.display().to_string(),
        "exists": path.exists(),
        "installed": installed(c, env),
        "configured": configured,
        "error": error,
        "transports": transports,
        "docs": c.docs,
        "note": c.note,
    })
}

// ---- edits --------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Install(Transport),
    Uninstall,
}

/// A previewed change of one file.
#[derive(Clone, Debug)]
pub struct Plan {
    pub path: PathBuf,
    /// the file now (None: it does not exist)
    pub before: Option<String>,
    /// the file afterwards (None: delete it)
    pub after: Option<String>,
    pub diff: String,
}

impl Plan {
    pub fn changes(&self) -> bool {
        self.before != self.after
    }

    pub fn to_json(&self) -> Value {
        json!({ "path": self.path.display().to_string(), "exists": self.before.is_some(), "deletes": self.after.is_none() && self.before.is_some(), "changes": self.changes(), "diff": self.diff })
    }
}

/// The new text of a config file (`before` is its current text, "" when it does not exist).
pub fn edit(c: &Client, before: Option<&str>, action: Action, s: &Server) -> Result<Option<String>, String> {
    if let Action::Install(t) = action {
        if (t == Transport::Http && !c.http) || (t == Transport::Stdio && !c.stdio) {
            return Err(format!("{} does not take {} servers in its config file", c.name, t.as_str()));
        }
    }
    let text = before.unwrap_or("");
    match (c.format, action) {
        (Format::Json(keys), Action::Install(t)) => jsonc::set(text, keys, SERVER_NAME, &entry(c, t, s)).map(Some),
        (Format::Json(keys), Action::Uninstall) => match before {
            None => Ok(None),
            Some(t) => Ok(Some(jsonc::remove(t, keys, SERVER_NAME)?.unwrap_or_else(|| t.to_owned()))),
        },
        (Format::Toml, Action::Install(t)) => toml::set(text, &toml_block(t, s)).map(Some),
        (Format::Toml, Action::Uninstall) => Ok(before.map(|_| toml::remove(text))),
        (Format::Yaml, Action::Install(t)) => Ok(Some(yaml_file(t, s))),
        (Format::Yaml, Action::Uninstall) => Ok(None),
    }
}

/// Reads the file (a symlink is followed to the file it points at).
fn real_path(p: &Path) -> PathBuf {
    match fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() => fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()),
        _ => p.to_path_buf(),
    }
}

fn read_opt(p: &Path) -> Result<Option<String>, String> {
    match fs::read_to_string(p) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {}: {e}", p.display())),
    }
}

pub fn plan(c: &Client, env: &Env, s: &Server, action: Action) -> Result<Plan, String> {
    let path = config_path(c, env);
    let before = read_opt(&real_path(&path))?;
    let after = edit(c, before.as_deref(), action, s).map_err(|e| format!("{}: {e}", path.display()))?;
    let diff = diff(&path.display().to_string(), before.as_deref().unwrap_or(""), after.as_deref().unwrap_or(""));
    Ok(Plan { path, before, after, diff })
}

/// What [`apply`] did.
#[derive(Debug)]
pub struct Applied {
    pub path: PathBuf,
    pub backup: Option<PathBuf>,
}

pub fn backup_path(p: &Path) -> PathBuf {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    p.with_file_name(format!("{name}.echodebug-backup-{secs}"))
}

/// Writes a previewed plan. Refuses when the file changed since the preview; backs up the old file
/// next to it; replaces it atomically, keeping its permissions (new files are private on Unix,
/// since an HTTP entry holds the token).
pub fn apply(plan: &Plan) -> Result<Applied, String> {
    let target = real_path(&plan.path);
    let now = read_opt(&target)?;
    if now != plan.before {
        return Err(format!("{} changed since the preview; preview again", plan.path.display()));
    }
    if !plan.changes() {
        return Ok(Applied { path: plan.path.clone(), backup: None });
    }
    let mut backup = None;
    if let Some(old) = &now {
        let b = backup_path(&target);
        fs::write(&b, old).map_err(|e| format!("write backup {}: {e}", b.display()))?;
        restrict(&b, &target);
        backup = Some(b);
    }
    match &plan.after {
        None => {
            if now.is_some() {
                fs::remove_file(&target).map_err(|e| format!("remove {}: {e}", target.display()))?;
            }
        }
        Some(text) => {
            if let Some(dir) = target.parent() {
                fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            }
            let tmp = target.with_file_name(format!("{}.echodebug-tmp", target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
            fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
            restrict(&tmp, &target);
            fs::rename(&tmp, &target).map_err(|e| {
                let _ = fs::remove_file(&tmp);
                format!("replace {}: {e}", target.display())
            })?;
        }
    }
    Ok(Applied { path: plan.path.clone(), backup })
}

/// Gives `file` the permissions of `like` (or 0600 when `like` does not exist yet).
fn restrict(file: &Path, like: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(like).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o600);
        let _ = fs::set_permissions(file, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (file, like);
    }
}

/// A unified-style diff: the changed middle of the file with up to 3 lines of context.
pub fn diff(name: &str, a: &str, b: &str) -> String {
    let al: Vec<&str> = a.lines().collect();
    let bl: Vec<&str> = b.lines().collect();
    let mut pre = 0;
    while pre < al.len() && pre < bl.len() && al[pre] == bl[pre] {
        pre += 1;
    }
    let mut suf = 0;
    while suf < al.len() - pre && suf < bl.len() - pre && al[al.len() - 1 - suf] == bl[bl.len() - 1 - suf] {
        suf += 1;
    }
    let mut out = format!("--- {name}\n+++ {name}\n");
    if pre == al.len() && pre == bl.len() {
        out.push_str("(no changes)\n");
        return out;
    }
    let ctx = 3;
    let start = pre.saturating_sub(ctx);
    out.push_str(&format!("@@ -{},{} +{},{} @@\n", start + 1, al.len() - suf - start + ctx.min(suf), start + 1, bl.len() - suf - start + ctx.min(suf)));
    for l in &al[start..pre] {
        out.push_str(&format!(" {l}\n"));
    }
    for l in &al[pre..al.len() - suf] {
        out.push_str(&format!("-{l}\n"));
    }
    for l in &bl[pre..bl.len() - suf] {
        out.push_str(&format!("+{l}\n"));
    }
    for l in al[al.len() - suf..].iter().take(ctx) {
        out.push_str(&format!(" {l}\n"));
    }
    out
}

// ---- TOML (Codex) ----------------------------------------------------------------------------------------

mod toml {
    use super::SERVER_NAME;

    /// The table name of a header line (`[a.b]`, `[[a.b]]`, quoted keys), split into keys.
    fn header(line: &str) -> Option<Vec<String>> {
        let t = line.trim();
        let inner = t.strip_prefix("[[").and_then(|r| r.split("]]").next()).or_else(|| t.strip_prefix('[').and_then(|r| r.split(']').next()))?;
        Some(inner.split('.').map(|k| k.trim().trim_matches('"').trim_matches('\'').to_owned()).collect())
    }

    fn ours(keys: &[String]) -> bool {
        keys.len() >= 2 && keys[0] == "mcp_servers" && keys[1] == SERVER_NAME
    }

    /// Line ranges of `[mcp_servers.echodebug]` and its sub-tables.
    pub fn regions(lines: &[&str]) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            if header(lines[i]).is_some_and(|k| ours(&k)) {
                let start = i;
                i += 1;
                while i < lines.len() && header(lines[i]).is_none() {
                    i += 1;
                }
                out.push((start, i));
            } else {
                i += 1;
            }
        }
        out
    }

    /// `echodebug = { … }` inside a `[mcp_servers]` table (not something this editor rewrites).
    pub fn inline_entry(lines: &[&str]) -> bool {
        let mut in_servers = false;
        for l in lines {
            if let Some(k) = header(l) {
                in_servers = k.len() == 1 && k[0] == "mcp_servers";
            } else if in_servers {
                let t = l.trim_start();
                if t.strip_prefix(SERVER_NAME).is_some_and(|r| r.trim_start().starts_with('=') || r.starts_with('.')) {
                    return true;
                }
            }
        }
        false
    }

    pub fn remove(text: &str) -> String {
        let lines: Vec<&str> = text.lines().collect();
        let regions = regions(&lines);
        if regions.is_empty() {
            return text.to_owned();
        }
        let mut keep: Vec<&str> = Vec::new();
        let mut i = 0;
        for (a, b) in &regions {
            keep.extend(&lines[i..*a]);
            i = *b;
        }
        keep.extend(&lines[i..]);
        // drop the blank lines the removed table leaves at the end
        while keep.last().is_some_and(|l| l.trim().is_empty()) {
            keep.pop();
        }
        let mut out = keep.join("\n");
        if !out.is_empty() {
            out.push('\n');
        }
        out
    }

    pub fn set(text: &str, block: &str) -> Result<String, String> {
        let lines: Vec<&str> = text.lines().collect();
        if inline_entry(&lines) {
            return Err("echodebug is defined inline under [mcp_servers]; edit or remove that entry by hand first".into());
        }
        let mut out = remove(text);
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(block);
        Ok(out)
    }
}

// ---- JSON with comments -------------------------------------------------------------------------------------

pub mod jsonc {
    //! Span-keeping JSONC (comments, trailing commas) parser and in-place member edits.

    use serde_json::Value;

    pub struct Obj {
        pub open: usize,
        pub close: usize,
        pub members: Vec<Member>,
    }

    pub struct Member {
        pub key: String,
        pub key_start: usize,
        pub value: Val,
        pub comma: Option<usize>,
    }

    pub enum Val {
        Obj(Obj),
        Other { start: usize, end: usize },
    }

    impl Val {
        pub fn start(&self) -> usize {
            match self {
                Val::Obj(o) => o.open,
                Val::Other { start, .. } => *start,
            }
        }
        /// exclusive
        pub fn end(&self) -> usize {
            match self {
                Val::Obj(o) => o.close + 1,
                Val::Other { end, .. } => *end,
            }
        }
    }

    struct P<'a> {
        s: &'a [u8],
        i: usize,
    }

    impl P<'_> {
        fn err(&self, what: &str) -> String {
            let line = self.s[..self.i.min(self.s.len())].iter().filter(|b| **b == b'\n').count() + 1;
            format!("not valid JSON at line {line}: {what}")
        }
        fn ws(&mut self) -> Result<(), String> {
            loop {
                while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
                    self.i += 1;
                }
                if self.s[self.i..].starts_with(b"//") {
                    while self.i < self.s.len() && self.s[self.i] != b'\n' {
                        self.i += 1;
                    }
                } else if self.s[self.i..].starts_with(b"/*") {
                    let rest = &self.s[self.i + 2..];
                    let end = rest.windows(2).position(|w| w == b"*/").ok_or_else(|| self.err("unterminated comment"))?;
                    self.i += end + 4;
                } else {
                    return Ok(());
                }
            }
        }
        fn string(&mut self) -> Result<String, String> {
            let start = self.i;
            self.i += 1;
            while self.i < self.s.len() {
                match self.s[self.i] {
                    b'\\' => self.i += 2,
                    b'"' => {
                        self.i += 1;
                        let raw = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| self.err("invalid UTF-8"))?;
                        return serde_json::from_str::<String>(raw).map_err(|_| self.err("invalid string"));
                    }
                    _ => self.i += 1,
                }
            }
            Err(self.err("unterminated string"))
        }
        fn value(&mut self) -> Result<Val, String> {
            self.ws()?;
            let start = self.i;
            match self.s.get(self.i) {
                Some(b'{') => self.object().map(Val::Obj),
                Some(b'[') => {
                    self.i += 1;
                    loop {
                        self.ws()?;
                        match self.s.get(self.i) {
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            Some(b',') => self.i += 1,
                            Some(_) => {
                                self.value()?;
                            }
                            None => return Err(self.err("unterminated array")),
                        }
                    }
                    Ok(Val::Other { start, end: self.i })
                }
                Some(b'"') => {
                    self.string()?;
                    Ok(Val::Other { start, end: self.i })
                }
                Some(_) => {
                    while self.i < self.s.len() && !matches!(self.s[self.i], b',' | b'}' | b']' | b'/') && !self.s[self.i].is_ascii_whitespace() {
                        self.i += 1;
                    }
                    let tok = std::str::from_utf8(&self.s[start..self.i]).unwrap_or("");
                    if tok.is_empty() || serde_json::from_str::<Value>(tok).is_err() {
                        return Err(self.err(&format!("unexpected '{tok}'")));
                    }
                    Ok(Val::Other { start, end: self.i })
                }
                None => Err(self.err("unexpected end")),
            }
        }
        fn object(&mut self) -> Result<Obj, String> {
            let open = self.i;
            self.i += 1;
            let mut members = Vec::new();
            loop {
                self.ws()?;
                match self.s.get(self.i) {
                    Some(b'}') => {
                        let close = self.i;
                        self.i += 1;
                        return Ok(Obj { open, close, members });
                    }
                    Some(b'"') => {
                        let key_start = self.i;
                        let key = self.string()?;
                        self.ws()?;
                        if self.s.get(self.i) != Some(&b':') {
                            return Err(self.err("expected ':'"));
                        }
                        self.i += 1;
                        let value = self.value()?;
                        self.ws()?;
                        let comma = if self.s.get(self.i) == Some(&b',') {
                            self.i += 1;
                            Some(self.i - 1)
                        } else {
                            None
                        };
                        let done = comma.is_none();
                        members.push(Member { key, key_start, value, comma });
                        if done {
                            self.ws()?;
                            if self.s.get(self.i) != Some(&b'}') {
                                return Err(self.err("expected ',' or '}'"));
                            }
                        }
                    }
                    _ => return Err(self.err("expected a key")),
                }
            }
        }
    }

    pub fn parse(text: &str) -> Result<Val, String> {
        let mut p = P { s: text.as_bytes(), i: 0 };
        let v = p.value()?;
        p.ws()?;
        if p.i != p.s.len() {
            return Err(p.err("trailing characters"));
        }
        Ok(v)
    }

    /// The plain JSON of a JSONC snippet (comments and trailing commas dropped).
    pub fn strip(text: &str) -> String {
        let b = text.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'"' => {
                    let s = i;
                    i += 1;
                    while i < b.len() && b[i] != b'"' {
                        i += if b[i] == b'\\' { 2 } else { 1 };
                    }
                    i = (i + 1).min(b.len());
                    out.extend_from_slice(&b[s..i]);
                }
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    i += 2;
                    while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                        i += 1;
                    }
                    i += 2;
                }
                b',' => {
                    let mut j = i + 1;
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if !matches!(b.get(j), Some(b'}') | Some(b']')) {
                        out.push(b',');
                    }
                    i += 1;
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn root(text: &str) -> Result<Obj, String> {
        if text.trim().is_empty() {
            return Ok(Obj { open: 0, close: 1, members: Vec::new() });
        }
        match parse(text)? {
            Val::Obj(o) => Ok(o),
            Val::Other { .. } => Err("the top level is not a JSON object".into()),
        }
    }

    /// The object at `path` (None: some key on the way is missing).
    fn find<'a>(obj: &'a Obj, path: &[&str]) -> Result<Option<&'a Obj>, String> {
        let mut cur = obj;
        for k in path {
            match cur.members.iter().find(|m| m.key == *k) {
                None => return Ok(None),
                Some(m) => match &m.value {
                    Val::Obj(o) => cur = o,
                    Val::Other { .. } => return Err(format!("'{k}' is not an object")),
                },
            }
        }
        Ok(Some(cur))
    }

    pub fn get(text: &str, path: &[&str], key: &str) -> Result<Option<Value>, String> {
        let r = root(text)?;
        let Some(o) = find(&r, path)? else { return Ok(None) };
        let Some(m) = o.members.iter().find(|m| m.key == key) else { return Ok(None) };
        let raw = &text[m.value.start()..m.value.end()];
        Ok(Some(serde_json::from_str(&strip(raw)).map_err(|e| format!("'{key}': {e}"))?))
    }

    fn line_indent(text: &str, pos: usize) -> String {
        let ls = text[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
        text[ls..].chars().take_while(|c| *c == ' ' || *c == '\t').collect()
    }

    /// The file's indentation step (default two spaces).
    fn unit(text: &str) -> String {
        for l in text.lines() {
            let ws: String = l.chars().take_while(|c| *c == ' ' || *c == '\t').collect();
            if !ws.is_empty() && l.trim_start().starts_with('"') {
                return if ws.starts_with('\t') { "\t".into() } else { " ".repeat(ws.len().min(8)) };
            }
        }
        "  ".into()
    }

    /// `v` pretty-printed with `unit` steps, continuation lines starting at `indent`.
    /// Two-space pretty JSON with the keys of a server entry in reading order (type, url,
    /// command, args, headers, …) instead of alphabetically.
    pub fn ordered_pretty(v: &Value) -> String {
        const ORDER: &[&str] = &["type", "url", "serverUrl", "httpUrl", "command", "args", "headers", "env", "disabled"];
        fn go(v: &Value, depth: usize, out: &mut String) {
            let pad = |d: usize| "  ".repeat(d);
            match v {
                Value::Object(m) if !m.is_empty() => {
                    let mut keys: Vec<&String> = m.keys().collect();
                    keys.sort_by_key(|k| ORDER.iter().position(|o| o == k).unwrap_or(ORDER.len()));
                    out.push_str("{\n");
                    for (i, k) in keys.iter().enumerate() {
                        out.push_str(&format!("{}{}: ", pad(depth + 1), serde_json::to_string(k).unwrap_or_default()));
                        go(&m[*k], depth + 1, out);
                        out.push_str(if i + 1 < keys.len() { ",\n" } else { "\n" });
                    }
                    out.push_str(&format!("{}}}", pad(depth)));
                }
                Value::Array(a) if !a.is_empty() => {
                    out.push_str("[\n");
                    for (i, x) in a.iter().enumerate() {
                        out.push_str(&pad(depth + 1));
                        go(x, depth + 1, out);
                        out.push_str(if i + 1 < a.len() { ",\n" } else { "\n" });
                    }
                    out.push_str(&format!("{}]", pad(depth)));
                }
                other => out.push_str(&other.to_string()),
            }
        }
        let mut out = String::new();
        go(v, 0, &mut out);
        out
    }

    fn pretty(v: &Value, unit: &str, indent: &str) -> String {
        let p = ordered_pretty(v);
        p.lines()
            .enumerate()
            .map(|(i, l)| {
                let n = l.len() - l.trim_start_matches(' ').len();
                let body = format!("{}{}", unit.repeat(n / 2), &l[n..]);
                if i == 0 {
                    body
                } else {
                    format!("{indent}{body}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn trim_back(text: &str, mut pos: usize) -> usize {
        let b = text.as_bytes();
        while pos > 0 && b[pos - 1].is_ascii_whitespace() {
            pos -= 1;
        }
        pos
    }

    /// Sets `path…/key` to `value`: replaces the member's value, or inserts the member (and any
    /// missing objects on the way). Everything else in the text is kept byte for byte.
    pub fn set(text: &str, path: &[&str], key: &str, value: &Value) -> Result<String, String> {
        let base = if text.trim().is_empty() { "{}\n".to_owned() } else { text.to_owned() };
        let r = root(&base)?;
        let u = unit(&base);
        let keys: Vec<&str> = path.iter().copied().chain([key]).collect();
        let mut cur = &r;
        for (i, k) in keys.iter().enumerate() {
            let found = cur.members.iter().find(|m| m.key == *k);
            match found {
                Some(m) if i == keys.len() - 1 => {
                    let ind = line_indent(&base, m.key_start);
                    let mut out = base.clone();
                    out.replace_range(m.value.start()..m.value.end(), &pretty(value, &u, &ind));
                    return Ok(out);
                }
                Some(m) => match &m.value {
                    Val::Obj(o) => cur = o,
                    Val::Other { .. } => return Err(format!("'{k}' is not an object; fix it by hand first")),
                },
                None => {
                    let mut v = value.clone();
                    for rest in keys[i + 1..].iter().rev() {
                        v = serde_json::json!({ *rest: v });
                    }
                    return Ok(insert(&base, cur, k, &v, &u));
                }
            }
        }
        unreachable!("keys is never empty")
    }

    fn insert(text: &str, obj: &Obj, key: &str, value: &Value, unit: &str) -> String {
        let outer = line_indent(text, obj.open);
        let ind = match obj.members.first() {
            Some(m) => line_indent(text, m.key_start),
            None => format!("{outer}{unit}"),
        };
        let member = format!("{}: {}", serde_json::to_string(key).unwrap_or_default(), pretty(value, unit, &ind));
        let mut out = text.to_owned();
        match obj.members.last() {
            Some(last) => {
                let at = trim_back(text, obj.close);
                out.insert_str(at, &format!("\n{ind}{member}"));
                if last.comma.is_none() {
                    out.insert(last.value.end(), ',');
                }
            }
            None => {
                let inner = &text[obj.open + 1..obj.close];
                if inner.trim().is_empty() {
                    out.replace_range(obj.open + 1..obj.close, &format!("\n{ind}{member}\n{outer}"));
                } else {
                    // only comments inside: keep them, add after
                    let at = trim_back(text, obj.close);
                    out.insert_str(at, &format!("\n{ind}{member}\n{outer}"));
                }
            }
        }
        if !out.ends_with('\n') && text.ends_with('\n') {
            out.push('\n');
        }
        out
    }

    /// Removes `path…/key`. None when it is not there.
    pub fn remove(text: &str, path: &[&str], key: &str) -> Result<Option<String>, String> {
        let r = root(text)?;
        let Some(o) = find(&r, path)? else { return Ok(None) };
        let Some(idx) = o.members.iter().position(|m| m.key == key) else { return Ok(None) };
        let m = &o.members[idx];
        let b = text.as_bytes();
        let mut out = text.to_owned();
        if let Some(c) = m.comma.filter(|_| idx + 1 < o.members.len()) {
            // a member follows: remove from this key (its whole line when alone on it) past the comma
            let ls = text[..m.key_start].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let a = if text[ls..m.key_start].trim().is_empty() { ls } else { m.key_start };
            let mut e = c + 1;
            while e < b.len() && (b[e] == b' ' || b[e] == b'\t') {
                e += 1;
            }
            if a == ls {
                if text[e..].starts_with("\r\n") {
                    e += 2;
                } else if text[e..].starts_with('\n') {
                    e += 1;
                }
            }
            out.replace_range(a..e, "");
        } else if idx > 0 {
            // the last member: remove it (from the end of what precedes it, so a comment after the
            // previous member stays), then the previous member's comma unless the file uses
            // trailing commas
            let from = trim_back(text, m.key_start);
            let end = m.comma.map(|c| c + 1).unwrap_or(m.value.end());
            out.replace_range(from..end, "");
            if m.comma.is_none() {
                if let Some(pc) = o.members[idx - 1].comma {
                    out.remove(pc);
                }
            }
        } else {
            let end = m.comma.map(|c| c + 1).unwrap_or(m.value.end());
            if text[end..o.close].trim().is_empty() {
                out.replace_range(o.open..o.close + 1, "{}");
            } else {
                out.replace_range(o.open + 1..end, "");
            }
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(token: Option<&str>) -> Server {
        Server { url: "http://127.0.0.1:47110/mcp".into(), token: token.map(str::to_owned), command: "C:\\Program Files\\EchoDebug\\EchoDebug.exe".into(), args: vec!["--mcp-stdio".into()] }
    }

    fn env(os: Os, root: &Path) -> Env {
        Env { os, home: root.join("home"), appdata: Some(root.join("appdata")), xdg_config: None, codex_home: None }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("echodebug-clients-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn paths_per_os() {
        let r = Path::new("/r");
        let p = |id: &str, os: Os| config_path(client(id).unwrap(), &env(os, r));
        assert_eq!(p("claude-desktop", Os::Windows), Path::new("/r/appdata/Claude/claude_desktop_config.json"));
        assert_eq!(p("claude-desktop", Os::Macos), Path::new("/r/home/Library/Application Support/Claude/claude_desktop_config.json"));
        assert_eq!(p("claude-desktop", Os::Linux), Path::new("/r/home/.config/Claude/claude_desktop_config.json"));
        assert_eq!(p("vscode", Os::Windows), Path::new("/r/appdata/Code/User/mcp.json"));
        assert_eq!(p("vscode", Os::Macos), Path::new("/r/home/Library/Application Support/Code/User/mcp.json"));
        assert_eq!(p("vscode", Os::Linux), Path::new("/r/home/.config/Code/User/mcp.json"));
        assert_eq!(p("zed", Os::Windows), Path::new("/r/appdata/Zed/settings.json"));
        assert_eq!(p("zed", Os::Macos), Path::new("/r/home/.config/zed/settings.json"));
        for os in [Os::Windows, Os::Macos, Os::Linux] {
            assert_eq!(p("claude-code", os), Path::new("/r/home/.claude.json"));
            assert_eq!(p("cursor", os), Path::new("/r/home/.cursor/mcp.json"));
            assert_eq!(p("windsurf", os), Path::new("/r/home/.codeium/windsurf/mcp_config.json"));
            assert_eq!(p("codex", os), Path::new("/r/home/.codex/config.toml"));
            assert_eq!(p("gemini", os), Path::new("/r/home/.gemini/settings.json"));
            assert_eq!(p("continue", os), Path::new("/r/home/.continue/mcpServers/echodebug.yaml"));
        }
        assert_eq!(p("cline", Os::Linux), Path::new("/r/home/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"));
        let mut e = env(Os::Linux, r);
        e.xdg_config = Some(PathBuf::from("/x"));
        e.codex_home = Some(PathBuf::from("/c"));
        assert_eq!(config_path(client("zed").unwrap(), &e), Path::new("/x/zed/settings.json"));
        assert_eq!(config_path(client("codex").unwrap(), &e), Path::new("/c/config.toml"));
        // the Cline CLI's file when only the CLI is installed
        let d = tmp("cline");
        let e = env(Os::Linux, &d);
        fs::create_dir_all(e.home.join(".cline")).unwrap();
        assert_eq!(config_path(client("cline").unwrap(), &e), e.home.join(".cline/data/settings/cline_mcp_settings.json"));
        assert!(installed(client("cline").unwrap(), &e) && !installed(client("cursor").unwrap(), &e));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn entries_follow_each_clients_format() {
        let s = server(Some("tok"));
        let e = |id: &str, t: Transport| entry(client(id).unwrap(), t, &s);
        assert_eq!(e("claude-code", Transport::Http), json!({ "type": "http", "url": s.url, "headers": { "Authorization": "Bearer tok" } }));
        assert_eq!(e("claude-code", Transport::Stdio)["type"], "stdio");
        assert_eq!(e("cursor", Transport::Http), json!({ "url": s.url, "headers": { "Authorization": "Bearer tok" } }));
        assert_eq!(e("vscode", Transport::Http)["type"], "http");
        assert_eq!(e("windsurf", Transport::Http)["serverUrl"], s.url);
        assert_eq!(e("gemini", Transport::Http)["httpUrl"], s.url);
        assert_eq!(e("cline", Transport::Http)["type"], "streamableHttp");
        assert_eq!(e("zed", Transport::Stdio), json!({ "command": s.command, "args": ["--mcp-stdio"] }));
        assert_eq!(e("claude-desktop", Transport::Stdio), json!({ "command": s.command, "args": ["--mcp-stdio"] }));
        assert!(e("cursor", Transport::Stdio).get("headers").is_none(), "stdio entries never hold the token");
        assert!(entry(client("cursor").unwrap(), Transport::Http, &server(None)).get("headers").is_none());
        assert!(edit(client("claude-desktop").unwrap(), None, Action::Install(Transport::Http), &s).is_err());
        let toml = snippet(client("codex").unwrap(), Transport::Stdio, &s);
        assert_eq!(toml, "[mcp_servers.echodebug]\ncommand = \"C:\\\\Program Files\\\\EchoDebug\\\\EchoDebug.exe\"\nargs = [\"--mcp-stdio\"]\n");
        assert!(snippet(client("codex").unwrap(), Transport::Http, &s).contains("http_headers = { \"Authorization\" = \"Bearer tok\" }"));
        let y = snippet(client("continue").unwrap(), Transport::Http, &s);
        assert!(y.contains("type: streamable-http") && y.contains("Authorization: \"Bearer tok\"") && y.contains("schema: v1"));
        let j: Value = serde_json::from_str(&snippet(client("vscode").unwrap(), Transport::Http, &s)).unwrap();
        assert_eq!(j["servers"]["echodebug"]["url"], s.url);
    }

    #[test]
    fn json_merge_keeps_comments_and_other_servers() {
        let c = client("cursor").unwrap();
        let s = server(Some("tok"));
        let before = "{\n  // my servers\n  \"mcpServers\": {\n    \"other\": { \"command\": \"x\" }, // keep me\n  },\n  \"theme\": \"dark\"\n}\n";
        let after = edit(c, Some(before), Action::Install(Transport::Http), &s).unwrap().unwrap();
        assert!(after.contains("// my servers") && after.contains("// keep me") && after.contains("\"theme\": \"dark\""), "{after}");
        assert!(after.contains("\"other\": { \"command\": \"x\" }"));
        let v: Value = serde_json::from_str(&jsonc::strip(&after)).unwrap();
        assert_eq!(v["mcpServers"]["echodebug"]["url"], s.url);
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(configured_in(c, &after).unwrap(), Some("http"));
        // installing again replaces the entry, switching transport
        let again = edit(c, Some(&after), Action::Install(Transport::Stdio), &s).unwrap().unwrap();
        assert_eq!(configured_in(c, &again).unwrap(), Some("stdio"));
        assert_eq!(again.matches("\"echodebug\"").count(), 1);
        // uninstall restores the original text exactly
        let removed = edit(c, Some(&again), Action::Uninstall, &s).unwrap().unwrap();
        let v: Value = serde_json::from_str(&jsonc::strip(&removed)).unwrap();
        assert!(v["mcpServers"].get("echodebug").is_none());
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert!(removed.contains("// keep me"));
    }

    #[test]
    fn json_insert_and_remove_shapes() {
        let s = server(None);
        let c = client("claude-desktop").unwrap();
        // missing file → a new one with the servers object
        let new = edit(c, None, Action::Install(Transport::Stdio), &s).unwrap().unwrap();
        let v: Value = serde_json::from_str(&new).unwrap();
        assert_eq!(v["mcpServers"]["echodebug"]["args"][0], "--mcp-stdio");
        // the only member removed → an empty object again, file kept
        let gone = edit(c, Some(&new), Action::Uninstall, &s).unwrap().unwrap();
        assert_eq!(serde_json::from_str::<Value>(&gone).unwrap(), json!({ "mcpServers": {} }));
        // no file: uninstall is nothing to do
        assert_eq!(edit(c, None, Action::Uninstall, &s).unwrap(), None);
        // the servers key missing in an existing file, tab indentation
        let tabbed = "{\n\t\"globalShortcut\": \"\"\n}";
        let t = edit(c, Some(tabbed), Action::Install(Transport::Stdio), &s).unwrap().unwrap();
        assert!(t.contains("\n\t\"mcpServers\": {\n\t\t\"echodebug\": {\n\t\t\t\"command\""), "{t}");
        serde_json::from_str::<Value>(&t).unwrap();
        // a middle member, a first member, one-line objects
        let three = r#"{"mcpServers": {"a": 1, "echodebug": {"url": "u"}, "b": 2}}"#;
        let r = jsonc::remove(three, &["mcpServers"], "echodebug").unwrap().unwrap();
        assert_eq!(serde_json::from_str::<Value>(&r).unwrap(), json!({ "mcpServers": { "a": 1, "b": 2 } }));
        let first = r#"{"mcpServers": {"echodebug": {"url": "u"}, "b": 2}}"#;
        let r = jsonc::remove(first, &["mcpServers"], "echodebug").unwrap().unwrap();
        assert_eq!(serde_json::from_str::<Value>(&r).unwrap(), json!({ "mcpServers": { "b": 2 } }));
        let last = "{\n  \"mcpServers\": {\n    \"a\": 1,\n    \"echodebug\": {}\n  }\n}\n";
        let r = jsonc::remove(last, &["mcpServers"], "echodebug").unwrap().unwrap();
        assert_eq!(r, "{\n  \"mcpServers\": {\n    \"a\": 1\n  }\n}\n");
        // broken files are never rewritten
        assert!(edit(c, Some("{ \"mcpServers\": "), Action::Install(Transport::Stdio), &s).is_err());
        assert!(edit(c, Some("{ \"mcpServers\": [] }"), Action::Install(Transport::Stdio), &s).unwrap_err().contains("not an object"));
        assert!(edit(c, Some("[1]"), Action::Install(Transport::Stdio), &s).is_err());
    }

    #[test]
    fn zed_and_vscode_nesting() {
        let s = server(Some("t"));
        let zed = client("zed").unwrap();
        let settings = "// Zed settings\n{\n  \"theme\": \"One Dark\",\n  /* fonts */ \"buffer_font_size\": 15,\n}\n";
        let out = edit(zed, Some(settings), Action::Install(Transport::Http), &s).unwrap().unwrap();
        assert!(out.starts_with("// Zed settings\n") && out.contains("/* fonts */"));
        let v: Value = serde_json::from_str(&jsonc::strip(&out)).unwrap();
        assert_eq!(v["context_servers"]["echodebug"]["headers"]["Authorization"], "Bearer t");
        assert_eq!(v["buffer_font_size"], 15);
        let vs = edit(client("vscode").unwrap(), Some("{\n  \"inputs\": []\n}"), Action::Install(Transport::Http), &s).unwrap().unwrap();
        let v: Value = serde_json::from_str(&vs).unwrap();
        assert_eq!(v["servers"]["echodebug"]["type"], "http");
        assert_eq!(v["inputs"], json!([]));
    }

    #[test]
    fn toml_merge_and_uninstall() {
        let c = client("codex").unwrap();
        let s = server(Some("tok"));
        let before = "model = \"o4\"\n\n[mcp_servers.other]\ncommand = \"npx\"\nargs = [\"-y\", \"x\"]\n\n[profiles.fast]\nmodel = \"mini\"\n";
        let after = edit(c, Some(before), Action::Install(Transport::Http), &s).unwrap().unwrap();
        assert!(after.starts_with(before.trim_end()), "{after}");
        assert!(after.ends_with("[mcp_servers.echodebug]\nurl = \"http://127.0.0.1:47110/mcp\"\nhttp_headers = { \"Authorization\" = \"Bearer tok\" }\n"));
        assert_eq!(configured_in(c, &after).unwrap(), Some("http"));
        // reinstall replaces our table (sub-tables too) and nothing else
        let with_env = format!("{after}\n[mcp_servers.echodebug.env]\nX = \"1\"\n");
        let again = edit(c, Some(&with_env), Action::Install(Transport::Stdio), &s).unwrap().unwrap();
        assert_eq!(again.matches("[mcp_servers.echodebug").count(), 1);
        assert!(again.contains("[mcp_servers.other]") && again.contains("[profiles.fast]"));
        assert_eq!(configured_in(c, &again).unwrap(), Some("stdio"));
        let removed = edit(c, Some(&again), Action::Uninstall, &s).unwrap().unwrap();
        assert_eq!(removed, before);
        let inline = "[mcp_servers]\nechodebug = { url = \"x\" }\n";
        assert!(edit(c, Some(inline), Action::Install(Transport::Http), &s).is_err());
        assert_eq!(configured_in(c, inline).unwrap(), Some("other"));
    }

    #[test]
    fn plan_apply_backup_and_uninstall_files() {
        let d = tmp("apply");
        let e = env(Os::Linux, &d);
        let s = server(Some("tok"));
        // gemini: existing settings are merged, a backup is written
        let gem = client("gemini").unwrap();
        let path = config_path(gem, &e);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{\n  \"theme\": \"GitHub\"\n}\n").unwrap();
        let p = plan(gem, &e, &s, Action::Install(Transport::Http)).unwrap();
        assert!(p.diff.contains("+  \"mcpServers\": {") && p.diff.contains("--- "), "{}", p.diff);
        let done = apply(&p).unwrap();
        let backup = done.backup.unwrap();
        assert_eq!(fs::read_to_string(&backup).unwrap(), "{\n  \"theme\": \"GitHub\"\n}\n");
        let v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "GitHub");
        assert_eq!(v["mcpServers"]["echodebug"]["httpUrl"], s.url);
        assert_eq!(status(gem, &e)["configured"], "http");
        // a stale preview is refused
        let stale = plan(gem, &e, &s, Action::Uninstall).unwrap();
        fs::write(&path, "{}").unwrap();
        assert!(apply(&stale).unwrap_err().contains("changed since the preview"));
        // continue: our own file, created then deleted on uninstall
        let cont = client("continue").unwrap();
        let p = plan(cont, &e, &s, Action::Install(Transport::Stdio)).unwrap();
        assert!(p.before.is_none());
        apply(&p).unwrap();
        let file = config_path(cont, &e);
        assert!(fs::read_to_string(&file).unwrap().contains("type: stdio"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600, "new files are private");
        }
        let p = plan(cont, &e, &s, Action::Uninstall).unwrap();
        assert!(p.to_json()["deletes"] == true);
        let done = apply(&p).unwrap();
        assert!(!file.exists() && done.backup.is_some_and(|b| b.exists()));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn diff_shows_only_the_change() {
        let d = diff("f", "a\nb\nc\nd\ne\nf\ng\nh\n", "a\nb\nc\nd\nX\nf\ng\nh\n");
        assert!(d.contains("-e\n+X\n") && d.contains(" d\n") && !d.contains(" a\n"), "{d}");
        assert!(diff("f", "same", "same").contains("no changes"));
    }
}
