use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use echo_debug_relay::{auth, mcp_clients, Relay, DEFAULT_PORT, DEFAULT_TIMEOUT};
use serde::Serialize;
use serde_json::{json, Value};
use tauri::Manager;

mod plugins;

const AGENT_SOURCE: &str = include_str!("../../agent/echo_debug.as");
const AGENT_PORT_LINE: &str = "const int RELAY_PORT = 47110;";

struct RelayState {
    port: u16,
    error: Option<String>,
    relay: Relay,
    token: Mutex<Option<String>>,
}

#[derive(Serialize)]
struct RelayInfo {
    port: u16,
    error: Option<String>,
    /// bearer token for /client and /mcp (None when ECHODEBUG_AUTH=0)
    token: Option<String>,
}

#[derive(Serialize)]
struct InstallResult {
    path: String,
    changed: bool,
}

/// Echo's scripts folder: `%APPDATA%\scripts` on Windows (dirs::config_dir() is %APPDATA% there).
fn scripts_path() -> Result<PathBuf, String> {
    dirs::config_dir()
        .map(|d| d.join("scripts"))
        .ok_or_else(|| "cannot locate the user config directory".to_owned())
}

fn install(port: u16) -> Result<InstallResult, String> {
    let dir = scripts_path()?;
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = dir.join("echo_debug.as");
    let source = AGENT_SOURCE.replace(AGENT_PORT_LINE, &format!("const int RELAY_PORT = {port};"));
    let changed = fs::read_to_string(&path).map_or(true, |current| current != source);
    if changed {
        fs::write(&path, &source).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(InstallResult {
        path: path.display().to_string(),
        changed,
    })
}

#[tauri::command]
fn relay_info(state: tauri::State<'_, RelayState>) -> RelayInfo {
    RelayInfo {
        port: state.port,
        error: state.error.clone(),
        token: state.token.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    }
}

/// Replaces the stored relay token (`auth::token_path`) and the running relay's; MCP clients
/// must be re-added with the new header. Open sockets stay up.
#[tauri::command]
fn regenerate_token(state: tauri::State<'_, RelayState>) -> Result<String, String> {
    let mut cur = state.token.lock().unwrap_or_else(|e| e.into_inner());
    if cur.is_none() {
        return Err("relay authentication is off (ECHODEBUG_AUTH=0)".into());
    }
    if std::env::var("ECHODEBUG_TOKEN").is_ok_and(|t| !t.trim().is_empty()) {
        return Err("the token comes from ECHODEBUG_TOKEN; change that variable instead".into());
    }
    let token = auth::new_token().map_err(|e| e.to_string())?;
    let path = auth::token_path();
    auth::store(&path, &token).map_err(|e| format!("write {}: {e}", path.display()))?;
    state.relay.set_token(Some(token.clone()));
    *cur = Some(token.clone());
    Ok(token)
}

/// Host OS ("windows", "linux", "macos", …) so the UI can gate Windows-only Echo features.
#[tauri::command]
fn host_os() -> String {
    std::env::consts::OS.to_string()
}

#[tauri::command]
fn install_agent(state: tauri::State<'_, RelayState>) -> Result<InstallResult, String> {
    if std::env::consts::OS != "windows" {
        return Err("the Echo agent (AngelScript) only runs inside Echo on Windows; on Linux the relay serves a local /proc backend".to_owned());
    }
    install(state.port)
}

#[tauri::command]
fn scripts_dir() -> Result<String, String> {
    scripts_path().map(|p| p.display().to_string())
}

/// Writes a session export next to the user's documents; the frontend picks the file
/// with the dialog plugin and passes the chosen path back.
#[tauri::command]
fn write_text_file(path: String, contents: String) -> Result<String, String> {
    let p = PathBuf::from(&path);
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    fs::write(&p, contents).map_err(|e| format!("write {}: {e}", p.display()))?;
    Ok(p.display().to_string())
}

/// Writes a binary file the user picked (rebuilt images, dumps).
#[tauri::command]
fn write_binary_file(path: String, contents: Vec<u8>) -> Result<String, String> {
    let p = PathBuf::from(&path);
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    fs::write(&p, contents).map_err(|e| format!("write {}: {e}", p.display()))?;
    Ok(p.display().to_string())
}

/// Streams a large binary file (full-memory dumps) in chunks: the body is the raw bytes (no JSON
/// array), the target path and whether to start a new file come in the `x-path` / `x-truncate`
/// headers (percent-encoded path).
#[tauri::command]
fn append_file_raw(request: tauri::ipc::Request<'_>) -> Result<u64, String> {
    use std::io::Write;
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else { return Err("append_file_raw takes a raw byte body".into()) };
    let header = |k: &str| request.headers().get(k).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let path = header("x-path").ok_or("missing x-path")?;
    let path = percent_decode(&path);
    let p = PathBuf::from(&path);
    if header("x-truncate").as_deref() == Some("1") {
        if let Some(dir) = p.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(header("x-truncate").as_deref() != Some("1"))
        .truncate(header("x-truncate").as_deref() == Some("1"))
        .open(&p)
        .map_err(|e| format!("open {}: {e}", p.display()))?;
    f.write_all(bytes).map_err(|e| format!("write {}: {e}", p.display()))?;
    f.metadata().map(|m| m.len()).map_err(|e| e.to_string())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Reads a session file the user picked.
#[tauri::command]
fn read_text_file(path: String) -> Result<String, String> {
    fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path))
}

/// Reads a binary file the user picked (FLIRT signature databases).
#[tauri::command]
fn read_binary_file(path: String) -> Result<Vec<u8>, String> {
    fs::read(&path).map_err(|e| format!("read {}: {e}", path))
}

// ---- MCP client setup ---------------------------------------------------------------------------
//
// One-click setup of MCP clients (relay/src/mcp_clients.rs). The file paths come only from that
// module's table of known client configs; the UI passes a client id and never a path, and nothing
// is written until the user confirms the previewed diff.

/// What a client config gets: the HTTP endpoint with the token, or this executable in stdio mode.
fn mcp_server_spec(state: &RelayState) -> mcp_clients::Server {
    let token = state.token.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let command = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "echodebug".into());
    let mut args = vec!["--mcp-stdio".to_owned()];
    if state.port != DEFAULT_PORT {
        args.push(state.port.to_string());
    }
    mcp_clients::Server { url: format!("http://127.0.0.1:{}/mcp", state.port), token, command, args }
}

fn mcp_action(action: &str, transport: Option<&str>) -> Result<mcp_clients::Action, String> {
    match action {
        "uninstall" => Ok(mcp_clients::Action::Uninstall),
        "install" => {
            let t = transport.and_then(mcp_clients::Transport::parse).ok_or("install needs transport 'http' or 'stdio'")?;
            Ok(mcp_clients::Action::Install(t))
        }
        other => Err(format!("unknown action '{other}'")),
    }
}

/// Every known client: whether it is installed, where its config is and how EchoDebug is in it.
#[tauri::command]
fn mcp_clients(state: tauri::State<'_, RelayState>) -> Value {
    let env = mcp_clients::Env::current();
    let server = mcp_server_spec(&state);
    let clients: Vec<Value> = mcp_clients::CLIENTS
        .iter()
        .map(|c| {
            let mut row = mcp_clients::status(c, &env);
            let mut snippets = serde_json::Map::new();
            if c.http {
                snippets.insert("http".into(), json!(mcp_clients::snippet(c, mcp_clients::Transport::Http, &server)));
            }
            if c.stdio {
                snippets.insert("stdio".into(), json!(mcp_clients::snippet(c, mcp_clients::Transport::Stdio, &server)));
            }
            row["snippets"] = Value::Object(snippets);
            row
        })
        .collect();
    json!({ "clients": clients, "stdio": { "command": server.command, "args": server.args } })
}

/// The diff one-click setup would apply to a client's config. Writes nothing.
#[tauri::command]
fn mcp_client_preview(state: tauri::State<'_, RelayState>, id: String, action: String, transport: Option<String>) -> Result<Value, String> {
    let c = mcp_clients::client(&id).ok_or_else(|| format!("unknown MCP client '{id}'"))?;
    let plan = mcp_clients::plan(c, &mcp_clients::Env::current(), &mcp_server_spec(&state), mcp_action(&action, transport.as_deref())?)?;
    Ok(plan.to_json())
}

/// Applies the change the user saw: refused when the planned diff is no longer `diff`.
#[tauri::command]
fn mcp_client_apply(state: tauri::State<'_, RelayState>, id: String, action: String, transport: Option<String>, diff: String) -> Result<Value, String> {
    let c = mcp_clients::client(&id).ok_or_else(|| format!("unknown MCP client '{id}'"))?;
    let plan = mcp_clients::plan(c, &mcp_clients::Env::current(), &mcp_server_spec(&state), mcp_action(&action, transport.as_deref())?)?;
    if plan.diff != diff {
        return Err(format!("{} changed since the preview; preview again", plan.path.display()));
    }
    let done = mcp_clients::apply(&plan)?;
    Ok(json!({ "path": done.path.display().to_string(), "backup": done.backup.map(|b| b.display().to_string()) }))
}

/// `EchoDebug --mcp-stdio [port]`: MCP over stdin/stdout for clients that launch servers
/// (bridged to the running app, or its own relay when the app is closed). No window opens.
pub fn run_mcp_stdio(args: &[String]) -> i32 {
    let port = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .or_else(|| std::env::var("ECHODEBUG_PORT").ok())
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    match tauri::async_runtime::block_on(echo_debug_relay::serve_stdio(port, env!("CARGO_PKG_VERSION").to_string())) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("echodebug --mcp-stdio failed: {e}");
            1
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let mut port = std::env::var("ECHODEBUG_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_PORT);
            let version = app.package_info().version.to_string();
            // The in-app assistant was removed: delete the API key it may have stored (a DPAPI
            // blob on Windows, a 0600 file elsewhere) so no secret is left behind.
            for p in auth::remove_assistant_key_files(&auth::config_dir()) {
                eprintln!("removed the stored assistant API key {}", p.display());
            }
            // Every /client and /mcp request must carry this token (see relay/src/auth.rs).
            let token = match auth::default_token() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("relay token unavailable ({e}); using a per-run token");
                    auth::new_token().ok()
                }
            };
            let relay = Relay::new(version, DEFAULT_TIMEOUT).with_token(token.clone());
            // A busy port must not kill the app: the UI shows the error from relay_info.
            let error = match echo_debug_relay::bind(port) {
                Ok(listener) => {
                    port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
                    let relay = relay.clone();
                    tauri::async_runtime::spawn(async move {
                        if let Err(e) = echo_debug_relay::run(listener, relay).await {
                            eprintln!("relay stopped: {e}");
                        }
                    });
                    None
                }
                Err(e) => Some(format!("cannot listen on 127.0.0.1:{port}: {e}")),
            };
            if let Some(e) = &error {
                eprintln!("{e}");
            }
            // The agent ships inside the app, so app updates also update the agent. Windows only:
            // on Linux the relay serves the local /proc backend instead.
            if std::env::consts::OS == "windows" {
                match install(port) {
                    Ok(r) => eprintln!("agent at {} (updated: {})", r.path, r.changed),
                    Err(e) => eprintln!("agent install failed: {e}"),
                }
            } else {
                eprintln!("host os '{}': skipping Echo agent install (Windows-only); local /proc backend active", std::env::consts::OS);
            }
            app.manage(RelayState { port, error, relay, token: Mutex::new(token) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            relay_info,
            regenerate_token,
            host_os,
            install_agent,
            scripts_dir,
            write_text_file,
            append_file_raw,
            write_binary_file,
            read_text_file,
            read_binary_file,
            plugins::plugins_dir,
            plugins::list_plugins,
            plugins::read_plugin_file,
            mcp_clients,
            mcp_client_preview,
            mcp_client_apply
        ])
        .run(tauri::generate_context!())
        .expect("error while running EchoDebug");
}
