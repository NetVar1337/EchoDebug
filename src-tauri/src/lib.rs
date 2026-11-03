use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use echo_debug_relay::{assistant, auth, Relay, DEFAULT_PORT, DEFAULT_TIMEOUT};
use serde::Serialize;
use serde_json::Value;
use tauri::ipc::Channel;
use tauri::Manager;

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

/// Running assistant requests by the UI's id, so the UI can cancel them.
#[derive(Default)]
struct AssistantState {
    streams: Mutex<HashMap<u32, Arc<AtomicBool>>>,
}

/// Whether an Anthropic API key is stored, and how (never the key itself).
#[tauri::command]
fn assistant_key_status() -> Value {
    assistant::key_info()
}

#[tauri::command]
fn assistant_set_key(key: String) -> Result<Value, String> {
    assistant::save_key(&key)
}

#[tauri::command]
fn assistant_clear_key() -> Result<Value, String> {
    assistant::clear_key()?;
    Ok(assistant::key_info())
}

/// Streams one Messages API request. The body comes from the UI and is checked by
/// `assistant::prepare_body` (read-only tools only, no fields that send data elsewhere); the key is
/// added here and goes nowhere but api.anthropic.com. Every SSE event is sent on `on_event`.
#[tauri::command]
async fn assistant_send(state: tauri::State<'_, AssistantState>, id: u32, body: Value, on_event: Channel<Value>) -> Result<(), String> {
    let key = assistant::load_key().ok_or("no Anthropic API key: add one in Settings → Assistant")?;
    let body = assistant::prepare_body(body)?;
    let cancel = Arc::new(AtomicBool::new(false));
    state.streams.lock().unwrap_or_else(|e| e.into_inner()).insert(id, cancel.clone());
    let flag = cancel.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        assistant::stream(&key, &body, &flag, |ev| {
            let _ = on_event.send(ev);
        })
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    state.streams.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    result
}

#[tauri::command]
fn assistant_cancel(state: tauri::State<'_, AssistantState>, id: u32) {
    if let Some(c) = state.streams.lock().unwrap_or_else(|e| e.into_inner()).get(&id) {
        c.store(true, Ordering::Relaxed);
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
            app.manage(AssistantState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            relay_info,
            regenerate_token,
            host_os,
            install_agent,
            scripts_dir,
            write_text_file,
            write_binary_file,
            read_text_file,
            read_binary_file,
            assistant_key_status,
            assistant_set_key,
            assistant_clear_key,
            assistant_send,
            assistant_cancel
        ])
        .run(tauri::generate_context!())
        .expect("error while running EchoDebug");
}
