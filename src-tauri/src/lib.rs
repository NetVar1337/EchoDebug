use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use echo_debug_relay::{Relay, DEFAULT_PORT, DEFAULT_TIMEOUT};
use serde::Serialize;
use tauri::Manager;

const AGENT_SOURCE: &str = include_str!("../../agent/echo_debug.as");
const AGENT_PORT_LINE: &str = "const int RELAY_PORT = 47110;";

struct RelayState {
    port: u16,
    error: Option<String>,
    relay: Relay,
    token: Mutex<String>,
    token_path: PathBuf,
}

#[derive(Serialize)]
struct RelayInfo {
    port: u16,
    error: Option<String>,
    /// bearer token for /mcp and /client
    token: String,
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

/// Writes the MCP/relay token readable by the current user only.
fn write_token(path: &Path, token: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    fs::write(path, token).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// The per-install token, generated on first start and kept in the app config dir.
fn load_or_create_token(path: &Path) -> String {
    if let Ok(t) = fs::read_to_string(path) {
        let t = t.trim();
        if !t.is_empty() {
            return t.to_owned();
        }
    }
    let token = echo_debug_relay::generate_token();
    if let Err(e) = write_token(path, &token) {
        eprintln!("token not persisted, it changes on next start: {e}");
    }
    token
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

/// Replaces the token; MCP clients must be re-added with the new header. Open sockets stay up.
#[tauri::command]
fn regenerate_token(state: tauri::State<'_, RelayState>) -> Result<String, String> {
    let token = echo_debug_relay::generate_token();
    write_token(&state.token_path, &token)?;
    state.relay.set_token(Some(token.clone()));
    *state.token.lock().unwrap_or_else(|e| e.into_inner()) = token.clone();
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
            let token_path = app.path().app_config_dir()?.join("mcp_token");
            let token = load_or_create_token(&token_path);
            let relay = Relay::new(version, DEFAULT_TIMEOUT).with_token(Some(token.clone()));
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
            app.manage(RelayState {
                port,
                error,
                relay,
                token: Mutex::new(token),
                token_path,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            relay_info,
            regenerate_token,
            host_os,
            install_agent,
            scripts_dir,
            write_text_file,
            read_text_file,
            read_binary_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running EchoDebug");
}
