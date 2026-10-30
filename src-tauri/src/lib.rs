use std::fs;
use std::path::PathBuf;

use echo_debug_relay::{Relay, DEFAULT_PORT, DEFAULT_TIMEOUT};
use serde::Serialize;
use tauri::Manager;

const AGENT_SOURCE: &str = include_str!("../../agent/echo_debug.as");
const AGENT_PORT_LINE: &str = "const int RELAY_PORT = 47110;";

struct RelayState {
    port: u16,
    error: Option<String>,
}

#[derive(Serialize)]
struct RelayInfo {
    port: u16,
    error: Option<String>,
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
    }
}

#[tauri::command]
fn install_agent(state: tauri::State<'_, RelayState>) -> Result<InstallResult, String> {
    install(state.port)
}

#[tauri::command]
fn scripts_dir() -> Result<String, String> {
    scripts_path().map(|p| p.display().to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let mut port = std::env::var("ECHODEBUG_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(DEFAULT_PORT);
            let version = app.package_info().version.to_string();
            // A busy port must not kill the app: the UI shows the error from relay_info.
            let error = match echo_debug_relay::bind(port) {
                Ok(listener) => {
                    port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
                    tauri::async_runtime::spawn(async move {
                        if let Err(e) =
                            echo_debug_relay::run(listener, Relay::new(version, DEFAULT_TIMEOUT))
                                .await
                        {
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
            // The agent ships inside the app, so app updates also update the agent.
            match install(port) {
                Ok(r) => eprintln!("agent at {} (updated: {})", r.path, r.changed),
                Err(e) => eprintln!("agent install failed: {e}"),
            }
            app.manage(RelayState { port, error });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            relay_info,
            install_agent,
            scripts_dir
        ])
        .run(tauri::generate_context!())
        .expect("error while running EchoDebug");
}
