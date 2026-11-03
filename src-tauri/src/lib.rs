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

/// Running assistant requests and OpenRouter sign-ins by the UI's id, so the UI can cancel them.
type SignIn = (Arc<assistant::oauth::Pending>, Arc<AtomicBool>);

#[derive(Default)]
struct AssistantState {
    streams: Mutex<HashMap<u32, Arc<AtomicBool>>>,
    signins: Mutex<HashMap<u32, SignIn>>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Every provider (built-in ones whether configured or not, then custom endpoints) with how its
/// credential is stored. Never a key or a header value.
#[tauri::command]
fn assistant_providers() -> Value {
    let st = assistant::creds::Store::default();
    let mut v = assistant::creds::storage_note();
    v["providers"] = Value::Array(st.infos());
    v["conversations"] = Value::String(assistant::convs::Convs::default().path_display());
    v
}

/// Saves a provider's key, or a custom endpoint (kind, name, base URL, optional key, headers).
/// An empty key keeps the stored one.
#[tauri::command]
fn assistant_save_provider(cred: Value) -> Result<Value, String> {
    let st = assistant::creds::Store::default();
    let id = cred.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
    let existing = st.get(&id);
    let c = assistant::creds::from_ui(&cred, existing.as_ref(), unix_now())?;
    st.save(&c)?;
    Ok(st.info(&c.id))
}

/// Sign out of a provider / forget a custom endpoint.
#[tauri::command]
fn assistant_remove_provider(id: String) -> Result<Value, String> {
    let st = assistant::creds::Store::default();
    st.remove(&id)?;
    Ok(st.info(&id))
}

/// Lists the provider's models live from its API.
#[tauri::command]
async fn assistant_models(provider: String) -> Result<Vec<Value>, String> {
    let ep = assistant::endpoint(&assistant::creds::Store::default(), &provider)?;
    tauri::async_runtime::spawn_blocking(move || assistant::models::list(&ep)).await.map_err(|e| e.to_string())?
}

/// Settings' "Test connection".
#[tauri::command]
async fn assistant_test(provider: String) -> Result<Value, String> {
    let ep = assistant::endpoint(&assistant::creds::Store::default(), &provider)?;
    tauri::async_runtime::spawn_blocking(move || assistant::models::test(&ep)).await.map_err(|e| e.to_string())?
}

/// Starts OpenRouter's OAuth PKCE sign-in: returns the URL the UI opens in the browser.
#[tauri::command]
fn assistant_signin_begin(state: tauri::State<'_, AssistantState>, id: u32) -> Result<String, String> {
    let p = assistant::oauth::begin()?;
    let url = p.url.clone();
    state.signins.lock().unwrap_or_else(|e| e.into_inner()).insert(id, (Arc::new(p), Arc::new(AtomicBool::new(false))));
    Ok(url)
}

/// Waits for the browser to come back, exchanges the code and stores the key as the OpenRouter
/// credential (method "oauth").
#[tauri::command]
async fn assistant_signin_finish(state: tauri::State<'_, AssistantState>, id: u32) -> Result<Value, String> {
    let (p, cancel) = state.signins.lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned().ok_or("no sign-in in progress")?;
    let r = tauri::async_runtime::spawn_blocking(move || -> Result<Value, String> {
        let code = p.wait(&cancel, std::time::Duration::from_secs(600))?;
        let key = assistant::oauth::exchange(assistant::oauth::EXCHANGE_URL, &code, &p.verifier)?;
        let st = assistant::creds::Store::default();
        let c = assistant::creds::from_ui(&serde_json::json!({ "id": "openrouter", "api_key": key, "method": "oauth" }), None, unix_now())?;
        st.save(&c)?;
        Ok(st.info("openrouter"))
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    state.signins.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    r
}

#[tauri::command]
fn assistant_signin_cancel(state: tauri::State<'_, AssistantState>, id: u32) {
    if let Some((_, c)) = state.signins.lock().unwrap_or_else(|e| e.into_inner()).get(&id) {
        c.store(true, Ordering::Relaxed);
    }
}

/// Saved conversations (`<config>/assistant-conversations`, mode 0600).
#[tauri::command]
fn assistant_conv_list() -> Vec<Value> {
    assistant::convs::Convs::default().list()
}

#[tauri::command]
fn assistant_conv_load(id: String) -> Result<String, String> {
    assistant::convs::Convs::default().load(&id)
}

#[tauri::command]
fn assistant_conv_save(id: String, body: String) -> Result<(), String> {
    assistant::convs::Convs::default().save(&id, &body)
}

#[tauri::command]
fn assistant_conv_delete(id: String) -> Result<(), String> {
    assistant::convs::Convs::default().delete(&id)
}

/// Streams one provider-neutral request. `assistant::send` checks it (read-only tools only, no
/// fields that send data elsewhere, the same for every provider) and builds the provider's own
/// body; the credential is looked up here and goes only to that provider. Every normalised event
/// is sent on `on_event`.
#[tauri::command]
async fn assistant_send(state: tauri::State<'_, AssistantState>, id: u32, provider: String, body: Value, on_event: Channel<Value>) -> Result<(), String> {
    let ep = assistant::endpoint(&assistant::creds::Store::default(), &provider)?;
    let cancel = Arc::new(AtomicBool::new(false));
    state.streams.lock().unwrap_or_else(|e| e.into_inner()).insert(id, cancel.clone());
    let flag = cancel.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        assistant::send(&ep, &body, &flag, |ev| {
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
            plugins::plugins_dir,
            plugins::list_plugins,
            plugins::read_plugin_file,
            assistant_providers,
            assistant_save_provider,
            assistant_remove_provider,
            assistant_models,
            assistant_test,
            assistant_signin_begin,
            assistant_signin_finish,
            assistant_signin_cancel,
            assistant_send,
            assistant_cancel,
            assistant_conv_list,
            assistant_conv_load,
            assistant_conv_save,
            assistant_conv_delete
        ])
        .run(tauri::generate_context!())
        .expect("error while running EchoDebug");
}
