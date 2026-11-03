//! EchoDebug plugins on disk: `<config>/EchoDebug/plugins/<folder>/manifest.json` plus an ES
//! module. The app only reads files here; validating manifests, permissions and loading the
//! module happen in the frontend (src/lib/plugins).

use std::fs;
use std::path::{Component, Path, PathBuf};

use echo_debug_relay::auth;
use serde::Serialize;

const MAX_MANIFEST: u64 = 256 * 1024;
const MAX_SOURCE: u64 = 8 * 1024 * 1024;

#[derive(Serialize)]
pub struct PluginFolder {
    /// folder name under the plugins directory
    dir: String,
    /// manifest.json text (validated by the frontend)
    manifest: Option<String>,
    error: Option<String>,
}

pub fn plugins_path() -> PathBuf {
    auth::config_dir().join("plugins")
}

/// `rel` as a path inside `root`: relative, no `..`, no prefixes, and still inside after
/// resolving symlinks.
fn inside(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let p = Path::new(rel);
    if rel.is_empty() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(format!("'{rel}' is not a relative path inside the plugin folder"));
    }
    let root = root.canonicalize().map_err(|e| format!("{}: {e}", root.display()))?;
    let full = root.join(p).canonicalize().map_err(|e| format!("{rel}: {e}"))?;
    if !full.starts_with(&root) {
        return Err(format!("'{rel}' leaves the plugin folder"));
    }
    Ok(full)
}

fn read_limited(path: &Path, max: u64) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > max {
        return Err(format!("{} is larger than {} KiB", path.display(), max / 1024));
    }
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn list_in(root: &Path) -> Vec<PluginFolder> {
    let Ok(rd) = fs::read_dir(root) else { return Vec::new() };
    let mut out: Vec<PluginFolder> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|d| !d.starts_with('.'))
        .map(|dir| match inside(root, &format!("{dir}/manifest.json")).and_then(|p| read_limited(&p, MAX_MANIFEST)) {
            Ok(text) => PluginFolder { dir, manifest: Some(text), error: None },
            Err(e) => PluginFolder { dir, manifest: None, error: Some(e) },
        })
        .collect();
    out.sort_by(|a, b| a.dir.cmp(&b.dir));
    out
}

pub fn read_in(root: &Path, dir: &str, path: &str) -> Result<String, String> {
    if dir.contains(['/', '\\']) || dir.starts_with('.') {
        return Err(format!("bad plugin folder '{dir}'"));
    }
    let folder = inside(root, dir)?;
    let file = inside(&folder, path)?;
    read_limited(&file, MAX_SOURCE)
}

/// The plugins directory (created on first use), for "Open plugins folder".
#[tauri::command]
pub fn plugins_dir() -> Result<String, String> {
    let p = plugins_path();
    fs::create_dir_all(&p).map_err(|e| format!("create {}: {e}", p.display()))?;
    Ok(p.display().to_string())
}

#[tauri::command]
pub fn list_plugins() -> Vec<PluginFolder> {
    list_in(&plugins_path())
}

/// A file of one plugin (its entry module), confined to that plugin's folder.
#[tauri::command]
pub fn read_plugin_file(dir: String, path: String) -> Result<String, String> {
    read_in(&plugins_path(), &dir, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confined_to_the_plugin_folder() {
        let root = std::env::temp_dir().join(format!("echodebug-plugins-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("hello")).unwrap();
        fs::write(root.join("hello/manifest.json"), "{}").unwrap();
        fs::write(root.join("hello/index.js"), "export function activate() {}").unwrap();
        fs::write(root.join("secret.txt"), "no").unwrap();
        fs::create_dir_all(root.join("broken")).unwrap();
        let list = list_in(&root);
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].dir, "hello");
        assert_eq!(list[1].manifest.as_deref(), Some("{}"));
        assert!(list[0].error.is_some(), "a folder without manifest.json is reported");
        assert!(read_in(&root, "hello", "index.js").unwrap().contains("activate"));
        for (d, p) in [("hello", "../secret.txt"), ("hello", "/etc/passwd"), ("..", "secret.txt"), ("hello/..", "secret.txt"), ("hello", "")] {
            assert!(read_in(&root, d, p).is_err(), "{d} {p}");
        }
        let _ = fs::remove_dir_all(&root);
    }
}
