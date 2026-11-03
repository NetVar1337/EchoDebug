//! Relay access token.
//!
//! The relay only listens on 127.0.0.1, but any local program can connect to it, and an `Origin`
//! header is trivially forged by non-browser clients. Every `/client`, `/sync` and `/mcp` request therefore
//! carries a shared secret: `Authorization: Bearer <token>` (MCP clients, scripts) or
//! `?token=<token>` (browser WebSockets cannot set headers).
//!
//! The token is created once per user and stored in `<config>/EchoDebug/relay-token` (mode 0600
//! on Unix). `ECHODEBUG_TOKEN` overrides it; `ECHODEBUG_AUTH=0` turns authentication off for
//! setups that have their own isolation.
//!
//! `/agent` and `/ext` stay open: Echo's `process::open_socket` and `ws::connect` cannot send
//! headers, and those endpoints only *receive* requests (an impostor upstream can drop or answer
//! requests, but cannot read the target's memory through the relay).

use std::fs;
use std::io;
use std::path::PathBuf;

use axum::http::{header, HeaderMap};

/// Per-user config directory: `%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or `~/.config` elsewhere.
pub fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("APPDATA").filter(|_| cfg!(windows)) {
        return PathBuf::from(d).join("EchoDebug");
    }
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(d).join("EchoDebug");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("EchoDebug")
}

pub fn token_path() -> PathBuf {
    config_dir().join("relay-token")
}

/// 32 random bytes as 64 lowercase hex characters.
pub fn new_token() -> io::Result<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn valid(t: &str) -> bool {
    t.len() >= 32 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Reads the stored token, creating it on first use.
pub fn load_or_create(path: &std::path::Path) -> io::Result<String> {
    if let Ok(t) = fs::read_to_string(path) {
        let t = t.trim().to_owned();
        if valid(&t) {
            return Ok(t);
        }
    }
    let t = new_token()?;
    store(path, &t)?;
    Ok(t)
}

/// Writes `token` to `path` (creating the directory), readable by the current user only. Used on
/// first start and when the app regenerates the token.
pub fn store(path: &std::path::Path, token: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// The token the app and the headless relay use: `ECHODEBUG_TOKEN`, else the stored one.
/// `None` when `ECHODEBUG_AUTH=0`.
pub fn default_token() -> io::Result<Option<String>> {
    if std::env::var("ECHODEBUG_AUTH").is_ok_and(|v| v == "0" || v.eq_ignore_ascii_case("off")) {
        return Ok(None);
    }
    if let Ok(t) = std::env::var("ECHODEBUG_TOKEN") {
        if !t.trim().is_empty() {
            return Ok(Some(t.trim().to_owned()));
        }
    }
    load_or_create(&token_path()).map(Some)
}

/// Constant-time comparison so the token cannot be guessed byte by byte from timings.
pub fn eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Token presented by a request: bearer header first, then the `token` query parameter.
pub fn presented(headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    if let Some(v) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if let Some(t) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
            return Some(t.trim().to_owned());
        }
    }
    query?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == "token").then(|| v.to_owned())
    })
}

pub fn authorized(expected: Option<&str>, headers: &HeaderMap, query: Option<&str>) -> bool {
    match expected {
        None => true,
        Some(want) => presented(headers, query).is_some_and(|got| eq(&got, want)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape_and_persistence() {
        let t = new_token().unwrap();
        assert_eq!(t.len(), 64);
        assert!(valid(&t));
        let dir = std::env::temp_dir().join(format!("echodebug-token-{}", std::process::id()));
        let path = dir.join("relay-token");
        let _ = fs::remove_dir_all(&dir);
        let a = load_or_create(&path).unwrap();
        let b = load_or_create(&path).unwrap();
        assert_eq!(a, b, "second load reuses the stored token");
        fs::write(&path, "short").unwrap();
        let c = load_or_create(&path).unwrap();
        assert_ne!(c, "short", "an invalid stored token is replaced");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn presented_token() {
        let mut h = HeaderMap::new();
        assert_eq!(presented(&h, Some("a=1&token=abc")), Some("abc".into()));
        assert_eq!(presented(&h, Some("a=1")), None);
        h.insert(header::AUTHORIZATION, "Bearer xyz".parse().unwrap());
        assert_eq!(presented(&h, Some("token=abc")), Some("xyz".into()));
        assert!(authorized(None, &HeaderMap::new(), None));
        assert!(authorized(Some("xyz"), &h, None));
        assert!(!authorized(Some("xy"), &h, None));
        assert!(!authorized(Some("xyz"), &HeaderMap::new(), None));
        assert!(eq("abc", "abc") && !eq("abc", "abd") && !eq("abc", "ab"));
    }
}
