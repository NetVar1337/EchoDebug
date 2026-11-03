//! Per-provider credentials: an API key (or the key OpenRouter's sign-in returned), a custom
//! endpoint's base URL and headers. One file per provider in the config directory, encrypted with
//! DPAPI for the user's login on Windows, a mode-0600 file elsewhere. Nothing here is ever returned
//! to the web view except [`Credential::info`], which leaves out the key and header values.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::provider::Kind;

/// How a credential was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    ApiKey,
    /// OpenRouter OAuth PKCE sign-in (the key it returned)
    OAuth,
    /// a local endpoint without a key
    None,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::ApiKey => "api_key",
            Method::OAuth => "oauth",
            Method::None => "none",
        }
    }
    fn parse(s: &str) -> Method {
        match s {
            "oauth" => Method::OAuth,
            "none" => Method::None,
            _ => Method::ApiKey,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Credential {
    /// "anthropic", "openai", "gemini", "openrouter", or "custom-<slug>"
    pub id: String,
    pub kind: Kind,
    pub name: String,
    /// custom endpoints only; built-in providers always use their own host
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub headers: Vec<(String, String)>,
    pub method: Method,
    /// unix seconds
    pub saved: u64,
}

pub const BUILTIN_IDS: &[(&str, Kind)] = &[("anthropic", Kind::Anthropic), ("openai", Kind::OpenAi), ("gemini", Kind::Gemini), ("openrouter", Kind::OpenRouter)];

pub fn builtin_kind(id: &str) -> Option<Kind> {
    BUILTIN_IDS.iter().find(|(i, _)| *i == id).map(|(_, k)| *k)
}

pub fn valid_id(id: &str) -> bool {
    builtin_kind(id).is_some()
        || id.strip_prefix("custom-").is_some_and(|s| (1..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

pub fn valid_key(k: &str) -> bool {
    (8..=1024).contains(&k.len()) && k.bytes().all(|b| b.is_ascii_graphic())
}

const FORBIDDEN_HEADERS: &[&str] = &["host", "content-length", "transfer-encoding", "connection", "content-type", "accept"];

fn valid_header(name: &str, value: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 100 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        return Err(format!("header name '{name}' is not valid"));
    }
    if FORBIDDEN_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
        return Err(format!("header '{name}' is set by the app"));
    }
    if value.len() > 4096 || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(format!("header '{name}' has an invalid value"));
    }
    Ok(())
}

/// A base URL for a custom endpoint: http(s), no credentials, query or fragment in it.
pub fn valid_base_url(u: &str) -> Result<String, String> {
    let u = u.trim().trim_end_matches('/');
    let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://")).ok_or("the base URL must start with http:// or https://")?;
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() || host.contains('@') || u.contains('?') || u.contains('#') || u.chars().any(char::is_whitespace) || u.len() > 500 {
        return Err("the base URL must be like https://host[:port]/path, without user info, query or fragment".into());
    }
    Ok(u.to_owned())
}

impl Credential {
    /// Checks a credential from the UI before it is stored.
    pub fn validate(&self) -> Result<(), String> {
        if !valid_id(&self.id) {
            return Err(format!("provider id '{}' is not valid", self.id));
        }
        match builtin_kind(&self.id) {
            Some(k) if k != self.kind => return Err(format!("provider '{}' is {}", self.id, k.as_str())),
            None if !matches!(self.kind, Kind::OpenAiCompat | Kind::AnthropicCompat) => {
                return Err("a custom endpoint is OpenAI-compatible or Anthropic-compatible".into())
            }
            _ => {}
        }
        if self.kind.is_custom() {
            valid_base_url(self.base_url.as_deref().unwrap_or(""))?;
        }
        if let Some(k) = &self.api_key {
            if !valid_key(k) {
                return Err("that does not look like an API key".into());
            }
        } else if self.kind.needs_key() {
            return Err(format!("{} needs an API key", self.kind.label()));
        }
        if self.headers.len() > 20 {
            return Err("at most 20 custom headers".into());
        }
        for (n, v) in &self.headers {
            valid_header(n, v)?;
        }
        if self.name.len() > 80 {
            return Err("name is too long".into());
        }
        Ok(())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id, "kind": self.kind.as_str(), "name": self.name, "base_url": self.base_url, "api_key": self.api_key,
            "headers": self.headers.iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(), "method": self.method.as_str(), "saved": self.saved,
        })
    }

    pub fn from_json(v: &Value) -> Option<Credential> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let headers = v
            .get("headers")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|h| Some((h.get(0)?.as_str()?.to_owned(), h.get(1)?.as_str()?.to_owned()))).collect())
            .unwrap_or_default();
        Some(Credential {
            id: s("id")?,
            kind: Kind::parse(&s("kind")?)?,
            name: s("name").unwrap_or_default(),
            base_url: s("base_url").filter(|x| !x.is_empty()),
            api_key: s("api_key").filter(|x| !x.is_empty()),
            headers,
            method: Method::parse(&s("method").unwrap_or_default()),
            saved: v.get("saved").and_then(Value::as_u64).unwrap_or(0),
        })
    }

    /// What Settings may see: never the key or header values.
    pub fn info(&self, path: &Path) -> Value {
        json!({
            "id": self.id, "kind": self.kind.as_str(), "name": if self.name.is_empty() { self.kind.label().to_owned() } else { self.name.clone() },
            "base_url": self.base_url.clone().unwrap_or_else(|| self.kind.default_base().to_owned()),
            "has_key": self.api_key.is_some(), "key_hint": self.api_key.as_deref().map(key_hint),
            "method": self.method.as_str(), "headers": self.headers.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
            "saved": self.saved, "path": path.display().to_string(),
        })
    }
}

/// "sk-…wxyz": enough to tell two keys apart, not enough to use one.
fn key_hint(k: &str) -> String {
    let tail: String = k.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    let head: String = k.chars().take(3).collect();
    if k.len() < 16 { "…".into() } else { format!("{head}…{tail}") }
}

/// The credential files of one config directory.
pub struct Store {
    pub dir: PathBuf,
}

const PREFIX: &str = "assistant-provider-";
const EXT: &str = if cfg!(windows) { "dpapi" } else { "cred" };

impl Default for Store {
    fn default() -> Self {
        Store { dir: crate::auth::config_dir() }
    }
}

impl Store {
    pub fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{PREFIX}{id}.{EXT}"))
    }

    /// The single-key file of earlier versions (Anthropic only).
    pub fn legacy_path(&self) -> PathBuf {
        self.dir.join(if cfg!(windows) { "anthropic-key.dpapi" } else { "anthropic-key" })
    }

    pub fn get(&self, id: &str) -> Option<Credential> {
        if !valid_id(id) {
            return None;
        }
        if let Some(c) = fs::read(self.path(id)).ok().and_then(|b| unprotect(&b).ok()).and_then(|p| serde_json::from_slice::<Value>(&p).ok()).and_then(|v| Credential::from_json(&v)) {
            return (c.id == id).then_some(c);
        }
        if id == "anthropic" {
            let k = String::from_utf8(unprotect(&fs::read(self.legacy_path()).ok()?).ok()?).ok()?.trim().to_owned();
            return valid_key(&k).then(|| Credential { id: id.into(), kind: Kind::Anthropic, name: String::new(), base_url: None, api_key: Some(k), headers: vec![], method: Method::ApiKey, saved: 0 });
        }
        None
    }

    /// Every stored credential, built-in providers first.
    pub fn list(&self) -> Vec<Credential> {
        let mut ids: Vec<String> = BUILTIN_IDS.iter().map(|(i, _)| (*i).to_owned()).collect();
        if let Ok(rd) = fs::read_dir(&self.dir) {
            let mut custom: Vec<String> = rd
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter_map(|n| n.strip_prefix(PREFIX)?.strip_suffix(&format!(".{EXT}")).map(str::to_owned))
                .filter(|id| id.starts_with("custom-"))
                .collect();
            custom.sort();
            ids.extend(custom);
        }
        ids.iter().filter_map(|id| self.get(id)).collect()
    }

    pub fn save(&self, c: &Credential) -> Result<(), String> {
        c.validate()?;
        fs::create_dir_all(&self.dir).map_err(|e| format!("create {}: {e}", self.dir.display()))?;
        let path = self.path(&c.id);
        let bytes = protect(c.to_json().to_string().as_bytes()).map_err(|e| format!("encrypt credential: {e}"))?;
        write_private(&path, &bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
        if c.id == "anthropic" {
            let _ = fs::remove_file(self.legacy_path());
        }
        Ok(())
    }

    /// Sign out / forget an endpoint.
    pub fn remove(&self, id: &str) -> Result<(), String> {
        if !valid_id(id) {
            return Err(format!("provider id '{id}' is not valid"));
        }
        let mut paths = vec![self.path(id)];
        if id == "anthropic" {
            paths.push(self.legacy_path());
        }
        for p in paths {
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("remove {}: {e}", p.display())),
            }
        }
        Ok(())
    }

    /// Settings' view of a provider (configured or not).
    pub fn info(&self, id: &str) -> Value {
        match self.get(id) {
            Some(c) => c.info(&self.path(id)),
            None => {
                let kind = builtin_kind(id).unwrap_or(Kind::OpenAiCompat);
                json!({ "id": id, "kind": kind.as_str(), "name": kind.label(), "base_url": kind.default_base(), "has_key": false, "key_hint": null,
                    "method": null, "headers": [], "saved": 0, "path": self.path(id).display().to_string() })
            }
        }
    }

    /// Every built-in provider (configured or not) and every saved custom endpoint.
    pub fn infos(&self) -> Vec<Value> {
        let mut out: Vec<Value> = BUILTIN_IDS.iter().map(|(id, _)| self.info(id)).collect();
        out.extend(self.list().iter().filter(|c| c.kind.is_custom()).map(|c| c.info(&self.path(&c.id))));
        out
    }
}

/// How credentials are kept on this platform, for Settings.
pub fn storage_note() -> Value {
    if cfg!(windows) {
        json!({ "storage": "dpapi", "note": "Encrypted with Windows DPAPI for your user account." })
    } else {
        json!({ "storage": "file", "note": "Stored in files readable only by your user (mode 0600); no system keychain is used on this platform." })
    }
}

/// A credential from Settings' JSON (`{id, kind, name, base_url, api_key, headers: {name: value} | [[n, v]], method}`).
/// An empty `api_key` keeps the stored one (so editing an endpoint's headers does not need the key again).
pub fn from_ui(v: &Value, existing: Option<&Credential>, now: u64) -> Result<Credential, String> {
    let o: &Map<String, Value> = v.as_object().ok_or("credential must be an object")?;
    let s = |k: &str| o.get(k).and_then(Value::as_str).map(|x| x.trim().to_owned()).filter(|x| !x.is_empty());
    let id = s("id").ok_or("missing provider id")?;
    let kind = match builtin_kind(&id) {
        Some(k) => k,
        None => Kind::parse(&s("kind").unwrap_or_default()).ok_or("unknown provider kind")?,
    };
    let headers = match o.get("headers") {
        Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.trim().to_owned(), v.as_str().unwrap_or("").trim().to_owned())).collect(),
        Some(Value::Array(a)) => a.iter().filter_map(|h| Some((h.get(0)?.as_str()?.trim().to_owned(), h.get(1)?.as_str()?.trim().to_owned()))).collect(),
        _ => existing.map(|e| e.headers.clone()).unwrap_or_default(),
    };
    let headers: Vec<(String, String)> = headers.into_iter().filter(|(k, _): &(String, String)| !k.is_empty()).collect();
    let api_key = s("api_key").or_else(|| if o.get("clear_key").and_then(Value::as_bool) == Some(true) { None } else { existing.and_then(|e| e.api_key.clone()) });
    let base_url = if kind.is_custom() { Some(valid_base_url(&s("base_url").or_else(|| existing.and_then(|e| e.base_url.clone())).unwrap_or_default())?) } else { None };
    let method = match s("method").as_deref() {
        Some("oauth") => Method::OAuth,
        _ if api_key.is_none() => Method::None,
        _ => Method::ApiKey,
    };
    let c = Credential { id, kind, name: s("name").unwrap_or_default(), base_url, api_key, headers, method, saved: now };
    c.validate()?;
    Ok(c)
}

pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)
    }
}

#[cfg(not(windows))]
fn protect(b: &[u8]) -> io::Result<Vec<u8>> {
    Ok(b.to_vec())
}

#[cfg(not(windows))]
fn unprotect(b: &[u8]) -> io::Result<Vec<u8>> {
    Ok(b.to_vec())
}

#[cfg(windows)]
fn dpapi(b: &[u8], encrypt: bool) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB};
    let input = CRYPT_INTEGER_BLOB { cbData: b.len() as u32, pbData: b.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    // SAFETY: `input` points at `b`, which outlives the call; DPAPI allocates `output` with
    // LocalAlloc and we free it with LocalFree after copying it out.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        } else {
            CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        }
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: DPAPI returned `cbData` bytes at `pbData`.
    let out = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as _) };
    Ok(out)
}

#[cfg(windows)]
fn protect(b: &[u8]) -> io::Result<Vec<u8>> {
    dpapi(b, true)
}

#[cfg(windows)]
fn unprotect(b: &[u8]) -> io::Result<Vec<u8>> {
    dpapi(b, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("echodebug-creds-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        Store { dir }
    }

    #[test]
    fn saves_lists_and_removes_per_provider() {
        let st = tmp("crud");
        assert!(st.list().is_empty());
        let a = from_ui(&json!({ "id": "anthropic", "api_key": "sk-ant-api03-abcdefghijklmnop" }), None, 1).unwrap();
        st.save(&a).unwrap();
        let local = from_ui(&json!({ "id": "custom-ollama", "kind": "openai_compat", "name": "Ollama", "base_url": "http://127.0.0.1:11434/v1/" }), None, 2).unwrap();
        assert_eq!(local.method, Method::None);
        assert_eq!(local.base_url.as_deref(), Some("http://127.0.0.1:11434/v1"));
        st.save(&local).unwrap();
        let gw = from_ui(&json!({ "id": "custom-gw", "kind": "anthropic_compat", "base_url": "https://gw.example", "api_key": "gw-key-123456789", "headers": { "X-Team": "re" } }), None, 3).unwrap();
        st.save(&gw).unwrap();
        let ids: Vec<String> = st.list().into_iter().map(|c| c.id).collect();
        assert_eq!(ids, ["anthropic", "custom-gw", "custom-ollama"]);
        assert_eq!(st.get("anthropic").unwrap().api_key.as_deref(), Some("sk-ant-api03-abcdefghijklmnop"));
        // info never carries the key or header values
        let info = st.info("custom-gw").to_string();
        assert!(!info.contains("gw-key-123456789") && !info.contains("\"re\"") && info.contains("X-Team") && info.contains("\"has_key\":true"), "{info}");
        let infos = st.infos();
        assert_eq!(infos.len(), 6);
        assert_eq!(infos[1]["has_key"], false);
        // editing headers keeps the stored key
        let edited = from_ui(&json!({ "id": "custom-gw", "kind": "anthropic_compat", "headers": [["X-Team", "blue"]] }), st.get("custom-gw").as_ref(), 4).unwrap();
        assert_eq!(edited.api_key.as_deref(), Some("gw-key-123456789"));
        assert_eq!(edited.base_url.as_deref(), Some("https://gw.example"));
        st.remove("custom-gw").unwrap();
        st.remove("custom-gw").unwrap();
        assert!(st.get("custom-gw").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(st.path("anthropic")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = fs::remove_dir_all(&st.dir);
    }

    #[test]
    fn reads_the_legacy_anthropic_key() {
        let st = tmp("legacy");
        fs::create_dir_all(&st.dir).unwrap();
        fs::write(st.legacy_path(), protect(b"sk-ant-api03-legacylegacylegacy\n").unwrap()).unwrap();
        assert_eq!(st.get("anthropic").unwrap().api_key.as_deref(), Some("sk-ant-api03-legacylegacylegacy"));
        st.remove("anthropic").unwrap();
        assert!(st.get("anthropic").is_none() && !st.legacy_path().exists());
        let _ = fs::remove_dir_all(&st.dir);
    }

    #[test]
    fn validates() {
        assert!(from_ui(&json!({ "id": "openai" }), None, 0).unwrap_err().contains("API key"));
        assert!(from_ui(&json!({ "id": "openai", "api_key": "has space in it ok" }), None, 0).is_err());
        assert!(from_ui(&json!({ "id": "custom-x", "kind": "openai", "base_url": "https://x", "api_key": "abcdefghij" }), None, 0).is_err());
        assert!(from_ui(&json!({ "id": "custom-x", "kind": "openai_compat", "base_url": "ftp://x" }), None, 0).is_err());
        assert!(from_ui(&json!({ "id": "custom-x", "kind": "openai_compat", "base_url": "https://u:p@x" }), None, 0).is_err());
        assert!(from_ui(&json!({ "id": "custom-x", "kind": "openai_compat", "base_url": "https://x", "headers": { "Host": "evil" } }), None, 0).is_err());
        assert!(from_ui(&json!({ "id": "custom-x", "kind": "openai_compat", "base_url": "https://x", "headers": { "X-A": "a\r\nb" } }), None, 0).is_err());
        assert!(from_ui(&json!({ "id": "../evil", "kind": "openai_compat", "base_url": "https://x" }), None, 0).is_err());
        assert!(from_ui(&json!({ "id": "custom-Bad", "kind": "openai_compat", "base_url": "https://x" }), None, 0).is_err());
        // a built-in's base URL can't be changed: its key only goes to its own host
        let c = from_ui(&json!({ "id": "openrouter", "api_key": "sk-or-v1-abcdefghijkl", "base_url": "https://evil.example", "method": "oauth" }), None, 0).unwrap();
        assert_eq!(c.base_url, None);
        assert_eq!(c.method, Method::OAuth);
        assert_eq!(key_hint("sk-or-v1-abcdefghijkl"), "sk-…ijkl");
    }
}
