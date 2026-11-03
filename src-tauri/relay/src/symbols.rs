//! PDB symbols for a module: located by the CodeView (RSDS) identity of the image in local
//! directories and symbol stores (an `_NT_SYMBOL_PATH`-style list), downloaded from symbol servers
//! only when the caller asks for it, cached in the standard `<pdb>/<GUID><age>/<pdb>` layout,
//! checked against the expected GUID/age, then read with `pdbinfo`.
//!
//! Verbs (relay-local, any backend):
//! - `pdb_symbols { pdb, key | path, symbol_path?, use_env?, image_path?, download?, servers?, allow_mismatch?, max? }`
//!   resolves locally (downloads synchronously only with `download:true`) and returns the symbols.
//! - `pdb_fetch { pdb, key, … }` starts a background download; `pdb_progress` lists the jobs.
//! - `pdb_types { path, filter?, max? }`, `pdb_type { path, name | index, depth? }`,
//!   `pdb_lines { path, rva, size? }`, `pdb_image { image_path }` (CodeView entry of a PE on disk).
//!
//! Servers default to Microsoft's (`https://msdl.microsoft.com/download/symbols`);
//! `ECHODEBUG_SYMBOL_SERVERS` (`;`-separated) overrides them, `srv*` entries of the symbol path add
//! to them. Cache: `<config>/EchoDebug/symbols/<pdb>/<key>/<pdb>` unless the symbol path names a
//! downstream store.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use serde_json::{json, Map, Value};

use crate::pdbinfo;

pub const DEFAULT_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

fn err(detail: impl Into<String>) -> Value {
    json!({ "type": "error", "code": 3003, "message": "symbols unavailable", "detail": detail.into() })
}

fn bad(detail: impl Into<String>) -> Value {
    json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": detail.into() })
}

/// File names may only be plain names (they become cache path components and URL segments).
fn plain(name: &str) -> bool {
    !name.is_empty() && name.len() < 256 && !name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|']) && name != "." && name != ".."
}

fn valid_key(key: &str) -> bool {
    key.len() >= 33 && key.len() <= 40 && key.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn cache_dir() -> PathBuf {
    crate::auth::config_dir().join("symbols")
}

// ------------------------------------------------------------------------------------------------
// CodeView identity

/// What an image's CodeView (RSDS) debug record says about its PDB.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeView {
    /// GUID as text, `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
    pub guid: String,
    pub age: u32,
    /// the PDB path as the linker wrote it
    pub path: String,
    /// symbol-store directory name: GUID (no dashes) + age in hex
    pub key: String,
}

impl CodeView {
    /// The file name part of `path` (what symbol stores index by).
    pub fn file_name(&self) -> &str {
        self.path.rsplit(['\\', '/']).next().unwrap_or(&self.path)
    }
}

/// Key and text of a GUID stored as in the RSDS record (first three fields little-endian).
pub fn guid_key(g: &[u8; 16], age: u32) -> (String, String) {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    let tail: String = g[8..].iter().map(|b| format!("{b:02X}")).collect();
    (format!("{d1:08X}{d2:04X}{d3:04X}{tail}{age:X}"), format!("{d1:08X}-{d2:04X}-{d3:04X}-{}-{}", &tail[..4], &tail[4..]))
}

/// Parses a CodeView debug record: `RSDS`, GUID (16), age (4), NUL-terminated UTF-8 path.
pub fn parse_rsds(b: &[u8]) -> Option<CodeView> {
    if b.len() < 25 || &b[..4] != b"RSDS" {
        return None;
    }
    let g: [u8; 16] = b[4..20].try_into().ok()?;
    let age = u32::from_le_bytes(b[20..24].try_into().ok()?);
    let rest = &b[24..];
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    let path = String::from_utf8_lossy(&rest[..end]).into_owned();
    let (key, guid) = guid_key(&g, age);
    Some(CodeView { guid, age, path, key })
}

/// The CodeView entry of a PE file on disk.
pub fn image_codeview(path: &Path) -> Result<CodeView, String> {
    use object::Object;
    let data = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let file = object::File::parse(&*data).map_err(|e| format!("{}: {e}", path.display()))?;
    let cv = file.pdb_info().map_err(|e| e.to_string())?.ok_or_else(|| format!("{} has no CodeView (RSDS) debug entry", path.display()))?;
    let (key, guid) = guid_key(&cv.guid(), cv.age());
    Ok(CodeView { guid, age: cv.age(), path: String::from_utf8_lossy(cv.path()).into_owned(), key })
}

/// Identity of a PDB: (GUID+age key, GUID as text, age).
pub fn pdb_identity(path: &Path) -> Result<(String, String, u32), String> {
    pdbinfo::guarded(path, || pdb_identity_unguarded(path))
}

fn pdb_identity_unguarded(path: &Path) -> Result<(String, String, u32), String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut pdb = pdb::PDB::open(file).map_err(|e| e.to_string())?;
    let info = pdb.pdb_information().map_err(|e| e.to_string())?;
    let age = pdb.debug_information().ok().and_then(|d| d.age()).unwrap_or(info.age);
    let (key, text) = pdbinfo::identity_key(info.guid.as_fields(), age);
    Ok((key, text, age))
}

// ------------------------------------------------------------------------------------------------
// where to look

/// Lookup plan: flat or store-layout directories, downstream stores, servers, download target.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// plain directories: `<dir>/<pdb>` and `<dir>/<pdb>/<key>/<pdb>`
    pub dirs: Vec<PathBuf>,
    /// symbol stores (`srv*<store>*…`, `cache*<store>`, the app cache): `<store>/<pdb>/<key>/<pdb>`
    pub stores: Vec<PathBuf>,
    pub servers: Vec<String>,
    /// where downloads go
    pub dest: PathBuf,
}

fn is_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://")
}

/// Parses an `_NT_SYMBOL_PATH`-style list into (dirs, stores, servers):
/// `C:\pdbs;srv*C:\sym*https://msdl.microsoft.com/download/symbols;cache*D:\c;symsrv*symsrv.dll*E:\s*https://x`.
pub fn parse_symbol_path(s: &str) -> (Vec<PathBuf>, Vec<PathBuf>, Vec<String>) {
    let (mut dirs, mut stores, mut servers) = (Vec::new(), Vec::new(), Vec::new());
    for part in s.split(';') {
        let p = part.trim().trim_matches('"');
        if p.is_empty() {
            continue;
        }
        let lower = p.to_ascii_lowercase();
        if lower.starts_with("srv*") || lower.starts_with("symsrv*") {
            let mut items: Vec<&str> = p.split('*').skip(1).map(str::trim).filter(|x| !x.is_empty()).collect();
            if lower.starts_with("symsrv*") && !items.is_empty() {
                items.remove(0); // the DLL name
            }
            for it in items {
                if is_url(it) {
                    servers.push(it.trim_end_matches('/').to_owned());
                } else {
                    stores.push(PathBuf::from(it));
                }
            }
        } else if lower.starts_with("cache*") {
            let d = p[6..].trim();
            stores.push(if d.is_empty() { cache_dir() } else { PathBuf::from(d) });
        } else if is_url(p) {
            servers.push(p.trim_end_matches('/').to_owned());
        } else {
            dirs.push(PathBuf::from(p));
        }
    }
    (dirs, stores, servers)
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, x: T) {
    if !v.contains(&x) {
        v.push(x);
    }
}

/// The lookup plan for a request: its `symbol_path`, `_NT_SYMBOL_PATH` / `_NT_ALT_SYMBOL_PATH`
/// unless `use_env:false`, the image's directory, `servers` (or `ECHODEBUG_SYMBOL_SERVERS`, or the
/// Microsoft server), and the app cache.
pub fn plan(req: &Map<String, Value>) -> Plan {
    let mut text = String::new();
    if let Some(s) = req.get("symbol_path").and_then(Value::as_str) {
        text.push_str(s);
    }
    if req.get("use_env").and_then(Value::as_bool).unwrap_or(true) {
        for v in ["_NT_SYMBOL_PATH", "_NT_ALT_SYMBOL_PATH"] {
            if let Ok(s) = std::env::var(v) {
                text.push(';');
                text.push_str(&s);
            }
        }
    }
    let (sp_dirs, sp_stores, sp_servers) = parse_symbol_path(&text);
    let mut p = Plan::default();
    if let Some(img) = req.get("image_path").and_then(Value::as_str) {
        if let Some(d) = Path::new(img).parent().filter(|d| !d.as_os_str().is_empty()) {
            p.dirs.push(d.to_owned());
        }
    }
    for d in sp_dirs {
        push_unique(&mut p.dirs, d);
    }
    for s in &sp_stores {
        push_unique(&mut p.stores, s.clone());
    }
    p.dest = sp_stores.first().cloned().unwrap_or_else(cache_dir);
    push_unique(&mut p.stores, cache_dir());
    let explicit: Vec<String> = req
        .get("servers")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|s| s.as_str()).map(|s| s.trim().trim_end_matches('/').to_owned()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    let env: Vec<String> = std::env::var("ECHODEBUG_SYMBOL_SERVERS")
        .map(|s| s.split(';').map(|x| x.trim().trim_end_matches('/').to_owned()).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();
    for s in explicit.into_iter().chain(sp_servers).chain(env) {
        push_unique(&mut p.servers, s);
    }
    if p.servers.is_empty() {
        p.servers.push(DEFAULT_SERVER.to_owned());
    }
    p
}

/// `ntdll.pdb` → `ntdll.pd_` (the CAB-compressed name on symbol servers).
pub fn compressed_name(name: &str) -> String {
    let mut s = name.to_owned();
    s.pop();
    s.push('_');
    s
}

/// Store-layout path of a PDB below a store root.
pub fn store_path(root: &Path, name: &str, key: &str) -> PathBuf {
    root.join(name).join(key).join(name)
}

/// Every local place the PDB could be, in lookup order, with where it came from.
pub fn candidates(plan: &Plan, name: &str, key: &str) -> Vec<(PathBuf, &'static str)> {
    let mut out = Vec::new();
    let z = compressed_name(name);
    for d in &plan.dirs {
        out.push((d.join(name), "symbol path"));
        out.push((store_path(d, name, key), "symbol path"));
        out.push((d.join(name).join(key).join(&z), "symbol path"));
    }
    for s in &plan.stores {
        out.push((store_path(s, name, key), "cache"));
        out.push((s.join(name).join(key).join(&z), "cache"));
    }
    out
}

/// Extracts the single file of a cabinet (`.pd_`).
pub fn uncab(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut cab = cab::Cabinet::new(std::io::Cursor::new(bytes)).map_err(|e| format!("bad cabinet: {e}"))?;
    let name = cab.folder_entries().flat_map(|f| f.file_entries()).next().map(|f| f.name().to_owned()).ok_or("empty cabinet")?;
    let mut out = Vec::new();
    // the same 4 GiB bound as a plain download: a small cabinet can expand far beyond its size
    const LIMIT: u64 = 4 << 30;
    cab.read_file(&name).map_err(|e| e.to_string())?.take(LIMIT + 1).read_to_end(&mut out).map_err(|e| format!("cabinet {name}: {e}"))?;
    if out.len() as u64 > LIMIT {
        return Err(format!("cabinet {name}: expands to more than 4 GiB"));
    }
    Ok(out)
}

fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = dest.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let tmp = dest.with_extension("part");
    fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, dest).map_err(|e| e.to_string())
}

#[derive(Debug, Default)]
pub struct Found {
    pub path: Option<PathBuf>,
    pub source: &'static str,
    pub matched: bool,
    pub tried: Vec<String>,
    /// files with the right name but another build: (path, their key)
    pub mismatches: Vec<(PathBuf, String)>,
}

/// Looks for the PDB locally; compressed copies are expanded into the plan's `dest` store.
pub fn find_local(plan: &Plan, name: &str, key: &str) -> Found {
    let mut f = Found::default();
    for (p, source) in candidates(plan, name, key) {
        if !p.is_file() {
            f.tried.push(p.display().to_string());
            continue;
        }
        let path = if p.extension().and_then(|e| e.to_str()).is_some_and(|e| e.ends_with('_')) {
            let dest = store_path(&plan.dest, name, key);
            match fs::read(&p).map_err(|e| e.to_string()).and_then(|b| uncab(&b)).and_then(|b| write_atomic(&dest, &b)) {
                Ok(()) => dest,
                Err(e) => {
                    f.tried.push(format!("{}: {e}", p.display()));
                    continue;
                }
            }
        } else {
            p
        };
        match pdb_identity(&path) {
            Ok((k, _, _)) if k.eq_ignore_ascii_case(key) => {
                f.path = Some(path);
                f.source = source;
                f.matched = true;
                return f;
            }
            Ok((k, _, _)) => {
                f.tried.push(format!("{}: another build ({k})", path.display()));
                f.mismatches.push((path, k));
            }
            Err(e) => f.tried.push(format!("{}: {e}", path.display())),
        }
    }
    f
}

// ------------------------------------------------------------------------------------------------
// downloading

/// Downloads `<server>/<pdb>/<key>/<pdb>` (or the compressed `<pdb minus last char>_`) into the
/// `cache` store; returns the cached path. `progress(done, total, url)` follows each transfer.
pub fn fetch_with(pdb_name: &str, key: &str, servers: &[String], cache: &Path, progress: &dyn Fn(u64, Option<u64>, &str)) -> Result<PathBuf, String> {
    let dest = store_path(cache, pdb_name, key);
    if dest.is_file() {
        return Ok(dest);
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(1800)))
        .timeout_connect(Some(std::time::Duration::from_secs(20)))
        .proxy(ureq::Proxy::try_from_env())
        .build()
        .into();
    let mut errors: Vec<String> = Vec::new();
    for s in servers {
        if !is_url(s) {
            errors.push(format!("{s}: not an http(s) URL"));
            continue;
        }
        for file in [pdb_name.to_owned(), compressed_name(pdb_name)] {
            let url = format!("{}/{pdb_name}/{key}/{file}", s.trim_end_matches('/'));
            progress(0, None, &url);
            match agent.get(&url).header("User-Agent", "Microsoft-Symbol-Server/10.0.0.0").call() {
                Ok(mut resp) => {
                    let total = resp.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
                    let mut bytes = Vec::with_capacity(total.unwrap_or(0).min(1 << 30) as usize);
                    let mut reader = resp.body_mut().as_reader();
                    let mut buf = vec![0u8; 1 << 16];
                    let mut last = Instant::now();
                    let res: Result<(), String> = loop {
                        match reader.read(&mut buf) {
                            Ok(0) => break Ok(()),
                            Ok(n) => {
                                bytes.extend_from_slice(&buf[..n]);
                                if bytes.len() as u64 > 4 << 30 {
                                    break Err("larger than 4 GiB".into());
                                }
                                if last.elapsed().as_millis() > 100 {
                                    progress(bytes.len() as u64, total, &url);
                                    last = Instant::now();
                                }
                            }
                            Err(e) => break Err(e.to_string()),
                        }
                    };
                    if let Err(e) = res {
                        errors.push(format!("{url}: {e}"));
                        continue;
                    }
                    progress(bytes.len() as u64, total, &url);
                    let pdb = if bytes.starts_with(b"MSCF") {
                        match uncab(&bytes) {
                            Ok(b) => b,
                            Err(e) => {
                                errors.push(format!("{url}: {e}"));
                                continue;
                            }
                        }
                    } else {
                        bytes
                    };
                    if !pdb.starts_with(b"Microsoft C/C++ MSF 7.00") {
                        errors.push(format!("{url}: not a PDB (MSF 7.00) file"));
                        continue;
                    }
                    write_atomic(&dest, &pdb)?;
                    return Ok(dest);
                }
                Err(ureq::Error::StatusCode(404)) => errors.push(format!("{url}: not on this server (404)")),
                Err(e) => {
                    errors.push(format!("{url}: {e}"));
                    break; // the server is unreachable: no point asking for the compressed name
                }
            }
        }
    }
    Err(if errors.is_empty() { "no symbol server configured".into() } else { errors.join("; ") })
}

pub fn fetch(pdb_name: &str, key: &str, servers: &[String], cache: &Path) -> Result<PathBuf, String> {
    fetch_with(pdb_name, key, servers, cache, &|_, _, _| {})
}

/// One background download.
#[derive(Clone, Debug)]
struct Job {
    id: String,
    pdb: String,
    key: String,
    state: &'static str,
    done: u64,
    total: Option<u64>,
    url: String,
    path: Option<String>,
    error: Option<String>,
    started: Instant,
}

fn jobs() -> &'static Mutex<Vec<Job>> {
    static J: OnceLock<Mutex<Vec<Job>>> = OnceLock::new();
    J.get_or_init(|| Mutex::new(Vec::new()))
}

fn job_json(j: &Job) -> Value {
    json!({ "job": j.id, "pdb": j.pdb, "key": j.key, "state": j.state, "done": j.done, "total": j.total, "url": j.url, "path": j.path, "error": j.error, "seconds": j.started.elapsed().as_secs_f64() })
}

fn update_job(id: &str, f: impl FnOnce(&mut Job)) {
    let mut js = jobs().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(j) = js.iter_mut().find(|j| j.id == id) {
        f(j);
    }
}

/// `pdb_fetch`: a matching local copy answers at once; otherwise a download job starts.
fn start_fetch(req: &Map<String, Value>) -> Value {
    let (name, key) = match name_key(req) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let plan = plan(req);
    let local = find_local(&plan, &name, &key);
    if let Some(p) = local.path {
        return json!({ "type": "pdb_fetch_result", "success": true, "state": "done", "path": p.display().to_string(), "source": local.source });
    }
    let id = format!("{name}/{key}");
    {
        let mut js = jobs().lock().unwrap_or_else(|e| e.into_inner());
        js.retain(|j| j.state == "downloading" || j.started.elapsed().as_secs() < 600);
        if let Some(j) = js.iter().find(|j| j.id == id && j.state == "downloading") {
            let mut v = job_json(j);
            v["type"] = "pdb_fetch_result".into();
            v["success"] = true.into();
            return v;
        }
        js.retain(|j| j.id != id);
        js.push(Job { id: id.clone(), pdb: name.clone(), key: key.clone(), state: "downloading", done: 0, total: None, url: String::new(), path: None, error: None, started: Instant::now() });
    }
    let jid = id.clone();
    let reply = json!({ "type": "pdb_fetch_result", "success": true, "state": "downloading", "job": id, "pdb": name, "key": key });
    std::thread::spawn(move || {
        let progress = |done: u64, total: Option<u64>, url: &str| {
            update_job(&jid, |j| {
                j.done = done;
                j.total = total;
                url.clone_into(&mut j.url);
            })
        };
        let r = fetch_with(&name, &key, &plan.servers, &plan.dest, &progress);
        update_job(&jid, |j| match r {
            Ok(p) => {
                j.state = "done";
                j.path = Some(p.display().to_string());
            }
            Err(e) => {
                j.state = "error";
                j.error = Some(e);
            }
        });
    });
    reply
}

// ------------------------------------------------------------------------------------------------
// verbs

fn name_key(req: &Map<String, Value>) -> Result<(String, String), Value> {
    let (Some(name), Some(key)) = (req.get("pdb").and_then(Value::as_str), req.get("key").and_then(Value::as_str)) else {
        return Err(bad("needs 'pdb' (file name) and 'key' (GUID + age), or 'path'"));
    };
    // directory parts are cut off (".../x/../evil.pdb" becomes "evil.pdb"); a bare ".." is refused
    let name = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let key = key.trim().to_uppercase();
    if !plain(name) || !valid_key(&key) {
        return Err(bad("pdb must be a file name and key 32 hex digits + age"));
    }
    Ok((name.to_owned(), key))
}

fn u32_arg(req: &Map<String, Value>, k: &str) -> Option<u32> {
    match req.get(k)? {
        Value::Number(n) => n.as_u64().map(|x| x as u32),
        Value::String(s) => {
            let s = s.trim();
            s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse().ok(), |h| u32::from_str_radix(h, 16).ok())
        }
        _ => None,
    }
}

/// The parsed PDB named by `path`.
fn opened(req: &Map<String, Value>) -> Result<std::sync::Arc<pdbinfo::Loaded>, Value> {
    let Some(p) = req.get("path").and_then(Value::as_str) else {
        return Err(bad("needs 'path' (a PDB returned by pdb_symbols)"));
    };
    pdbinfo::open(Path::new(p)).map_err(err)
}

fn symbols(req: &Map<String, Value>) -> Value {
    let max = req.get("max").and_then(Value::as_u64).unwrap_or(500_000).min(5_000_000) as usize;
    let want = req.get("key").and_then(Value::as_str).map(|k| k.trim().to_uppercase());
    let allow_mismatch = req.get("allow_mismatch").and_then(Value::as_bool).unwrap_or(false);
    let mut tried: Vec<String> = Vec::new();
    let (path, source) = match req.get("path").and_then(Value::as_str) {
        Some(p) => (PathBuf::from(p), "path"),
        None => {
            let (name, key) = match name_key(req) {
                Ok(x) => x,
                Err(e) => return e,
            };
            let plan = plan(req);
            let local = find_local(&plan, &name, &key);
            tried = local.tried.clone();
            match local.path {
                Some(p) => (p, local.source),
                None if req.get("download").and_then(Value::as_bool).unwrap_or(false) => match fetch(&name, &key, &plan.servers, &plan.dest) {
                    Ok(p) => (p, "server"),
                    Err(e) => return err(e),
                },
                None if allow_mismatch && !local.mismatches.is_empty() => (local.mismatches[0].0.clone(), "mismatch"),
                None => {
                    // a reply (not an error frame) so callers get the places tried and other builds found
                    let mut v = json!({ "type": "pdb_symbols_result", "success": false, "found": false, "code": 3004, "message": "PDB not found locally",
                        "detail": format!("{name} {key}: not in the image directory, the symbol path or the cache{}; download it from a symbol server (Symbols view) or add its folder to the symbol path",
                            if local.mismatches.is_empty() { String::new() } else { format!(" (found other builds: {})", local.mismatches.iter().map(|m| m.1.clone()).collect::<Vec<_>>().join(", ")) }),
                        "tried": tried });
                    if !local.mismatches.is_empty() {
                        v["mismatches"] = local.mismatches.iter().map(|(p, k)| json!({ "path": p.display().to_string(), "key": k })).collect();
                    }
                    return v;
                }
            }
        }
    };
    let l = match pdbinfo::open(&path) {
        Ok(l) => l,
        Err(e) => return err(e),
    };
    let matched = want.as_ref().is_none_or(|w| *w == l.key);
    if !matched && !allow_mismatch {
        return err(format!("{} is {}, the image expects {}: a different build", path.display(), l.key, want.unwrap_or_default()));
    }
    let syms: Vec<Value> = l.syms.iter().take(max).map(|s| l.sym_json(s)).collect();
    json!({
        "type": "pdb_symbols_result", "success": true, "path": path.display().to_string(), "source": source,
        "guid": l.guid, "age": l.age, "key": l.key, "expected_key": want, "matched": matched, "machine": l.machine,
        "count": syms.len(), "functions": l.syms.iter().filter(|s| s.kind == "function").count(),
        "types": l.types.types.len(), "lines": l.lines.len(), "files": l.files.len(),
        "tried": tried, "symbols": syms,
    })
}

/// Dispatches the `pdb_*` verbs (blocking; the relay runs them on a blocking thread).
pub fn handle_verb(verb: &str, req: &Map<String, Value>) -> Value {
    match verb {
        "pdb_symbols" => symbols(req),
        "pdb_fetch" => start_fetch(req),
        "pdb_progress" => {
            let js = jobs().lock().unwrap_or_else(|e| e.into_inner());
            json!({ "type": "pdb_progress_result", "success": true, "jobs": js.iter().rev().map(job_json).collect::<Vec<_>>() })
        }
        "pdb_image" => {
            let Some(p) = req.get("image_path").and_then(Value::as_str) else { return bad("needs 'image_path'") };
            match image_codeview(Path::new(p)) {
                Ok(cv) => json!({ "type": "pdb_image_result", "success": true, "pdb": cv.file_name(), "pdb_path": cv.path, "guid": cv.guid, "age": cv.age, "key": cv.key }),
                Err(e) => err(e),
            }
        }
        "pdb_types" => match opened(req) {
            Ok(l) => {
                let max = req.get("max").and_then(Value::as_u64).unwrap_or(2000).min(50_000) as usize;
                let (total, types) = l.types.list(req.get("filter").and_then(Value::as_str).unwrap_or(""), max);
                json!({ "type": "pdb_types_result", "success": true, "total": total, "types": types })
            }
            Err(e) => e,
        },
        "pdb_type" => match opened(req) {
            Ok(l) => {
                let idx = u32_arg(req, "index").or_else(|| req.get("name").and_then(Value::as_str).and_then(|n| l.types.find(n.trim())));
                let Some(idx) = idx else { return err(format!("no type named '{}'", req.get("name").and_then(Value::as_str).unwrap_or(""))) };
                let depth = req.get("depth").and_then(Value::as_u64).unwrap_or(6).min(32) as usize;
                // a typedef or pointer names the thing it stands for
                let mut target = l.types.strip(idx);
                if let Some(pdbinfo::Ty::Ptr { to, .. }) = l.types.get(target) {
                    target = l.types.strip(*to);
                }
                match l.types.layout_with_nested(target, depth) {
                    Some(mut v) => {
                        v["type"] = "pdb_type_result".into();
                        v["success"] = true.into();
                        v["text"] = l.types.name(idx).into();
                        v
                    }
                    None => err(format!("type 0x{idx:x} ({}) is not a struct, class, union or enum", l.types.name(idx))),
                }
            }
            Err(e) => e,
        },
        "pdb_lines" => match opened(req) {
            Ok(l) => {
                let Some(rva) = u32_arg(req, "rva") else { return bad("needs 'rva'") };
                let size = u32_arg(req, "size").unwrap_or(0);
                let max = req.get("max").and_then(Value::as_u64).unwrap_or(20_000).min(200_000) as usize;
                let lines: Vec<Value> = l.lines_in(rva, size, max).into_iter().map(|x| l.line_json(x)).collect();
                json!({ "type": "pdb_lines_result", "success": true, "lines": lines, "function": l.function_at(rva).map(|s| l.sym_json(s)) })
            }
            Err(e) => e,
        },
        _ => bad(format!("unknown verb {verb}")),
    }
}

/// The original `pdb_symbols` entry point.
pub fn handle(req: &Map<String, Value>) -> Value {
    symbols(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fix.pdb")
    }
    fn types_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdbtypes")
    }
    const TYPES_KEY: &str = "3204B8A9E64144054C4C44205044422E1";

    fn obj(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("echodebug-sym-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn reads_the_lld_fixture() {
        let (key, guid, age) = pdb_identity(&fixture()).unwrap();
        // llvm-pdbutil dump -summary: GUID {E5F4837E-BE62-2C4A-4C4C-44205044422E}, age 1
        assert_eq!(guid, "E5F4837E-BE62-2C4A-4C4C-44205044422E");
        assert_eq!(age, 1);
        assert_eq!(key, "E5F4837EBE622C4A4C4C44205044422E1");
        let l = pdbinfo::load(&fixture()).unwrap();
        let main = l.syms.iter().find(|s| s.name == "mainCRTStartup").expect("mainCRTStartup");
        // publics: mainCRTStartup at 0001:0048 → .text (RVA 0x1000) + 0x30
        assert_eq!(main.rva, 0x1030);
        assert_eq!(main.kind, "function");
        assert!(l.syms.iter().any(|s| s.name == "_tls_used"));
    }

    #[test]
    fn parses_rsds_records_and_images() {
        let mut b = b"RSDS".to_vec();
        b.extend_from_slice(&[0xA9, 0xB8, 0x04, 0x32, 0x41, 0xE6, 0x05, 0x44, 0x4C, 0x4C, 0x44, 0x20, 0x50, 0x44, 0x42, 0x2E]);
        b.extend_from_slice(&0x1au32.to_le_bytes());
        b.extend_from_slice(b"C:\\build\\out\\types.pdb\0junk");
        let cv = parse_rsds(&b).unwrap();
        assert_eq!(cv.guid, "3204B8A9-E641-4405-4C4C-44205044422E");
        assert_eq!(cv.age, 0x1a);
        assert_eq!(cv.key, "3204B8A9E64144054C4C44205044422E1A");
        assert_eq!(cv.file_name(), "types.pdb");
        assert!(parse_rsds(b"NB10xxxxxxxxxxxxxxxxxxxxxxxxx").is_none());
        assert!(parse_rsds(&b[..20]).is_none());
        // the fixture image and its PDB agree
        let img = image_codeview(&types_dir().join("types.exe")).unwrap();
        assert_eq!(img.key, TYPES_KEY);
        assert_eq!(img.path, "types.pdb");
        assert_eq!(pdb_identity(&types_dir().join("types.pdb")).unwrap().0, TYPES_KEY);
        let r = handle_verb("pdb_image", &obj(json!({ "image_path": types_dir().join("types.exe").display().to_string() })));
        assert_eq!(r["key"], TYPES_KEY);
    }

    #[test]
    fn symbol_path_syntax_and_cache_layout() {
        let (dirs, stores, servers) = parse_symbol_path(r"C:\pdbs ; srv*C:\sym*https://msdl.microsoft.com/download/symbols/;cache*D:\c;symsrv*symsrv.dll*E:\s*http://intranet/sym;https://x.example/s;");
        assert_eq!(dirs, vec![PathBuf::from(r"C:\pdbs")]);
        assert_eq!(stores, vec![PathBuf::from(r"C:\sym"), PathBuf::from(r"D:\c"), PathBuf::from(r"E:\s")]);
        assert_eq!(servers, vec!["https://msdl.microsoft.com/download/symbols", "http://intranet/sym", "https://x.example/s"]);
        assert_eq!(compressed_name("ntdll.pdb"), "ntdll.pd_");
        assert_eq!(store_path(Path::new("/c"), "ntdll.pdb", "ABC1"), PathBuf::from("/c/ntdll.pdb/ABC1/ntdll.pdb"));
        let p = plan(&obj(json!({ "symbol_path": "/opt/pdbs;srv*/var/sym*https://s.example", "use_env": false, "image_path": "/games/x/game.exe", "servers": ["https://first.example/"] })));
        assert_eq!(p.dirs, vec![PathBuf::from("/games/x"), PathBuf::from("/opt/pdbs")]);
        assert_eq!(p.stores, vec![PathBuf::from("/var/sym"), cache_dir()]);
        assert_eq!(p.dest, PathBuf::from("/var/sym"));
        assert_eq!(p.servers[..2], ["https://first.example".to_owned(), "https://s.example".to_owned()]);
        let c = candidates(&p, "game.pdb", "K1");
        assert_eq!(c[0], (PathBuf::from("/games/x/game.pdb"), "symbol path"));
        assert!(c.contains(&(PathBuf::from("/var/sym/game.pdb/K1/game.pdb"), "cache")));
        assert!(c.contains(&(PathBuf::from("/var/sym/game.pdb/K1/game.pd_"), "cache")));
        // without a downstream store, downloads go to the app cache
        assert_eq!(plan(&obj(json!({ "use_env": false }))).dest, cache_dir());
    }

    #[test]
    fn finds_local_copies_checks_builds_and_expands_cabinets() {
        let root = scratch("local");
        let flat = root.join("flat");
        fs::create_dir_all(&flat).unwrap();
        // another build under the right name in a flat directory
        fs::copy(fixture(), flat.join("types.pdb")).unwrap();
        // the right build compressed in a store
        let store = root.join("store");
        let zdir = store.join("types.pdb").join(TYPES_KEY);
        fs::create_dir_all(&zdir).unwrap();
        let mut b = cab::CabinetBuilder::new();
        b.add_folder(cab::CompressionType::MsZip).add_file("types.pdb");
        let mut w = b.build(std::io::Cursor::new(Vec::new())).unwrap();
        while let Some(mut f) = w.next_file().unwrap() {
            std::io::Write::write_all(&mut f, &fs::read(types_dir().join("types.pdb")).unwrap()).unwrap();
        }
        let z = w.finish().unwrap().into_inner();
        assert!(z.starts_with(b"MSCF"));
        fs::write(zdir.join("types.pd_"), &z).unwrap();
        let plan = Plan { dirs: vec![flat.clone()], stores: vec![store.clone()], servers: vec![], dest: root.join("dest") };
        let f = find_local(&plan, "types.pdb", TYPES_KEY);
        assert!(f.matched);
        assert_eq!(f.source, "cache");
        assert_eq!(f.path.as_deref(), Some(store_path(&root.join("dest"), "types.pdb", TYPES_KEY).as_path()));
        assert_eq!(f.mismatches.len(), 1);
        assert_eq!(f.mismatches[0].1, "E5F4837EBE622C4A4C4C44205044422E1");
        // the verb reports a miss without downloading, and can load the other build when asked
        let req = |extra: Value| {
            let mut m = obj(json!({ "pdb": "types.pdb", "key": "00000000000000000000000000000000001", "symbol_path": flat.display().to_string(), "use_env": false }));
            m.extend(obj(extra));
            m
        };
        let r = handle(&req(json!({})));
        assert_eq!(r["code"], 3004, "{r}");
        assert_eq!(r["mismatches"][0]["key"], "E5F4837EBE622C4A4C4C44205044422E1");
        let r = handle(&req(json!({ "allow_mismatch": true })));
        assert_eq!((r["success"].as_bool(), r["matched"].as_bool()), (Some(true), Some(false)), "{r}");
        let _ = fs::remove_dir_all(&root);
    }

    /// A one-shot HTTP server: answers `ok_path` with `body`, anything else with 404.
    fn serve(requests: usize, ok_path: &'static str, body: Vec<u8>) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..requests {
                let (mut s, _) = listener.accept().unwrap();
                let mut first = String::new();
                let mut r = BufReader::new(s.try_clone().unwrap());
                r.read_line(&mut first).unwrap();
                loop {
                    let mut l = String::new();
                    if r.read_line(&mut l).unwrap() == 0 || l == "\r\n" {
                        break;
                    }
                }
                let ok = first.starts_with(&format!("GET {ok_path} "));
                let status = if ok { "200 OK" } else { "404 Not Found" };
                write!(s, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", if ok { body.len() } else { 0 }).unwrap();
                if ok {
                    s.write_all(&body).unwrap();
                }
                seen.push(first);
            }
            seen
        });
        (port, h)
    }

    #[test]
    fn fetches_from_a_symbol_server_and_caches() {
        let (port, server) = serve(1, "/fix.pdb/E5F4837EBE622C4A4C4C44205044422E1/fix.pdb", fs::read(fixture()).unwrap());
        let cache = scratch("fetch");
        let p = fetch("fix.pdb", "E5F4837EBE622C4A4C4C44205044422E1", &[format!("http://127.0.0.1:{port}")], &cache).unwrap();
        assert!(server.join().unwrap()[0].contains("/fix.pdb/E5F4837EBE622C4A4C4C44205044422E1/fix.pdb"));
        assert_eq!(p, cache.join("fix.pdb/E5F4837EBE622C4A4C4C44205044422E1/fix.pdb"));
        assert_eq!(fs::read(&p).unwrap(), fs::read(fixture()).unwrap());
        // second call is served from the cache (no server is listening any more)
        assert_eq!(fetch("fix.pdb", "E5F4837EBE622C4A4C4C44205044422E1", &[format!("http://127.0.0.1:{port}")], &cache).unwrap(), p);
        let _ = fs::remove_dir_all(&cache);
    }

    #[test]
    fn falls_back_to_the_compressed_name_and_reports_progress() {
        let mut b = cab::CabinetBuilder::new();
        b.add_folder(cab::CompressionType::MsZip).add_file("types.pdb");
        let mut w = b.build(std::io::Cursor::new(Vec::new())).unwrap();
        while let Some(mut f) = w.next_file().unwrap() {
            std::io::Write::write_all(&mut f, &fs::read(types_dir().join("types.pdb")).unwrap()).unwrap();
        }
        let z = w.finish().unwrap().into_inner();
        let (port, server) = serve(2, "/types.pdb/3204B8A9E64144054C4C44205044422E1/types.pd_", z.clone());
        let cache = scratch("cab");
        let seen = std::sync::Mutex::new(Vec::new());
        let p = fetch_with("types.pdb", TYPES_KEY, &[format!("http://127.0.0.1:{port}")], &cache, &|d, t, u| seen.lock().unwrap().push((d, t, u.to_owned()))).unwrap();
        let reqs = server.join().unwrap();
        assert!(reqs[0].contains("/types.pdb ") && reqs[1].contains("/types.pd_ "), "{reqs:?}");
        assert_eq!(fs::read(&p).unwrap(), fs::read(types_dir().join("types.pdb")).unwrap());
        let last = seen.lock().unwrap().last().cloned().unwrap();
        assert_eq!((last.0, last.1), (z.len() as u64, Some(z.len() as u64)));
        let _ = fs::remove_dir_all(&cache);
    }

    #[test]
    fn background_fetch_job() {
        let (port, server) = serve(1, "/types.pdb/3204B8A9E64144054C4C44205044422E1/types.pdb", fs::read(types_dir().join("types.pdb")).unwrap());
        let store = scratch("job");
        let req = obj(json!({ "pdb": "types.pdb", "key": TYPES_KEY, "use_env": false, "symbol_path": format!("srv*{}*http://127.0.0.1:{port}", store.display()) }));
        let r = handle_verb("pdb_fetch", &req);
        assert_eq!(r["state"], "downloading", "{r}");
        server.join().unwrap();
        let mut state = String::new();
        for _ in 0..200 {
            let p = handle_verb("pdb_progress", &Map::new());
            let j = p["jobs"].as_array().unwrap().iter().find(|j| j["job"] == format!("types.pdb/{TYPES_KEY}")).cloned().unwrap();
            state = j["state"].as_str().unwrap().to_owned();
            if state != "downloading" {
                assert_eq!(j["path"], store_path(&store, "types.pdb", TYPES_KEY).display().to_string());
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(state, "done");
        // now local: pdb_fetch answers at once and pdb_symbols loads it from the store
        assert_eq!(handle_verb("pdb_fetch", &req)["state"], "done");
        let s = handle_verb("pdb_symbols", &req);
        assert_eq!((s["matched"].as_bool(), s["source"].as_str()), (Some(true), Some("cache")), "{s}");
        let _ = fs::remove_dir_all(&store);
    }

    #[test]
    fn type_and_line_verbs() {
        let path = types_dir().join("types.pdb").display().to_string();
        let r = handle_verb("pdb_types", &obj(json!({ "path": path, "filter": "e" })));
        assert!(r["types"].as_array().unwrap().iter().any(|t| t["name"] == "Entity" && t["kind"] == "struct"), "{r}");
        let r = handle_verb("pdb_type", &obj(json!({ "path": path, "name": "Entity" })));
        assert_eq!(r["name"], "Entity");
        assert!(r["nested"].as_array().unwrap().len() >= 4);
        // the checked-in layout the UI's importer tests use is what the relay produces
        let mut want: Value = serde_json::from_str(&fs::read_to_string(types_dir().join("entity.json")).unwrap()).unwrap();
        let mut got = r.clone();
        for v in [&mut want, &mut got] {
            if let Some(o) = v.as_object_mut() {
                o.remove("type");
                o.remove("success");
            }
        }
        if std::env::var_os("ECHODEBUG_BLESS").is_some() {
            fs::write(types_dir().join("entity.json"), serde_json::to_string_pretty(&r).unwrap() + "\n").unwrap();
        } else {
            assert_eq!(got, want, "regenerate with ECHODEBUG_BLESS=1 cargo test -p echo-debug-relay type_and_line_verbs");
        }
        // a typedef of a pointer to a struct names that struct
        assert_eq!(handle_verb("pdb_type", &obj(json!({ "path": path, "name": "Callback" })))["code"], 3003);
        let syms = handle_verb("pdb_symbols", &obj(json!({ "path": path })));
        let score = syms["symbols"].as_array().unwrap().iter().find(|s| s["name"] == "entity_score").unwrap().clone();
        let r = handle_verb("pdb_lines", &obj(json!({ "path": path, "rva": format!("0x{:x}", score["rva"].as_u64().unwrap() + 4) })));
        assert_eq!(r["function"]["name"], "entity_score");
        assert_eq!(r["lines"].as_array().unwrap().len(), 1);
        assert!(r["lines"][0]["file"].as_str().unwrap().ends_with("types.c"));
    }

    #[test]
    fn rejects_unsafe_names_and_other_builds() {
        let r = handle(&obj(json!({ "pdb": "..", "key": "E5F4837EBE622C4A4C4C44205044422E1" })));
        assert_eq!(r["code"], 3002);
        let r = handle(&obj(json!({ "pdb": "fix.pdb", "key": "not-hex" })));
        assert_eq!(r["code"], 3002);
        let r = handle(&obj(json!({ "path": fixture().display().to_string(), "key": "00000000000000000000000000000000001" })));
        assert!(r["detail"].as_str().unwrap().contains("different build"), "{r}");
        let r = handle(&obj(json!({ "path": fixture().display().to_string() })));
        assert_eq!(r["success"], true, "{r}");
    }
}
