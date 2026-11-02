//! PDB symbols for a module: fetched from a symbol server by the CodeView (RSDS) identity of the
//! image, cached on disk, checked against the expected GUID/age, then read with the `pdb` crate.
//!
//! Relay-local verb `pdb_symbols { pdb, key, servers?, max? }` where `pdb` is the PDB file name from
//! the debug directory and `key` is GUID (32 hex, no dashes) + age (hex). Servers default to
//! Microsoft's (`https://msdl.microsoft.com/download/symbols`); `ECHODEBUG_SYMBOL_SERVERS`
//! (`;`-separated) overrides them. A `path` argument loads a local PDB instead.
//! Cache: `<config>/EchoDebug/symbols/<pdb>/<key>/<pdb>`, the usual symbol-store layout.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

pub const DEFAULT_SERVER: &str = "https://msdl.microsoft.com/download/symbols";

fn err(detail: impl Into<String>) -> Value {
    json!({ "type": "error", "code": 3003, "message": "symbols unavailable", "detail": detail.into() })
}

/// File names may only be plain names (they become cache path components and URL segments).
fn plain(name: &str) -> bool {
    !name.is_empty() && name.len() < 256 && !name.contains(['/', '\\', ':']) && name != "." && name != ".."
}

pub fn cache_dir() -> PathBuf {
    crate::auth::config_dir().join("symbols")
}

/// Identity of a PDB: (GUID+age key, GUID as text, age).
pub fn pdb_identity(path: &Path) -> Result<(String, String, u32), String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut pdb = pdb::PDB::open(file).map_err(|e| e.to_string())?;
    let info = pdb.pdb_information().map_err(|e| e.to_string())?;
    // the DBI stream's age is the one the image's CodeView entry carries
    let age = pdb.debug_information().ok().and_then(|d| d.age()).unwrap_or(info.age);
    let (d1, d2, d3, d4) = info.guid.as_fields();
    let tail: String = d4.iter().map(|b| format!("{b:02X}")).collect();
    let key = format!("{d1:08X}{d2:04X}{d3:04X}{tail}{age:X}");
    let text = format!("{d1:08X}-{d2:04X}-{d3:04X}-{}-{}", &tail[..4], &tail[4..]);
    Ok((key, text, age))
}

/// Public symbols and procedures with their RVAs, sorted by RVA.
pub fn read_symbols(path: &Path, max: usize) -> Result<Vec<(u32, String, &'static str)>, String> {
    use pdb::FallibleIterator;
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut pdb = pdb::PDB::open(file).map_err(|e| e.to_string())?;
    let map = pdb.address_map().map_err(|e| e.to_string())?;
    let mut out: Vec<(u32, String, &'static str)> = Vec::new();
    let globals = pdb.global_symbols().map_err(|e| e.to_string())?;
    let mut it = globals.iter();
    while let Some(sym) = it.next().map_err(|e| e.to_string())? {
        if out.len() >= max {
            break;
        }
        if let Ok(pdb::SymbolData::Public(p)) = sym.parse() {
            if let Some(rva) = p.offset.to_rva(&map) {
                out.push((rva.0, p.name.to_string().into_owned(), if p.function { "function" } else { "data" }));
            }
        }
    }
    // procedures live in the module streams (private symbols, when the PDB has them)
    let dbi = pdb.debug_information().map_err(|e| e.to_string())?;
    let mut modules = dbi.modules().map_err(|e| e.to_string())?;
    while let Some(m) = modules.next().map_err(|e| e.to_string())? {
        let Ok(Some(info)) = pdb.module_info(&m) else { continue };
        let Ok(mut syms) = info.symbols() else { continue };
        while let Ok(Some(sym)) = syms.next() {
            if out.len() >= max {
                break;
            }
            if let Ok(pdb::SymbolData::Procedure(p)) = sym.parse() {
                if let Some(rva) = p.offset.to_rva(&map) {
                    out.push((rva.0, p.name.to_string().into_owned(), "function"));
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    out.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    Ok(out)
}

fn servers(req: &Map<String, Value>) -> Vec<String> {
    if let Some(list) = req.get("servers").and_then(Value::as_array) {
        let v: Vec<String> = list.iter().filter_map(|s| s.as_str().map(str::to_owned)).collect();
        if !v.is_empty() {
            return v;
        }
    }
    match std::env::var("ECHODEBUG_SYMBOL_SERVERS") {
        Ok(s) if !s.trim().is_empty() => s.split(';').map(|x| x.trim().to_owned()).filter(|x| !x.is_empty()).collect(),
        _ => vec![DEFAULT_SERVER.to_owned()],
    }
}

/// Downloads `<server>/<pdb>/<key>/<pdb>` into the cache; returns the cached path.
pub fn fetch(pdb_name: &str, key: &str, servers: &[String], cache: &Path) -> Result<PathBuf, String> {
    let dest = cache.join(pdb_name).join(key).join(pdb_name);
    if dest.exists() {
        return Ok(dest);
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .proxy(ureq::Proxy::try_from_env())
        .build()
        .into();
    let mut last = String::from("no symbol server configured");
    for s in servers {
        let url = format!("{}/{pdb_name}/{key}/{pdb_name}", s.trim_end_matches('/'));
        match agent.get(&url).header("User-Agent", "Microsoft-Symbol-Server/10.0.0.0").call() {
            Ok(mut resp) => {
                let mut bytes = Vec::new();
                resp.body_mut().as_reader().take(1 << 31).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                if bytes.starts_with(b"MSCF") {
                    last = format!("{url}: compressed (.pd_) symbols are not supported");
                    continue;
                }
                if let Some(dir) = dest.parent() {
                    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                }
                let tmp = dest.with_extension("part");
                fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
                fs::rename(&tmp, &dest).map_err(|e| e.to_string())?;
                return Ok(dest);
            }
            Err(ureq::Error::StatusCode(404)) => last = format!("{url}: not on this server (404)"),
            Err(e) => last = format!("{url}: {e}"),
        }
    }
    Err(last)
}

/// The `pdb_symbols` verb (blocking; the relay runs it on a blocking thread).
pub fn handle(req: &Map<String, Value>) -> Value {
    let max = req.get("max").and_then(Value::as_u64).unwrap_or(200_000).min(2_000_000) as usize;
    let want = req.get("key").and_then(Value::as_str).map(|k| k.trim().to_uppercase());
    let path = match req.get("path").and_then(Value::as_str) {
        Some(p) => PathBuf::from(p),
        None => {
            let (Some(name), Some(key)) = (req.get("pdb").and_then(Value::as_str), want.as_deref()) else {
                return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "pdb_symbols needs 'pdb' and 'key' (or 'path')" });
            };
            let name = name.rsplit(['\\', '/']).next().unwrap_or(name);
            if !plain(name) || !key.chars().all(|c| c.is_ascii_hexdigit()) || key.len() < 33 {
                return json!({ "type": "error", "code": 3002, "message": "bad arguments", "detail": "pdb must be a file name and key 32 hex digits + age" });
            }
            match fetch(name, key, &servers(req), &cache_dir()) {
                Ok(p) => p,
                Err(e) => return err(e),
            }
        }
    };
    let (key, guid, age) = match pdb_identity(&path) {
        Ok(x) => x,
        Err(e) => return err(format!("{}: {e}", path.display())),
    };
    if let Some(w) = &want {
        if *w != key {
            return err(format!("{} is {key}, the image expects {w}: a different build", path.display()));
        }
    }
    match read_symbols(&path, max) {
        Ok(syms) => json!({
            "type": "pdb_symbols_result", "success": true, "path": path.display().to_string(), "guid": guid, "age": age, "key": key,
            "count": syms.len(),
            "symbols": syms.iter().map(|(rva, name, kind)| json!({ "rva": rva, "name": name, "kind": kind })).collect::<Vec<_>>(),
        }),
        Err(e) => err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fix.pdb")
    }

    #[test]
    fn reads_the_lld_fixture() {
        let (key, guid, age) = pdb_identity(&fixture()).unwrap();
        // llvm-pdbutil dump -summary: GUID {E5F4837E-BE62-2C4A-4C4C-44205044422E}, age 1
        assert_eq!(guid, "E5F4837E-BE62-2C4A-4C4C-44205044422E");
        assert_eq!(age, 1);
        assert_eq!(key, "E5F4837EBE622C4A4C4C44205044422E1");
        let syms = read_symbols(&fixture(), 10_000).unwrap();
        let main = syms.iter().find(|s| s.1 == "mainCRTStartup").expect("mainCRTStartup");
        // publics: mainCRTStartup at 0001:0048 → .text (RVA 0x1000) + 0x30
        assert_eq!(main.0, 0x1030);
        assert_eq!(main.2, "function");
        assert!(syms.iter().any(|s| s.1 == "_tls_used"));
    }

    #[test]
    fn fetches_from_a_symbol_server_and_caches() {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = fs::read(fixture()).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut first = String::new();
            BufReader::new(&s).read_line(&mut first).unwrap();
            let ok = first.starts_with("GET /fix.pdb/E5F4837EBE622C4A4C4C44205044422E1/fix.pdb ");
            let status = if ok { "200 OK" } else { "404 Not Found" };
            write!(s, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", if ok { body.len() } else { 0 }).unwrap();
            if ok {
                s.write_all(&body).unwrap();
            }
            first
        });
        let cache = std::env::temp_dir().join(format!("echodebug-sym-{}", std::process::id()));
        let _ = fs::remove_dir_all(&cache);
        let p = fetch("fix.pdb", "E5F4837EBE622C4A4C4C44205044422E1", &[format!("http://127.0.0.1:{port}")], &cache).unwrap();
        assert!(server.join().unwrap().contains("/fix.pdb/E5F4837EBE622C4A4C4C44205044422E1/fix.pdb"));
        assert_eq!(p, cache.join("fix.pdb/E5F4837EBE622C4A4C4C44205044422E1/fix.pdb"));
        assert_eq!(fs::read(&p).unwrap(), fs::read(fixture()).unwrap());
        // second call is served from the cache (no server is listening any more)
        assert_eq!(fetch("fix.pdb", "E5F4837EBE622C4A4C4C44205044422E1", &[format!("http://127.0.0.1:{port}")], &cache).unwrap(), p);
        let _ = fs::remove_dir_all(&cache);
    }

    #[test]
    fn rejects_unsafe_names_and_other_builds() {
        // directory parts are cut off (".../x/../evil.pdb" becomes "evil.pdb"); a bare ".." is refused
        let r = handle(&match json!({ "pdb": "..", "key": "E5F4837EBE622C4A4C4C44205044422E1" }) { Value::Object(m) => m, _ => unreachable!() });
        assert_eq!(r["code"], 3002);
        let r = handle(&match json!({ "pdb": "fix.pdb", "key": "not-hex" }) { Value::Object(m) => m, _ => unreachable!() });
        assert_eq!(r["code"], 3002);
        let r = handle(&match json!({ "path": fixture().display().to_string(), "key": "00000000000000000000000000000000001" }) { Value::Object(m) => m, _ => unreachable!() });
        assert!(r["detail"].as_str().unwrap().contains("different build"), "{r}");
        let r = handle(&match json!({ "path": fixture().display().to_string() }) { Value::Object(m) => m, _ => unreachable!() });
        assert_eq!(r["success"], true, "{r}");
    }
}
