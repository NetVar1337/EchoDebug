//! Saved assistant conversations: one JSON file per conversation in
//! `<config>/assistant-conversations/`, readable only by the user (they hold code and data read
//! from the target). The UI owns the format; this checks ids and sizes and lists the files by the
//! `id`, `title`, `updated`, `provider`, `model` and `count` fields at their top level.

use std::fs;
use std::io;
use std::path::PathBuf;

use serde_json::{json, Value};

use super::creds::write_private;

pub const MAX_BYTES: usize = 32 * 1024 * 1024;

pub struct Convs {
    pub dir: PathBuf,
}

impl Default for Convs {
    fn default() -> Self {
        Convs { dir: crate::auth::config_dir().join("assistant-conversations") }
    }
}

pub fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Convs {
    fn path(&self, id: &str) -> Result<PathBuf, String> {
        if !valid_id(id) {
            return Err(format!("conversation id '{id}' is not valid"));
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    pub fn save(&self, id: &str, body: &str) -> Result<(), String> {
        let path = self.path(id)?;
        if body.len() > MAX_BYTES {
            return Err(format!("conversation is too large to save ({} MiB)", body.len() / (1024 * 1024)));
        }
        let v: Value = serde_json::from_str(body).map_err(|e| format!("conversation is not JSON: {e}"))?;
        if v.get("id").and_then(Value::as_str) != Some(id) {
            return Err("conversation id does not match".into());
        }
        fs::create_dir_all(&self.dir).map_err(|e| format!("create {}: {e}", self.dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
        }
        // write then rename, so a crash never leaves half a conversation
        let tmp = self.dir.join(format!(".{id}.tmp"));
        write_private(&tmp, body.as_bytes()).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        fs::rename(&tmp, &path).map_err(|e| format!("save {}: {e}", path.display()))
    }

    pub fn load(&self, id: &str) -> Result<String, String> {
        let path = self.path(id)?;
        fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        match fs::remove_file(self.path(id)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Every saved conversation's summary, newest first. Unreadable files are skipped.
    pub fn list(&self) -> Vec<Value> {
        let Ok(rd) = fs::read_dir(&self.dir) else { return vec![] };
        let mut out: Vec<Value> = rd
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().into_string().ok()?;
                let id = name.strip_suffix(".json")?;
                if !valid_id(id) {
                    return None;
                }
                let v: Value = serde_json::from_str(&fs::read_to_string(e.path()).ok()?).ok()?;
                (v.get("id").and_then(Value::as_str) == Some(id)).then(|| {
                    json!({ "id": id, "title": v.get("title").cloned().unwrap_or(json!("")), "updated": v.get("updated").cloned().unwrap_or(json!(0)),
                        "provider": v.get("provider").cloned().unwrap_or(Value::Null), "model": v.get("model").cloned().unwrap_or(Value::Null),
                        "count": v.get("count").cloned().unwrap_or(json!(0)) })
                })
            })
            .collect();
        out.sort_by(|a, b| b["updated"].as_f64().unwrap_or(0.0).total_cmp(&a["updated"].as_f64().unwrap_or(0.0)));
        out
    }

    pub fn path_display(&self) -> String {
        self.dir.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_lists_loads_and_deletes() {
        let c = Convs { dir: std::env::temp_dir().join(format!("echodebug-convs-{}", std::process::id())) };
        let _ = fs::remove_dir_all(&c.dir);
        assert!(c.list().is_empty());
        c.save("a1", r#"{"id":"a1","title":"First","updated":10,"provider":"anthropic","model":"claude-opus-5-5","count":2,"entries":[]}"#).unwrap();
        c.save("b2", r#"{"id":"b2","title":"Second","updated":20,"count":1}"#).unwrap();
        c.save("a1", r#"{"id":"a1","title":"First (renamed)","updated":30,"count":3}"#).unwrap();
        let l = c.list();
        assert_eq!(l.iter().map(|x| x["title"].as_str().unwrap()).collect::<Vec<_>>(), ["First (renamed)", "Second"]);
        assert_eq!(l[0]["count"], 3);
        assert!(c.load("b2").unwrap().contains("Second"));
        assert!(c.save("../x", "{}").is_err());
        assert!(c.save("c3", "not json").is_err());
        assert!(c.save("c3", r#"{"id":"other"}"#).is_err());
        assert!(c.load("nope").is_err());
        c.delete("a1").unwrap();
        c.delete("a1").unwrap();
        assert_eq!(c.list().len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(c.dir.join("b2.json")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = fs::remove_dir_all(&c.dir);
    }
}
