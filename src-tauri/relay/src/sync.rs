//! Live sync with IDA, Ghidra and Binary Ninja (ret-sync style, both ways).
//!
//! Disassembler plugins (`integrations/`) connect to `/sync` with the relay token and speak small
//! JSON frames: `hello`, `cursor`, `name`, `comment`, `modules`, `ping`. Locations always travel as
//! **module name + RVA**, so a rebased database (IDA/Ghidra/Binja image base ≠ the live load
//! address) maps onto the live module wherever ASLR put it: each side adds its own base.
//!
//! The app talks to the hub over its `/client` socket with the relay-local verbs `sync_status`
//! (also the read-only MCP tool), `sync_config`, `sync_send` and `sync_log`, and receives
//! `{"type":"sync_event", ...}` broadcasts.
//!
//! Rules kept here (unit-tested below):
//! - per-direction toggles (`*_in`: disassembler → EchoDebug, `*_out`: EchoDebug → disassemblers;
//!   tool-to-tool forwarding counts as `out`);
//! - a module map (disassembler module name → live module name) for renamed or dumped files;
//! - names and comments: **last writer wins**; a value replacing a different value from another
//!   source is logged as a conflict; a write equal to the current value is dropped (this is what
//!   stops echo loops between the app and the plugins);
//! - a cursor equal to the last cursor is dropped for the same reason.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde_json::{json, Map, Value};
use tokio::sync::mpsc;

/// Bumped on incompatible changes of the `/sync` frames.
pub const PROTOCOL: u32 = 1;
pub const APP: &str = "echodebug";
const LOG_CAP: usize = 300;
const MAX_NAME: usize = 512;
const MAX_COMMENT: usize = 4096;
const MAX_DECLS: usize = 1 << 20;

/// Which way each kind of event may travel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directions {
    pub cursor_in: bool,
    pub cursor_out: bool,
    pub names_in: bool,
    pub names_out: bool,
    pub comments_in: bool,
    pub comments_out: bool,
    pub types_out: bool,
}

impl Default for Directions {
    fn default() -> Self {
        Directions { cursor_in: true, cursor_out: true, names_in: true, names_out: true, comments_in: true, comments_out: true, types_out: true }
    }
}

const DIRECTION_KEYS: [&str; 7] = ["cursor_in", "cursor_out", "names_in", "names_out", "comments_in", "comments_out", "types_out"];

impl Directions {
    fn get(&self, k: &str) -> bool {
        match k {
            "cursor_in" => self.cursor_in,
            "cursor_out" => self.cursor_out,
            "names_in" => self.names_in,
            "names_out" => self.names_out,
            "comments_in" => self.comments_in,
            "comments_out" => self.comments_out,
            _ => self.types_out,
        }
    }
    fn set(&mut self, k: &str, v: bool) {
        match k {
            "cursor_in" => self.cursor_in = v,
            "cursor_out" => self.cursor_out = v,
            "names_in" => self.names_in = v,
            "names_out" => self.names_out = v,
            "comments_in" => self.comments_in = v,
            "comments_out" => self.comments_out = v,
            _ => self.types_out = v,
        }
    }
    pub fn to_json(&self) -> Value {
        Value::Object(DIRECTION_KEYS.iter().map(|k| ((*k).to_owned(), Value::Bool(self.get(k)))).collect())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolModule {
    pub name: String,
    /// the database's image base (informational: the plugin does the arithmetic)
    pub base: Option<String>,
    pub size: Option<u64>,
}

pub struct Peer {
    pub id: u64,
    pub tool: String,
    pub version: String,
    /// free text from the plugin: the database / file it has open
    pub file: String,
    pub modules: Vec<ToolModule>,
    pub connected_at: u64,
    pub last_seen: u64,
    pub tx: mpsc::UnboundedSender<String>,
}

/// The current value of a name or comment and who wrote it.
#[derive(Clone, Debug)]
pub struct Mark {
    pub value: String,
    pub source: String,
    pub ts: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cursor {
    module: String,
    rva: u64,
    from: String,
    ts: u64,
}

/// Where an output frame goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// every `/client` socket (as a broadcast)
    App,
    Peer(u64),
}

pub type Out = Vec<(Dest, Value)>;

#[derive(Default)]
pub struct Hub {
    peers: BTreeMap<u64, Peer>,
    dirs: Directions,
    /// lowercased disassembler module name → live module name
    map: BTreeMap<String, String>,
    marks: HashMap<(String, u64, &'static str), Mark>,
    cursor: Option<Cursor>,
    log: VecDeque<Value>,
    log_seq: u64,
}

/// `"0x1a2b"`, `"1a2b"` (hex) or a JSON number.
pub fn parse_rva(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => {
            let s = s.trim();
            let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
            if h.is_empty() || h.len() > 16 {
                return None;
            }
            u64::from_str_radix(h, 16).ok()
        }
        _ => None,
    }
}

fn hex(v: u64) -> String {
    format!("{v:#x}")
}

fn str_field<'a>(m: &'a Map<String, Value>, k: &str) -> &'a str {
    m.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn clean_module(s: &str) -> Option<String> {
    // a path from the plugin: keep the file name (IDA's root filename, Ghidra's program name)
    let name = s.rsplit(['/', '\\']).next().unwrap_or(s).trim();
    (!name.is_empty() && name.len() <= 260).then(|| name.to_owned())
}

/// Disassembler names may not hold control characters; comments may hold newlines.
fn clean_text(s: &str, max: usize, multiline: bool) -> Result<String, String> {
    if s.len() > max {
        return Err(format!("text longer than {max} bytes"));
    }
    if s.chars().any(|c| c.is_control() && !(multiline && (c == '\n' || c == '\t' || c == '\r'))) {
        return Err("control characters are not allowed".into());
    }
    Ok(if multiline { s.replace("\r\n", "\n") } else { s.trim().to_owned() })
}

fn modules_from(v: Option<&Value>) -> Vec<ToolModule> {
    let Some(Value::Array(a)) = v else { return Vec::new() };
    a.iter()
        .filter_map(|m| {
            let (name, base, size) = match m {
                Value::String(s) => (s.as_str(), None, None),
                Value::Object(o) => (
                    str_field(o, "name"),
                    o.get("base").and_then(parse_rva).map(hex),
                    o.get("size").and_then(parse_rva),
                ),
                _ => return None,
            };
            Some(ToolModule { name: clean_module(name)?, base, size })
        })
        .take(64)
        .collect()
}

pub enum Applied {
    /// same value as the current one: nothing to do
    Duplicate,
    /// stored; `Some` when it replaced a different value written by another side
    Stored(Option<Mark>),
}

impl Hub {
    pub fn directions(&self) -> &Directions {
        &self.dirs
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// The live module a disassembler's module name stands for.
    pub fn live_name(&self, tool_module: &str) -> String {
        self.map.get(&tool_module.to_lowercase()).cloned().unwrap_or_else(|| tool_module.to_owned())
    }

    /// The module name `peer` knows for `live`: one of its modules that maps onto `live`. A peer
    /// that reported no modules gets the live name (it decides itself).
    fn tool_name_for(&self, peer: &Peer, live: &str) -> Option<String> {
        if peer.modules.is_empty() {
            return Some(live.to_owned());
        }
        peer.modules.iter().find(|m| self.live_name(&m.name).eq_ignore_ascii_case(live)).map(|m| m.name.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn push_log(&mut self, now: u64, kind: &str, dir: &str, from: &str, module: &str, rva: Option<u64>, text: String) -> Value {
        self.log_seq += 1;
        let e = json!({ "seq": self.log_seq, "ts": now, "kind": kind, "dir": dir, "from": from, "module": module, "rva": rva.map(hex), "text": text });
        if self.log.len() >= LOG_CAP {
            self.log.pop_front();
        }
        self.log.push_back(e.clone());
        e
    }

    #[allow(clippy::too_many_arguments)]
    fn log_out(&mut self, out: &mut Out, now: u64, kind: &str, dir: &str, from: &str, module: &str, rva: Option<u64>, text: String) {
        let e = self.push_log(now, kind, dir, from, module, rva, text);
        out.push((Dest::App, json!({ "type": "sync_event", "kind": "log", "entry": e })));
    }

    /// Last writer wins: stores `value` for (module, rva, kind) unless it is already the value.
    pub fn apply_mark(&mut self, module: &str, rva: u64, kind: &'static str, value: &str, source: &str, now: u64) -> Applied {
        let key = (module.to_lowercase(), rva, kind);
        let prev = self.marks.get(&key).cloned();
        if prev.as_ref().is_some_and(|p| p.value == value) {
            return Applied::Duplicate;
        }
        self.marks.insert(key, Mark { value: value.to_owned(), source: source.to_owned(), ts: now });
        Applied::Stored(prev.filter(|p| p.source != source && !p.value.is_empty()))
    }

    // ---- peers ----------------------------------------------------------------------------------

    /// Registers a peer from its `hello`; returns the `hello_result` and the app broadcast.
    pub fn hello(&mut self, id: u64, msg: &Map<String, Value>, tx: mpsc::UnboundedSender<String>, now: u64) -> (Value, Out) {
        let tool = match str_field(msg, "tool").to_lowercase() {
            t if t.is_empty() => "unknown".to_owned(),
            t => t.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(32).collect(),
        };
        let peer = Peer {
            id,
            tool: tool.clone(),
            version: str_field(msg, "version").chars().take(64).collect(),
            file: str_field(msg, "file").chars().take(260).collect(),
            modules: modules_from(msg.get("modules")),
            connected_at: now,
            last_seen: now,
            tx,
        };
        let mods = peer.modules.iter().map(|m| m.name.clone()).collect::<Vec<_>>().join(", ");
        self.peers.insert(id, peer);
        let mut out = Vec::new();
        self.log_out(&mut out, now, "peer", "info", &tool, "", None, format!("{tool} connected ({})", if mods.is_empty() { "no modules".into() } else { mods }));
        out.push((Dest::App, json!({ "type": "sync_event", "kind": "peers" })));
        let reply = json!({ "type": "hello_result", "success": true, "peer": id, "protocol": PROTOCOL, "directions": self.dirs.to_json() });
        (reply, out)
    }

    pub fn remove(&mut self, id: u64, now: u64) -> Out {
        let Some(p) = self.peers.remove(&id) else { return Vec::new() };
        let mut out = Vec::new();
        self.log_out(&mut out, now, "peer", "info", &p.tool, "", None, format!("{} disconnected", p.tool));
        out.push((Dest::App, json!({ "type": "sync_event", "kind": "peers" })));
        out
    }

    pub fn peer_sender(&self, id: u64) -> Option<mpsc::UnboundedSender<String>> {
        self.peers.get(&id).map(|p| p.tx.clone())
    }

    /// One frame from a disassembler plugin. Replies (pong, errors) go to `Dest::Peer(id)`.
    pub fn from_peer(&mut self, id: u64, msg: &Map<String, Value>, now: u64) -> Out {
        let Some(peer) = self.peers.get_mut(&id) else { return Vec::new() };
        peer.last_seen = now;
        let tool = peer.tool.clone();
        let ty = str_field(msg, "type");
        let err = |text: String| vec![(Dest::Peer(id), json!({ "type": "error", "message": text, "for": ty }))];
        match ty {
            "ping" => vec![(Dest::Peer(id), json!({ "type": "pong" }))],
            "modules" => {
                let mods = modules_from(msg.get("modules"));
                if let Some(p) = self.peers.get_mut(&id) {
                    p.modules = mods;
                }
                vec![(Dest::App, json!({ "type": "sync_event", "kind": "peers" }))]
            }
            "cursor" | "name" | "comment" => {
                let Some(module) = clean_module(str_field(msg, "module")) else { return err("missing module".into()) };
                let Some(rva) = msg.get("rva").and_then(parse_rva) else { return err("missing or bad rva".into()) };
                let live = self.live_name(&module);
                match ty {
                    "cursor" => self.cursor(&live, rva, &tool, Some(id), now),
                    "name" => match clean_text(str_field(msg, "name"), MAX_NAME, false) {
                        Ok(v) => self.mark(&live, rva, "name", &v, &tool, Some(id), now),
                        Err(e) => err(e),
                    },
                    _ => match clean_text(str_field(msg, "comment"), MAX_COMMENT, true) {
                        Ok(v) => self.mark(&live, rva, "comment", &v, &tool, Some(id), now),
                        Err(e) => err(e),
                    },
                }
            }
            "" => err("missing type".into()),
            other => err(format!("unknown sync frame '{other}'")),
        }
    }

    /// Frames for every peer except `except` that knows `live`.
    fn to_peers(&self, except: Option<u64>, live: &str, frame: impl Fn(&str) -> Value) -> Out {
        self.peers
            .values()
            .filter(|p| Some(p.id) != except)
            .filter_map(|p| self.tool_name_for(p, live).map(|name| (Dest::Peer(p.id), frame(&name))))
            .collect()
    }

    fn cursor(&mut self, live: &str, rva: u64, from: &str, origin: Option<u64>, now: u64) -> Out {
        if self.cursor.as_ref().is_some_and(|c| c.module.eq_ignore_ascii_case(live) && c.rva == rva) {
            return Vec::new();
        }
        self.cursor = Some(Cursor { module: live.to_owned(), rva, from: from.to_owned(), ts: now });
        let mut out = Vec::new();
        if origin.is_some() && self.dirs.cursor_in {
            out.push((Dest::App, json!({ "type": "sync_event", "kind": "cursor", "module": live, "rva": hex(rva), "from": from })));
        }
        if self.dirs.cursor_out {
            out.extend(self.to_peers(origin, live, |m| json!({ "type": "cursor", "module": m, "rva": hex(rva), "from": from })));
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn mark(&mut self, live: &str, rva: u64, kind: &'static str, value: &str, from: &str, origin: Option<u64>, now: u64) -> Out {
        let (din, dout) = if kind == "name" { (self.dirs.names_in, self.dirs.names_out) } else { (self.dirs.comments_in, self.dirs.comments_out) };
        let mut out = Vec::new();
        let conflict = match self.apply_mark(live, rva, kind, value, from, now) {
            Applied::Duplicate => return out,
            Applied::Stored(c) => c,
        };
        let shown = if value.is_empty() { "removed".to_owned() } else { format!("= {}", truncate(value, 120)) };
        let dir = if origin.is_some() { "in" } else { "out" };
        self.log_out(&mut out, now, kind, dir, from, live, Some(rva), format!("{kind} {shown}"));
        if let Some(prev) = conflict {
            self.log_out(
                &mut out,
                now,
                kind,
                "conflict",
                from,
                live,
                Some(rva),
                format!("{kind} '{}' from {} replaced by '{}' from {from} (last writer wins)", truncate(&prev.value, 60), prev.source, truncate(value, 60)),
            );
        }
        if origin.is_some() && din {
            out.push((Dest::App, json!({ "type": "sync_event", "kind": kind, "module": live, "rva": hex(rva), kind: value, "from": from })));
        }
        if dout {
            out.extend(self.to_peers(origin, live, |m| json!({ "type": kind, "module": m, "rva": hex(rva), kind: value, "from": from })));
        }
        out
    }

    // ---- the app ----------------------------------------------------------------------------------

    /// `sync_send` from the app: `{kind: cursor|name|comment|types, module, rva, name|comment|decls}`.
    /// Returns the frames to deliver and the number of peers reached.
    pub fn from_app(&mut self, req: &Map<String, Value>, now: u64) -> Result<(Out, usize), String> {
        let kind = str_field(req, "kind");
        let out = match kind {
            "types" => {
                let decls = str_field(req, "decls");
                if decls.trim().is_empty() {
                    return Err("decls is empty".into());
                }
                if decls.len() > MAX_DECLS {
                    return Err("decls is larger than 1 MiB".into());
                }
                let names: Vec<Value> = req.get("names").and_then(Value::as_array).cloned().unwrap_or_default();
                let mut out = Vec::new();
                if !self.dirs.types_out {
                    self.log_out(&mut out, now, "types", "info", APP, "", None, "types not pushed: types out is off".into());
                    return Ok((out, 0));
                }
                let frame = json!({ "type": "types", "decls": decls, "names": names, "from": APP });
                out.extend(self.peers.keys().map(|id| (Dest::Peer(*id), frame.clone())));
                let n = out.len();
                self.log_out(&mut out, now, "types", "out", APP, "", None, format!("{} type(s) pushed to {n} tool(s)", names.len()));
                out
            }
            "cursor" | "name" | "comment" => {
                let module = clean_module(str_field(req, "module")).ok_or("missing module")?;
                let rva = req.get("rva").and_then(parse_rva).ok_or("missing or bad rva")?;
                match kind {
                    "cursor" => self.cursor(&module, rva, APP, None, now),
                    "name" => {
                        let v = clean_text(str_field(req, "name"), MAX_NAME, false)?;
                        self.mark(&module, rva, "name", &v, APP, None, now)
                    }
                    _ => {
                        let v = clean_text(str_field(req, "comment"), MAX_COMMENT, true)?;
                        self.mark(&module, rva, "comment", &v, APP, None, now)
                    }
                }
            }
            other => return Err(format!("unknown sync kind '{other}' (cursor, name, comment, types)")),
        };
        let peers = out.iter().filter(|(d, _)| matches!(d, Dest::Peer(_))).count();
        Ok((out, peers))
    }

    /// `sync_config {directions?: {cursor_in: bool, ...}, map?: {toolModule: liveModule}}`;
    /// omitted fields keep their value, an empty live name removes a mapping.
    pub fn configure(&mut self, req: &Map<String, Value>) -> Result<Out, String> {
        if let Some(d) = req.get("directions") {
            let Value::Object(d) = d else { return Err("directions must be an object".into()) };
            for (k, v) in d {
                if !DIRECTION_KEYS.contains(&k.as_str()) {
                    return Err(format!("unknown direction '{k}' ({})", DIRECTION_KEYS.join(", ")));
                }
                self.dirs.set(k, v.as_bool().ok_or_else(|| format!("direction '{k}' must be a boolean"))?);
            }
        }
        if let Some(m) = req.get("map") {
            let Value::Object(m) = m else { return Err("map must be an object".into()) };
            if req.get("replace_map").and_then(Value::as_bool).unwrap_or(false) {
                self.map.clear();
            }
            for (k, v) in m {
                let key = clean_module(k).ok_or("empty module name in map")?.to_lowercase();
                match v.as_str().and_then(clean_module) {
                    Some(live) => self.map.insert(key, live),
                    None => self.map.remove(&key),
                };
            }
        }
        let cfg = json!({ "directions": self.dirs.to_json(), "map": self.map });
        let mut out: Out = self.peers.keys().map(|id| (Dest::Peer(*id), json!({ "type": "config", "directions": self.dirs.to_json() }))).collect();
        out.push((Dest::App, json!({ "type": "sync_event", "kind": "config", "config": cfg })));
        Ok(out)
    }

    /// `sync_log {text, kind?}`: a note from the app (e.g. a name it overwrote locally).
    pub fn note(&mut self, req: &Map<String, Value>, now: u64) -> Out {
        let text = truncate(str_field(req, "text"), 400);
        let kind = match str_field(req, "kind") {
            "name" => "name",
            "comment" => "comment",
            _ => "info",
        };
        let dir = if str_field(req, "dir") == "conflict" { "conflict" } else { "info" };
        let module = clean_module(str_field(req, "module")).unwrap_or_default();
        let rva = req.get("rva").and_then(parse_rva);
        let mut out = Vec::new();
        self.log_out(&mut out, now, kind, dir, APP, &module, rva, text);
        out
    }

    /// Everything the Sync panel and the `sync_status` MCP tool show. `log_limit` caps the log.
    pub fn status(&self, log_limit: usize) -> Value {
        let peers: Vec<Value> = self
            .peers
            .values()
            .map(|p| {
                json!({
                    "id": p.id, "tool": p.tool, "version": p.version, "file": p.file,
                    "modules": p.modules.iter().map(|m| json!({ "name": m.name, "base": m.base, "size": m.size, "live": self.live_name(&m.name) })).collect::<Vec<_>>(),
                    "connected_at": p.connected_at, "last_seen": p.last_seen,
                })
            })
            .collect();
        let skip = self.log.len().saturating_sub(log_limit);
        json!({
            "protocol": PROTOCOL,
            "peers": peers,
            "directions": self.dirs.to_json(),
            "map": self.map,
            "cursor": self.cursor.as_ref().map(|c| json!({ "module": c.module, "rva": hex(c.rva), "from": c.from, "ts": c.ts })),
            "marks": self.marks.len(),
            "log": self.log.iter().skip(skip).cloned().collect::<Vec<_>>(),
        })
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// ---- relay glue: the /sync socket and the app's sync_* verbs --------------------------------------

impl crate::Relay {
    fn sync_hub(&self) -> std::sync::MutexGuard<'_, Hub> {
        self.0.sync.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sync_deliver(&self, out: Out) {
        for (dest, frame) in out {
            match dest {
                Dest::App => self.emit(frame),
                Dest::Peer(id) => {
                    let tx = self.sync_hub().peer_sender(id);
                    if let Some(tx) = tx {
                        let _ = tx.send(frame.to_string());
                    }
                }
            }
        }
    }

    /// The relay-local verbs `sync_status`, `sync_config`, `sync_send`, `sync_log`.
    pub(crate) fn sync_verb(&self, verb: &str, req: &Map<String, Value>) -> Value {
        let now = now_ms();
        let ty = format!("{verb}_result");
        let fail = |e: String| json!({ "type": "error", "code": 2000, "message": e });
        match verb {
            "sync_status" => {
                let limit = req.get("log_limit").and_then(Value::as_u64).unwrap_or(100).min(LOG_CAP as u64) as usize;
                let mut v = self.sync_hub().status(limit);
                v["type"] = json!(ty);
                v["success"] = json!(true);
                v
            }
            "sync_config" => {
                let r = self.sync_hub().configure(req);
                match r {
                    Ok(out) => {
                        self.sync_deliver(out);
                        let mut v = self.sync_hub().status(0);
                        v["type"] = json!(ty);
                        v["success"] = json!(true);
                        v
                    }
                    Err(e) => fail(e),
                }
            }
            "sync_send" => {
                let r = self.sync_hub().from_app(req, now);
                match r {
                    Ok((out, peers)) => {
                        self.sync_deliver(out);
                        json!({ "type": ty, "success": true, "peers": peers })
                    }
                    Err(e) => fail(e),
                }
            }
            _ => {
                let out = self.sync_hub().note(req, now);
                self.sync_deliver(out);
                json!({ "type": ty, "success": true })
            }
        }
    }

    /// One disassembler plugin on `/sync`: `hello` first, then cursor / name / comment frames.
    pub(crate) async fn sync_socket(self, socket: axum::extract::ws::WebSocket) {
        use axum::extract::ws::Message;
        use futures_util::{SinkExt, StreamExt};
        let id = self.next_id();
        let (mut sink, mut stream) = socket.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let writer = tokio::spawn(async move {
            while let Some(text) = rx.recv().await {
                if sink.send(Message::Text(text.into())).await.is_err() {
                    break;
                }
            }
            let _ = sink.send(Message::Close(None)).await;
        });
        let mut registered = false;
        loop {
            let next = tokio::time::timeout(std::time::Duration::from_secs(if registered { 3600 } else { 10 }), stream.next()).await;
            let text = match next {
                Ok(Some(Ok(Message::Text(t)))) => t.as_str().to_owned(),
                Ok(Some(Ok(Message::Binary(b)))) => match String::from_utf8(b.to_vec()) {
                    Ok(t) => t,
                    Err(_) => continue,
                },
                Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => break,
                Ok(Some(Ok(_))) => continue,
                // no hello in time, or an hour of silence (plugins ping every 15 s)
                Err(_) => break,
            };
            let Ok(Value::Object(msg)) = serde_json::from_str::<Value>(&text) else {
                let _ = tx.send(json!({ "type": "error", "message": "frames are JSON objects" }).to_string());
                continue;
            };
            if msg.get("type").and_then(Value::as_str) == Some("hello") {
                if registered {
                    self.sync_hub().remove(id, now_ms());
                }
                let (reply, out) = self.sync_hub().hello(id, &msg, tx.clone(), now_ms());
                let _ = tx.send(reply.to_string());
                registered = true;
                self.sync_deliver(out);
                continue;
            }
            if !registered {
                let _ = tx.send(json!({ "type": "error", "message": "send hello first" }).to_string());
                continue;
            }
            let out = self.sync_hub().from_peer(id, &msg, now_ms());
            self.sync_deliver(out);
        }
        let out = self.sync_hub().remove(id, now_ms());
        self.sync_deliver(out);
        drop(tx);
        let _ = writer.await;
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut t: String = s.chars().take(max).collect();
    t.push('…');
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(v: Value) -> Map<String, Value> {
        let Value::Object(m) = v else { panic!("not an object") };
        m
    }

    fn peer(hub: &mut Hub, id: u64, tool: &str, modules: Value) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        hub.hello(id, &obj(json!({ "type": "hello", "tool": tool, "version": "9.1", "modules": modules })), tx, 1);
        rx
    }

    fn app_frames(out: &Out, kind: &str) -> Vec<Value> {
        out.iter().filter(|(d, f)| *d == Dest::App && f["kind"] == kind).map(|(_, f)| f.clone()).collect()
    }

    fn peer_frames(out: &Out, id: u64) -> Vec<Value> {
        out.iter().filter(|(d, _)| *d == Dest::Peer(id)).map(|(_, f)| f.clone()).collect()
    }

    #[test]
    fn rva_parsing() {
        assert_eq!(parse_rva(&json!("0x1A2b")), Some(0x1a2b));
        assert_eq!(parse_rva(&json!("ff")), Some(0xff));
        assert_eq!(parse_rva(&json!(4096)), Some(4096));
        assert_eq!(parse_rva(&json!("0x")), None);
        assert_eq!(parse_rva(&json!("xyz")), None);
        assert_eq!(parse_rva(&json!(-1)), None);
        assert_eq!(parse_rva(&json!("0x11112222333344445")), None);
    }

    #[test]
    fn cursor_routes_and_dedups() {
        let mut hub = Hub::default();
        let _a = peer(&mut hub, 1, "ida", json!([{ "name": "C:\\re\\game.exe", "base": "0x140000000" }]));
        let _b = peer(&mut hub, 2, "ghidra", json!(["game.exe"]));
        let out = hub.from_peer(1, &obj(json!({ "type": "cursor", "module": "game.exe", "rva": "0x1234" })), 2);
        let app = app_frames(&out, "cursor");
        assert_eq!(app.len(), 1);
        assert_eq!(app[0]["module"], "game.exe");
        assert_eq!(app[0]["rva"], "0x1234");
        assert_eq!(app[0]["from"], "ida");
        assert!(peer_frames(&out, 1).is_empty(), "never echoed to the sender");
        assert_eq!(peer_frames(&out, 2)[0]["type"], "cursor");
        // the app follows, Ghidra jumps and reports the same place: dropped
        assert!(hub.from_app(&obj(json!({ "kind": "cursor", "module": "game.exe", "rva": 0x1234 })), 3).unwrap().0.is_empty());
        assert!(hub.from_peer(2, &obj(json!({ "type": "cursor", "module": "game.exe", "rva": "0x1234" })), 3).is_empty());
        // the app moves: both tools follow
        let (out, n) = hub.from_app(&obj(json!({ "kind": "cursor", "module": "GAME.EXE", "rva": "0x2000" })), 4).unwrap();
        assert_eq!(n, 2);
        assert!(app_frames(&out, "cursor").is_empty(), "the app is not told about its own cursor");
    }

    #[test]
    fn directions_gate_each_way() {
        let mut hub = Hub::default();
        let _a = peer(&mut hub, 1, "ida", json!(["game.exe"]));
        hub.configure(&obj(json!({ "directions": { "cursor_in": false, "names_out": false } }))).unwrap();
        let out = hub.from_peer(1, &obj(json!({ "type": "cursor", "module": "game.exe", "rva": 16 })), 2);
        assert!(app_frames(&out, "cursor").is_empty());
        let (out, n) = hub.from_app(&obj(json!({ "kind": "name", "module": "game.exe", "rva": 16, "name": "main" })), 3).unwrap();
        assert_eq!(n, 0, "names out is off");
        assert_eq!(app_frames(&out, "log").len(), 1, "still logged");
        assert!(hub.configure(&obj(json!({ "directions": { "bogus": true } }))).is_err());
        assert!(hub.configure(&obj(json!({ "directions": { "names_in": "yes" } }))).is_err());
        assert_eq!(hub.status(10)["directions"]["cursor_in"], false);
        hub.configure(&obj(json!({ "directions": { "types_out": false } }))).unwrap();
        let (_, n) = hub.from_app(&obj(json!({ "kind": "types", "decls": "struct A { int x; };", "names": ["A"] })), 4).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn last_writer_wins_and_conflicts_are_logged() {
        let mut hub = Hub::default();
        let _a = peer(&mut hub, 1, "ida", json!(["game.exe"]));
        let _b = peer(&mut hub, 2, "binja", json!(["game.exe"]));
        let out = hub.from_peer(1, &obj(json!({ "type": "name", "module": "game.exe", "rva": "0x10", "name": "init" })), 2);
        assert_eq!(app_frames(&out, "name")[0]["name"], "init");
        assert_eq!(peer_frames(&out, 2)[0]["name"], "init");
        // the app writes something else: wins, conflict logged, both tools get it
        let (out, n) = hub.from_app(&obj(json!({ "kind": "name", "module": "game.exe", "rva": "0x10", "name": "game_init" })), 3).unwrap();
        assert_eq!(n, 2);
        let logs = app_frames(&out, "log");
        assert!(logs.iter().any(|l| l["entry"]["dir"] == "conflict" && l["entry"]["text"].as_str().unwrap().contains("last writer wins")), "{logs:?}");
        // IDA re-reports the value it just received: duplicate, nothing happens
        assert!(hub.from_peer(1, &obj(json!({ "type": "name", "module": "game.exe", "rva": "0x10", "name": "game_init" })), 4).is_empty());
        // the same source changing its own value is not a conflict
        let (out, _) = hub.from_app(&obj(json!({ "kind": "name", "module": "game.exe", "rva": "0x10", "name": "game_init2" })), 5).unwrap();
        assert!(!app_frames(&out, "log").iter().any(|l| l["entry"]["dir"] == "conflict"));
        // comments keep newlines, names refuse control characters
        let out = hub.from_peer(2, &obj(json!({ "type": "comment", "module": "game.exe", "rva": "0x10", "comment": "a\r\nb" })), 6);
        assert_eq!(app_frames(&out, "comment")[0]["comment"], "a\nb");
        let out = hub.from_peer(2, &obj(json!({ "type": "name", "module": "game.exe", "rva": "0x10", "name": "a\nb" })), 7);
        assert_eq!(peer_frames(&out, 2)[0]["type"], "error");
        let st = hub.status(500);
        assert_eq!(st["marks"], 2);
        assert!(st["log"].as_array().unwrap().len() >= 5);
    }

    #[test]
    fn module_map_and_peer_filtering() {
        let mut hub = Hub::default();
        let _a = peer(&mut hub, 1, "ida", json!(["game_dump.exe"]));
        let _b = peer(&mut hub, 2, "ghidra", json!(["other.dll"]));
        let _c = peer(&mut hub, 3, "binja", json!([]));
        hub.configure(&obj(json!({ "map": { "game_dump.exe": "game.exe" } }))).unwrap();
        let out = hub.from_peer(1, &obj(json!({ "type": "cursor", "module": "game_dump.exe", "rva": 1 })), 2);
        assert_eq!(app_frames(&out, "cursor")[0]["module"], "game.exe", "mapped to the live module");
        assert!(peer_frames(&out, 2).is_empty(), "ghidra has another module open");
        assert_eq!(peer_frames(&out, 3)[0]["module"], "game.exe", "a peer without modules gets the live name");
        let (out, _) = hub.from_app(&obj(json!({ "kind": "cursor", "module": "game.exe", "rva": 2 })), 3).unwrap();
        assert_eq!(peer_frames(&out, 1)[0]["module"], "game_dump.exe", "translated back to IDA's name");
        let st = hub.status(0);
        assert_eq!(st["peers"][0]["modules"][0]["live"], "game.exe");
        assert_eq!(st["log"].as_array().unwrap().len(), 0);
        hub.configure(&obj(json!({ "map": { "game_dump.exe": "" } }))).unwrap();
        assert_eq!(hub.live_name("game_dump.exe"), "game_dump.exe");
        let out = hub.remove(1, 9);
        assert_eq!(app_frames(&out, "peers").len(), 1);
        assert_eq!(hub.peer_count(), 2);
    }

    #[test]
    fn bad_frames_get_errors() {
        let mut hub = Hub::default();
        let _a = peer(&mut hub, 1, "ida", json!([]));
        for f in [json!({ "type": "cursor", "rva": 1 }), json!({ "type": "cursor", "module": "a", "rva": "zz" }), json!({ "type": "nope" }), json!({})] {
            let out = hub.from_peer(1, &obj(f.clone()), 2);
            assert_eq!(out.len(), 1, "{f}");
            assert_eq!(out[0].1["type"], "error");
        }
        assert_eq!(hub.from_peer(1, &obj(json!({ "type": "ping" })), 2)[0].1["type"], "pong");
        assert!(hub.from_peer(99, &obj(json!({ "type": "ping" })), 2).is_empty(), "unknown peer");
        assert!(hub.from_app(&obj(json!({ "kind": "warp" })), 2).is_err());
        assert!(hub.from_app(&obj(json!({ "kind": "types", "decls": " " })), 2).is_err());
        assert!(hub.from_app(&obj(json!({ "kind": "name", "module": "a", "rva": 1, "name": "x".repeat(600) })), 2).is_err());
    }
}
