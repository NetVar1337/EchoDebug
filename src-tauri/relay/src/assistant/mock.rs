//! A tiny local HTTP server for the assistant's tests: routes by method + path prefix, records
//! every request (request line, headers, body) and answers with `Connection: close`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

pub struct Route {
    /// "POST /v1/messages" (prefix of "METHOD path?query")
    pub prefix: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub fn route(prefix: &str, status: u16, content_type: &str, body: &str) -> Route {
    Route { prefix: prefix.into(), status, headers: vec![("Content-Type".into(), content_type.into())], body: body.into() }
}

#[derive(Clone, Debug)]
pub struct Seen {
    pub line: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub struct Mock {
    pub base: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

/// Serves `routes` until the test ends (the thread is detached). Unknown paths get a 404.
pub fn serve(routes: Vec<Route>) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            if r.read_line(&mut line).is_err() {
                continue;
            }
            let line = line.trim_end().to_owned();
            let mut headers = Vec::new();
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap_or(0) == 0 || h.trim_end().is_empty() {
                    break;
                }
                if let Some((k, v)) = h.trim_end().split_once(':') {
                    headers.push((k.trim().to_owned(), v.trim().to_owned()));
                }
            }
            let len: usize = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
            let mut body = vec![0u8; len];
            let _ = r.read_exact(&mut body);
            let seen = Seen { line: line.clone(), headers, body: String::from_utf8_lossy(&body).into_owned() };
            log.lock().unwrap().push(seen);
            let rt = routes.iter().find(|rt| line.starts_with(&rt.prefix));
            let (status, hs, body) = match rt {
                Some(rt) => (rt.status, rt.headers.clone(), rt.body.clone()),
                None => (404, vec![("Content-Type".to_owned(), "application/json".to_owned())], r#"{"error":{"message":"no such route"}}"#.to_owned()),
            };
            let mut head = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
            for (k, v) in hs {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
            head.push_str("\r\n");
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(body.as_bytes());
        }
    });
    Mock { base, seen }
}
