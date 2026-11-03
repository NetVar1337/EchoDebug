//! OpenRouter's OAuth PKCE sign-in for apps (https://openrouter.ai/docs, "OAuth PKCE").
//!
//! 1. [`begin`] makes a verifier, its S256 challenge and a `state`, binds a loopback listener and
//!    returns `https://openrouter.ai/auth?callback_url=http://127.0.0.1:<port>/callback&…` for the
//!    app to open in the user's browser.
//! 2. [`Pending::wait`] accepts the browser's redirect to `/callback?code=…&state=…` (anything else
//!    gets a 404), answers with a short page and returns the code.
//! 3. [`exchange`] POSTs `{code, code_verifier, code_challenge_method}` to
//!    `https://openrouter.ai/api/v1/auth/keys` and returns the user-controlled API key, which is
//!    stored like any other credential (it uses the user's own OpenRouter credits).
//!
//! This is OpenRouter's documented flow for third-party apps; no other product's OAuth client is
//! used for anything.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const AUTH_URL: &str = "https://openrouter.ai/auth";
pub const EXCHANGE_URL: &str = "https://openrouter.ai/api/v1/auth/keys";

/// base64url without padding (RFC 7636 appendix A)
pub fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        let chars = c.len() + 1;
        for i in 0..chars {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// S256 challenge of a verifier.
pub fn challenge(verifier: &str) -> String {
    b64url(&Sha256::digest(verifier.as_bytes()))
}

fn random(n: usize) -> Result<String, String> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).map_err(|e| e.to_string())?;
    Ok(b64url(&b))
}

/// A fresh verifier (43 characters from 32 random bytes, within RFC 7636's 43-128).
pub fn verifier() -> Result<String, String> {
    random(32)
}

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn unpct(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub fn auth_url(callback: &str, challenge: &str, state: &str) -> String {
    format!("{AUTH_URL}?callback_url={}&code_challenge={challenge}&code_challenge_method=S256&state={state}&key_label=EchoDebug", pct(callback))
}

/// What the browser's request to the loopback listener means.
#[derive(Debug, PartialEq, Eq)]
pub enum Callback {
    Code(String),
    /// the user declined, or the provider reported an error
    Denied(String),
    /// not our callback (favicon, wrong path, wrong state): 404 and keep waiting
    Ignore,
}

/// Parses `GET /callback?code=…&state=… HTTP/1.1`.
pub fn parse_callback(request_line: &str, state: &str) -> Callback {
    let mut it = request_line.split_whitespace();
    let (Some("GET"), Some(target)) = (it.next(), it.next()) else { return Callback::Ignore };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/callback" {
        return Callback::Ignore;
    }
    let mut code = None;
    let mut got_state = None;
    let mut error = None;
    for kv in query.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = unpct(v).unwrap_or_default();
        match k {
            "code" => code = Some(v),
            "state" => got_state = Some(v),
            "error" | "error_description" => error = Some(error.map(|e: String| format!("{e}: {v}")).unwrap_or(v)),
            _ => {}
        }
    }
    if let Some(e) = error {
        return Callback::Denied(e);
    }
    match code {
        // OpenRouter returns state unchanged; a missing or different one is not our redirect
        Some(c) if got_state.as_deref() == Some(state) && (1..=512).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~".contains(&b)) => Callback::Code(c),
        Some(_) => Callback::Ignore,
        None if got_state.as_deref() == Some(state) => Callback::Denied("no authorization code in the callback (sign-in declined?)".into()),
        None => Callback::Ignore,
    }
}

/// A sign-in waiting for the browser.
pub struct Pending {
    listener: TcpListener,
    pub verifier: String,
    pub state: String,
    pub callback: String,
    pub url: String,
}

/// Starts a sign-in: binds `127.0.0.1:<free port>` and builds the authorization URL.
pub fn begin() -> Result<Pending, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| format!("cannot open a local callback port: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let verifier = verifier()?;
    let state = random(16)?;
    let callback = format!("http://127.0.0.1:{port}/callback");
    let url = auth_url(&callback, &challenge(&verifier), &state);
    Ok(Pending { listener, verifier, state, callback, url })
}

const PAGE_OK: &str = "<!doctype html><meta charset=utf-8><title>EchoDebug</title><body style=\"font:15px system-ui;padding:40px;background:#111;color:#ddd\"><h2>Signed in to OpenRouter</h2><p>You can close this tab and return to EchoDebug.</p>";
const PAGE_ERR: &str = "<!doctype html><meta charset=utf-8><title>EchoDebug</title><body style=\"font:15px system-ui;padding:40px;background:#111;color:#ddd\"><h2>Sign-in did not complete</h2><p>Return to EchoDebug and try again.</p>";

impl Pending {
    pub fn port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Waits for the browser's redirect (or `cancel`, or `timeout`) and returns the code.
    pub fn wait(&self, cancel: &AtomicBool, timeout: Duration) -> Result<String, String> {
        let t = Instant::now();
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("sign-in cancelled".into());
            }
            if t.elapsed() > timeout {
                return Err("sign-in timed out; start it again".into());
            }
            match self.listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut line = String::new();
                    let mut r = BufReader::new(match s.try_clone() {
                        Ok(c) => c,
                        Err(_) => continue,
                    });
                    if r.read_line(&mut line).is_err() {
                        continue;
                    }
                    // drain the headers so the browser sees a clean reply
                    let mut h = String::new();
                    while r.read_line(&mut h).unwrap_or(0) > 2 {
                        h.clear();
                    }
                    let res = parse_callback(line.trim_end(), &self.state);
                    let (status, page) = match &res {
                        Callback::Code(_) => ("200 OK", PAGE_OK),
                        Callback::Denied(_) => ("200 OK", PAGE_ERR),
                        Callback::Ignore => ("404 Not Found", ""),
                    };
                    let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{page}", page.len());
                    match res {
                        Callback::Code(c) => return Ok(c),
                        Callback::Denied(e) => return Err(format!("OpenRouter sign-in failed: {e}")),
                        Callback::Ignore => {}
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(format!("callback listener: {e}")),
            }
        }
    }
}

/// Exchanges the code for the user's key at `url` (normally [`EXCHANGE_URL`]).
pub fn exchange(url: &str, code: &str, verifier: &str) -> Result<String, String> {
    let agent = super::agent(Duration::from_secs(30));
    let body = json!({ "code": code, "code_verifier": verifier, "code_challenge_method": "S256" });
    let mut resp = agent.post(url).header("content-type", "application/json").send(body.to_string()).map_err(|e| format!("cannot reach openrouter.ai: {e}"))?;
    let status = resp.status().as_u16();
    let mut text = String::new();
    let _ = resp.body_mut().as_reader().take(64 * 1024).read_to_string(&mut text);
    if status != 200 {
        let hint = match status {
            403 => " (the code expired or was already used; sign in again)",
            _ => "",
        };
        return Err(format!("{}{hint}", super::error_message(super::provider::Kind::OpenRouter, status, &text, None)));
    }
    let v: Value = serde_json::from_str(&text).map_err(|_| "OpenRouter's reply was not JSON".to_owned())?;
    let key = v.get("key").and_then(Value::as_str).ok_or("OpenRouter's reply has no key")?;
    if !super::creds::valid_key(key) {
        return Err("OpenRouter returned an unexpected key".into());
    }
    Ok(key.to_owned())
}

#[cfg(test)]
mod tests {
    use super::super::mock::{route, serve};
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc7636() {
        // RFC 7636 appendix B
        assert_eq!(challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let v = verifier().unwrap();
        assert_eq!(v.len(), 43);
        assert!(v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_ne!(v, verifier().unwrap());
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn auth_url_has_the_documented_parameters() {
        let u = auth_url("http://127.0.0.1:5000/callback", "CH", "ST");
        assert_eq!(u, "https://openrouter.ai/auth?callback_url=http%3A%2F%2F127.0.0.1%3A5000%2Fcallback&code_challenge=CH&code_challenge_method=S256&state=ST&key_label=EchoDebug");
    }

    #[test]
    fn parses_callbacks() {
        assert_eq!(parse_callback("GET /callback?code=abc-123&state=s1 HTTP/1.1", "s1"), Callback::Code("abc-123".into()));
        assert_eq!(parse_callback("GET /callback?state=s1&code=abc HTTP/1.1", "s1"), Callback::Code("abc".into()));
        assert_eq!(parse_callback("GET /callback?code=abc&state=other HTTP/1.1", "s1"), Callback::Ignore);
        assert_eq!(parse_callback("GET /callback?code=abc HTTP/1.1", "s1"), Callback::Ignore);
        assert_eq!(parse_callback("GET /favicon.ico HTTP/1.1", "s1"), Callback::Ignore);
        assert_eq!(parse_callback("POST /callback?code=abc&state=s1 HTTP/1.1", "s1"), Callback::Ignore);
        assert_eq!(parse_callback("GET /callback?code=a%22b&state=s1 HTTP/1.1", "s1"), Callback::Ignore);
        assert!(matches!(parse_callback("GET /callback?error=access_denied&state=s1 HTTP/1.1", "s1"), Callback::Denied(e) if e == "access_denied"));
        assert!(matches!(parse_callback("GET /callback?state=s1 HTTP/1.1", "s1"), Callback::Denied(_)));
    }

    #[test]
    fn waits_for_the_browser_and_exchanges_the_code() {
        let p = begin().unwrap();
        assert!(p.url.contains(&format!("callback_url=http%3A%2F%2F127.0.0.1%3A{}%2Fcallback", p.port())));
        assert!(p.url.contains(&format!("code_challenge={}", challenge(&p.verifier))));
        let port = p.port();
        let state = p.state.clone();
        let browser = std::thread::spawn(move || {
            use std::net::TcpStream;
            let get = |path: &str| {
                let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
                write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
                let mut r = String::new();
                let _ = s.read_to_string(&mut r);
                r
            };
            let a = get("/favicon.ico");
            let b = get(&format!("/callback?code=THE-CODE&state={state}"));
            (a, b)
        });
        let cancel = AtomicBool::new(false);
        let code = p.wait(&cancel, Duration::from_secs(10)).unwrap();
        assert_eq!(code, "THE-CODE");
        let (a, b) = browser.join().unwrap();
        assert!(a.starts_with("HTTP/1.1 404"));
        assert!(b.starts_with("HTTP/1.1 200") && b.contains("Signed in"));

        let m = serve(vec![route("POST /api/v1/auth/keys", 200, "application/json", r#"{"key":"sk-or-v1-0123456789abcdef","user_id":"u1"}"#)]);
        let key = exchange(&format!("{}/api/v1/auth/keys", m.base), &code, &p.verifier).unwrap();
        assert_eq!(key, "sk-or-v1-0123456789abcdef");
        let seen = m.seen.lock().unwrap().clone();
        let body: Value = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(body, json!({ "code": "THE-CODE", "code_verifier": p.verifier, "code_challenge_method": "S256" }));

        let m = serve(vec![route("POST /api/v1/auth/keys", 403, "application/json", r#"{"error":{"code":403,"message":"Invalid code or code_verifier"}}"#)]);
        let e = exchange(&format!("{}/api/v1/auth/keys", m.base), "x", "y").unwrap_err();
        assert!(e.contains("Invalid code") && e.contains("sign in again"), "{e}");
    }

    #[test]
    fn wait_can_be_cancelled() {
        let p = begin().unwrap();
        let cancel = AtomicBool::new(true);
        assert!(p.wait(&cancel, Duration::from_secs(5)).unwrap_err().contains("cancelled"));
        let cancel = AtomicBool::new(false);
        assert!(p.wait(&cancel, Duration::from_millis(150)).unwrap_err().contains("timed out"));
    }
}
