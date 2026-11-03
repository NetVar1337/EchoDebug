// Headless relay: the same backend + MCP server as the desktop app, without a window.
// Usage: echodebug-relay [port]           (default 47110, or ECHODEBUG_PORT)
//        echodebug-relay --stdio [port]   MCP over stdin/stdout (bridges to a running relay, or embeds one)
use echo_debug_relay::{serve, serve_stdio, DEFAULT_PORT};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdio = args.iter().any(|a| a == "--stdio");
    let port = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .or_else(|| std::env::var("ECHODEBUG_PORT").ok())
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let r = if stdio {
        serve_stdio(port, env!("CARGO_PKG_VERSION").to_string()).await
    } else {
        eprintln!("echodebug relay on ws://127.0.0.1:{port} (MCP: http://127.0.0.1:{port}/mcp)");
        serve(port, env!("CARGO_PKG_VERSION").to_string()).await
    };
    if let Err(e) = r {
        eprintln!("relay failed: {e}");
        std::process::exit(1);
    }
}
