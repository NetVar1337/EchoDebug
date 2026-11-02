// Headless relay: the same backend + MCP server as the desktop app, without a window.
// Usage: echodebug-relay [port]   (default 47110, or ECHODEBUG_PORT)
// The bearer token comes from ECHODEBUG_TOKEN, otherwise a fresh one is generated and printed.
use echo_debug_relay::{generate_token, serve, DEFAULT_PORT};

#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ECHODEBUG_PORT").ok())
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let token = std::env::var("ECHODEBUG_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .unwrap_or_else(generate_token);
    eprintln!("echodebug relay on ws://127.0.0.1:{port} (MCP: http://127.0.0.1:{port}/mcp)");
    eprintln!("  claude mcp add --transport http echodebug http://127.0.0.1:{port}/mcp --header \"Authorization: Bearer {token}\"");
    eprintln!("  browser dev UI: append ?port={port}&token={token} to the Vite URL");
    if let Err(e) = serve(port, env!("CARGO_PKG_VERSION").to_string(), Some(token)).await {
        eprintln!("relay failed: {e}");
        std::process::exit(1);
    }
}
