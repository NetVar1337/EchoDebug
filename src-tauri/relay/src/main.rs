// Headless relay: the same backend + MCP server as the desktop app, without a window.
// Usage: echodebug-relay [port]   (default 47110, or ECHODEBUG_PORT)
use echo_debug_relay::{serve, DEFAULT_PORT};

#[tokio::main]
async fn main() {
    let port = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ECHODEBUG_PORT").ok())
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    eprintln!("echodebug relay on ws://127.0.0.1:{port} (MCP: http://127.0.0.1:{port}/mcp)");
    if let Err(e) = serve(port, env!("CARGO_PKG_VERSION").to_string()).await {
        eprintln!("relay failed: {e}");
        std::process::exit(1);
    }
}
