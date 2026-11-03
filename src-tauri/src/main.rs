// Prevents an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // `EchoDebug --mcp-stdio [port]`: an MCP server on stdin/stdout for clients that launch it
    // (configured by the MCP panel's "Connect a client"); no window.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--mcp-stdio") {
        std::process::exit(echo_debug_lib::run_mcp_stdio(&args));
    }
    echo_debug_lib::run()
}
