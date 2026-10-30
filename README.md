<p align="center"><img src="src-tauri/icons/128x128.png" width="96" alt="EchoDebug" /></p>

# EchoDebug

A Windows reverse-engineering workbench with Reverse-Slap's interface, the feature set of
Reverse-Slap and AiDA Private, and **Echo's hypervisor as its only backend**. It ships no kernel
driver, no mapper and no injected DLL. All process access goes through Echo's Universal API.

> [!WARNING]
> Use EchoDebug only on software and systems you own or are authorized to test. Memory writes and
> freezes can crash the target.

## How it fits together

```
Echo (Discord overlay host)                      EchoDebug.exe (Tauri)
┌────────────────────────────┐                   ┌──────────────────────────────┐
│ echo_debug.as              │── ws /ext ──────▶ │ relay  127.0.0.1:47110       │◀── React UI
│ process::open_socket ──────┼── ws /agent ────▶ │ MCP    POST /mcp             │◀── Claude Code / any MCP client
└────────────────────────────┘                   └──────────────────────────────┘
```

- **Echo's built-in memory server** (`process::open_socket`) serves reads, batch reads, modules,
  signature/string scans, RTTI, function enumeration and disassembly.
- **`agent/echo_debug.as`** adds everything Echo's server doesn't expose: attach, writes, region walk,
  pointer chains, the value scanner, pointer scan, Unicorn emulation, module dumps and freezing.
- **The desktop app** runs the relay. It routes every request to the right side, so the UI, the AI
  assistant and external MCP clients all use the same verbs. See [PROTOCOL.md](PROTOCOL.md).

## Quick start

1. Install the latest `EchoDebug_x.y.z_x64-setup.exe` from
   [Releases](https://github.com/NetVar1337/EchoDebug/releases/latest).
2. Start EchoDebug. On every start it installs or updates the agent at `%APPDATA%\scripts\echo_debug.as`.
3. In Echo, open the menu and load `echo_debug.as`. It connects to the app automatically and keeps
   retrying if the app isn't running yet.
4. In **Targets**, pick a process and click **Attach**. The status bar should show
   `Memory server` and `Agent` as green.

## Features

| Area | What you get |
|---|---|
| Shell | Reverse-Slap layout: activity rail, targets/modules/watch/AI panels, scanner, tabbed workspace, output, inspector, status bar, splitters, three themes plus accent colours, Ctrl+G go-to |
| Targets & modules | Local process list, attach by pid/name, module list, open a module in PE/Strings/Disassembly/Memory, dump to `scripts\dmp` |
| Disassembly | Function list (`enumerate_functions`), virtualized listing, clickable branch targets with history, xrefs (rel32 + RIP-relative), make-signature, bookmarks |
| Memory | Live hex/ASCII view with change highlighting, in-place byte writes, region map with r/w/x flags, data inspector |
| Structs | ReClass-style typed fields, follow pointers, RTTI class names, C++ header export |
| Scanner | Cheat Engine-style first/next value scan (u8–u64, i8–i64, f32/f64, bytes, string, wstring; exact/unknown/changed/increased/…), AOB (IDA pattern) scan, string scan |
| Watchlist | Live values, inline edits, freeze (rewritten by the agent at 20 Hz), bookmarks |
| Strings | ASCII + UTF-16 extraction, category/regex filters, CSV export, xrefs per string |
| PE browser | Headers, sections, data directories, imports (with IAT slots), exports |
| Signatures | IDA-style sigmaker for code or raw bytes, auto-wildcards rel32/disp32, grows until unique, IDA / `\x..`+mask / byte-array output |
| Pointers | Live pointer-chain resolver, bounded pointer scan whose results load straight into the resolver |
| Emulator | Unicorn emulation against the live process image (the process is never modified): registers, instruction trace linked to the disassembly |
| AI assistant | Chat with Anthropic or any OpenAI-compatible endpoint; the model drives the same tools as MCP |
| MCP server | `http://127.0.0.1:47110/mcp` (Streamable HTTP), 20 tools |
| Headless | `echodebug-relay [port]` runs the relay and MCP server without the UI |
| Updates | Signed in-app auto-update from GitHub Releases; the Echo agent updates with the app |

**Not available on the Echo backend:** the native debugger (breakpoints, stepping, VEH), Frida,
kernel inspection, network capture/proxy, and Reverse-Slap/AiDA's decompilers and .NET explorer.
Echo exposes no API for these, and EchoDebug deliberately ships no driver to replace them.

### MCP

```bash
claude mcp add --transport http echodebug http://127.0.0.1:47110/mcp
```

The relay listens on `127.0.0.1` only. It rejects browser origins other than the app's own and
localhost dev servers, so web pages can't reach your target's memory.

### AI settings

Under **Settings → AI**, choose the provider, model and API key. The key is stored in the app's
local storage on this machine and is sent only to the endpoint you configure.

## Development

Requirements: Node 22+, Rust (stable, 1.90+), and on Windows the WebView2 runtime and MSVC build tools.

```bash
npm ci
npm run tauri dev            # desktop app with hot reload
npm run dev                  # UI only in a browser (needs a relay: cargo run -p echo-debug-relay --manifest-path src-tauri/Cargo.toml)
npm test                     # frontend unit tests (PE parser, sigmaker, strings, structs, AI loop)
cargo test -p echo-debug-relay --manifest-path src-tauri/Cargo.toml
node scripts/lint-agent.mjs <echo-angelscript-lsp checkout> agent/echo_debug.as
```

### Releases are automatic

Use [Conventional Commits](https://www.conventionalcommits.org/). Every push to `main`:

1. runs CI (frontend, relay, AngelScript lint, Windows `cargo check`);
2. computes the next version from commits since the last tag (`feat` → minor, `fix`/`perf`/`refactor`/`revert` → patch,
   `!`/`BREAKING CHANGE` → major; minor while < 1.0). `docs`/`chore`/`ci`/`test` alone don't release;
3. writes the version into `package.json`, `Cargo.toml`, `Cargo.lock` and the agent, then commits `chore(release): vX.Y.Z`
   and pushes the `vX.Y.Z` tag;
4. builds the signed NSIS installer, publishes the GitHub release with notes, `latest.json` and `echo_debug.as`.

Installed apps pick up the release on their next start. You can force a release with **Actions → Release → Run workflow**.
The updater signing key is the `TAURI_SIGNING_PRIVATE_KEY` repo secret. If it's lost, existing installs
can no longer verify updates. Dependabot keeps npm, cargo and Actions dependencies current.

## Credits

- UI/UX after [Reverse-Slap](https://github.com/kaizer1308/reverse-slap) by kaizer1308; features after
  [AiDA Private](https://github.com/sigwl/AiDAPrivate) by sigwl. The code here is new: neither
  project has a license, so nothing was copied from them.
- [Echo](https://echo-23.gitbook.io/angel) Universal API. Ideas from
  [web-mv](https://github.com/Jozkah/web-mv), [angel-menu-mcp](https://github.com/Jozkah/angel-menu-mcp),
  [echo-angelscript-lsp](https://github.com/speedsunderscore/echo-angelscript-lsp) (used for the agent lint),
  [as_bundler](https://github.com/sinistercodes/as_bundler), [Signature-Doctor](https://github.com/b4rzY/Signature-Doctor),
  [Dumper-7](https://github.com/Encryqed/Dumper-7) and [echo-esp-preview](https://github.com/speedsunderscore/echo-esp-preview).

Licensed under GPL-3.0.
