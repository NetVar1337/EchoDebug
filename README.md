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

1. Download an installer from [Releases](https://github.com/NetVar1337/EchoDebug/releases/latest):
   `EchoDebug_x.y.z_x64-setup.exe` (per-user setup, no admin needed) or
   `EchoDebug_x.y.z_x64_en-US.msi` (per-machine, for managed deployment). Both auto-update.
2. Start EchoDebug. On every start it installs or updates the agent at `%APPDATA%\scripts\echo_debug.as`.
3. In Echo, open the menu and load `echo_debug.as`. It connects to the app automatically and keeps
   retrying if the app isn't running yet.
4. In **Targets**, pick a process and click **Attach**. The status bar should show
   `Memory server` and `Agent` as green.

## Features

| Area | What you get |
|---|---|
| Shell | Reverse-Slap layout: frameless title bar with File/View/Window/Theme/Help menus and window buttons, activity rail, targets/modules/watch/names/AI panels, scanner, tabbed workspace, output, inspector, status bar, splitters, three themes plus accent colours, boot splash, global tooltips, motion preference (on/auto/off) |
| Navigation | Ctrl+G go-to, **Ctrl+Shift+P command palette** over every action, Alt+← back in the disassembly, X for xrefs, N to rename, `;` to comment |
| Targets & modules | Local process list, attach by pid/name, module list, open a module in PE/Strings/Disassembly/Memory, dump to `scripts\dmp` |
| Disassembly | Function list (`enumerate_functions`), virtualized listing, clickable branch targets with history, xrefs (rel32 + RIP-relative), make-signature, bookmarks, user names and comments |
| Memory | Live hex/ASCII view with change highlighting, in-place byte writes, region map with r/w/x flags, data inspector |
| Structs | ReClass-style typed fields, follow pointers, RTTI class names, C++ header export |
| RTTI | Every class the module declares, with its base class and the vftables that belong to it; resolve any live object to its vtable and the virtual functions behind it |
| Scanner | Cheat Engine-style first/next value scan (u8–u64, i8–i64, f32/f64, bytes, string, wstring; exact/unknown/changed/increased/…), AOB (IDA pattern) scan, string scan |
| Watchlist | Live values, inline edits, freeze (rewritten by the agent at 20 Hz), bookmarks |
| Strings | ASCII + UTF-16 extraction, category/regex filters, CSV export, xrefs per string |
| PE browser | Headers, sections, data directories, imports (with IAT slots), exports, **Analysis tab** with per-section entropy and packer/protector heuristics |
| Signatures | IDA-style sigmaker for code or raw bytes, auto-wildcards rel32/disp32, grows until unique, IDA / `\x..`+mask / byte-array / x64dbg / YARA output, saved to a catalog; **FLIRT** signature files (IDA `.sig`, versions 5-10) can be loaded and matched against the module, with the CRC of the function tail verified |
| Pointers | Live pointer-chain resolver, bounded pointer scan whose results load straight into the resolver |
| Call graph | The function under the cursor with its direct callees (from Echo's own disassembly) and the call sites that reference it; a module mode that draws the whole binary at once |
| Xrefs | The whole reference graph of a module indexed in one pass: who points here, what this points at, and the most referenced addresses in the binary |
| .NET explorer | ECMA-335 metadata parsed straight out of the loaded module: namespaces, types, methods, fields, base types |
| Crypto scanner | Finds known constant tables (AES S-box, SHA-256 K/H, MD5 T, CRC-32, Blowfish, ChaCha/Salsa sigma, TEA delta, Base64 alphabet, Rijndael mix) |
| Code caves | Padding runs inside executable sections (0xCC / 0x90 / 0x00) with their size and section |
| Snapshots | Capture a window of process memory, diff two captures byte by byte |
| Binary map | Module section layout as a proportional bar plus the live region map with protection flags |
| Patches | Every write EchoDebug makes is journalled with the bytes that were there before, and can be reverted with one click |
| Triage | The imports of a module that deserve a second look (memory tampering, injection, anti-analysis), each with the callsites that use it |
| Anti-debug | The places a module tries to find out whether it is analysed: INT 2D, the red-pill descriptor reads, VMCALL, PEB/TEB reads, timing checks, the debugger-detection APIs and the debugger window names in the strings |
| Emulator | Unicorn emulation against the live process image (the process is never modified): registers, instruction trace linked to the disassembly, and a **decrypt oracle** that feeds a buffer into a routine and reads the result back |
| AI assistant | Chat with Anthropic or any OpenAI-compatible endpoint (OpenAI, OpenRouter, Groq, Mistral, DeepSeek, Ollama, LM Studio); the model drives the same 29 tools as MCP, sees the current target/module/selection, and asks before running a mutating tool |
| MCP server | `http://127.0.0.1:47110/mcp` (Streamable HTTP), 29 tools |
| Sessions | Export/import the whole workspace (theme, watchlist, bookmarks, names, struct layout) as one JSON file; names export as an IDA `.idc` or Ghidra script |
| Headless | `echodebug-relay [port]` runs the relay and MCP server without the UI |
| Updates | Signed auto-update from GitHub Releases: checks at startup and every 30 min, downloads in the background, then a **Restart to update** button (status bar, Help menu, Settings); an update left pending installs at the next launch. Help → Check for updates on demand. The Echo agent updates with the app |

**Not available on the Echo backend:** the native debugger (breakpoints, stepping, VEH), Frida,
kernel inspection, network capture/proxy, and Reverse-Slap/AiDA's decompilers and .NET decompiler.
Echo exposes no API for these, and EchoDebug deliberately ships no driver to replace them.

### MCP

```bash
claude mcp add --transport http echodebug http://127.0.0.1:47110/mcp
```

The relay listens on `127.0.0.1` only. It rejects browser origins other than the app's own and
localhost dev servers, so web pages can't reach your target's memory.

### AI settings

Under **Settings → AI**, choose the provider endpoint, model and API key. The key is stored in the app's
local storage on this machine and is sent only to the endpoint you configure. Local servers
(Ollama, LM Studio) need no key.

## Development

Requirements: Node 22+, Rust (stable, 1.90+), and on Windows the WebView2 runtime and MSVC build tools.

```bash
npm ci
npm run tauri dev            # desktop app with hot reload
npm run dev                  # UI only in a browser (needs a relay: cargo run -p echo-debug-relay --manifest-path src-tauri/Cargo.toml)
npm test                     # frontend unit tests (PE parser, sigmaker, strings, structs, CLR metadata, crypto, caves, entropy, AI loop)
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
4. builds the signed NSIS setup and MSI installers, publishes the GitHub release with notes, `latest.json` and `echo_debug.as`.

Installed apps pick up the release on their next start. You can force a release with **Actions → Release → Run workflow**.
The updater signing key is the `TAURI_SIGNING_PRIVATE_KEY` repo secret. If it's lost, existing installs
can no longer verify updates. Dependabot keeps npm, cargo and Actions dependencies current.

## Credits

- UI/UX and logo from [Reverse-Slap](https://github.com/kaizer1308/reverse-slap) by kaizer1308; features after
  [AiDA Private](https://github.com/sigwl/AiDAPrivate) by sigwl. The code here is new: neither
  project has a license, so no code was copied from them.
- [Echo](https://echo-23.gitbook.io/angel) Universal API. Ideas from
  [web-mv](https://github.com/Jozkah/web-mv), [angel-menu-mcp](https://github.com/Jozkah/angel-menu-mcp),
  [echo-angelscript-lsp](https://github.com/speedsunderscore/echo-angelscript-lsp) (used for the agent lint),
  [as_bundler](https://github.com/sinistercodes/as_bundler), [Signature-Doctor](https://github.com/b4rzY/Signature-Doctor),
  [Dumper-7](https://github.com/Encryqed/Dumper-7) and [echo-esp-preview](https://github.com/speedsunderscore/echo-esp-preview).

Licensed under GPL-3.0.
