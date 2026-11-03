# Disassembler sync (IDA, Ghidra, Binary Ninja)

Live two-way sync between EchoDebug and a disassembler, in the style of ret-sync:

| What | Disassembler → EchoDebug | EchoDebug → disassembler |
|---|---|---|
| Cursor | the disassembly view jumps to the address you are on | the disassembler follows the address you select |
| Names | user names / labels / function names | names you set in EchoDebug (N, the Names panel, scripts, MCP `set_name`) |
| Comments | regular (EOL) comments | EchoDebug comments |
| Struct types | — | the Structs catalog as C declarations (**Push struct types** in the Sync panel) |

Each direction can be switched off in EchoDebug's **Sync** panel (the ⇄ icon in the activity rail).
When two sides write a different name or comment for the same place, the **last writer wins**; the
value it replaced is logged as a conflict in the panel's sync log (and in the Output panel).

## How it works

The plugins connect to the relay inside the EchoDebug app (or the headless `echodebug-relay`):

```
IDA / Ghidra / Binary Ninja ── ws://127.0.0.1:47110/sync (Bearer token) ──▶ relay ◀── /client ── EchoDebug window
```

- **Authentication**: the same relay token as `/client` and `/mcp`. Plugins read it from
  `relay-token` in the EchoDebug config folder (`%APPDATA%\EchoDebug` on Windows,
  `$XDG_CONFIG_HOME/EchoDebug` or `~/.config/EchoDebug` elsewhere), or from `ECHODEBUG_TOKEN`.
  `ECHODEBUG_PORT` changes the port (default 47110). Browser pages cannot connect (Origin check).
- **Addresses** travel as **module name + RVA**. The plugin computes `RVA = address - image base`
  of its database and EchoDebug adds the live load address of the module, so ASLR and rebased
  databases both line up. If the file name in the disassembler differs from the live module
  (a dump called `game_dump.exe`, say), pick the live module next to it in the Sync panel.
- The relay drops a write equal to the current value and a cursor equal to the last cursor, so
  applying a change never bounces back and forth between the tools.
- Several tools can be connected at once (IDA and Ghidra on the same binary, for instance); a
  change in one reaches the others too.

## IDA Pro 9.x

1. Copy `ida/echodebug_sync_ida.py` **and** `python/echodebug_sync.py` into IDA's plugins folder
   (`%APPDATA%\Hex-Rays\IDA Pro\plugins` on Windows, `~/.idapro/plugins` on Linux and macOS).
2. Open the database of the module you are debugging (its input file name must match the module,
   or map it in the Sync panel).
3. **Edit → Plugins → EchoDebug sync** (Ctrl-Alt-E) connects; run it again to disconnect. Set
   `ECHODEBUG_SYNC_AUTOSTART=1` to connect whenever a database opens.

Uses `ida_kernwin.UI_Hooks.screen_ea_changed` for the cursor, `ida_idp.IDB_Hooks.renamed` /
`cmt_changed` for names and comments, `ida_kernwin.jumpto`, `ida_name.set_name`,
`ida_bytes.set_cmt` and `idc.parse_decls` (Local Types) to apply changes. Auto-generated names and
function-local labels are not sent.

## Ghidra 11.1+

1. Copy `ghidra/EchoDebugSync.java` into one of your script directories (for example
   `~/ghidra_scripts`; add it in **Window → Script Manager → Manage Script Directories**).
2. Open the program in the CodeBrowser and run **Tools → EchoDebug Sync** (or the script from the
   Script Manager, category *EchoDebug*; Ctrl-Alt-E). Run it again to disconnect.

The script stays connected after it returns: it listens to the listing's field locations for the
cursor (`FieldPanel.addFieldLocationListener` + `ListingPanel.getProgramLocation`) and to the
program's `DomainObjectListener` events (`SYMBOL_RENAMED` / `SYMBOL_ADDED` / `SYMBOL_REMOVED`,
`COMMENT_CHANGED`) for user-defined names and EOL comments. Incoming changes go through
`GoToService`, `Function.setName` / `SymbolTable.createLabel`, `Listing.setComment` and the C
parser (`CParser`) for struct types, each in its own transaction. It needs Java 17+ (the
`java.net.http` WebSocket client, which Ghidra 11 requires anyway) and the GUI.

## Binary Ninja

1. Copy the `binaryninja/echodebug_sync` folder into Binary Ninja's plugins folder
   (**Plugins → Open Plugin Folder**) and copy `python/echodebug_sync.py` into that
   `echodebug_sync` folder, next to `__init__.py`.
2. Restart Binary Ninja, open the binary and choose **Plugins → EchoDebug → Start sync**
   (**Stop sync** disconnects).

The cursor comes from `UIContextNotification.OnAddressChange` and is applied with
`BinaryView.navigate`; user symbols come from `BinaryDataNotification.symbol_added` /
`symbol_updated` / `symbol_removed`; function comments are compared on `function_updated` and
address comments on a 1.5 s timer (Binary Ninja has no comment notification). Struct types are
parsed with `parse_types_from_string` and defined with `define_user_type`. Without the UI
(headless) everything but the cursor works.

## Protocol

JSON text frames on `/sync`. The plugin sends `hello` first:

```json
{ "type": "hello", "tool": "ida", "version": "IDA 9.1", "file": "C:/re/game.i64", "protocol": 1,
  "modules": [{ "name": "game.exe", "base": "0x140000000", "size": 1048576 }] }
```

and receives `{"type":"hello_result","peer":7,"protocol":1,"directions":{...}}`. After that, in both
directions:

| Frame | Fields |
|---|---|
| `cursor` | `module`, `rva` (`"0x1a2b"`) |
| `name` | `module`, `rva`, `name` (empty removes) |
| `comment` | `module`, `rva`, `comment` (empty removes, newlines allowed) |
| `types` (relay → plugin) | `decls` (C declarations), `names` |
| `config` (relay → plugin) | `directions` |
| `modules` (plugin → relay) | `modules`, when the database changes |
| `ping` → `pong` | keep-alive (plugins send one every 15 s) |

Frames from the relay carry `from` (the tool that made the change, or `echodebug`). Bad frames get
`{"type":"error","message","for"}`. See [PROTOCOL.md](../PROTOCOL.md#disassembler-sync-sync) for the
app-side verbs (`sync_status`, `sync_config`, `sync_send`, `sync_log`).

## Tests

The plugins need their host applications and are not run in CI. What is tested:

- the relay hub (`src-tauri/relay/src/sync.rs` unit tests and `src-tauri/relay/tests/sync.rs`, with
  fake plugins over real sockets: token, routing, module map, directions, conflicts, MCP tool);
- the shared Python core used by the IDA and Binary Ninja plugins
  (`python3 -m unittest discover -s integrations/python`: WebSocket framing, handshake and token,
  RVA mapping with rebasing, echo suppression, against a fake relay);
- the Ghidra script compiles against the Ghidra 11.2 jars (`javac -cp "<ghidra>/Ghidra/**/*.jar"`).
