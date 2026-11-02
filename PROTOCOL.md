# EchoDebug wire protocol

Everything is JSON over WebSocket text frames on `127.0.0.1` (default port **47110**).
Addresses are always hex strings with a `0x` prefix (`"0x7ff600001000"`), byte payloads
are lowercase hex strings without a prefix (`"4883ec28"`). Sizes and counts are JSON numbers.

```
 Echo (Discord overlay host)                    EchoDebug desktop app (Tauri)
 ┌──────────────────────────────┐               ┌────────────────────────────────────┐
 │ echo_debug.as (AngelScript)   │──ws /ext────▶ │ relay (Rust, axum)                 │
 │   ws::connect  → ext verbs   │               │   routes by "type"                 │◀── ws /client ── React UI
 │ process::open_socket ────────┼──ws /agent──▶ │   rewrites ids per upstream        │◀── ws /client ── other tools
 └──────────────────────────────┘               │   POST /mcp  (MCP, Streamable HTTP)│◀── MCP clients (Claude Code…)
                                                │   GET /health                      │
                                                └────────────────────────────────────┘
```

## Endpoints (relay)

| Path | Who connects | Notes |
|---|---|---|
| `/agent` | Echo's native memory server (`process::open_socket(url)`) | Relay is the *requester*: it sends Echo native requests and receives `*_result` / `error` frames. One connection at a time; a new one replaces the old. |
| `/ext` | `echo_debug.as` via `ws::connect` | Relay sends ext requests and receives replies + id-less events. One at a time; a new one replaces the old. |
| `/client` | UI, scripts, anything | Sends requests `{ "type", "id", ... }`, receives replies with the same `id`, plus broadcast events. Many clients. |
| `POST /mcp` | MCP clients | Streamable HTTP, JSON responses only (no SSE). Tools are defined in `src/lib/tools.json`. |
| `GET /health` | anyone | `200 {"ok":true,"version":"x.y.z"}` |

## Routing

A `/client` request is routed by its `type`:

1. **Native verbs** → `/agent`: `ping`, `read`, `read_batch`, `modules`, `sig_scan`, `sig_scan_ida`,
   `string_scan`, `resolve_relative`, `rtti_resolve`, `rtti_resolve_batch`, `enumerate_functions`,
   `disassemble`. Shapes are exactly Echo's documented "Process socket" routes.
2. **Local verbs** → answered by the relay itself:
   - `status` → `{ "type":"status_result", "id", "success":true, "agent":bool, "ext":bool,
     "ext_version":"x.y.z"|"" , "app_version":"x.y.z", "target": <last attach_result payload or null> }`
   - `processes` → `{ "type":"processes_result", "id", "success":true,
     "processes":[{ "pid":1234, "name":"game.exe", "path":"C:\\...\\game.exe", "memory":123456 }] }`
     (local process list of the machine running the app, sorted by name)
3. **Everything else** → `/ext`.

Two more local verbs feed the app's MCP panel: `mcp_log` → `{ "type":"mcp_log_result", ..., "entries":[...] }`
(ring buffer of the last 200 `tools/call` requests the relay saw) and `mcp_meta` → serverInfo,
capabilities, prompt and resource catalogs.

The relay replaces the client's `id` with a relay-unique integer before forwarding and restores the
original `id` (any JSON value; default `0`) on the reply. If the needed upstream is not connected the relay
replies immediately with:

```json
{ "type":"error", "id":<orig>, "code":2001, "message":"echo memory server not connected" }   // /agent missing
{ "type":"error", "id":<orig>, "code":2002, "message":"EchoDebug agent not connected" }      // /ext missing
```

**Local backend (Linux):** on non-Windows hosts, when no `/agent` or `/ext` upstream is connected, the
relay serves the verbs itself from `/proc/<pid>` (`mem`/`maps`, ELF symbols via `object`, iced-x86 for
disassembly): native verbs `ping`, `read`, `read_batch`, `modules`, `sig_scan`, `sig_scan_ida`,
`string_scan`, `disassemble`, `enumerate_functions`, `resolve_relative`; ext verbs `attach`, `detach`,
`alive`, `write`, `query`, `regions`, `chain`, `scan_new`/`scan_next`/`scan_results`/`scan_clear`,
`read_typed`, `region_stats`, `dump`. Agent-only verbs (freeze, watch, emulate, pointer_scan,
peb_walk, resolve_export, reopen_socket) and RTTI answer with a clear "requires the Echo agent"
error. Status frames carry `"backend": "echo" | "local" | "none"` and `"local": bool`.

Requests that get no reply within **120 s** fail with code `2003` (`"timed out"`). If an upstream
disconnects, all its in-flight requests fail with code `2004` (`"upstream disconnected"`).

### Broadcasts (relay → every `/client`)

- Any id-less frame from `/ext` is forwarded verbatim (these are `{"type":"event", "event": ..., ...}`).
- The relay emits `{ "type":"status", "agent":bool, "ext":bool, "ext_version":"...", "target":... }`
  whenever either upstream connects/disconnects or an `attach_result` / `detach_result` passes through.

## Ext verbs (served by `agent/echo_debug.as`)

Every reply is `{ "type":"<verb>_result", "id":<same>, "success":true, ...fields }` or
`{ "type":"error", "id":<same>, "code":<3000+>, "message":"...", "detail":"..." }`.

Error codes: `3000` unknown verb · `3001` not attached · `3002` bad arguments · `3003` operation failed ·
`3004` busy (another long job running) · `3005` limit exceeded.

On connect the agent sends (id-less) `{ "type":"event", "event":"hello", "version":"x.y.z", "protocol":1,
"user":"<util::get_username()>", "attached":bool, "pid":N, "base":"0x..", "peb":"0x..", "name":"..." }`.
When the agent is already attached at (re)connect it also re-sends an `attached` event. If the
relay sees `hello` with `attached:true` but has no `/agent` upstream (e.g. after an app restart,
which kills Echo's old `process::open_socket` connection), the relay pokes the agent with a
one-shot `reopen_socket` request; the agent re-opens the native socket and emits a
`native_socket` event with `ok`.

| verb | request fields | reply fields |
|---|---|---|
| `attach` | `name` (string) **or** `pid` (number) | `pid`, `base`, `peb`, `name`, `native_socket` (bool: `process::open_socket` result) |
| `detach` | – | – |
| `alive` | – | `alive` (bool), `pid` |
| `write` | `address`, `data` (hex), `force?` (bool, default false) | `written` (byte count), `region` ({base,size,present,writable,executable} of the target). Without `force`, writes whose range is not fully mapped are refused (Echo writes physical memory, so an unmapped target must not be written blindly) |
| `reopen_socket` | – | `ok` (bool: `process::open_socket` result) |
| `resolve_export` | `module`, `name` | `address`, `module_base` |
| `peb_walk` | – | `count`, `modules:[{base,entry,size,name}]` (PEB Ldr walk via a process-backed Unicorn emulator; runs on the job slot) |
| `watch` | `address`, `size?` (1–16, default 4), `label?` | `watched` (count). The agent samples the address at 10 tps and emits `watch_event` on change |
| `unwatch` | `address` | `watched` (count) |
| `watch_list` | – | `entries:[{address,size,label,last}]` (last = hex of the most recent sample) |
| `read_typed` | `address`, `type` (`u8..u64`,`i8..i64`,`f32`,`f64`,`string`,`wstring`,`bytes`), `length?` (bytes/string/wstring cap, ≤ 4096) | `ok`, `value` (decoded string / hex), `raw` (hex bits) |
| `region_stats` | `start?`, `end?` | region counts and byte totals split by present/writable/executable, `truncated` |
| `query` | `address` | `region: {base,size,present,writable,executable}` |
| `regions` | `start?` (default `0x10000`), `end?` (default `0x7fffffffffff`), `max?` (default 20000), `present_only?` (default true) | `regions:[{base,size,present,writable,executable}]`, `truncated` (bool) |
| `chain` | `base` (address), `offsets` (array of numbers; may be negative) | `hops:[{address, value}]` (value = pointer read at that hop, hex), `final` (address), `ok` (bool) |
| `scan_new` | `value_type` (`u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 bytes string wstring`), `compare` (`exact`\|`unknown`\|`greater`\|`less`\|`between`), `value?` (string; hex for `bytes`), `value2?`, `module?` (restrict to a module) or `start?`/`end?`, `writable_only?` (default true), `alignment?` (default natural size, 1 for bytes/strings), `float_epsilon?` | `count`, `sample:[{address, value}]` (≤ 200; value as hex bytes) |
| `scan_next` | `compare` (`exact changed unchanged increased decreased greater less between`), `value?`, `value2?` | `count`, `sample` |
| `scan_results` | `offset`, `limit` (≤ 2000) | `count`, `results:[{address, value, previous}]` (hex bytes) |
| `scan_clear` | – | – |
| `pointer_scan` | `target` (address), `max_depth?` (1–5, default 3), `max_offset?` (default 0x400), `max_results?` (default 500), `module_only_roots?` (default true) | `results:[{module, module_offset, offsets:[n...]}]`, `truncated` |
| `emulate` | `start` (address), `end` (address where emulation stops; reaching it is success), `code?` (hex; if present it is mapped at `start` in a blank emulator, otherwise `uc::create_process()` is used so code/data fault in from the attached process), `regs?` (`{"rcx":"0x1", ...}` 64-bit GPRs), `write?` (array of `{address, data}` — bytes injected into the emulator before the run; the page is mapped on demand), `read?` (array of `{address, size}` — bytes read back after the run), `max_insns?` (default 100000, max 5000000), `timeout_us?` (default 1000000, max 5000000), `trace?` (bool), `trace_limit?` (default 2000) | `error` (uc::error int), `error_name`, `fault_address`, `regs:{rax..r15,rip,rsp,rbp,eflags}`, `trace:[address...]`, `mem:[{address,size,ok,data}]`, `instructions`, `reached_end` (bool) |
| `dump` | `module?`, `filename` | `path` (relative to the Echo scripts `dmp` folder) |
| `freeze` | `address`, `data` (hex), `enabled` (bool) | `frozen` (count) — agent rewrites `data` at 20 Hz while enabled |
| `freeze_list` | – | `entries:[{address,data}]` |

Long jobs (`attach`, `scan_new`, `scan_next`, `pointer_scan`, `emulate`, `peb_walk`, `auto_attach`) run on a
one-shot thread; only one at a time (otherwise `3004`). Scans and pointer scans emit progress events
`{ "type":"event", "event":"progress", "job":"scan_new", "done":N, "total":N }` and finish with the
normal reply carrying the original `id`. Emulation is hard-bounded (`timeout_us` <= 5 s, `max_insns` <= 5M)
but still goes through the slot so a long run never blocks the other verbs.

Other events: `log` (`level`, `message`), `attached` (`pid`,`base`,`name` — also re-sent on reconnect),
`detached`, `freeze_error` (`address`), `patched` (`address`,`old`,`new` — emitted once per `freeze`
enable so clients can journal the pre-freeze bytes; frozen values are restored on detach/unload),
`native_socket` (`ok` — health of Echo's native memory socket after a `reopen_socket` poke),
`watch_event` (`address`,`label?`,`old`,`new` — hex bytes before/after a watched address changed).

The agent restores the pre-freeze bytes of every frozen address on `detach`, on target exit and in
`on_unload`, and calls `process::detach()` in `on_unload` (Echo docs teardown rule).

## Versioning

`protocol` is bumped on incompatible changes. The app shows a warning when the agent's `version`
differs from the app version and (re)installs the bundled agent into `%APPDATA%\scripts\echo_debug.as`.

## MCP surface

`POST /mcp` speaks JSON-RPC 2.0 (single messages and batches; notifications get `202 Accepted`).
Supported methods: `initialize` (advertises `tools`, `prompts` and `resources` capabilities plus
`instructions`), `ping`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get`,
`resources/list`, `resources/read`. Every tool in `src/lib/tools.json` maps one-to-one onto a verb
above; the tool's `verb` becomes the request `type`, the tool's `input_schema` is passed through as
the request body, and the reply is returned as pretty-printed JSON in a single text content block
(`isError` is set when the relay replied with an error frame). Each `tools/call` is appended to a
200-entry ring buffer, exposed as the `echodebug://mcp/log` resource and the local `mcp_log` verb.

Prompts (`prompts/get` returns ready-to-use user messages with arguments substituted):
`explain_function` (address), `find_pattern` (pattern, module?), `find_string` (text, module?),
`pointer_path` (target, max_depth?), `scan_value` (value_type, value), `triage_module` (module).

Resources: `echodebug://status`, `echodebug://tools`, `echodebug://mcp/log`,
`echodebug://target/modules` (fails when no memory server is connected).

The tool set covers the whole backend: process control (`status`, `list_processes`, `attach`,
`detach`, `is_alive`), memory (`read_memory`, `read_memory_batch`, `write_memory`, `query_region`,
`memory_regions`), analysis (`disassemble`, `enumerate_functions`, `signature_scan`,
`signature_scan_masked`, `string_scan`, `resolve_relative`, `rtti_resolve`, `rtti_resolve_batch`,
`resolve_export`, `peb_walk`), scanning (`value_scan_first`, `value_scan_next`, `value_scan_results`,
`value_scan_clear`, `pointer_scan`), emulation (`emulate`), freezing (`freeze_value`, `list_frozen`),
dumping (`dump_module`) and socket housekeeping (`reopen_native_socket`).

Because the relay routes by verb, an MCP client gets exactly the same behaviour as the desktop UI.
