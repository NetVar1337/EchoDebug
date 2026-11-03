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
disassembly, Unicorn for emulation, ptrace for debugging): native verbs `ping`, `read`, `read_batch`,
`modules`, `sig_scan`, `sig_scan_ida`, `string_scan`, `disassemble`, `enumerate_functions` (ELF symbols,
rebased by the load bias), `resolve_relative`, and `rtti_resolve` / `rtti_resolve_batch` (Itanium C++ ABI:
`vptr[-1]` → `type_info` → mangled name, demangled, with base classes); ext verbs `attach`, `detach`,
`alive`, `write`, `query`, `regions`, `chain`, `scan_new`/`scan_next`/`scan_results`/`scan_clear`,
`read_typed`, `region_stats`, `dump`, `freeze`/`freeze_list` (20 Hz relay ticker, pre-freeze bytes restored
on unfreeze and detach), `watch`/`unwatch`/`watch_list` (10 Hz `watch_event`s), `pointer_scan`,
`resolve_export` (ELF `.dynsym`/`.symtab`), `peb_walk` (the dynamic loader's `r_debug` → `link_map` list,
found through `AT_PHDR` → `PT_DYNAMIC` → `DT_DEBUG`; reply adds `source: "link_map" | "maps"` and per
module `l_addr`/`dynamic`), `emulate` (same request/reply as the agent; pages fault in from the process),
plus the Linux-only verbs below. Only `reopen_socket` and the conditional alerts (`alert_add` /
`alert_remove` / `alert_list`, use watch conditions instead) answer with an error. Status frames carry
`"backend": "echo" | "local" | "none"` and `"local": bool`.

| Linux-only verb | request | reply |
|---|---|---|
| `itanium_classes` | `module?` | `classes:[{name, mangled, typeinfo, vtable (first virtual slot), slots, bases}]` from `_ZTI*`/`_ZTV*` symbols |
| `module_file` | `module`, `offset?`, `size?` (≤ 1 MiB) | `path`, `base`, `file_size`, `data` (hex) — the module's file on disk, for the ELF browser |
| `dbg_attach` | `pid?` (default: attached process) | `pid`, `threads`, `state:"stopped"` — PTRACE_SEIZE of every thread (+TRACECLONE), all-stop |
| `dbg_detach` | – | – (breakpoints and DR7 restored first; `detach` also ends the session) |
| `dbg_status` | – | `active`, `state` (`running`\|`stopped`), `focus`, `threads`, `breakpoints`, `hardware`, `last` |
| `dbg_break` | `address`, `enabled?` | `breakpoints` — int3, written through `/proc/<pid>/mem` |
| `dbg_hwbreak` | `slot` (0-3), `address`, `kind` (`exec`\|`write`\|`rw`), `len` (1/2/4/8), `enabled?` | status — DR0-DR3/DR7 on every thread |
| `dbg_continue` / `dbg_pause` | – | `state` (steps over a breakpoint under rip first) |
| `dbg_step` | `tid?` | `tid`, `from`, `address`, `regs`. A thread blocked in a system call only finishes the step when the call returns: the step is cancelled with an explanation instead of hanging |
| `dbg_regs` / `dbg_set_regs` | `tid?`, `regs?` (`{"rax":"0x1",…}`) | `regs` (rax…r15, rip, eflags, fs_base, gs_base) |

Debugger events: `{ "type":"event", "event":"dbg_stop", "reason":"breakpoint"|"hardware"|"step"|"signal"|"trap"|"pause", "tid", "address", "regs", "slot?", "watch?", "signal?" }`
and `{ "type":"event", "event":"dbg_exit", "pid", "code?"|"signal?" }`.

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
| `watch` | `address`, `size?` (1–256, default 4), `label?`, `value_type?` (u8..f64), `condition?` (`any` default, `eq`, `ne`, `gt`, `lt`, `delta`), `value?`, `alert?` (Echo alert per hit) | `watched` (count). The agent samples at 10 tps and emits `watch_event` (`old`, `new`, `hits`; with `value_type` also `old_value`/`new_value`) when the value changes and the condition holds; `watch_list` adds `hits` and `history` (last 16 values) |
| `unwatch` | `address` | `watched` (count) |
| `watch_list` | – | `entries:[{address,size,label,last}]` (last = hex of the most recent sample) |
| `alert_add` | `address`, `value_type` (`u8..u64`,`i8..i64`,`f32`,`f64`,`bytes`,`string`,`wstring`), `condition` (`equals`\|`not_equals`\|`changed`\|`greater`\|`less`; patterns only `equals`/`not_equals`/`changed`), `value?` (as in `scan_new`; not for `changed`), `size?` (patterns + `changed`: bytes compared, 1–256, default 16), `once?` (default false), `snapshot?` (bytes captured around the address, 0–1024, default 64), `label?`, `float_epsilon?` | `alert_id`, `alerts` (count). At most 64 alerts; checked at 50 tps |
| `alert_remove` | `alert_id` | `removed` (bool), `alerts` |
| `alert_list` | – | `entries:[{alert_id,address,value_type,condition,value,size,label,once,snapshot,fired,last}]` |
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
| `emulate` | `start` (address), `end` (address where emulation stops; reaching it is success), `code?` (hex; if present it is mapped at `start` in a blank emulator, otherwise `uc::create_process()` is used so code/data fault in from the attached process), `regs?` (`{"rcx":"0x1", ...}` 64-bit GPRs), `write?` (array of `{address, data}` — bytes injected into the emulator before the run; the page is mapped on demand), `read?` (array of `{address, size}` — bytes read back after the run), `max_insns?` (default 100000, max 5000000), `timeout_us?` (default 1000000, max 5000000), `trace?` (bool), `trace_limit?` (default 2000), `mem_log?` (bool; every explicit memory operand is decoded with Zydis before the instruction runs), `mem_log_limit?` (default 2000, max 20000), `trace_regs?` (per-instruction register changes), `stubs?` (API stand-ins), `layers?` (unpacking layers), `on_unmapped?` (`stop` default, `zero`), `xmm?` (`{"xmm0":"<32 hex>"}`) | `error` (uc::error int), `error_name`, `fault_address`, `regs:{rax..r15,rip,rsp,rbp,eflags}`, `trace:[address...]`, `mem:[{address,size,ok,data}]`, `mem_log?:[{rip,address,size,access:"r"\|"w"\|"rw",before,after?}]` (hex values; `after` only for writes; `size` comes from the operand's `ptr` width; implicit stack accesses such as push/pop/call are not logged), `mem_log_truncated?`, `instructions`, `reached_end` (bool); the agent also returns `ymm:{ymm0..ymm15}` (little-endian hex, only where the emulated CPU exposes it) and `regions:[{address,end,perms:"rwx"}]` (`uc::mem_regions` after the run: code, stack and every page faulted in; ≤ 4096), `regions_truncated` |
| `dump` | `module?`, `filename` | `path` (relative to the Echo scripts `dmp` folder) |
| `freeze` | `address`, `data` (hex, mode `set`), `enabled` (bool), `mode?` (`set` default, `add`: value += `step` per second, `clamp`: keep within `min`..`max`), `value_type?` (needed by add/clamp), `group?` | `frozen` (count) — applied at 20 Hz while enabled; `freeze_group {group, enabled}` pauses/resumes a group; `freeze_list` shows mode, group and paused |
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
`watch_event` (`address`,`label?`,`old`,`new` — hex bytes before/after a watched address changed),
`alert_event` (`alert_id`,`address`,`label?`,`value_type`,`condition`,`old`,`new` (hex),`value` (decoded),
`once`,`snapshot?:{address,data}` — a conditional alert fired; the agent also writes it to Echo's
console and, with alerts enabled in its settings, raises an Echo notification naming the alert (no
memory values)). A condition fires on its false→true edge (immediately if it already holds when
added), `changed` on every change; each alert fires at most every 200 ms, and a `once` alert is
removed after its first event. Watches and alerts are cleared on attach/detach.

**Echo menu.** The agent's *EchoDebug* tab in Echo's menu (`ui::`) also shows read-only
*App connected* / *Target attached* checkboxes (re-synced every second) and a *Clear alerts* button.

The agent restores the pre-freeze bytes of every frozen address on `detach`, on target exit and in
`on_unload`, and calls `process::detach()` in `on_unload` (Echo docs teardown rule).

### Emulated debugger (`emu_*`)

One persistent Unicorn x86-64 session (agent: `uc::create_process` / `uc::create`; Linux backend: the
relay's own thread). The target process is never modified. Every reply carries the session state:
`regs:{rax..r15,rip,eflags}`, `rip`, `instructions` (session total), `stop:{reason, ...}`,
`next:[{address,bytes,text}]` (up to 6 instructions at rip), `stack:[{address,value}]` (8 slots at rsp),
`breakpoints:[address]`, `dirty_pages:[address]`.

| verb | request | notes |
|---|---|---|
| `emu_start` | `start`, `code?` (hex: blank emulator), `regs?`, `write?:[{address,data}]`, `breakpoints?:[address]` | replaces any session; a `ret` from the start function stops with `returned` |
| `emu_step` | `count?` (default 1), `timeout_us?` | `stop.reason`: `step`, `count`, `breakpoint`, `returned`, `fault`, `timeout` |
| `emu_run` | `until?`, `max_insns?` (default 1M), `timeout_us?` (≤ 5 s) | adds `until`; a resumed run never stops on the breakpoint it starts on |
| `emu_break` | `address?`, `enabled?` (default true), `clear?` | |
| `emu_set` | `regs?`, `write?:[{address,data}]` | emulator memory only; code writes flush the translation cache |
| `emu_read` | `address`, `size?` (≤ 64 KiB) | untouched pages read through to the process |
| `emu_state`, `emu_close` | — | `emu_close` → `closed: bool` |

`fault` stops carry `error_name`, `fault_address`, `fault_rip` and leave rip on the faulting instruction.
A detach closes process-backed sessions.

#### Emulation options (`emulate`, `emu_start`)

- `trace_regs`: `reg_trace:[{rip, changes:{reg:value}}]` (up to `trace_limit`).
- `stubs`: calls to common APIs are simulated and return to the caller; `api_calls:[{api, address,
  return_to, result, args, note?}]`, `api_call_count`. Windows (agent): VirtualAlloc/Free/Protect,
  GetProcAddress (real export address), GetModuleHandleA/W, LoadLibrary*, Heap*/RtlAllocateHeap,
  malloc/calloc/free, memcpy/memmove/memset, strlen/wcslen, GetTickCount*, QueryPerformanceCounter,
  IsDebuggerPresent / CheckRemoteDebuggerPresent (report "not debugged"), Sleep and a few more.
  Linux (local): libc memcpy/memmove/memset/strlen/strcmp/malloc/calloc/free/puts/getpid/sleep,
  keyed by the export and by every resolved GOT slot (glibc's IFUNCs).
- `layers`: `layers:[{entry, page}]` — the first execution of a page written during the run.
- `on_unmapped: "zero"`: unmapped reads map a zero page and continue; `faults`, `fault_count`.
- `xmm` in, `xmm` out (xmm0..xmm15, 16 bytes each, hex).

Session additions: `emu_watch {address, size?, access? (r|w|rw), enabled?, clear?}` stops with reason
`watchpoint` (`hit:{rip, address, size, access, watch}`); `emu_break` takes `condition` (`rax==0x10`,
`!=`, `<`, `>`, `<=`, `>=`, `&` bit test); `emu_snapshot {name}` / `emu_restore {name}` save and restore
registers, xmm and all emulator memory (8 snapshots, 128 MiB each). `cancel` stops a running emulation.

### Backend extras

| verb | request | reply |
|---|---|---|
| `hash_pages` | `ranges:[{address, size}]` (≤ 64 MiB) | `ranges:[{address, pages, hashes}]` (16 hex digits per page, FNV-1a over qwords, 0 = unreadable). The relay's page monitor uses it |
| `mem_snapshot` | `name?`, `address`+`size` or `module` (≤ 16 MiB) | `name`, `address`, `size` (kept by the backend) |
| `mem_diff` | `name?`, `update?`, `max_ranges?` | `changed_bytes`, `ranges:[{address, size, old, new}]`, `truncated` |
| `mem_snapshot_list` | — | `snapshots:[{name, address, size}]` |
| `ptr_save` | `name` | saves the last `pointer_scan` results (agent: `echodebug/pointers_<name>.json`; local: `<config>/EchoDebug/pointer-maps`) |
| `ptr_compare` | `names:[...]` (`@last` = last scan) | `common` (paths present in every map), `count` |
| `find_instances` | `vtable`, `max?` | `instances:[address]`, `class`, `count`, `truncated` |
| `rtti_name` | `address`, `object?` | `vtable`, `raw`, `name` (MSVC COL on Windows, Itanium type_info on Linux) |
| `xref_scan` | `target`, `module?`, `max?`, `pointers?` | `results:[{address, kind: call\|jmp\|jump\|riprel\|pointer, text?}]` |
| `cancel` | — | `cancelling`; long jobs stop at their next check |
| `stats` | — | `verbs:[{verb, calls, ms}]`, `job`, `job_ms`, `queued_events` |
| `journal` | `limit?`, `clear?` | `entries:[{t, kind: write\|freeze, target, address, old, new}]` |
| `agent_config` | `port?`, `auto_attach?`, `alerts?` | agent only: saved to `echodebug/agent.json` (the port applies on the next load) |

The agent also queues events (newest 500) while the app is away and sends them on reconnect, runs
first scans on four threads, and adds an **EchoDebug** tab to Echo's menu (status, reconnect, cancel,
pause freezes/watches, restore frozen values and detach, alerts).

### Batch verbs

| verb | request | reply |
|---|---|---|
| `sig_scan_batch` | `patterns:[ida]` (≤ 512), `module?` (default main), `max_hits?` (≤ 64) | `results:[{pattern, count, results:[address]}]` (agent: `process::find_signatures`) |
| `disasm_function` | `address`, `max_bytes?` (≤ 16 KiB) | `count`, `size`, `complete`, `results:[{address,length,bytes,text}]` (agent: `zydis::disasm_func`) |
| `read_fields` | `address`, `fields:[{offset, type}]` (u8..u64, i8..i64, f32, f64, ptr; ≤ 1024 within 64 KiB) | `fields:[{offset,type,value}]` from one snapshot (agent: `process::read_buffer`) |

### Lifting, deobfuscation, devirtualization (relay)

Answered by the relay for every backend: code bytes come through `read`, traces through `emulate`.

| verb | request | reply |
|---|---|---|
| `lift_block` | `address`, `max_insns?` (default 256) | `instructions:[{address,text,effect,live}]`, `registers:[{register,value}]`, `stores:[{address,size,value}]`, `end:{kind, condition?, taken?, fallthrough?, opaque?}`, `dead`, `unsupported` |
| `lift_trace` | `trace?:[address]`, or `start`, `end?`, `max_insns?` (default 200000), `regs?`, `write?` (emulated by the relay), `max_listing?` | `registers`, `stores` (strided runs folded: `"rdi + i  for i in 0..0x15"`), `listing` (live instructions; `{loop, times}` markers fold repeated cycles), `conditions:[{address,instruction,condition,taken,opaque}]`, `executed`, `live`, `removed`, `opaque_predicates`, `emulation?` |
| `devirt` | as `lift_trace` | `dispatcher`, `dispatch_targets`, `handler_executions`, `vip_register`, `handlers:[{id,address,executions,length,registers,stores,body}]`, `virtual_trace:[handler id]` |

Model: GPRs start as symbols (`rax`…), reads of memory not written earlier in the run are `[addr]` loads
(`.b`/`.w`/`.d` for 1/2/4 bytes), stores at structurally different addresses are assumed not to alias, and
flags are tracked as the last compare/test. Expressions are simplified structurally (constant folding,
identities, mask/known-bits rules) and, for final values, by sampling-verified MBA replacement (a smaller
candidate over the same ≤ 3 inputs that agrees on 96 random and edge-case inputs). Liveness is a backward slice
from the changed registers and the memory left behind (stack slots below the final `rsp` excluded).
Instructions outside the model turn their outputs into fresh unknowns and are counted in `unsupported`.
The local emulators map a zeroed TLS block for `fs:`/`gs:` (`fs_base`/`gs_base` are settable registers).

### Relay monitors

Built on `modules` / `read`, so they work with every backend:

| verb | request | reply / events |
|---|---|---|
| `module_monitor` | `enabled?` (default true), `interval_ms?` (default 1000) | events `module_loaded` / `module_unloaded` (`name`, `base`, `size`, `ts`) |
| `module_timeline` | — | `enabled`, `entries` (last 500 events) |
| `page_monitor` | `address`, `size?`, `label?`, `interval_ms?`, `enabled?` | `page_changed` events (`address`, `size`, `label`, `count`, `pages`), FNV-1a per 4 KiB page; 64 MiB total |
| `page_monitor_list` | — | `entries:[{address,size,label,interval_ms,changes,last_change}]` |

## Provider verbs (`ui_*`) and authentication

Verbs that start with `ui_` are answered by the desktop app window, because the analyses behind them
(PE parsing, strings, xrefs, crypto, FLIRT, YARA, CFG, IL, …) live in the UI's TypeScript. The app
registers with `{ "type":"provide", "verbs":[...] }` on its `/client` socket. The relay forwards each call as
`{ "type":"provider_call", "call":<n>, "verb", "args" }` and the app answers
`{ "type":"provider_reply", "call":<n>, "verb", "result":{...} }` or `{ ..., "error":"..." }`. Without an app
window the call fails with code `2005`. Status frames carry `"provider": bool`.

Annotation verbs (MCP tools without the `ui_` prefix) read and change the app's own stores:

| Verb (tool) | Args | Result |
|---|---|---|
| `ui_list_names` (`list_names`) | – | `names:[{address,name}]` |
| `ui_set_name` (`set_name`) | `address` (0x hex), `name` (empty removes) | `address`, `name` |
| `ui_list_comments` (`list_comments`) | – | `comments:[{address,comment}]` |
| `ui_set_comment` (`set_comment`) | `address`, `comment` (empty removes) | `address`, `comment` |
| `ui_list_patches` (`list_patches`) | – | `patches:[{id,address,written,before,note,created,reverted}]` |
| `ui_revert_patch` (`revert_patch`) | `patch_id` | `patch_id`, `address`, `restored` (the app writes `before` back via `write`, then marks the patch reverted) |
| `ui_list_signatures` (`list_signatures`) | – | `signatures:[{id,name,module,ida,address,hits,note}]` |

`/client` and `/mcp` require the relay token: `Authorization: Bearer <token>` or `?token=<token>` (browser
WebSockets). Missing or wrong tokens get `401`. The token lives in `<config>/EchoDebug/relay-token`
(`%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or `~/.config` elsewhere; created with mode 0600);
`ECHODEBUG_TOKEN` overrides it and `ECHODEBUG_AUTH=0` disables the check. `/agent`, `/ext` and `/health`
stay open (Echo cannot send headers; those endpoints only receive requests). The desktop app can
regenerate the stored token (Settings or the MCP Server panel); the running relay switches to it at once
(`Relay::set_token`), already-open sockets stay connected, and MCP clients must be re-added.

## Versioning

`protocol` is bumped on incompatible changes. The app shows a warning when the agent's `version`
differs from the app version and (re)installs the bundled agent into `%APPDATA%\scripts\echo_debug.as`.

## MCP surface

`POST /mcp` speaks JSON-RPC 2.0 (single messages and batches; notifications get `202 Accepted`).
Supported methods: `initialize` (advertises `tools`, `prompts`, `resources` (with `subscribe`),
`completions` and `logging` capabilities plus `instructions`), `ping`, `tools/list`, `tools/call`,
`prompts/list`, `prompts/get`, `resources/list`, `resources/templates/list`, `resources/read`,
`resources/subscribe`/`unsubscribe`, `completion/complete`, `logging/setLevel`.

**Tools** carry `title`, `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`, derived from the verb) and an object `outputSchema`; results add `structuredContent`
(the reply object) next to the text block.

**Call policy.** The app pushes `{ "type":"mcp_policy", "mode":"allow"|"ask"|"readonly", "allow":[tool],
"deny":[tool], "audit":bool }` (omitted fields keep their value; the reply echoes the policy and
`audit_path`). Deny and allow lists apply to every tool. `ask` and `readonly` gate the calls that change
the target (`write`, `freeze`, `ui_revert_patch`) and `dump`: `readonly` refuses them, `ask` sends the app window a
`ui_approve` provider call (`tool`, `verb`, `arguments` → `approved: bool`) and refuses when no window
answers. Refusals are tool errors with code `4003`; the call log records `outcome: ok | error | denied`.
With `audit` on, every call is appended to `<config>/EchoDebug/mcp-audit.jsonl`; `mcp_audit_export` returns
the in-memory log as JSONL plus the audit file.

**Resource templates:** `echodebug://memory/{address}/{size}`, `echodebug://disasm/{address}`,
`echodebug://module/{name}/pe|exports|strings`, `echodebug://names` (answered by the app window;
`+` in a module-relative address may be sent as `%2B`).

**Completion** (`completion/complete`): `module`/`name` arguments complete module names, address-like
arguments complete named addresses (app window) and `module+0x`, `value_type` and `format` their enums.

**stdio.** `echodebug-relay --stdio [port]` speaks newline-delimited JSON-RPC on stdin/stdout. If a relay
already listens on the port it forwards to its `/mcp` with the token from the config directory; otherwise
it becomes the relay on that port and also writes notifications to stdout.

**Server-sent events.** `GET /mcp` with `Accept: text/event-stream` opens a notification stream:
`notifications/resources/updated` for `echodebug://status` and `echodebug://target/modules` on every status
change, and `notifications/message` (logger = event name) for agent and debugger events such as
`watch_event`, `patched`, `dbg_stop`. A single `tools/call` sent with `Accept: text/event-stream` and
`params._meta.progressToken` is answered as an event stream: `notifications/progress` for each agent
`progress` event (scans, pointer scans), then the JSON-RPC result. Every tool in `src/lib/tools.json` maps one-to-one onto a verb
above; the tool's `verb` becomes the request `type`, the tool's `input_schema` is passed through as
the request body, and the reply is returned as pretty-printed JSON in a single text content block
(`isError` is set when the relay replied with an error frame). Each `tools/call` is appended to a
200-entry ring buffer, exposed as the `echodebug://mcp/log` resource and the local `mcp_log` verb.

Prompts (`prompts/get` returns ready-to-use user messages with arguments substituted):
`explain_function` (address), `find_pattern` (pattern, module?), `find_string` (text, module?),
`pointer_path` (target, max_depth?), `scan_value` (value_type, value), `triage_module` (module),
`find_vtable` (class, module?), `make_signature` (address), `diff_snapshots` (address, size?),
`unpack_module` (module), `decrypt_strings` (address), `deobfuscate_function` (address, end?),
`devirtualize` (address, max_insns?), `find_value_references` (value_type, value), `rebuild_class`
(address, size?), `update_signatures_after_patch` (module?). Arguments the caller leaves out read
"(not given)". Prompt texts name tools in backticks; a relay unit test checks that every one of them
exists in `src/lib/tools.json`.

Resources: `echodebug://status`, `echodebug://tools`, `echodebug://mcp/log`,
`echodebug://target/modules` (fails when no memory server is connected). Module monitor events also send
`notifications/resources/updated` for `echodebug://target/modules`.

The tool set covers the whole backend: process control (`status`, `list_processes`, `attach`,
`detach`, `is_alive`), memory (`read_memory`, `read_memory_batch`, `write_memory`, `query_region`,
`memory_regions`), analysis (`disassemble`, `enumerate_functions`, `signature_scan`,
`signature_scan_masked`, `string_scan`, `resolve_relative`, `rtti_resolve`, `rtti_resolve_batch`,
`resolve_export`, `peb_walk`), scanning (`value_scan_first`, `value_scan_next`, `value_scan_results`,
`value_scan_clear`, `pointer_scan`), emulation (`emulate`), freezing (`freeze_value`, `list_frozen`),
watching (`watch_add`, `watch_remove`, `list_watched`), alerts (`alert_add`,
`alert_remove`, `alert_list`),
dumping (`dump_module`) and socket housekeeping (`reopen_native_socket`).

Because the relay routes by verb, an MCP client gets exactly the same behaviour as the desktop UI.
