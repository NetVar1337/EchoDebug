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
| `/sync` | IDA / Ghidra / Binary Ninja plugins (`integrations/`) | Disassembler sync, token-protected like `/client`. See [Disassembler sync](#disassembler-sync-sync). Many peers. |
| `/mcp` | MCP clients | Streamable HTTP: `POST` (JSON or SSE answers), `GET` (a legacy session's event stream), `DELETE` (ends a legacy session). Token-protected. See [MCP surface](#mcp-surface). Tools are defined in `src/lib/tools.json`. |
| `GET /mcp/health` | MCP clients that probe | `{ok, server, version, endpoint, protocolVersions, latest, transports, auth, authorized, appWindow, backend, tools}`; no token needed, `authorized` says whether a presented one is right (null when none) |
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

More local verbs feed the app's MCP panel: `mcp_log` → `{ "type":"mcp_log_result", ..., "entries":[...] }`
(ring buffer of the last 200 `tools/call` requests the relay saw), `mcp_meta` → serverInfo, protocol
versions, prompt and resource catalogs, tool counts, `mcp_sessions` → the connected MCP clients,
`mcp_disconnect {session}` and `mcp_test_call {name, arguments}` (see [MCP surface](#mcp-surface)).

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
| `dbg_all_regs` | – | `threads:[{tid, regs}]`, `was_running` (stops the session for the read if it was running, then resumes) |

**Architectures.** x86-64 is the default. `disassemble`, `disasm_function` and `disasm_bytes` take
`arch` (`"x86_64"` | `"arm64"`, aliases `aarch64`, `x64`, …). The lines keep their shape
(`address`, `length` = 4, `bytes`, `text`); PC-relative operands are printed as absolute addresses
(`bl 0x210168`, `cbz x9, 0x210194`, `adrp x20, 0x220000`) and an `add`/`ldr`/`str` that completes an
`adrp` pair ends in `  ; 0x<resolved address>`; undecodable words read `.inst 0x…`; the reply adds
`"arch":"arm64"`. With an Echo upstream the relay serves `arch:"arm64"` itself (Echo's disassembler
is x86-64 only): it reads the code with `read` and decodes it (size 0 / `disasm_function`: page by
page up to the first ret, at most 64 KiB). The local backend detects the architecture from the
module's ELF header when `arch` is omitted, reports `arch` per module in `modules_result` and on the
attach target, and `emulate` with `arch:"arm64"` (or a start address inside an AArch64 module) runs
Unicorn's AArch64 CPU: `regs` takes/returns `x0`…`x30` (`fp`, `lr` accepted), `sp`, `pc`, `nzcv`,
`tpidr_el0`; `v` (`{"v0":"<32 hex>"}`) or `simd:true` adds `v0`…`v31` to the reply; `x30` starts at
`end` so a `ret` ends the run; `mem_log` entries and `faults` carry `pc` instead of `rip`; `stubs`,
`layers`, `trace_regs` and `xmm` are x86-64 only and refused. There is no ARM64 debugger backend
(`dbg_*` is x86-64 ptrace), and the emulated debugger (`emu_*`) and lifter are x86-64 only.

Debugger events: `{ "type":"event", "event":"dbg_stop", "reason":"breakpoint"|"hardware"|"step"|"signal"|"trap"|"pause", "tid", "address", "regs", "slot?", "watch?", "signal?" }`
and `{ "type":"event", "event":"dbg_exit", "pid", "code?"|"signal?" }`.

### Threads, call stacks, handles (relay)

Echo's script API has no thread enumeration, thread context or handle access, so these verbs are
served by the relay: on the Linux local backend (`local_threads.rs`), and on Windows when no Echo agent
is connected (`win_threads.rs`, `pid` argument or the attached target). **While the Echo agent is
connected they fail with code `2006`** ("the Echo backend can't list threads, call stacks or handles").

| verb | request | reply |
|---|---|---|
| `threads` | `stacks?` (bool, default false), `registers?` (default true; false lists without stopping anything), `max_frames?` (default 64, ≤ 512), `pid?` (Windows) | `pid`, `platform` (`linux`\|`windows`), `registers_from` (`ptrace`\|`debugger`\|`GetThreadContext`), `threads:[{tid, name?, main?, state, state_name, wait?, priority, nice? \| base_priority?, time_ms, start?, start_label?, start_source?, teb? (Windows), tls? (Linux fs_base), rip?, rsp?, registers?, registers_error?, suspend_count? (Windows), frames?}]` |
| `stack` | `tid` (Linux default: the main thread), `max_frames?`, `pid?` (Windows) | `tid`, `registers`, `registers_from`, `frames` |
| `handles` | `pid?` (Windows) | `handles:[…]`: Linux `{handle (fd), type (file\|socket\|pipe\|device\|eventfd\|epoll\|…), name (link target), position, flags:[O_*]}` from `/proc/<pid>/fd` + `fdinfo`; Windows `{handle, type (object type name), name?, access, object, attributes}` from `SystemExtendedHandleInformation`, `truncated` |

A frame is `{index, address, sp, module, offset, symbol, symbol_offset, method, guessed}`. `method` says
how the frame was recovered from the one below it: `context` (the thread's registers), `pdata` (PE
`.pdata` + UNWIND_INFO, interpreted like `RtlVirtualUnwind`: all UWOP codes, chained info, machine
frames, the prolog offset and `ret` / tail-call epilogs), `leaf` (PE function without unwind data),
`cfi` (ELF `.eh_frame` through `PT_GNU_EH_FRAME`, DWARF CFA programs and expressions), or the
fallbacks `frame-pointer` and `stack-scan` (a return address preceded by a `call`), which set
`guessed: true`. Symbols are the nearest export (PE, bounded by the `.pdata` function) or ELF
`.symtab`/`.dynsym` entry; the app shows the user's names first.

How registers are read: on Linux every thread is `PTRACE_SEIZE`d, `PTRACE_INTERRUPT`ed, read with
`GETREGS`, unwound while still stopped, then detached (signals that arrived meanwhile are re-delivered);
while a `dbg_*` session owns the threads, the registers come from it (`dbg_all_regs`). On Windows each
thread is `SuspendThread`ed, read with `GetThreadContext`, unwound and `ResumeThread`ed. Thread start
addresses: Windows `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` and the TEB from
`ThreadBasicInformation`; Linux the entry point (`AT_ENTRY`) for the main thread and, for the others,
the outermost frame below glibc's `start_thread` / `clone3` on the unwound stack. Nothing is written to
the target.

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

### Time-travel traces (relay)

Recorded and stored by the relay for every backend (`trace.rs`, `trace_rec.rs`, `trace_emu.rs`). A trace is
one thread's run, step by step: step `i` executed the instruction at `pc(i)`, changed some registers and
read / wrote memory (reads keep the bytes read, writes the bytes before and after). **Position** `p`
(0..=`steps`) is the state *before* step `p`; `p == steps` is the end. Registers: rax…r15, rip, eflags,
fs_base, gs_base. Trace ids travel as `trace` in requests and `trace_id` in replies (the relay owns `id`).

| verb | request | reply |
|---|---|---|
| `trace_record` | `source` (`emu` default \| `ptrace`), `max_steps?` (10000, ≤ 5M), `until?` (address), `max_mb?` (64, ≤ 1024), `keyframe?` (256), `name?`, `save?` (true), `tid?` (ptrace), `start?`/`code?`/`regs?`/`write?` (emu: `emu_start` first), `timeout_us?` | `trace:{trace_id, name, source, steps, stop_reason (count, until, returned, size limit, cancelled, fault, breakpoint, signal …), truncated, keyframe, unique_pcs, accesses, writes, initial_regs, final_regs, saved}` plus, for `emu`, the session state as `emu_*` replies carry it |
| `trace_cancel` / `trace_status` | — | `cancelling` / `recording`, `steps` |
| `trace_list` | — | `traces:[summary + file_size]`, `current`, `dir` |
| `trace_info` | `trace?` | the summary (default the current trace; the list when there is none) |
| `trace_query` | `trace?`, `kind`, `pos?` (default the end), kind arguments | see below |
| `trace_export` / `trace_import` | `trace?` / `data` (base64 `.edt`), `name?` | `data`, `size` / the imported summary |
| `trace_delete` | `trace` | `removed` |

`trace_query` kinds: `reg_at` (`reg?` → `value`, else `regs`), `mem_at` (`address`, `size` ≤ 64 KiB → `data`, hex
with `??` for bytes the trace never touched; a byte's value is the newest write before `pos`, else what its
first access saw), `last_write` (`address`, `size?`, `changed_only?` (true: skip writes that stored the same
bytes) → `write:{step, pc, address, size, old, new, text}` or null), `writes_to` / `reads_of` (`address`, `size?`,
`limit?` → `writes` / `reads`, `total`), `executions_of` (`address` → `steps`, `total`), `seek` (`address`,
`direction` forward\|back → the next / previous `step` from `pos`), `reg_series` (`reg`, `from?`, `to?`, `max?` →
`points:[[pos, value]]`, every change or a sampled step function), `step` (`pos` → `pc`, `bytes`, `text`, `changes`,
`accesses`, `regs_before`), `steps` (`from`, `count` ≤ 5000 → listing), `taint` (`reg`, or `address`+`size`,
`max_hops?` → `hops:[{id, parent, step, pc, text, loc, value, kind, sources}]`: the producer of the value, then
the producers of its sources; `kind` `mov` / `arith` / `const` (immediate, `xor r,r`) / `initial` (there before the
trace) / `unmodeled` (an instruction the walk does not follow)), `touched` (merged ranges with read/write counts).

Sources. **emu**, local backend: the Emu Debugger's Unicorn thread records with code and memory hooks
(`emu_record`; breakpoints, watchpoints, stand-ins and `cancel` keep working). **emu**, Windows agent: the relay
drives the agent's session with `emu_step {count:1}` and reads each instruction's memory operands (decoded with
iced-x86 from the step's registers) with `emu_read` before and after: same trace, a few round trips per
instruction. **ptrace** (Linux, after `dbg_attach`): `dbg_record` on the debugger thread single-steps the focused (or
`tid`) thread the same way, stepping over int3 breakpoints with their original bytes; writes the kernel makes
during a system call are not seen, and a thread blocked in a call ends the recording. While recording the relay
broadcasts `{event:"trace_progress", steps, max_steps}` every 250 ms and `{event:"trace_done", trace_id, steps,
stop_reason}` at the end. MCP: `trace_record` is stateful and gated by the ask / read-only policies (the ptrace
source runs the real thread); `trace_info` and `trace_query` are read-only.

**`.edt` file format** (little-endian, LEB128 varints, signed values zigzag): `"EDTRACE1"`, version `1`,
JSON header (length-prefixed: name, source, created_ms, pid, tid, stop_reason, truncated, steps, keyframe,
regs), the initial register file (20 × u64), the step count, then per step: Δpc (signed), a register change
mask, `new XOR old` for each changed register, the access count and per access `len << 1 | write`, Δaddress
(signed), the bytes (old, plus new for writes); then the instruction bytes per pc, the keyframes (full register
file every `keyframe` steps, XOR-chained; checked against the steps on load) and an FNV-1a 64 checksum.

### Relay monitors

Built on `modules` / `read`, so they work with every backend:

| verb | request | reply / events |
|---|---|---|
| `module_monitor` | `enabled?` (default true), `interval_ms?` (default 1000) | events `module_loaded` / `module_unloaded` (`name`, `base`, `size`, `ts`) |
| `module_timeline` | — | `enabled`, `entries` (last 500 events) |
| `page_monitor` | `address`, `size?`, `label?`, `interval_ms?`, `enabled?` | `page_changed` events (`address`, `size`, `label`, `count`, `pages`), FNV-1a per 4 KiB page; 64 MiB total |
| `page_monitor_list` | — | `entries:[{address,size,label,interval_ms,changes,last_change}]` |

### PDB symbols (relay)

Relay-local, any backend; blocking work runs on a worker thread. `key` is the symbol-store key of the
image's CodeView (RSDS) record: GUID (32 hex digits, no dashes) followed by the age in hex.

| verb | request | reply |
|---|---|---|
| `pdb_symbols` | `pdb` (file name) + `key`, or `path`; `symbol_path?` (`_NT_SYMBOL_PATH` syntax), `use_env?` (default true: also `_NT_SYMBOL_PATH` / `_NT_ALT_SYMBOL_PATH`), `image_path?` (its folder is searched), `servers?`, `download?` (default **false**), `allow_mismatch?`, `max?` | `path`, `source` (`symbol path` / `cache` / `server` / `path` / `mismatch`), `guid`, `age`, `key`, `expected_key`, `matched`, `machine`, counts (`count`, `functions`, `types`, `lines`, `files`), `tried`, `symbols:[{rva,name,kind,size,type?,ret?,cc?,params?:[{name,type,size}],mangled?}]`. Not found locally: `success:false, found:false, code:3004`, `tried`, `mismatches:[{path,key}]` |
| `pdb_fetch` | as `pdb_symbols` (name + key) | a matching local copy: `state:"done", path`; else starts a background download: `state:"downloading", job` |
| `pdb_progress` | — | `jobs:[{job,pdb,key,state:"downloading" \| "done" \| "error",done,total,url,path,error,seconds}]` |
| `pdb_image` | `image_path` (a PE on disk) | `pdb`, `pdb_path`, `guid`, `age`, `key` |
| `pdb_types` | `path`, `filter?`, `max?` | `total`, `types:[{index,name,kind,size,fields or target}]` (struct/class/union/interface/enum/typedef) |
| `pdb_type` | `path`, `name` or `index`, `depth?` | `index`, `name`, `kind`, `size`, `fields:[{name,offset,size,type,type_index,kind:"member" \| "base" \| "vtable",category,scalar?,udt?,points_to?,count?,elem?,bit_pos?,bit_len?}]`, enum `values`/`underlying`, `nested:[…same…]` (types embedded by value), `text` |
| `pdb_lines` | `path`, `rva`, `size?` | `lines:[{rva,size,file,line}]`, `function` (the symbol containing `rva`) |

Lookup order: the image's folder, the symbol path's folders (`<dir>/<pdb>` and `<dir>/<pdb>/<key>/<pdb>`),
its stores and the app cache (`<config>/EchoDebug/symbols`) in store layout, each also as a compressed
`<pdb minus last char>_` cabinet (expanded into the download store). Every candidate's GUID/age is checked.
Downloads try `<server>/<pdb>/<key>/<pdb>`, then the `.pd_` name, and go to the first `srv*`/`cache*` store of
the symbol path, else the app cache. Servers: `servers`, then the symbol path's `srv*` URLs, then
`ECHODEBUG_SYMBOL_SERVERS` (`;`-separated), else `https://msdl.microsoft.com/download/symbols`.

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

Module tables read from the loaded image (every backend):

| Verb (tool) | Args | Result |
|---|---|---|
| `ui_tls_callbacks` (`tls_callbacks`) | `module?` | `directory` (raw data range, index, callbacks array), `callbacks:[{index,address,label,name?,section,executable,inModule}]` |
| `ui_exception_handlers` (`exception_handlers`) | `module?`, `limit?` (default 2000) | `functions_with_unwind_info`, `chained_fragments`, `handler_routines:[{address,name,kind,functions}]`, `functions:[{function,end,flags,handler,handler_name,kind,handler_data,scopes?:[{try_begin,try_end,kind:"except"\|"finally",filter?,target?,finally?}],scopes_heuristic?}]`, `vectored_handlers` (why they are not listed) |

Vectored exception handlers are not listed: ntdll keeps them in the private `LdrpVectorHandlerList`
with pointers encoded by `RtlEncodePointer` (a per-process cookie), so they cannot be enumerated reliably
without undocumented internals.

Heap explorer verbs (read-only; the walk is cached per process, `refresh:true` walks again):

| Verb (tool) | Args | Result |
|---|---|---|
| `ui_heaps` (`heaps`) | `refresh?` | `platform` (`glibc`/`windows`), `source` (how the heaps were found), `version?`, `heaps:[{id,kind,label,address,committed,reserved?,in_use,in_use_count,free,free_count,largest_free,fragmentation,chunks,counters,ranges,notes}]`, `bins:[{heap,kind,index,chunk_size,length,count?,total?,owner?,error?}]` (non-empty only), `errors:[{heap,address,message}]`, `notes`, `truncated` |
| `ui_heap_chunks` (`heap_chunks`) | `heap?`, `state?` (a state, `free` or `used`), `min_size?`, `max_size?`, `offset?`, `limit?` (≤ 2000, default 200), `rtti?`, `refresh?` | `total`, `offset`, `limit`, `next_offset`, `chunks:[{address,user,size,user_size,state,flags,heap,bin?,note?,preview?,type?}]` |
| `ui_heap_find` (`heap_find`) | `address`, `refresh?` | `found`, `chunk`, `offset_in_chunk`, `offset_in_user`, `heap`, `bins:[{kind,index,position,length}]` |

Chunk states: `in-use`, `free`, `top`, `fencepost`, `mmapped`, `internal` (the allocator's own, e.g.
`tcache_perthread_struct`), `tcache`, `fastbin`, `unsorted`, `smallbin`, `largebin` (glibc), `lfh` (a backend
block holding an LFH subsegment; `note` has its busy count) and `large` (VirtualAlloc / segment-heap large
allocations). Everything is read through the `read` verb, so the Windows heaps work on the Echo backend.

`/client` and `/mcp` require the relay token: `Authorization: Bearer <token>` or `?token=<token>` (browser
WebSockets). Missing or wrong tokens get `401`. The token lives in `<config>/EchoDebug/relay-token`
(`%APPDATA%` on Windows, `$XDG_CONFIG_HOME` or `~/.config` elsewhere; created with mode 0600);
`ECHODEBUG_TOKEN` overrides it and `ECHODEBUG_AUTH=0` disables the check. `/agent`, `/ext`, `/health`
and `/mcp/health` stay open (Echo cannot send headers; those endpoints only receive requests or report
status). MCP over stdio needs no token from the client: the stdio process reads it from the config
directory itself. The desktop app can regenerate the stored token (Settings or the MCP Server panel);
the running relay switches to it at once (`Relay::set_token`), already-open sockets stay connected, and
HTTP MCP clients must be updated (MCP Server panel → Connect a client → Update).

On start the desktop app deletes the API key the removed in-app assistant may have stored in that
directory (`anthropic-key.dpapi` on Windows, `anthropic-key` elsewhere).

## Disassembler sync (`/sync`)

Disassembler plugins connect to `/sync` with the relay token (`Authorization: Bearer` or `?token=`;
browser origins are refused) and send `hello` first: `{ "type":"hello", "tool":"ida"|"ghidra"|"binja",
"version", "file", "protocol":1, "modules":[{ "name", "base", "size" }] }` → `{ "type":"hello_result",
"peer", "protocol":1, "directions" }`. Then, both ways, `cursor` / `name` / `comment` frames with `module`
(file name), `rva` (`"0x…"`) and `name` / `comment` (empty removes); the relay also sends `types`
(`decls`, `names`) and `config` (`directions`); plugins may send `modules` and `ping` (→ `pong`). Frames
from the relay carry `from`. Details and the plugins: [integrations/README.md](integrations/README.md).

The relay keeps the hub state (sync.rs): direction toggles, a module map (disassembler file name → live
module), the current value of every synced name and comment with its writer (**last writer wins**; a
write that replaces another side's value is logged as a conflict; a write equal to the current value
is dropped, as is a cursor equal to the last one, so applied changes do not echo), and a 300-entry log.

App verbs on `/client` (relay-local):

| verb | request | reply |
|---|---|---|
| `sync_status` (MCP `sync_status`, read-only) | `log_limit?` (default 100, max 300) | `protocol`, `peers:[{id,tool,version,file,modules:[{name,base,size,live}],connected_at,last_seen}]`, `directions`, `map`, `cursor:{module,rva,from,ts}`, `marks`, `log:[{seq,ts,kind,dir:"in"|"out"|"conflict"|"info",from,module,rva,text}]` |
| `sync_config` | `directions?:{cursor_in,cursor_out,names_in,names_out,comments_in,comments_out,types_out}`, `map?:{toolModule: liveModule ("" removes)}`, `replace_map?` | the status (log omitted) |
| `sync_send` | `kind: cursor\|name\|comment\|types`, `module`, `rva`, `name` / `comment` / `decls`+`names` | `peers` (tools reached) |
| `sync_log` | `text`, `kind?`, `dir?` (`conflict`), `module?`, `rva?` | — (adds an entry, e.g. a name the app overwrote) |

`*_in` is disassembler → EchoDebug, `*_out` EchoDebug → disassemblers (tool-to-tool forwarding counts as
out). Broadcasts to every `/client`: `{ "type":"sync_event", "kind":"cursor"|"name"|"comment", "module",
"rva", "name"|"comment", "from" }`, `{ "type":"sync_event", "kind":"log", "entry" }`, and `kind:"peers"` /
`"config"` when those change. `sync_event` frames are not MCP notifications.

## Versioning

`protocol` is bumped on incompatible changes. The app shows a warning when the agent's `version`
differs from the app version and (re)installs the bundled agent into `%APPDATA%\scripts\echo_debug.as`.

## MCP surface

The relay is an MCP server on two transports: **Streamable HTTP** at `/mcp` (token-protected, see
[authentication](#provider-verbs-ui_-and-authentication)) and **stdio** (`echodebug-relay --stdio [port]`,
or `EchoDebug --mcp-stdio [port]` from the app executable). Code: `relay/src/mcp_server.rs` (protocol),
`mcp.rs` (annotations, policy, templates, completion), `mcp_bridge.rs` (stdio bridge),
`mcp_clients.rs` (the panel's client config writer).

### Protocol versions

| Version | Era | Notes |
|---|---|---|
| `2026-07-28` (latest) | stateless | every request carries `params._meta` with `io.modelcontextprotocol/protocolVersion` and `…/clientCapabilities` (required) and `…/clientInfo`, `…/logLevel` (optional) |
| `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05` | initialize-based | `initialize` negotiates: the requested version when it is one of these, else `2025-11-25` |

A request with a `_meta` protocolVersion follows the 2026-07-28 rules; an unsupported version gets
`-32022 Unsupported protocol version` with `data: {supported: [newest first], requested}` (HTTP 400).
`server/discover` answers `{supportedVersions, capabilities, instructions, _meta: {serverInfo}, ttlMs,
cacheScope}`, with or without `_meta` (the dual-era probe). Requests with neither `_meta` nor a session
use the `MCP-Protocol-Version` header's version, else `2025-11-25` result shapes (they only add fields
older clients ignore).

Per version: `title` on tools, prompts and resources, `outputSchema`, `structuredContent`,
`resource_link` results and elicitation exist from 2025-06-18; the elicitation `mode` field from
2025-11-25. 2026-07-28 results carry `resultType` (`complete` or `input_required`) and
`_meta["io.modelcontextprotocol/serverInfo"]`; list results and `resources/read` add `ttlMs` and
`cacheScope`. Resource-not-found is `-32002` before 2026-07-28 and `-32602` (with `data.uri`) after.

### HTTP

| Request | Answer |
|---|---|
| `POST`, 2026-07-28 request | headers `MCP-Protocol-Version` (= the `_meta` version), `Mcp-Method` (= method) and, on `tools/call`, `prompts/get`, `resources/read`, `Mcp-Name` (= `params.name` / `params.uri`; `=?base64?…?=` allowed) are required: missing or different → 400 `-32020` HeaderMismatch. Missing clientCapabilities → 400 `-32602`. Unknown method (the initialize-era `initialize`, `logging/setLevel`, `resources/subscribe` too) → 404 `-32601` |
| `POST initialize` | the result plus an `Mcp-Session-Id` header; the session's requests send it back (an ended or unknown session → 404: initialize again) |
| `POST`, other legacy request | `MCP-Protocol-Version`, when sent, must be a supported version (else 400 `-32022`) |
| `POST`, notification or client response | `202 Accepted` |
| `POST`, batch (array) | legacy only: each request answered, 2026-07-28 messages refused (`-32600`) |
| `GET` + `Accept: text/event-stream` | the event stream of the session named by `Mcp-Session-Id` (every event without one) |
| `GET` without SSE accept | 405 with `Allow` and a pointer to `/mcp/health` |
| `DELETE` + `Mcp-Session-Id` | ends the session (204; 404 when unknown) |
| `OPTIONS` | CORS preflight for the origins the relay accepts (the app's web view, localhost dev servers); their responses carry `Access-Control-Allow-Origin` and expose `Mcp-Session-Id` |

A request is answered as **SSE** (`text/event-stream`, `X-Accel-Buffering: no`) when the client accepts
it and the request needs a stream: a `progressToken`, a 2026-07-28 `tools/call` with `logLevel`, a legacy
`tools/call` that may need an elicitation, or `subscriptions/listen`; otherwise as one JSON object.
JSON-RPC errors: `-32700` parse error (400), `-32600` invalid request (no `"jsonrpc":"2.0"`, a null or
non-scalar id, an empty batch), `-32601`, `-32602` (bad params, unknown tool or prompt, a missing
required prompt argument, an invalid cursor or requestState), `-32603` (a resource the backend could not
read). HTTP refusals carry a JSON-RPC error without id: 401 (code `401`, a message that says whether the
token is missing or wrong and where to copy it; `WWW-Authenticate: Bearer realm="EchoDebug"`) and 403
(a foreign `Origin`).

### Methods and features

`ping`, `server/discover`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get`, `resources/list`,
`resources/templates/list`, `resources/read`, `completion/complete`; legacy also `initialize`,
`logging/setLevel`, `resources/subscribe` / `unsubscribe`; 2026-07-28 also `subscriptions/listen`.
Capabilities: `tools {listChanged: true}`, `prompts {listChanged: false}`, `resources {subscribe: true,
listChanged: false}`, `logging`, `completions`.

**Pagination.** The four list methods take `cursor` and return `nextCursor` while more remain. A page
holds 500 entries, so every list fits one page today and clients that ignore cursors still see
everything; a cursor of another list or a malformed one is `-32602`.

**Tool set.** `tools/list` lists what a client can use now: `ui_*` tools only while an app window is
connected, the thread tools (`list_threads`, `thread_stack`, `list_handles`) not under the Echo backend,
and nothing the call policy always refuses (the deny list, tools missing from a non-empty allow list,
gated tools under `readonly`). When that set changes (window, backend, policy) the server sends
`notifications/tools/list_changed`. `tools/call` still takes every tool name and explains a refusal.

**Tools** carry `title`, `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`, derived from the verb; `ui_load_symbols` is the one open-world tool: it may download from
the symbol servers, while `ui_pdb_symbols`, `ui_pdb_types`, `ui_pdb_type` and `ui_pdb_lookup` only read local
copies and `ui_import_pdb_type` changes the Structs catalog) and an `outputSchema`: an object schema with
the reply's fields (`status`, `list_processes`, `list_modules`, `read_memory`, `disassemble`,
`dump_module` describe theirs) and none required, so error replies (`code`, `message`, `detail`) conform
too. A result is the reply as pretty JSON text, `structuredContent` (the reply object), `isError`, and on
success `resource_link` items: `read_memory` → `echodebug://memory/{address}/{size}`, `disassemble` →
`echodebug://disasm/{address}`, `list_modules` → `echodebug://module/{name}/pe` (first 16 modules),
`dump_module` → the dump's `file://` URI. A missing required argument is a tool error the model can fix.

**Logging.** Legacy sessions set a level with `logging/setLevel` (`debug` … `emergency`; default
`info`); their event stream carries `notifications/message` at or above it for agent and debugger events
(`watch_event`, `patched`, `dbg_stop`, `module_loaded`, …; logger = event name). A 2026-07-28 request
opts in with `_meta["io.modelcontextprotocol/logLevel"]`; its own SSE answer then carries the messages
of that call (the relay's routing notes, backend events while it runs), never the listen stream.

**Progress.** A request with `_meta.progressToken` answered as SSE gets `notifications/progress`
(`progress` = `done`, `total`, `message` = the job) for each backend `progress` event while it runs,
strictly increasing, then the result.

**Cancellation.** `notifications/cancelled {requestId}` (a legacy HTTP session, the stdio bridge, stdio)
and closing a request's SSE stream (2026-07-28) stop the call; a cancelled backend tool call also sends
`cancel` to the backend so its scan, pointer scan or emulation stops. A cancelled plain-JSON request is
answered `204`.

**Change notifications.** Legacy: the session's `GET /mcp` stream (stdio: stdout after `initialize`)
carries `notifications/tools/list_changed`, `notifications/resources/updated` for the URIs it subscribed
(`echodebug://status` and `echodebug://target/modules` change on every status change and module event)
and log messages; a `GET` without a session gets every update. 2026-07-28: `subscriptions/listen
{notifications: {toolsListChanged, resourceSubscriptions}}` answers as a long-lived stream: first
`notifications/subscriptions/acknowledged` with the filter the server honours (prompt and resource list
changes never happen and are left out; only the two subscribable URIs are kept), then the matching
notifications, each with `_meta["io.modelcontextprotocol/subscriptionId"]` = the request id.
Disconnecting the client in the panel ends it with a `{resultType: "complete"}` result.

**Sessions and clients.** The relay keeps a table of clients: each legacy session (id, transport
`http` / `stdio` / `stdio (bridged)`, negotiated version, `clientInfo` and capabilities from
`initialize`) and each 2026-07-28 client by its `clientInfo`. The `/client` verb `mcp_sessions` lists
`{id, transport, era: session|stateless, protocolVersion, client, elicitation, created, last_seen, calls,
last_call: {tool, ts, outcome}, streams, log_level}`; `mcp_disconnect {session}` ends one (its streams
close, its in-flight calls stop, a legacy session id gets 404 afterwards). At most 64 are kept.

**Call policy.** The app pushes `{ "type":"mcp_policy", "mode":"allow"|"ask"|"readonly", "allow":[tool],
"deny":[tool], "audit":bool, "elicit":bool }` (omitted fields keep their value; the reply echoes the
policy and `audit_path`). The panel's tool profiles are policies: *Read-only analysis* = `readonly` with
every tool that is not read-only denied except `attach`, `detach`, `cancel_job`; *Reverse engineering* =
`ask`; *Full control* = `allow`. Deny and allow lists apply to every tool. `ask` and `readonly` gate the
calls that change the target (`write`, `freeze`, `ui_revert_patch`), `dump` and `trace_record` (its
ptrace source runs the real thread): `readonly` refuses them; `ask` asks the user:

- when `elicit` is on (default) and the client declared form elicitation (2025-06-18 and later):
  2026-07-28 → the call returns `{resultType: "input_required", inputRequests: {echodebug_approval:
  {method: "elicitation/create", params: {mode: "form", message, requestedSchema: {allow: boolean}}}},
  requestState}`; the client retries the same call with `inputResponses.echodebug_approval` and the
  `requestState`, which is single-use, expires after 5 minutes and only matches the same tool and
  arguments (else `-32602`). Earlier versions → an `elicitation/create` request on the call's SSE
  stream (or stdout), answered by the client's response (POSTed, `202`); no answer within 100 s denies;
- otherwise the app window gets a `ui_approve` provider call (`tool`, `verb`, `arguments` →
  `approved: bool`); no window → refused.

Refusals are tool errors with code `4003`; the call log records `outcome: ok | error | denied`, the
client, session, transport and `approved_via`. With `audit` on, every call is appended to
`<config>/EchoDebug/mcp-audit.jsonl`; `mcp_audit_export` returns the in-memory log as JSONL plus the
audit file. `mcp_test_call {name, arguments}` runs one call exactly like a 2026-07-28 client without
elicitation (policy and approval included, logged with transport `panel`) and returns `{result, ms}`.

**Resource templates:** `echodebug://memory/{address}/{size}`, `echodebug://disasm/{address}`,
`echodebug://module/{name}/pe|exports|strings`, `echodebug://names` (answered by the app window;
segments are percent-decoded, so `+` in a module-relative address may be sent as `%2B`).

**Completion** (`completion/complete`): `module`/`name` arguments complete module names, address-like
arguments complete named addresses (app window) and `module+0x`, `value_type` and `format` their enums.

### stdio

`echodebug-relay --stdio [port]` (and `EchoDebug --mcp-stdio [port]`) speaks newline-delimited JSON-RPC
on stdin/stdout, both eras on one pipe. stdio is local, so the client's config holds no token:

- **bridge**: a relay already listens on the port (the app, a headless relay). Each message is POSTed to
  its `/mcp` with the token from `<config>/EchoDebug/relay-token` (or `ECHODEBUG_TOKEN`; re-read once on
  a 401, then a clear error), the headers its version needs and `X-EchoDebug-Bridge` /
  `X-EchoDebug-Transport: stdio`; JSON answers and every SSE event go to stdout; after a legacy
  `initialize` the session's event stream is forwarded too, and stdin closing ends the session.
- **embedded**: nothing listens, so the process becomes the relay on that port (Echo and the app
  connect as usual) and serves stdio itself; the `ui_*` tools need an app window.

### Catalog

Every tool in `src/lib/tools.json` maps one-to-one onto a verb above; the tool's `verb` becomes the
request `type` and its `input_schema` is passed through as the request body. Each `tools/call` is
appended to a 200-entry ring buffer, exposed as the `echodebug://mcp/log` resource and the local
`mcp_log` verb.

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
`echodebug://target/modules` (`-32603` when no backend can list modules). Module monitor events also send
`notifications/resources/updated` for `echodebug://target/modules`.

The tool set covers the whole backend: process control (`status`, `list_processes`, `attach`,
`detach`, `is_alive`), memory (`read_memory`, `read_memory_batch`, `write_memory`, `query_region`,
`memory_regions`), analysis (`disassemble`, `enumerate_functions`, `signature_scan`,
`signature_scan_masked`, `string_scan`, `resolve_relative`, `rtti_resolve`, `rtti_resolve_batch`,
`resolve_export`, `peb_walk`), threads (`list_threads`, `thread_stack`, `list_handles`,
`tls_callbacks`, `exception_handlers`), scanning (`value_scan_first`, `value_scan_next`, `value_scan_results`,
`value_scan_clear`, `pointer_scan`), emulation (`emulate`), freezing (`freeze_value`, `list_frozen`),
watching (`watch_add`, `watch_remove`, `list_watched`), alerts (`alert_add`,
`alert_remove`, `alert_list`),
dumping (`dump_module`) and socket housekeeping (`reopen_native_socket`).

Because the relay routes by verb, an MCP client gets exactly the same behaviour as the desktop UI.
