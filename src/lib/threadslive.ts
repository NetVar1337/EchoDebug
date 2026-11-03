// Threads / stacks / handles from the backend (`threads`, `stack`, `handles` verbs) and the static
// per-module tables behind the "TLS & SEH" view (TLS callbacks, .pdata exception handlers), with
// names layered on top: the user's names first, then the backend's symbol (exports / ELF symbols).
import { request } from "./client";
import { fmtAddr, labelAddr, toBig, type Module } from "./hex";
import { loadImage } from "./memory";
import { parsePe } from "./analysis/pe";
import { kHandlerKindLabel, listExceptionHandlers, tlsCallbacks, type HandlerEntry } from "./analysis/seh";
import { useNames } from "@/store/names";

export type StackFrame = {
  index: number;
  address: string;
  sp: string;
  module: string | null;
  offset: string | null;
  symbol: string | null;
  symbol_offset: number | null;
  method: "context" | "pdata" | "leaf" | "cfi" | "frame-pointer" | "stack-scan";
  guessed: boolean;
};

export type ThreadInfo = {
  tid: number;
  name?: string;
  main?: boolean;
  state?: string | number;
  state_name?: string;
  wait?: string | null;
  priority?: number;
  base_priority?: number;
  nice?: number;
  time_ms?: number;
  start?: string;
  start_label?: string;
  start_source?: string;
  teb?: string;
  tls?: string;
  rip?: string;
  rsp?: string;
  suspend_count?: number;
  registers?: Record<string, string>;
  registers_error?: string;
  error?: string;
  frames?: StackFrame[];
};

export type ThreadsReply = { pid: number; platform: "linux" | "windows"; registers_from: string; threads: ThreadInfo[] };
export type HandleInfo = { handle: number | string; type: string; name: string | null; position?: number | null; flags?: string[] | null; access?: string; object?: string };

/** Code the relay answers while the Echo agent is the backend (Echo has no thread APIs). */
export const kEchoUnsupported = 2006;

export async function fetchThreads(opts: { stacks?: boolean; maxFrames?: number } = {}): Promise<ThreadsReply> {
  return request<ThreadsReply>("threads", { stacks: Boolean(opts.stacks), max_frames: opts.maxFrames ?? 64 });
}

export async function fetchStack(tid: number, maxFrames = 128): Promise<StackFrame[]> {
  return (await request<{ frames: StackFrame[] }>("stack", { tid, max_frames: maxFrames })).frames;
}

export async function fetchHandles(): Promise<HandleInfo[]> {
  return (await request<{ handles: HandleInfo[] }>("handles")).handles;
}

/** A frame's name: the user's name at the address or at the start of its symbol, else the
 * backend's symbol (exports / ELF symbols), else module+offset. */
export function frameName(f: StackFrame, modules: readonly Module[]): string {
  const names = useNames.getState();
  const exact = names.nameOf(f.address);
  if (exact) return exact;
  if (f.symbol) {
    // a user name on the symbol's start wins over the symbol itself
    const start = toBig(f.address) - BigInt(f.symbol_offset ?? 0);
    const user = names.nameOf(fmtAddr(start));
    const base = user || f.symbol;
    return f.symbol_offset ? `${base}+0x${f.symbol_offset.toString(16)}` : base;
  }
  return labelAddr(f.address, modules);
}

// ---- static per-module tables ---------------------------------------------------------------

function nameAt(base: bigint): (rva: number) => string | undefined {
  const names = useNames.getState();
  return (rva) => names.nameOf(fmtAddr(base + BigInt(rva))) || undefined;
}

export async function tlsReport(m: Module) {
  const img = await loadImage(m);
  const base = toBig(m.base);
  const pe = parsePe(img);
  const { callbacks, directory } = tlsCallbacks(img, base, pe);
  const user = useNames.getState();
  const exportAt = new Map(pe.exports.map((e) => [e.rva, e.name]));
  return {
    module: m.name,
    directory: directory && {
      startRaw: fmtAddr(directory.startRaw), endRaw: fmtAddr(directory.endRaw), index: fmtAddr(directory.indexAddress),
      callbacksArray: fmtAddr(directory.callbacksAddress), zeroFill: directory.zeroFill, characteristics: directory.characteristics,
    },
    callbacks: callbacks.map((c, i) => ({
      index: i,
      address: fmtAddr(c.address),
      label: labelAddr(c.address, [m]),
      name: user.nameOf(fmtAddr(c.address)) || (c.rva !== null ? exportAt.get(c.rva) : undefined),
      section: c.section,
      executable: c.executable,
      inModule: c.rva !== null,
    })),
  };
}

export type SehRow = HandlerEntry & { address: string; handlerAddress: string; kindLabel: string };

export async function sehReport(m: Module) {
  const img = await loadImage(m);
  const base = toBig(m.base);
  const pe = parsePe(img);
  const r = listExceptionHandlers(img, pe, { nameOf: nameAt(base) });
  const at = (rva: number) => fmtAddr(base + BigInt(rva));
  return {
    module: m.name,
    base,
    functions: r.functions,
    chained: r.chained,
    routines: r.routines.map((x) => ({ ...x, address: at(x.rva), kindLabel: kHandlerKindLabel[x.kind] })),
    handlers: r.handlers.map((h): SehRow => ({ ...h, address: at(h.begin), handlerAddress: at(h.handlerRva), kindLabel: kHandlerKindLabel[h.kind] })),
  };
}

/** The handler listing in MCP shape (addresses as hex, scope entries absolute). */
export async function sehForMcp(m: Module, limit: number) {
  const r = await sehReport(m);
  const at = (rva: number) => fmtAddr(r.base + BigInt(rva));
  return {
    module: r.module,
    functions_with_unwind_info: r.functions,
    chained_fragments: r.chained,
    handler_routines: r.routines.map((x) => ({ address: x.address, name: x.name ?? null, kind: x.kindLabel, functions: x.count })),
    count: r.handlers.length,
    truncated: r.handlers.length > limit,
    functions: r.handlers.slice(0, limit).map((h) => ({
      function: h.address,
      end: at(h.end),
      flags: h.flags,
      handler: h.handlerAddress,
      handler_name: h.handlerName ?? null,
      kind: h.kindLabel,
      handler_data: at(h.dataRva),
      scopes: h.scopes?.map((s) => ({
        try_begin: at(s.begin), try_end: at(s.end), kind: s.kind,
        ...(s.kind === "finally" ? { finally: at(s.handler) } : { filter: s.filter === "rva" ? at(s.handler) : s.handler, target: at(s.target) }),
      })),
      scopes_heuristic: h.scopesHeuristic || undefined,
    })),
    vectored_handlers: "not listed: AddVectoredExceptionHandler entries live in ntdll's private LdrpVectorHandlerList with RtlEncodePointer-encoded pointers; they cannot be enumerated reliably without undocumented internals",
  };
}
