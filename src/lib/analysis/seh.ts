// x64 structured exception handling, statically: the exception directory (.pdata) entries whose
// UNWIND_INFO carries a language handler (UNW_FLAG_EHANDLER / UHANDLER), the handler each one
// names, and for the C-specific handler (__C_specific_handler: __try/__except/__finally) the
// scope table with its guarded ranges, filters and targets. Also the TLS callbacks of the image.
//
// Vectored handlers (AddVectoredExceptionHandler) are not listed: they live in ntdll's private
// LdrpVectorHandlerList with pointers encoded by RtlEncodePointer (a per-process cookie), so they
// cannot be enumerated reliably without undocumented internals.
import { parsePe, parseRuntimeFunctions, type PeInfo, type RuntimeFunction } from "./pe";
import { parseTls } from "./peextra";

export const UNW_FLAG_EHANDLER = 1;
export const UNW_FLAG_UHANDLER = 2;
export const UNW_FLAG_CHAININFO = 4;

const kOps = ["PUSH_NONVOL", "ALLOC_LARGE", "ALLOC_SMALL", "SET_FPREG", "SAVE_NONVOL", "SAVE_NONVOL_FAR", "EPILOG", "SPARE", "SAVE_XMM128", "SAVE_XMM128_FAR", "PUSH_MACHFRAME"];
const kRegs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

export type UnwindCode = { offset: number; op: number; name: string; info: number; operand: number; text: string };
export type UnwindInfo = {
  rva: number;
  version: number;
  flags: number;
  prologSize: number;
  frameReg: number;
  frameOffset: number;
  codes: UnwindCode[];
  handlerRva?: number;
  /** RVA of the language-specific data right after the handler RVA */
  handlerDataRva?: number;
  chained?: RuntimeFunction;
};

function slots(op: number, info: number): number {
  if (op === 1) return info === 0 ? 2 : 3;
  if (op === 4 || op === 8) return 2;
  if (op === 5 || op === 9) return 3;
  return 1;
}

function codeText(op: number, info: number, operand: number, frameOffset: number): string {
  switch (op) {
    case 0: return `push ${kRegs[info]}`;
    case 1: return `sub rsp, 0x${(info === 0 ? operand * 8 : operand).toString(16)}`;
    case 2: return `sub rsp, 0x${(info * 8 + 8).toString(16)}`;
    case 3: return `frame register = rsp + 0x${(frameOffset * 16).toString(16)}`;
    case 4: return `mov [frame+0x${(operand * 8).toString(16)}], ${kRegs[info]}`;
    case 5: return `mov [frame+0x${operand.toString(16)}], ${kRegs[info]}`;
    case 8: return `movaps [frame+0x${(operand * 16).toString(16)}], xmm${info}`;
    case 9: return `movaps [frame+0x${operand.toString(16)}], xmm${info}`;
    case 10: return info ? "machine frame (with error code)" : "machine frame";
    case 6: return "epilog descriptor";
    default: return `op ${op}`;
  }
}

/** Parses the UNWIND_INFO at `rva` of a mapped image (RVA-indexed). */
export function parseUnwindInfo(img: Uint8Array, rva: number): UnwindInfo | null {
  if (rva <= 0 || rva + 4 > img.length) return null;
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const version = img[rva] & 7;
  const flags = img[rva] >> 3;
  if (version !== 1 && version !== 2) return null;
  const count = img[rva + 2];
  const frameReg = img[rva + 3] & 15;
  const frameOffset = img[rva + 3] >> 4;
  if (rva + 4 + count * 2 > img.length) return null;
  const slot = (i: number) => dv.getUint16(rva + 4 + i * 2, true);
  const codes: UnwindCode[] = [];
  for (let i = 0; i < count; ) {
    const offset = img[rva + 4 + i * 2];
    const b = img[rva + 5 + i * 2];
    const op = b & 15;
    const info = b >> 4;
    const n = slots(op, info);
    if (i + n > count) return null;
    const operand = n === 2 ? slot(i + 1) : n === 3 ? (slot(i + 1) | (slot(i + 2) << 16)) >>> 0 : 0;
    codes.push({ offset, op, name: kOps[op] ?? `OP_${op}`, info, operand, text: codeText(op, info, operand, frameOffset) });
    i += n;
  }
  const tail = rva + 4 + ((count + 1) & ~1) * 2;
  const out: UnwindInfo = { rva, version, flags, prologSize: img[rva + 1], frameReg, frameOffset, codes };
  if (flags & UNW_FLAG_CHAININFO) {
    if (tail + 12 > img.length) return null;
    out.chained = { begin: dv.getUint32(tail, true), end: dv.getUint32(tail + 4, true), unwind: dv.getUint32(tail + 8, true), chained: false };
  } else if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
    if (tail + 4 > img.length) return null;
    out.handlerRva = dv.getUint32(tail, true);
    out.handlerDataRva = tail + 4;
  }
  return out;
}

export type HandlerKind = "c" | "cxx3" | "cxx4" | "gcc" | "unknown";
export const kHandlerKindLabel: Record<HandlerKind, string> = {
  c: "C (__try/__except/__finally)",
  cxx3: "C++ (FH3)",
  cxx4: "C++ (FH4)",
  gcc: "GCC / MinGW",
  unknown: "custom",
};

/** One C_SCOPE_TABLE entry. `target` 0 = __finally (termination handler at `handler`). */
export type ScopeEntry = { begin: number; end: number; handler: number; target: number; kind: "finally" | "except"; filter?: "EXCEPTION_EXECUTE_HANDLER" | "rva" | "constant" };

export type HandlerEntry = {
  /** function covered (RUNTIME_FUNCTION bounds) */
  begin: number;
  end: number;
  unwindRva: number;
  flags: ("EHANDLER" | "UHANDLER")[];
  handlerRva: number;
  handlerName?: string;
  kind: HandlerKind;
  dataRva: number;
  scopes?: ScopeEntry[];
  /** scope table read without knowing the handler is __C_specific_handler */
  scopesHeuristic?: boolean;
};

function classify(name: string | undefined): HandlerKind {
  if (!name) return "unknown";
  const n = name.replace(/^_+/, "");
  if (/^C_specific_handler(_noexcept)?$/i.test(n)) return "c";
  if (/^CxxFrameHandler4$/i.test(n)) return "cxx4";
  if (/^CxxFrameHandler(2|3)?$/i.test(n) || /^GSHandlerCheck_EH$/i.test(n)) return "cxx3";
  if (/^GSHandlerCheck_EH4$/i.test(n)) return "cxx4";
  if (/^GSHandlerCheck_SEH$/i.test(n)) return "c";
  if (/gcc_personality|GCC_specific_handler/i.test(n)) return "gcc";
  return "unknown";
}

/**
 * Name of the function at `rva`: user/export names first, then an import thunk
 * (`jmp [rip+disp32]`, optionally REX-prefixed) whose IAT slot is a named import.
 */
export function resolveHandlerName(img: Uint8Array, pe: PeInfo, rva: number, nameOf?: (rva: number) => string | undefined): string | undefined {
  const direct = nameOf?.(rva) ?? pe.exports.find((e) => e.rva === rva && !e.forwarder)?.name;
  if (direct) return direct;
  let o = rva;
  if (img[o] === 0x48) o++;
  if (img[o] === 0xff && img[o + 1] === 0x25 && o + 6 <= img.length) {
    const disp = new DataView(img.buffer, img.byteOffset, img.byteLength).getInt32(o + 2, true);
    const slot = o + 6 + disp;
    for (const d of pe.imports) {
      const f = d.funcs.find((x) => x.iatRva === slot);
      if (f) return f.name ?? `${d.dll}#${f.ordinal}`;
    }
  }
  return undefined;
}

function readScopes(img: Uint8Array, at: number, fn: RuntimeFunction, strict: boolean): ScopeEntry[] | null {
  if (at + 4 > img.length) return null;
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const count = dv.getUint32(at, true);
  if (count === 0 || count > 1024 || at + 4 + count * 16 > img.length) return count === 0 ? [] : null;
  const out: ScopeEntry[] = [];
  for (let i = 0; i < count; i++) {
    const o = at + 4 + i * 16;
    const begin = dv.getUint32(o, true);
    const end = dv.getUint32(o + 4, true);
    const handler = dv.getUint32(o + 8, true);
    const target = dv.getUint32(o + 12, true);
    if (strict && !(begin >= fn.begin && end <= fn.end && begin < end)) return null;
    if (target === 0) out.push({ begin, end, handler, target, kind: "finally" });
    else out.push({ begin, end, handler, target, kind: "except", filter: handler === 1 ? "EXCEPTION_EXECUTE_HANDLER" : handler < 0x1000 ? "constant" : "rva" });
  }
  return out;
}

export type ExceptionReport = {
  functions: number;
  chained: number;
  handlers: HandlerEntry[];
  /** distinct handler routines and how many functions use each */
  routines: { rva: number; name?: string; kind: HandlerKind; count: number }[];
};

/** Every function with a language handler, from .pdata + UNWIND_INFO. */
export function listExceptionHandlers(img: Uint8Array, pe?: PeInfo, opts: { nameOf?: (rva: number) => string | undefined } = {}): ExceptionReport {
  const info = pe ?? parsePe(img);
  const fns = parseRuntimeFunctions(img, info);
  // ARM64 .pdata points at packed words or ARM64 .xdata, not x64 UNWIND_INFO: ranges only
  if (info.machine === 0xaa64) return { functions: fns.length, chained: 0, handlers: [], routines: [] };
  const handlers: HandlerEntry[] = [];
  const names = new Map<number, string | undefined>();
  let chained = 0;
  for (const f of fns) {
    let rva = f.unwind;
    // UnwindData with bit 0 set points at another RUNTIME_FUNCTION whose unwind info is shared
    if (rva & 1) rva = rva + 8 < img.length ? new DataView(img.buffer, img.byteOffset, img.byteLength).getUint32((rva & ~1) + 8, true) : 0;
    const u = parseUnwindInfo(img, rva);
    if (!u) continue;
    if (u.chained) chained++;
    if (u.handlerRva === undefined || u.handlerDataRva === undefined) continue;
    if (!names.has(u.handlerRva)) names.set(u.handlerRva, resolveHandlerName(img, info, u.handlerRva, opts.nameOf));
    const handlerName = names.get(u.handlerRva);
    const kind = classify(handlerName);
    const e: HandlerEntry = {
      begin: f.begin, end: f.end, unwindRva: rva, handlerRva: u.handlerRva, handlerName, kind, dataRva: u.handlerDataRva,
      flags: [...(u.flags & UNW_FLAG_EHANDLER ? ["EHANDLER" as const] : []), ...(u.flags & UNW_FLAG_UHANDLER ? ["UHANDLER" as const] : [])],
    };
    if (kind === "c") e.scopes = readScopes(img, u.handlerDataRva, f, false) ?? undefined;
    else if (kind === "unknown") {
      const s = readScopes(img, u.handlerDataRva, f, true);
      if (s && s.length) {
        e.scopes = s;
        e.scopesHeuristic = true;
      }
    }
    handlers.push(e);
  }
  const routines = new Map<number, { rva: number; name?: string; kind: HandlerKind; count: number }>();
  for (const h of handlers) {
    const r = routines.get(h.handlerRva) ?? { rva: h.handlerRva, name: h.handlerName, kind: h.kind, count: 0 };
    r.count++;
    routines.set(h.handlerRva, r);
  }
  return { functions: fns.length, chained, handlers, routines: [...routines.values()].sort((a, b) => b.count - a.count) };
}

export type TlsCallback = { address: bigint; rva: number | null; section?: string; executable: boolean };

/** TLS callbacks of a mapped image loaded at `base` (live images hold relocated pointers). */
export function tlsCallbacks(img: Uint8Array, base: bigint, pe?: PeInfo): { callbacks: TlsCallback[]; directory: ReturnType<typeof parseTls> } {
  const info = pe ?? parsePe(img);
  const dir = parseTls(img, base, info);
  const callbacks = (dir?.callbacks ?? []).map((a) => {
    const off = a - base;
    const rva = off >= 0n && off < BigInt(img.length) ? Number(off) : null;
    const sec = rva === null ? undefined : info.sections.find((s) => rva >= s.rva && rva < s.rva + Math.max(s.vsize, s.rawSize));
    return { address: a, rva, section: sec?.name, executable: Boolean(sec?.x) };
  });
  return { callbacks, directory: dir };
}
