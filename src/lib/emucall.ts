// Emulate-a-call (#3): run a function from its start up to (and including) one call site in the
// emulator — never touching the live process — and read back registers, API calls and memory.
// Used to resolve indirect calls (`call rax` -> rax after the run), to preview a call with chosen
// arguments, and to let the decryption campaign emulate call sites in ranked order.
import { request } from "./client";
import { fmtAddr } from "./hex";

export type EmuWrite = { address: string; data: string };
export type EmuRead = { address: string; size: number };

export type EmuReply = {
  error_name: string;
  reached_end: boolean;
  instructions: number;
  regs: Record<string, string>;
  trace?: string[];
  api_calls?: { address: string; name: string; args?: string[]; ret?: string }[];
  mem_log?: { address: string; size: number; access: string; before?: string; after?: string }[];
};

export type CallResult = {
  stop: string;
  reachedEnd: boolean;
  instructions: number;
  regs: Record<string, string>;
  /** resolved target of an indirect call: rax/rbx/... right after `call reg` ran */
  apiCalls: EmuReply["api_calls"];
  reads: { address: string; bytes: string }[];
};

export type CallOpts = {
  /** win64 args: rcx, rdx, r8, r9, xmm0.. (hex strings) */
  regs?: Record<string, string>;
  write?: EmuWrite[];
  /** buffers to read back after the run */
  read?: EmuRead[];
  maxInsns?: number;
  timeoutUs?: number;
  stubs?: boolean;
  memLog?: boolean;
};

/**
 * Emulates [fnStart, end) where `end` is the instruction after the call (call site + its length).
 * `callSite` is only used to disassemble the call's length when `end` is not given.
 */
export async function emulateCall(
  fnStart: bigint,
  callSite: bigint,
  opts: CallOpts & { end?: bigint } = {},
): Promise<CallResult> {
  let end = opts.end;
  if (end === undefined) {
    const d = await request<{ results: { length: number }[] }>("disassemble", { address: fmtAddr(callSite), size: 16 }, true);
    end = callSite + BigInt(d.results[0]?.length ?? 5);
  }
  const r = await request<EmuReply & { read?: { address: string; data: string }[] }>("emulate", {
    start: fmtAddr(fnStart),
    end: fmtAddr(end),
    ...(opts.regs ? { regs: opts.regs } : {}),
    ...(opts.write ? { write: opts.write } : {}),
    ...(opts.read ? { read: opts.read } : {}),
    max_insns: opts.maxInsns ?? 500_000,
    timeout_us: opts.timeoutUs ?? 2_000_000,
    ...(opts.stubs ? { stubs: true } : {}),
    ...(opts.memLog ? { mem_log: true, mem_log_limit: 20000 } : {}),
  });
  return {
    stop: r.reached_end ? "returned" : r.error_name,
    reachedEnd: r.reached_end,
    instructions: r.instructions,
    regs: r.regs,
    apiCalls: r.api_calls,
    reads: (r.read ?? []).map((x) => ({ address: x.address, bytes: x.data })),
  };
}

/** Convenience: the value `reg` holds right after the call at `callSite` ran (indirect-call resolution). */
export async function resolveCallTarget(fnStart: bigint, callSite: bigint, reg = "rax", opts: CallOpts = {}): Promise<bigint | null> {
  const r = await emulateCall(fnStart, callSite, opts);
  const v = r.regs[reg];
  return v ? BigInt(v) : null;
}
