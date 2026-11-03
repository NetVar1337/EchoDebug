// The `ed` object scripts in the Script tab run against: the same verbs the MCP server exposes,
// plus memory, names, disassembly and the app's own analyses.
import { request } from "./client";
import { bytesToHex, fmtAddr, hexToBytes, labelAddr, parseAddress, toBig, type Module } from "./hex";
import { readBytes, readU64 } from "./memory";
import { writeJournaled } from "./patch";
import { callProvider } from "./provider";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";

export type ScriptApi = ReturnType<typeof makeApi>;

export function makeApi(print: (...a: unknown[]) => void, signal: { aborted: boolean }) {
  const check = () => { if (signal.aborted) throw new Error("script stopped"); };
  const addr = (a: string | number | bigint): bigint => {
    if (typeof a === "bigint") return a;
    if (typeof a === "number") return BigInt(a);
    const v = parseAddress(a, useConn.getState().modules);
    if (v === null) throw new Error(`cannot parse address ${a}`);
    return v;
  };
  return {
    /** any relay verb: ed.request("read", { address, size }) */
    request: (verb: string, args: Record<string, unknown> = {}) => { check(); return request(verb, args); },
    /** an app analysis: ed.ui("ui_strings", { module }) */
    ui: (verb: string, args: Record<string, unknown> = {}) => { check(); return callProvider(verb, args); },
    read: async (a: string | number | bigint, size: number) => { check(); return readBytes(addr(a), size); },
    readU64: async (a: string | number | bigint) => { check(); return readU64(addr(a)); },
    readU32: async (a: string | number | bigint) => { check(); const b = await readBytes(addr(a), 4); return b ? new DataView(b.buffer).getUint32(0, true) : null; },
    write: async (a: string | number | bigint, data: Uint8Array | string, note = "script") => { check(); return writeJournaled(addr(a), typeof data === "string" ? hexToBytes(data) : data, note); },
    disasm: async (a: string | number | bigint, size = 0) => { check(); return (await request<{ results: { address: string; text: string; bytes: string; length: number }[] }>("disassemble", { address: fmtAddr(addr(a)), size })).results; },
    modules: (): Module[] => useConn.getState().modules,
    module: (name?: string): Module => {
      const mods = useConn.getState().modules;
      const m = name ? mods.find((x) => x.name.toLowerCase() === name.toLowerCase()) : mods.find((x) => x.base === useConn.getState().target?.base) ?? mods[0];
      if (!m) throw new Error(name ? `no module ${name}` : "no modules: attach first");
      return m;
    },
    addr: (a: string | number | bigint) => addr(a),
    hex: (a: bigint | number) => fmtAddr(a),
    label: (a: string | number | bigint) => labelAddr(addr(a), useConn.getState().modules),
    toHex: bytesToHex,
    fromHex: hexToBytes,
    big: toBig,
    names: {
      get: (a: string | number | bigint) => useNames.getState().nameOf(fmtAddr(addr(a))),
      set: (a: string | number | bigint, name: string) => useNames.getState().rename(fmtAddr(addr(a)), name),
      comment: (a: string | number | bigint, text: string) => useNames.getState().comment(fmtAddr(addr(a)), text),
      all: () => useNames.getState().names,
    },
    sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, ms)),
    print: (...a: unknown[]) => print(...a),
  };
}

const AsyncFunction = Object.getPrototypeOf(async () => undefined).constructor as new (...args: string[]) => (...a: unknown[]) => Promise<unknown>;

/** Runs a script; resolves with its return value. */
export async function runScript(code: string, print: (...a: unknown[]) => void, signal: { aborted: boolean }): Promise<unknown> {
  const fn = new AsyncFunction("ed", `"use strict";\n${code}`);
  return fn(makeApi(print, signal));
}

export function show(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "bigint") return fmtAddr(v);
  if (v instanceof Uint8Array) return bytesToHex(v);
  try {
    return JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? fmtAddr(x) : x instanceof Uint8Array ? bytesToHex(x) : x), 2);
  } catch {
    return String(v);
  }
}
