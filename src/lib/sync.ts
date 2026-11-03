// Live sync with IDA / Ghidra / Binary Ninja through the relay's /sync hub (see
// src-tauri/relay/src/sync.rs and integrations/README.md). Locations travel as module + RVA, so the
// live module can sit anywhere ASLR put it and the disassembler's database can be rebased.
import { client, request, type Frame } from "./client";
import { fmtAddr, moduleOf, toBig, type Module } from "./hex";
import type { NameEntry } from "@/store/names";
import type { TypeDef } from "@/store/types";
import { toC } from "./analysis/typeexport";

export type ModRva = { module: string; rva: number };

/** `addr` as module + RVA, or null when it is in no loaded module. */
export function toModuleRva(addr: bigint | string, modules: readonly Module[]): ModRva | null {
  const a = typeof addr === "bigint" ? addr : toBig(addr);
  const m = moduleOf(a, modules);
  if (!m) return null;
  return { module: m.name, rva: Number(a - toBig(m.base)) };
}

/** The live address of module + RVA (module name case-insensitive, RVA within the image). */
export function fromModuleRva(module: string, rva: string | number, modules: readonly Module[]): bigint | null {
  const m = modules.find((x) => x.name.toLowerCase() === module.toLowerCase());
  if (!m) return null;
  let r: bigint;
  try {
    r = typeof rva === "number" ? BigInt(rva) : BigInt(rva.startsWith("0x") || rva.startsWith("0X") ? rva : `0x${rva}`);
  } catch {
    return null;
  }
  if (r < 0n || (m.size > 0 && r >= BigInt(m.size))) return null;
  return toBig(m.base) + r;
}

export type NameChange = { address: string; name?: string; comment?: string };

const key = (a: string) => a.toLowerCase().replace(/^0x/, "").padStart(16, "0");

/** What changed between two name lists: new or changed names/comments, and removals (""). */
export function diffNames(prev: readonly NameEntry[], next: readonly NameEntry[]): NameChange[] {
  const before = new Map(prev.map((n) => [key(n.address), n]));
  const after = new Map(next.map((n) => [key(n.address), n]));
  const out: NameChange[] = [];
  for (const [k, n] of after) {
    const p = before.get(k);
    const c: NameChange = { address: "0x" + k };
    if ((p?.name ?? "") !== n.name) c.name = n.name;
    if ((p?.comment ?? "") !== n.comment) c.comment = n.comment;
    if (c.name !== undefined || c.comment !== undefined) out.push(c);
  }
  for (const [k, p] of before) {
    if (after.has(k)) continue;
    const c: NameChange = { address: "0x" + k };
    if (p.name) c.name = "";
    if (p.comment) c.comment = "";
    if (c.name !== undefined || c.comment !== undefined) out.push(c);
  }
  return out;
}

/** The struct catalog as C declarations the disassemblers parse (IDA parse_decls, Ghidra CParser, Binja parse_types). */
export function structDecls(types: readonly TypeDef[]): { decls: string; names: string[] } {
  const usable = types.filter((t) => /^[A-Za-z_]\w*$/.test(t.name) && t.fields.length);
  const fwd = usable.map((t) => `struct ${t.name};`);
  const bodies = usable.map((t) => toC(t.name, t.fields));
  return { decls: [...fwd, ...(fwd.length ? [""] : []), ...bodies].join("\n"), names: usable.map((t) => t.name) };
}

export type SyncKind = "cursor" | "name" | "comment" | "types";

/** One `sync_send`; resolves with the number of tools reached (0 when nothing is connected). */
export async function syncSend(kind: SyncKind, fields: Record<string, unknown>): Promise<number> {
  if (!client.connected) return 0;
  const r = await request<{ peers: number }>("sync_send", { kind, ...fields });
  return r.peers;
}

export function onSyncEvent(l: (f: Frame) => void): () => void {
  return client.on((f) => {
    if (f.type === "sync_event") l(f);
  });
}

/** Throttle to the trailing call: the cursor moves often while the user scrolls. */
export function trailing<A extends unknown[]>(ms: number, f: (...a: A) => void): (...a: A) => void {
  let t: ReturnType<typeof setTimeout> | null = null;
  let last: A | null = null;
  return (...a: A) => {
    last = a;
    if (t) return;
    t = setTimeout(() => {
      t = null;
      if (last) f(...last);
    }, ms);
  };
}

export { fmtAddr };
