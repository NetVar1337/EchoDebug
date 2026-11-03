// Which architecture a module's code is: the backend's `arch` field (the Linux local backend
// reports it per module), else the PE / ELF header read from the module's base, cached per module.
// `installArchHook` makes every `disassemble` / `disasm_function` request carry the right `arch`,
// so arm64 modules get the AArch64 decoder in every view without each view asking.
import { client, request } from "./client";
import { fmtAddr, hexToBytes, moduleOf, toBig, type Module } from "./hex";
import { detectArch, parseArch, type Arch } from "./analysis/arch";

const cache = new Map<string, Promise<Arch>>();
const known = new Map<string, Arch>();
const key = (m: Module) => `${m.name}@${m.base}`;

/** The module's architecture; x86-64 when the headers cannot be read. */
export function moduleArch(m: Module): Promise<Arch> {
  const given = parseArch(m.arch);
  if (given) return Promise.resolve(given);
  const k = key(m);
  let p = cache.get(k);
  if (!p) {
    p = request<{ data: string; success: boolean }>("read", { address: fmtAddr(toBig(m.base)), size: 0x400 }, true)
      .then((r) => (r.success && r.data ? detectArch(hexToBytes(r.data), false)?.arch : undefined) ?? "x86_64")
      .catch(() => "x86_64" as Arch);
    p.then((a) => known.set(k, a));
    cache.set(k, p);
  }
  return p;
}

/** What is known right now, without a read: the backend's field or an earlier detection. */
export function knownArch(m: Module | undefined): Arch | null {
  if (!m) return null;
  return parseArch(m.arch) ?? known.get(key(m)) ?? null;
}

/** Architecture at an address (the module that holds it); x86-64 outside every module. */
export async function archAt(address: bigint | string, modules: readonly Module[]): Promise<Arch> {
  const m = moduleOf(toBig(address), modules);
  return m ? moduleArch(m) : "x86_64";
}

export function clearArchCache(): void {
  cache.clear();
  known.clear();
}

/** The request's fields plus `arch: "arm64"` when its `address` lies in an arm64 module. */
export async function withArch(fields: Record<string, unknown>, modules: readonly Module[]): Promise<Record<string, unknown>> {
  if (fields.arch !== undefined || typeof fields.address !== "string") return fields;
  let a: bigint;
  try {
    a = toBig(fields.address);
  } catch {
    return fields;
  }
  const m = moduleOf(a, modules);
  if (!m) return fields;
  const arch = await moduleArch(m);
  return arch === "arm64" ? { ...fields, arch } : fields;
}

/** Adds `arch` to disassembly requests that do not name one. */
export function installArchHook(modules: () => readonly Module[]): void {
  const hook = (fields: Record<string, unknown>) => withArch(fields, modules());
  client.setRequestHook("disassemble", hook);
  client.setRequestHook("disasm_function", hook);
}
