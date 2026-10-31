// Import Address Table resolution: turns `call qword ptr [rip+0x...]` into
// the imported function name, the way a disassembler with symbols does.
import { parsePe, type PeInfo } from "./pe";

export type IatEntry = {
  /** IAT slot RVA */
  rva: number;
  /** absolute address of the slot */
  address: string;
  dll: string;
  name: string;
  ordinal?: number;
};

export type IatMap = {
  /** IAT slot RVA -> entry */
  byRva: Map<number, IatEntry>;
  /** absolute slot address -> entry */
  byAddress: Map<string, IatEntry>;
  entries: IatEntry[];
};

export function buildIat(img: Uint8Array, base: bigint, pe?: PeInfo): IatMap {
  const byRva = new Map<number, IatEntry>();
  const byAddress = new Map<string, IatEntry>();
  const entries: IatEntry[] = [];
  let info = pe;
  if (!info) {
    try {
      info = parsePe(img);
    } catch {
      return { byRva, byAddress, entries };
    }
  }
  for (const dll of info.imports) {
    for (const fn of dll.funcs) {
      const entry: IatEntry = {
        rva: fn.iatRva,
        address: "0x" + (base + BigInt(fn.iatRva)).toString(16),
        dll: dll.dll,
        name: fn.name ?? `#${fn.ordinal ?? 0}`,
      };
      if (fn.ordinal !== undefined) entry.ordinal = fn.ordinal;
      byRva.set(fn.iatRva, entry);
      byAddress.set(entry.address, entry);
      entries.push(entry);
    }
  }
  entries.sort((a, b) => a.rva - b.rva);
  return { byRva, byAddress, entries };
}

/**
 * Signed displacement of a RIP-relative memory operand, or null when the
 * instruction does not use one. The target is `next instruction + disp`.
 */
export function ripDisplacement(text: string): bigint | null {
  const m = /\[rip([+-])0x([0-9a-f]+)\]/i.exec(text);
  if (!m) return null;
  const v = BigInt("0x" + m[2]);
  return m[1] === "-" ? -v : v;
}
