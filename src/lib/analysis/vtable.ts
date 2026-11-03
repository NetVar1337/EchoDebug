// Resolves a live object to its vtable and to the functions behind it.
//
// Given the address of an object we read the vtable pointer out of it, then
// every slot of that vtable, and resolve each slot to the module it lives in
// and its offset. The class name comes from the complete object locator that
// the vtable points at.
import { readBytes } from "../memory";
import { fmtAddr, moduleOf, toBig, type Module } from "../hex";

export type VSlot = {
  /** index in the vtable */
  index: number;
  /** absolute address of the slot */
  slotAddress: string;
  /** absolute address of the function the slot points at */
  target: string;
  /** the module the function lives in */
  module: string;
  /** offset of the function inside that module */
  offset: string;
  /** false when the slot does not point at code */
  valid: boolean;
};

export type VObject = {
  /** the object address that was resolved */
  object: string;
  /** the vtable pointer read out of the object */
  vtable: string;
  /** the class name, when the locator could be read */
  className: string;
  /** the base class name, when it could be read */
  baseName: string;
  slots: VSlot[];
  /** true when the vtable pointer did not look like a pointer */
  failed: string | null;
};

const kMaxSlots = 128;

/**
 * Reads the class name out of a vtable: the first slot points at the complete
 * object locator, whose fourth field points at the type descriptor, whose
 * third field points at the mangled name.
 */
async function readClassName(vtable: bigint, modules: readonly Module[]): Promise<{ name: string; base: string }> {
  const locBytes = await readBytes(vtable, 8);
  if (!locBytes || locBytes.length < 8) return { name: "", base: "" };
  const loc = new DataView(locBytes.buffer, locBytes.byteOffset, locBytes.byteLength).getBigUint64(0, true);
  if (loc < 0x1000n) return { name: "", base: "" };
  const col = await readBytes(loc, 32);
  if (!col || col.length < 32) return { name: "", base: "" };
  const dv = new DataView(col.buffer, col.byteOffset, col.byteLength);
  if (dv.getUint32(0, true) !== 1) return { name: "", base: "" };
  const td = dv.getBigUint64(16, true);
  if (td < 0x1000n) return { name: "", base: "" };
  const tdBytes = await readBytes(td, 16);
  if (!tdBytes || tdBytes.length < 16) return { name: "", base: "" };
  const tdv = new DataView(tdBytes.buffer, tdBytes.byteOffset, tdBytes.byteLength);
  const namePtr = tdv.getBigUint64(8, true);
  const name = await readCString(namePtr);
  // The base class descriptor sits just before the type descriptor.
  const bcd = await readBytes(td - 0x10n, 8);
  let base = "";
  if (bcd && bcd.length === 8) {
    const bptr = new DataView(bcd.buffer, bcd.byteOffset, bcd.byteLength).getBigUint64(0, true);
    if (bptr > 0x1000n) {
      const btd = await readBytes(bptr, 16);
      if (btd && btd.length === 16) {
        const bn = new DataView(btd.buffer, btd.byteOffset, btd.byteLength).getBigUint64(8, true);
        base = await readCString(bn);
      }
    }
  }
  void modules;
  return { name, base };
}

async function readCString(address: bigint): Promise<string> {
  if (address < 0x1000n) return "";
  const b = await readBytes(address, 256);
  if (!b) return "";
  let s = "";
  for (const c of b) {
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

/** Resolves an object address to its vtable and the functions behind it. */
export async function resolveVirtualCalls(object: string, modules: readonly Module[]): Promise<VObject> {
  const addr = toBig(object);
  const head = await readBytes(addr, 8);
  if (!head || head.length < 8) {
    return { object, vtable: "", className: "", baseName: "", slots: [], failed: "could not read the object" };
  }
  const vtable = new DataView(head.buffer, head.byteOffset, head.byteLength).getBigUint64(0, true);
  if (vtable < 0x1000n || vtable > 0x7fffffffffffn) {
    return { object, vtable: "", className: "", baseName: "", slots: [], failed: "the object does not start with a pointer" };
  }
  const raw = await readBytes(vtable, 8 * kMaxSlots);
  if (!raw) {
    return { object, vtable: fmtAddr(vtable), className: "", baseName: "", slots: [], failed: "could not read the vtable" };
  }
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const slots: VSlot[] = [];
  for (let i = 0; i * 8 < raw.length; i++) {
    const target = dv.getBigUint64(i * 8, true);
    const slotAddress = fmtAddr(vtable + BigInt(i * 8));
    const m = moduleOf(target, modules);
    const valid = m !== undefined;
    slots.push({
      index: i,
      slotAddress,
      target: fmtAddr(target),
      module: m?.name ?? "",
      offset: m ? "0x" + (target - toBig(m.base)).toString(16) : "",
      valid,
    });
    // The vtable ends at the first slot that is not a pointer.
    if (target < 0x1000n || target > 0x7fffffffffffn) break;
  }
  const { name, base } = await readClassName(vtable, modules);
  return {
    object,
    vtable: fmtAddr(vtable),
    className: demangle(name),
    baseName: demangle(base),
    slots,
    failed: null,
  };
}

/** Turns ".?AVFoo@@" into "Foo"; anything else is returned unchanged. */
export function demangle(mangled: string): string {
  if (!mangled) return "";
  const angle = /^(\.\?A[VUW])<(.+)>@@$/.exec(mangled);
  let s = angle ? angle[2] : (/^\.\?A[VUW](.+)@@$/.exec(mangled)?.[1] ?? mangled);
  s = s.replace(/^\?\$/, "").replace(/@H@$/, "");
  return s.replace(/@/g, "::");
}
