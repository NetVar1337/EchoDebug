// MSVC x64 RTTI inventory: finds the type descriptors in a module image and
// reconstructs the class inventory (name, base class, vftable slots) that
// `rtti_resolve` can only answer one object at a time.
//
// Layout (x64):
//   TypeDescriptor      { pVFTable, spare, name[] }   name = ".?AVClass@@"
//   CompleteObjectLocator { signature, offset, cdOffset, pTypeDescriptor,
//                           pClassDescriptor, pSelf }     (RTTI_TYPE_DESCRIPTOR)
//   Vftable             { pVFTable, ... }                points at the COL
import { parsePe, type PeInfo } from "./pe";

export type RttiClass = {
  /** the mangled name, e.g. ".?AVPlayerController@@" */
  mangled: string;
  /** the demangled name, e.g. "PlayerController" */
  name: string;
  /** the base class name, empty when unknown */
  base: string;
  /** absolute address of the type descriptor */
  address: string;
  /** RVA of the type descriptor */
  rva: number;
  /** the vftable slots found for this class */
  vftables: { address: string; rva: number; slots: number }[];
};

export type RttiInventory = {
  classes: RttiClass[];
  /** number of type descriptors that could not be demangled */
  unnamed: number;
};

/**
 * Demangles the MSVC type-descriptor names:
 *   ".?AVFoo@@"          -> "Foo"
 *   ".?AVFoo@Bar@@"      -> "Foo@Bar"      (namespace as a trailing @chain)
 *   ".?AU<Foo@Bar>@@"    -> "Foo@Bar"      (struct)
 *   ".?AVFoo@@\u0000..."  -> "Foo"
 */
export function demangleTypeName(mangled: string): string {
  let s = mangled;
  // Structs use .?AU<...>@@, classes .?AV..., enums .?AW...
  const angle = /^(\.\?A[VUW])<(.+)>@@$/.exec(s);
  if (angle) s = angle[2];
  else {
    const plain = /^\.\?A[VUW](.+)@@$/.exec(s);
    if (!plain) return s;
    s = plain[1];
  }
  // A leading number is the template arity: "??$Foo@H@".
  s = s.replace(/^\?\$/, "").replace(/@H@$/, "");
  // The namespace chain is encoded as trailing @segments.
  return s.replace(/@/g, "::").replace(/::/g, "@");
}

/** RTTI type descriptors are 16-byte aligned in .data and start with a vtable pointer. */
function scanTypeDescriptors(img: Uint8Array, pe: PeInfo): { rva: number; name: string }[] {
  const out: { rva: number; name: string }[] = [];
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  for (const s of pe.sections) {
    if (!s.r || s.x) continue;
    const start = s.rva;
    const end = Math.min(img.length, s.rva + s.vsize);
    for (let i = start; i + 16 < end; i += 8) {
      // The name pointer is at +8 and points at the ".?A..." string.
      const namePtr = dv.getBigUint64(i + 8, true);
      if (namePtr < 0x1000n || namePtr > 0x7fffffffffffn) continue;
      const nameOff = Number(namePtr);
      if (nameOff < 0 || nameOff + 8 > img.length) continue;
      // The name must start with ".?A".
      const c0 = img[nameOff];
      const c1 = img[nameOff + 1];
      const c2 = img[nameOff + 2];
      if (c0 !== 0x2e || c1 !== 0x3f || c2 !== 0x41) continue;
      let name = "";
      for (let k = nameOff; k < img.length && img[k] !== 0 && name.length < 200; k++) name += String.fromCharCode(img[k]);
      if (!name.endsWith("@@")) continue;
      out.push({ rva: i, name });
    }
  }
  return out;
}

/** Reads the base-class name out of a type descriptor's base-class descriptor, if resolvable. */
function baseClassOf(img: Uint8Array, typeRva: number): string {
  // The base class descriptor sits at pTypeDescriptor - 16 on x64; it points at
  // the base type descriptor. We look for it directly rather than trusting a
  // fixed offset, by scanning backwards for a plausible pointer.
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  for (const delta of [0x10, 0x18, 0x20, 0x28]) {
    const bcd = typeRva - delta;
    if (bcd < 0 || bcd + 8 > img.length) continue;
    const ptr = dv.getBigUint64(bcd, true);
    if (ptr < 0x1000n || ptr > 0x7fffffffffffn) continue;
    const baseOff = Number(ptr);
    if (baseOff < 0 || baseOff + 16 > img.length) continue;
    const namePtr = dv.getBigUint64(baseOff + 8, true);
    if (namePtr < 0x1000n || namePtr > 0x7fffffffffffn) continue;
    const nameOff = Number(namePtr);
    if (nameOff < 0 || nameOff + 8 > img.length) continue;
    if (img[nameOff] !== 0x2e || img[nameOff + 1] !== 0x3f || img[nameOff + 2] !== 0x41) continue;
    let name = "";
    for (let k = nameOff; k < img.length && img[k] !== 0 && name.length < 200; k++) name += String.fromCharCode(img[k]);
    if (!name.endsWith("@@")) continue;
    return demangleTypeName(name);
  }
  return "";
}

/**
 * Builds the class inventory of a module image.
 * `base` is the module's absolute base address so the entries carry absolute addresses.
 */
export function buildRtti(img: Uint8Array, base: bigint, pe?: PeInfo): RttiInventory {
  let info = pe;
  if (!info) {
    try {
      info = parsePe(img);
    } catch {
      return { classes: [], unnamed: 0 };
    }
  }
  const descriptors = scanTypeDescriptors(img, info);
  const classes: RttiClass[] = [];
  let unnamed = 0;
  for (const d of descriptors) {
    const name = demangleTypeName(d.name);
    if (!name || name === d.name) unnamed++;
    classes.push({
      mangled: d.name,
      name,
      base: baseClassOf(img, d.rva),
      address: "0x" + (base + BigInt(d.rva)).toString(16),
      rva: d.rva,
      vftables: [],
    });
  }
  classes.sort((a, b) => a.name.localeCompare(b.name));
  return { classes, unnamed };
}

/**
 * Finds the vftables of a class: a vftable's first slot points at the
 * CompleteObjectLocator, whose fourth field points at the type descriptor.
 *
 * The locator's own self-pointer would otherwise look like a vftable, so a
 * candidate is only accepted when it also carries a function pointer into an
 * executable section.
 */
export function findVftables(img: Uint8Array, base: bigint, cls: RttiClass, pe?: PeInfo): RttiClass["vftables"] {
  let info = pe;
  if (!info) {
    try {
      info = parsePe(img);
    } catch {
      return [];
    }
  }
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const out: RttiClass["vftables"] = [];
  const want = BigInt(cls.rva);
  const codeRanges = info.sections.filter((s) => s.x).map((s) => ({ start: base + BigInt(s.rva), end: base + BigInt(s.rva + s.vsize) }));
  const inCode = (p: bigint) => codeRanges.some((r) => p >= r.start && p < r.end);
  for (const s of info.sections) {
    if (!s.r || s.x) continue;
    const start = s.rva;
    const end = Math.min(img.length, s.rva + s.vsize);
    for (let i = start; i + 16 <= end; i += 8) {
      const col = dv.getBigUint64(i, true);
      if (col < 0x1000n || col > 0x7fffffffffffn) continue;
      const colOff = Number(col);
      if (colOff + 32 > img.length) continue;
      // The COL signature is 1 for x64; the type descriptor pointer is at +16.
      if (dv.getUint32(colOff, true) !== 1) continue;
      const td = dv.getBigUint64(colOff + 16, true);
      if (td !== want) continue;
      // The first entry after the locator must be a function pointer.
      const first = dv.getBigUint64(i + 8, true);
      if (!inCode(first)) continue;
      // Count the slots: consecutive pointers into the module.
      let slots = 0;
      for (let k = i; k + 8 <= end; k += 8) {
        const p = dv.getBigUint64(k, true);
        if (p < 0x1000n || p > 0x7fffffffffffn) break;
        slots++;
      }
      if (slots === 0) continue;
      out.push({ address: "0x" + (base + BigInt(i)).toString(16), rva: i, slots });
    }
  }
  return out;
}
