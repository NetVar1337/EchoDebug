// Unity IL2CPP dumper: global-metadata.dat (versions 24–31) for images, types, fields and
// methods, plus method RVAs from GameAssembly's Il2CppCodeGenModule tables (v24.2+).
//
// Struct sizes change between metadata versions, so they are derived instead of hard-coded:
// the images give the total type count, the types give the method and field totals, and each
// table's byte size divided by its count is the record size. Within a record only fields whose
// position is stable across 24–31 are read (names first; counts, starts and token at the end).

export type Il2CppMethod = { name: string; token: number; rva?: number; flags: number; params: number };
export type Il2CppField = { name: string; token: number };
export type Il2CppType = { name: string; namespace: string; token: number; fields: Il2CppField[]; methods: Il2CppMethod[] };
export type Il2CppImage = { name: string; types: Il2CppType[]; methodCount: number };
export type Il2CppMetadata = { version: number; images: Il2CppImage[]; sizes: { image: number; type: number; method: number; field: number } };

const kSanity = 0xfab11baf;

/** Longest identifier read from the string table (a table without NULs is not a name). */
const kMaxName = 4096;

function cstr(b: Uint8Array, o: number): string {
  if (o < 0 || o >= b.length) return "";
  let e = o;
  const stop = Math.min(b.length, o + kMaxName);
  while (e < stop && b[e] !== 0) e++;
  return new TextDecoder().decode(b.subarray(o, e));
}

export function isMetadata(b: Uint8Array): boolean {
  return b.length >= 0x100 && new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0, true) === kSanity;
}

export function parseMetadata(b: Uint8Array): Il2CppMetadata {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (!isMetadata(b)) throw new Error("not an IL2CPP global-metadata.dat (bad sanity value; the file may be encrypted — try finding it in memory)");
  const version = dv.getInt32(4, true);
  if (version < 24 || version > 31) throw new Error(`unsupported metadata version ${version} (24–31)`);
  const pair = (o: number) => ({ off: dv.getUint32(o, true), size: dv.getUint32(o + 4, true) });
  const strings = pair(0x18).off;
  const methods = pair(0x30);
  const fields = pair(0x60);
  const types = pair(0xa0);
  // names are decoded once per string index (hostile tables point every record at one run)
  const names = new Map<number, string>();
  const str = (i: number) => {
    let v = names.get(i);
    if (v === undefined) names.set(i, (v = cstr(b, strings + i)));
    return v;
  };
  // every table must lie inside the file and hold records big enough for the fields read
  const inFile = (t: { off: number; size: number }) => t.off + t.size <= b.length;

  // images: the header slot moved (rgctx entries were dropped in 24.2); the record grew in 24.1
  let images: { name: string; typeStart: number; typeCount: number }[] | null = null;
  let imageSize = 0;
  for (const slot of [0xa8, 0xb0, 0xb8]) {
    const im = pair(slot);
    for (const size of [40, 32]) {
      if (!im.size || im.size % size || im.off + im.size > b.length) continue;
      const list = Array.from({ length: im.size / size }, (_, i) => {
        const o = im.off + i * size;
        return { name: str(dv.getInt32(o, true)), typeStart: dv.getInt32(o + 8, true), typeCount: dv.getUint32(o + 12, true) };
      });
      const ok = list.length > 0 && list[0].typeStart === 0 && list.every((x, i) => /\.(dll|winmd)$/i.test(x.name) && (i === 0 || x.typeStart === list[i - 1].typeStart + list[i - 1].typeCount));
      if (ok) {
        images = list;
        imageSize = size;
        break;
      }
    }
    if (images) break;
  }
  if (!images) throw new Error("cannot locate the image table in this metadata version");

  const totalTypes = images.reduce((a, x) => a + x.typeCount, 0);
  if (!totalTypes || types.size % totalTypes) throw new Error("type table size does not match the image type counts");
  const ts = types.size / totalTypes;
  if (!inFile(types) || ts < 56) throw new Error("type table does not fit the file");
  const t = (i: number) => types.off + i * ts;
  let totalMethods = 0;
  let totalFields = 0;
  for (let i = 0; i < totalTypes; i++) {
    const o = t(i);
    totalMethods = Math.max(totalMethods, dv.getInt32(o + ts - 52, true) + dv.getUint16(o + ts - 24, true));
    totalFields = Math.max(totalFields, dv.getInt32(o + ts - 56, true) + dv.getUint16(o + ts - 20, true));
  }
  const ms = totalMethods ? methods.size / totalMethods : 0;
  const fs = totalFields ? fields.size / totalFields : 0;
  if ((totalMethods && !Number.isInteger(ms)) || (totalFields && !Number.isInteger(fs))) throw new Error("method/field table sizes do not match the type counts");
  if ((totalMethods && (!inFile(methods) || ms < 12)) || (totalFields && (!inFile(fields) || fs < 4))) throw new Error("method/field tables do not fit the file");
  // Every field / method belongs to one type in valid metadata, so the totals bound what is
  // listed; hostile types all claim the same 65535 records.
  let fieldBudget = totalFields;
  let methodBudget = totalMethods;

  const out: Il2CppImage[] = images.map((im) => ({ name: im.name, types: [], methodCount: 0 }));
  images.forEach((im, k) => {
    for (let i = im.typeStart; i < im.typeStart + im.typeCount; i++) {
      const o = t(i);
      const fieldStart = dv.getInt32(o + ts - 56, true);
      const methodStart = dv.getInt32(o + ts - 52, true);
      const mc = dv.getUint16(o + ts - 24, true);
      const fc = dv.getUint16(o + ts - 20, true);
      const type: Il2CppType = { name: str(dv.getInt32(o, true)), namespace: str(dv.getInt32(o + 4, true)), token: dv.getUint32(o + ts - 4, true), fields: [], methods: [] };
      for (let f = 0; f < fc && fieldStart >= 0 && fieldBudget > 0; f++, fieldBudget--) {
        const fo = fields.off + (fieldStart + f) * fs;
        type.fields.push({ name: str(dv.getInt32(fo, true)), token: dv.getUint32(fo + fs - 4, true) });
      }
      for (let m = 0; m < mc && methodStart >= 0 && methodBudget > 0; m++, methodBudget--) {
        const mo = methods.off + (methodStart + m) * ms;
        type.methods.push({ name: str(dv.getInt32(mo, true)), token: dv.getUint32(mo + ms - 12, true), flags: dv.getUint16(mo + ms - 8, true), params: dv.getUint16(mo + ms - 2, true) });
      }
      out[k].methodCount += mc;
      out[k].types.push(type);
    }
  });
  return { version, images: out, sizes: { image: imageSize, type: ts, method: ms, field: fs } };
}

/**
 * Method RVAs from the Il2CppCodeGenModule of every image: { char* moduleName; uint32
 * methodPointerCount; Il2CppMethodPointer* methodPointers; ... } in GameAssembly's data, found by
 * a pointer to the image's name string followed by that image's method count. Method i of an
 * image (by token RID) runs at methodPointers[RID-1]. Fills `rva` in place; returns the modules found.
 */
export function applyMethodPointers(md: Il2CppMetadata, img: Uint8Array, base: bigint, dataRanges: { rva: number; size: number }[]): string[] {
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const found: string[] = [];
  const enc = new TextEncoder();
  const needle = (s: Uint8Array) => {
    const hits: number[] = [];
    outer: for (let i = 0; i + s.length < img.length; i++) {
      for (let k = 0; k < s.length; k++) if (img[i + k] !== s[k]) continue outer;
      hits.push(i);
      if (hits.length > 8) break;
    }
    return hits;
  };
  for (const im of md.images) {
    if (!im.methodCount) continue;
    const strs = new Set(needle(enc.encode(im.name + "\0")).map((o) => base + BigInt(o)));
    if (!strs.size) continue;
    let table = -1;
    for (const r of dataRanges) {
      for (let o = r.rva; o + 24 <= Math.min(img.length, r.rva + r.size) && table < 0; o += 8) {
        if (!strs.has(dv.getBigUint64(o, true))) continue;
        if (dv.getUint32(o + 8, true) !== im.methodCount) continue;
        const p = dv.getBigUint64(o + 16, true) - base;
        if (p > 0n && p + BigInt(im.methodCount * 8) <= BigInt(img.length)) table = Number(p);
      }
    }
    if (table < 0) continue;
    found.push(im.name);
    for (const t of im.types) {
      for (const m of t.methods) {
        const rid = m.token & 0xffffff;
        if (rid < 1 || rid > im.methodCount) continue;
        const ptr = dv.getBigUint64(table + (rid - 1) * 8, true);
        if (ptr > base && ptr < base + BigInt(img.length)) m.rva = Number(ptr - base);
      }
    }
  }
  return found;
}

/** dump.cs-style text. */
export function dumpCs(md: Il2CppMetadata): string {
  const out: string[] = [`// IL2CPP metadata v${md.version}, generated by EchoDebug`, ""];
  for (const im of md.images) {
    out.push(`// Image: ${im.name} (${im.types.length} types)`);
    for (const t of im.types) {
      out.push(`// Namespace: ${t.namespace}`, `class ${t.name} // TypeDefIndex token 0x${t.token.toString(16)}`, "{");
      if (t.fields.length) out.push("\t// Fields", ...t.fields.map((f) => `\t${f.name}; // token 0x${f.token.toString(16)}`));
      if (t.methods.length) {
        out.push("", "\t// Methods");
        for (const m of t.methods) out.push(`\t// RVA: ${m.rva !== undefined ? "0x" + m.rva.toString(16).toUpperCase() : "-"} Token: 0x${m.token.toString(16)}`, `\t${m.name}(${m.params ? `/* ${m.params} params */` : ""}) { }`);
      }
      out.push("}", "");
    }
  }
  return out.join("\n");
}

/** Il2CppDumper-compatible script.json (ScriptMethod) for the IDA / Ghidra / Binary Ninja importers. */
export function scriptJson(md: Il2CppMetadata): { ScriptMethod: { Address: number; Name: string; Signature: string; TypeSignature: string }[] } {
  const list: { Address: number; Name: string; Signature: string; TypeSignature: string }[] = [];
  for (const im of md.images)
    for (const t of im.types)
      for (const m of t.methods)
        if (m.rva !== undefined) list.push({ Address: m.rva, Name: `${t.namespace ? t.namespace.replace(/\./g, "_") + "_" : ""}${t.name}$$${m.name}`, Signature: "", TypeSignature: "" });
  return { ScriptMethod: list };
}
