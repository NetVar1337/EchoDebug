// Respawn-Source (Titanfall / Apex) class-report automation.
//
// These routines turn the manual EchoDebug-MCP workflow — "find the string, find what points at
// it, read the offset out of the descriptor, cross-check the second table layout" — into single
// passes over the module image:
//
// - harvestOffsets:   netvar offsets from the two descriptor-table layouts a Respawn binary
//                     carries (the compact RecvProp-style table and the DataDesc table with the
//                     string pointer at +0x28/+0x38). Agreement across layouts = confirmed.
// - findClientClass:  locate a ClientClass struct by its network name ("CWeaponX"), pulling the
//                     class name, RecvTable and list linkage out of the neighboring pointers.
// - dumpScriptBindings: enumerate a Squirrel script-binding table ({name, handler} pairs), the
//                     300+ entry table behind GetScriptBindingTable.
// - findRipLeas:      one pass over .text indexing every `lea r64,[rip+disp32]` (registration
//                     sites, table addresses, constructor vtable loads).
// - findCtorVtables:  best-effort scan of a constructor for `mov [rcx+off], vtable` stores so a
//                     class's secondary vtables (IClientRenderable, …) come along for free.
import { extractStrings } from "../strings";

export type RvaRange = { rva: number; size: number };

type D = { dv: DataView; img: Uint8Array };

function helpers(img: Uint8Array): D {
  return { img, dv: new DataView(img.buffer, img.byteOffset, img.byteLength) };
}

function inRanges(rva: number, ranges: readonly RvaRange[]): boolean {
  for (const r of ranges) if (rva >= r.rva && rva < r.rva + r.size) return true;
  return false;
}

/** RVA of the first byte of the NUL-terminated ASCII string at rva, or -1. */
function asciiAt(d: D, rva: number, max = 128): string {
  if (rva < 0 || rva >= d.img.length) return "";
  let s = "";
  for (let i = rva; i < Math.min(d.img.length, rva + max); i++) {
    const c = d.img[i];
    if (c === 0) return s.length ? s : "";
    if (c < 0x20 || c > 0x7e) return "";
    s += String.fromCharCode(c);
  }
  return "";
}

const ident = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Every (targetRva -> site rvas) pair for qwords in `ranges` that hold an in-image pointer. */
export function buildDataPtrIndex(img: Uint8Array, ranges: readonly RvaRange[]): Map<number, number[]> {
  const d = helpers(img);
  const to = new Map<number, number[]>();
  for (const r of ranges) {
    const end = Math.min(img.length, r.rva + r.size) & ~7;
    for (let o = r.rva & ~7; o + 8 <= end; o += 8) {
      const v = d.dv.getBigUint64(o, true);
      if (v < 8n || v >= BigInt(img.length)) continue;
      const t = Number(v);
      const list = to.get(t);
      if (list) list.push(o);
      else to.set(t, [o]);
    }
  }
  return to;
}

// -------------------------------------------------------------------------------------------------
// Netvar offset harvest
// -------------------------------------------------------------------------------------------------

export type OffsetHit = {
  /** descriptor layout: "table1" = compact RecvProp-style (offset at string+8), "table2" = DataDesc (string at +0x28/+0x38) */
  layout: "table1" | "table2";
  /** absolute address of the descriptor's name-pointer field */
  site: bigint;
  /** member offset inside the entity class */
  offset: number;
  /** DataDesc type field (0 = field, 1 = composite/nested, 0x0A = array/handle); -1 for table1 */
  type: number;
};

export type FieldOffsets = {
  name: string;
  hits: OffsetHit[];
  /** offset value agreed on by both layouts (0 when none) */
  confirmed: number;
  composite: boolean;
  strings: number;
};

const kMaxOffset = 0x20000;

function plausibleOffset(v: number): boolean {
  return v > 0 && v < kMaxOffset;
}

/** Offsets of one member name via every descriptor instance that names it. */
export function offsetsForName(d: D, base: bigint, nameRvas: number[], ptrIdx: Map<number, number[]>): OffsetHit[] {
  const hits: OffsetHit[] = [];
  for (const rva of nameRvas) {
    for (const site of ptrIdx.get(rva) ?? []) {
      // TABLE-1 (compact RecvProp-style): [string_ptr:8][offset:i32][flags:i32]
      const off1 = d.dv.getInt32(site + 8, true);
      if (plausibleOffset(off1)) hits.push({ layout: "table1", site: base + BigInt(site), offset: off1, type: -1 });
      // TABLE-2 (DataDesc): [type:i32][offset:i32]…[string_ptr:8] with the string at +0x28 (type 0/1) or +0x38 (type 0x0A)
      for (const delta of [0x28, 0x38]) {
        const b = site - delta;
        if (b < 0) continue;
        const type = d.dv.getUint32(b, true);
        if (type !== 0 && type !== 1 && type !== 0x0a) continue;
        const off2 = d.dv.getInt32(b + 4, true);
        if (plausibleOffset(off2)) hits.push({ layout: "table2", site: base + BigInt(site), offset: off2, type });
      }
    }
  }
  return hits;
}

export type OffsetHarvest = {
  module_base: bigint;
  fields: FieldOffsets[];
  /** quick-reference C defines, one per confirmed (or best-guess) offset */
  cpp: string;
};

/**
 * Harvest entity/weapon member offsets for `names` from a module image. `dataRanges` are the
 * RVA ranges holding descriptor tables (the read-only data sections); pass the module's
 * non-executable sections.
 */
export function harvestOffsets(img: Uint8Array, base: bigint, names: string[], dataRanges: RvaRange[]): OffsetHarvest {
  const d = helpers(img);
  const byText = new Map<string, number[]>();
  for (const s of extractStrings(img, 3, 4_000_000)) {
    if (s.wide || s.text.length > 64) continue;
    const list = byText.get(s.text);
    if (list) list.push(s.rva);
    else byText.set(s.text, [s.rva]);
  }
  const ptrIdx = buildDataPtrIndex(img, dataRanges);
  const fields: FieldOffsets[] = [];
  for (const name of names) {
    const nameRvas = byText.get(name) ?? [];
    const hits = offsetsForName(d, base, nameRvas, ptrIdx);
    const t1 = new Set(hits.filter((h) => h.layout === "table1").map((h) => h.offset));
    const t2 = new Set(hits.filter((h) => h.layout === "table2").map((h) => h.offset));
    const confirmed = [...t1].find((o) => t2.has(o)) ?? 0;
    fields.push({
      name,
      hits,
      confirmed,
      composite: hits.some((h) => h.type === 1),
      strings: nameRvas.length,
    });
  }
  const line = (f: FieldOffsets) => {
    const off = f.confirmed || f.hits[0]?.offset || 0;
    return `#define OFF_${f.name.replace(/[^A-Za-z0-9]/g, "_").toUpperCase()}  0x${off.toString(16).padStart(4, "0").toUpperCase()}`;
  };
  return { module_base: base, fields, cpp: fields.map(line).join("\n") };
}

/** The field set of the classic Apex/Titanfall offset dump, used when the caller passes none. */
export const kRespawnPresetFields = [
  "m_iHealth", "m_iMaxHealth", "m_shieldHealth", "m_armorType", "m_lifeState", "m_bleedoutState",
  "m_iTeamNum", "m_vecAbsOrigin", "m_vecVelocity", "m_bZooming", "m_angEyeAngles", "m_vecViewOffset",
  "m_latestPrimaryWeapons", "m_ammoInClip", "m_weaponOwner", "m_contextAction", "m_fFlags",
];

// -------------------------------------------------------------------------------------------------
// ClientClass
// -------------------------------------------------------------------------------------------------

export type ClientClassHit = {
  address: bigint;
  network_name: string;
  class_name: string;
  table: bigint;
  table_name: string;
  next: bigint;
  id: number;
  /** how the struct was recognised: "classic" = full DT_ table + next + id, "heuristic" = name neighbors only */
  kind: "classic" | "heuristic";
};

/**
 * Find the ClientClass whose network name is `networkName` (e.g. "CWeaponX"). The name field's
 * offset differs between builds, so every data reference to the string is tried as a candidate
 * base at the known field offsets and validated on its neighbors.
 */
export function findClientClass(img: Uint8Array, base: bigint, networkName: string, dataRanges: RvaRange[]): ClientClassHit | null {
  const d = helpers(img);
  const nameRvas: number[] = [];
  for (const s of extractStrings(img, 3, 4_000_000)) if (!s.wide && s.text === networkName) nameRvas.push(s.rva);
  if (!nameRvas.length) return null;
  const ptrIdx = buildDataPtrIndex(img, dataRanges);
  let best: ClientClassHit | null = null;
  let bestScore = -1;
  for (const rva of nameRvas) {
    for (const site of ptrIdx.get(rva) ?? []) {
      for (const nameOff of [0x8, 0x10, 0x18, 0x20, 0x28]) {
        const b = site - nameOff;
        if (b < 0 || b + 0x40 > img.length) continue;
        // neighbors: other identifier strings (the class name) and in-image pointers (table/next)
        let className = "";
        let table = 0n;
        let tableName = "";
        let next = 0n;
        let id = -1;
        let score = 0;
        for (let f = 0; f < 0x40; f += 8) {
          const p = d.dv.getBigUint64(b + f, true);
          if (p < 8n || p >= BigInt(img.length)) continue;
          const t = asciiAt(d, Number(p));
          if (ident.test(t) && t !== networkName && !className) { className = t; score += 2; }
        }
        // classic x64 Source ClientClass: table @ +0x18, next @ +0x20, id @ +0x28
        const tp = d.dv.getBigUint64(b + 0x18, true);
        if (tp > 7n && tp < BigInt(img.length)) {
          const tn = asciiAt(d, Number(d.dv.getBigUint64(Number(tp) + 0x18, true)));
          if (tn.startsWith("DT_")) { table = base + tp; tableName = tn; score += 4; }
        }
        const np = d.dv.getBigUint64(b + 0x20, true);
        if (np === 0n || (np > 7n && np < BigInt(img.length))) { next = base + np; score += 1; }
        const cid = d.dv.getInt32(b + 0x28, true);
        if (cid >= 0 && cid < 8192) { id = cid; score += 1; }
        if (score < 3) continue;
        const kind = tableName ? "classic" : "heuristic";
        if (score > bestScore) {
          bestScore = score;
          best = { address: base + BigInt(b), network_name: networkName, class_name: className, table, table_name: tableName, next, id, kind };
        }
      }
    }
  }
  return bestScore >= 3 ? best : null;
}

// -------------------------------------------------------------------------------------------------
// Squirrel script bindings
// -------------------------------------------------------------------------------------------------

export type ScriptBinding = { index: number; name: string; name_rva: number; handler: bigint };

export type ScriptBindingDump = {
  table: bigint;
  stride: number;
  count: number;
  entries: ScriptBinding[];
  /** true when the run ended at a non-entry (table size is exact) */
  complete: boolean;
};

/**
 * Enumerate the {name, handler} pairs of a Squirrel script-binding table (the table behind the
 * GetScriptBindingTable vfunc). The entry stride is auto-detected across the plausible layouts
 * (16/24/32 bytes); a run of ≥4 valid entries picks the winner. Names must be identifier-like
 * strings in the image, handlers must land in `execRanges`.
 */
export function dumpScriptBindings(img: Uint8Array, base: bigint, table: bigint, execRanges: RvaRange[], maxEntries = 4096): ScriptBindingDump | null {
  const d = helpers(img);
  const tRva = Number(table - base);
  if (tRva < 0 || tRva >= img.length) return null;
  const valid = (o: number): ScriptBinding | null => {
    if (o + 16 > img.length) return null;
    const nameP = d.dv.getBigUint64(o, true);
    const fn = d.dv.getBigUint64(o + 8, true);
    if (nameP < 8n || nameP >= BigInt(img.length)) return null;
    const nameRva = Number(nameP);
    const name = asciiAt(d, nameRva, 96);
    if (!ident.test(name)) return null;
    const fnRva = Number(fn - base);
    if (!inRanges(fnRva, execRanges)) return null;
    return { index: 0, name, name_rva: nameRva, handler: base + BigInt(fnRva) };
  };
  let best: { stride: number; entries: ScriptBinding[]; complete: boolean } | null = null;
  for (const stride of [16, 24, 32]) {
    const entries: ScriptBinding[] = [];
    let complete = true;
    for (let i = 0; i < maxEntries; i++) {
      const e = valid(tRva + i * stride);
      if (!e) { complete = i >= 4; break; }
      e.index = i;
      entries.push(e);
    }
    if (entries.length >= 4 && (!best || entries.length > best.entries.length)) best = { stride, entries, complete };
    if (best && entries.length === best.entries.length && stride === 16) best = { stride, entries, complete };
  }
  if (!best) return null;
  return { table, stride: best.stride, count: best.entries.length, entries: best.entries, complete: best.complete };
}

// -------------------------------------------------------------------------------------------------
// rip-relative lea map + constructor vtable stores
// -------------------------------------------------------------------------------------------------

/** Every `lea r64,[rip+disp32]` in `ranges`: target RVA -> site rvas (one linear pass). */
export function findRipLeas(img: Uint8Array, ranges: readonly RvaRange[]): Map<number, number[]> {
  const d = helpers(img);
  const to = new Map<number, number[]>();
  for (const r of ranges) {
    const end = Math.min(img.length, r.rva + r.size);
    for (let i = r.rva; i + 7 <= end; i++) {
      const rex = img[i];
      if (rex !== 0x48 && rex !== 0x4c) continue;
      if (img[i + 1] !== 0x8d) continue;
      const modrm = img[i + 2];
      if ((modrm & 0xc7) !== 0x05) continue; // mod=00 rm=101 -> [rip+disp32]
      const disp = d.dv.getInt32(i + 3, true);
      const target = i + 7 + disp;
      if (target < 0 || target >= img.length) continue;
      const list = to.get(target);
      if (list) list.push(i);
      else to.set(target, [i]);
    }
  }
  return to;
}

export type CtorVtableStore = {
  /** rva of the lea that loads the vtable */
  site: bigint;
  vtable: bigint;
  /** object offset the vtable pointer is stored to */
  object_offset: number;
};

/**
 * Best-effort constructor scan: a `lea r,[rip]` whose target looks like a vtable (in
 * `rdataRanges`) followed within a few bytes by `mov [rcx+disp], r` — the pattern a C++ ctor
 * uses to install main and secondary vtables. Falsy positives are possible; treat as leads.
 */
export function findCtorVtables(img: Uint8Array, base: bigint, codeRanges: RvaRange[], rdataRanges: RvaRange[]): CtorVtableStore[] {
  const d = helpers(img);
  const leas = findRipLeas(img, codeRanges);
  const out: CtorVtableStore[] = [];
  for (const [target, sites] of leas) {
    if (!inRanges(target, rdataRanges)) continue;
    for (const site of sites) {
      // look for mov [rcx+disp32|disp8], reg within the next 16 bytes
      for (let j = site + 7; j + 3 <= Math.min(img.length, site + 7 + 16); j++) {
        const rex = img[j];
        if (rex !== 0x48 && rex !== 0x4c) continue;
        if (img[j + 1] !== 0x89) continue;
        const modrm = img[j + 2];
        const regOk = ((modrm >> 3) & 7) === 0; // rax/r8 carry the lea result
        if (!regOk) continue;
        if ((modrm & 0xc7) === 0x81 && j + 7 <= img.length) {
          out.push({ site: base + BigInt(site), vtable: base + BigInt(target), object_offset: d.dv.getInt32(j + 3, true) });
          break;
        }
        if ((modrm & 0xc7) === 0x41 && j + 4 <= img.length) {
          out.push({ site: base + BigInt(site), vtable: base + BigInt(target), object_offset: img[j + 3] });
          break;
        }
      }
    }
  }
  return out;
}
