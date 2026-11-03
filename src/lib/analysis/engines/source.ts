// Source engine netvar dumper. client.dll keeps a static linked list of ClientClass objects
// (network class name, RecvTable, next, class id); every RecvTable lists RecvProps with a name,
// type, offset and, for DPT_DataTable props, a nested table. Everything is static data inside
// the client module, so the dump works from the module image alone: find a ClientClass chain,
// then walk the tables. Both x86 and x64 builds.

export type NetvarProp = { name: string; type: string; offset: number; table?: string; elements?: number };
export type NetvarTable = { name: string; props: NetvarProp[] };
export type ClientClassInfo = { name: string; id: number; table: string; address: bigint };
export type NetvarDump = { is64: boolean; head: bigint; classes: ClientClassInfo[]; tables: Record<string, NetvarTable> };

const kTypes = ["int", "float", "vector", "vectorxy", "string", "array", "datatable", "int64"];

type L = { ptr: number; ccName: number; ccTable: number; ccNext: number; ccId: number; ccSize: number; rtProps: number; rtCount: number; rtName: number; rpSize: number; rpName: number; rpType: number; rpTable: number; rpOffset: number; rpElems: number };
const kL64: L = { ptr: 8, ccName: 0x10, ccTable: 0x18, ccNext: 0x20, ccId: 0x28, ccSize: 0x30, rtProps: 0, rtCount: 8, rtName: 0x18, rpSize: 0x60, rpName: 0, rpType: 8, rpTable: 0x40, rpOffset: 0x48, rpElems: 0x50 };
const kL32: L = { ptr: 4, ccName: 8, ccTable: 0xc, ccNext: 0x10, ccId: 0x14, ccSize: 0x18, rtProps: 0, rtCount: 4, rtName: 0xc, rpSize: 0x3c, rpName: 0, rpType: 4, rpTable: 0x28, rpOffset: 0x2c, rpElems: 0x34 };

class Img {
  dv: DataView;
  constructor(readonly img: Uint8Array, readonly base: bigint, readonly l: L) {
    this.dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  }
  off(a: bigint): number {
    const o = a - this.base;
    return o >= 0n && o < BigInt(this.img.length) ? Number(o) : -1;
  }
  ptr(o: number): bigint {
    if (o < 0 || o + this.l.ptr > this.img.length) return 0n;
    return this.l.ptr === 8 ? this.dv.getBigUint64(o, true) : BigInt(this.dv.getUint32(o, true));
  }
  i32(o: number): number {
    return o >= 0 && o + 4 <= this.img.length ? this.dv.getInt32(o, true) : 0;
  }
  /** ASCII identifier at an absolute address inside the image, else "". */
  str(a: bigint, max = 128): string {
    const o = this.off(a);
    if (o < 0) return "";
    let s = "";
    for (let i = o; i < Math.min(this.img.length, o + max); i++) {
      const c = this.img[i];
      if (c === 0) return s;
      if (c < 0x20 || c > 0x7e) return "";
      s += String.fromCharCode(c);
    }
    return "";
  }
}

const ident = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** A plausible ClientClass at image offset o: name, a RecvTable named DT_*, next is 0 or in-image. */
function isClientClass(m: Img, o: number): boolean {
  const l = m.l;
  const name = m.str(m.ptr(o + l.ccName));
  if (!name || !ident.test(name)) return false;
  const t = m.off(m.ptr(o + l.ccTable));
  if (t < 0) return false;
  const tn = m.str(m.ptr(t + l.rtName));
  if (!tn.startsWith("DT_")) return false;
  const n = m.i32(t + l.rtCount);
  if (n < 0 || n > 4096) return false;
  const next = m.ptr(o + l.ccNext);
  if (next !== 0n && m.off(next) < 0) return false;
  const id = m.i32(o + l.ccId);
  return id >= 0 && id < 8192;
}

/** Props read per dump: a real client.dll has tens of thousands, hostile tables share one 4096-prop array. */
const kMaxProps = 1 << 20;

function walkTable(m: Img, tableAddr: bigint, tables: Record<string, NetvarTable>, depth = 0, budget = { props: kMaxProps }): string {
  const l = m.l;
  const t = m.off(tableAddr);
  const name = m.str(m.ptr(t + l.rtName)) || `table_${tableAddr.toString(16)}`;
  if (tables[name] || depth > 32) return name;
  const tbl: NetvarTable = { name, props: [] };
  tables[name] = tbl;
  const props = m.off(m.ptr(t + l.rtProps));
  const n = Math.min(m.i32(t + l.rtCount), 4096);
  for (let i = 0; i < n && props >= 0 && budget.props > 0; i++, budget.props--) {
    const p = props + i * l.rpSize;
    const pname = m.str(m.ptr(p + l.rpName));
    if (!pname) continue;
    const type = kTypes[m.i32(p + l.rpType)] ?? `type${m.i32(p + l.rpType)}`;
    const prop: NetvarProp = { name: pname, type, offset: m.i32(p + l.rpOffset) };
    const elems = m.i32(p + l.rpElems);
    if (elems > 1) prop.elements = elems;
    const sub = m.ptr(p + l.rpTable);
    if (type === "datatable" && m.off(sub) >= 0) prop.table = walkTable(m, sub, tables, depth + 1, budget);
    tbl.props.push(prop);
  }
  return name;
}

/** Finds the ClientClass list in a client module image and dumps every RecvTable. */
export function dumpNetvars(img: Uint8Array, base: bigint, is64: boolean, sections?: { rva: number; size: number }[]): NetvarDump | null {
  const m = new Img(img, base, is64 ? kL64 : kL32);
  const l = m.l;
  const ranges = sections?.length ? sections : [{ rva: 0, size: img.length }];
  // every ClientClass candidate, then the chains through their next pointers
  const cands = new Set<number>();
  let left = 2 * img.length + 0x10000; // overlapping section ranges cannot multiply the scan
  for (const r of ranges) {
    if (r.size > left) continue;
    left -= r.size;
    for (let o = r.rva; o + l.ccSize <= Math.min(img.length, r.rva + r.size); o += l.ptr) if (isClientClass(m, o)) cands.add(o);
  }
  if (!cands.size) return null;
  const pointedTo = new Set<number>();
  for (const o of cands) {
    const n = m.off(m.ptr(o + l.ccNext));
    if (n >= 0) pointedTo.add(n);
  }
  // chain length from every candidate, memoised: heads that merge into one long tail used to walk
  // it once each (quadratic in the candidates)
  const next = (c: number) => m.off(m.ptr(c + l.ccNext));
  const lengthFrom = new Map<number, number>();
  const chainLength = (o: number): number => {
    const path: number[] = [];
    const onPath = new Set<number>();
    let c = o;
    let tail = 0;
    for (; c >= 0 && cands.has(c); c = next(c)) {
      const known = lengthFrom.get(c);
      if (known !== undefined) { tail = known; break; }
      if (onPath.has(c)) break; // a cycle ends the chain where it closes
      onPath.add(c);
      path.push(c);
    }
    for (let i = path.length - 1; i >= 0; i--) lengthFrom.set(path[i], ++tail);
    return lengthFrom.get(o) ?? 0;
  };
  let bestHead = -1;
  let bestLen = 0;
  for (const o of cands) {
    if (pointedTo.has(o)) continue; // not a head
    const n = chainLength(o);
    if (n > bestLen) { bestLen = n; bestHead = o; }
  }
  const best: number[] = [];
  const seen = new Set<number>();
  for (let c = bestHead; c >= 0 && cands.has(c) && !seen.has(c) && best.length < bestLen; c = next(c)) {
    seen.add(c);
    best.push(c);
  }
  if (best.length < 2) return null;
  const tables: Record<string, NetvarTable> = {};
  const budget = { props: kMaxProps };
  const classes = best.map((o) => ({ name: m.str(m.ptr(o + l.ccName)), id: m.i32(o + l.ccId), table: walkTable(m, m.ptr(o + l.ccTable), tables, 0, budget), address: base + BigInt(o) }));
  return { is64, head: base + BigInt(best[0]), classes, tables };
}

/** Flattened "table.prop = offset" view, nested tables resolved (offsets add up). */
export function flatten(d: NetvarDump, table: string, prefix = 0, depth = 0): { name: string; offset: number; type: string }[] {
  const t = d.tables[table];
  if (!t || depth > 16) return [];
  const out: { name: string; offset: number; type: string }[] = [];
  for (const p of t.props) {
    if (p.name === "baseclass" && p.table) out.push(...flatten(d, p.table, prefix + p.offset, depth + 1));
    else if (p.table && p.type === "datatable" && !/^\d+$/.test(p.name)) {
      out.push({ name: p.name, offset: prefix + p.offset, type: p.table });
      out.push(...flatten(d, p.table, prefix + p.offset, depth + 1).map((x) => ({ ...x, name: `${p.name}.${x.name}` })));
    } else if (!/^\d+$/.test(p.name)) out.push({ name: p.name, offset: prefix + p.offset, type: p.type });
  }
  return out;
}

/** Text dump in the common "netvars.txt" layout. */
export function netvarText(d: NetvarDump): string {
  const lines: string[] = [];
  for (const c of d.classes) {
    lines.push(`${c.name} (${c.table}, id ${c.id})`);
    for (const p of flatten(d, c.table)) lines.push(`  0x${p.offset.toString(16).padStart(4, "0")}  ${p.name}  [${p.type}]`);
  }
  return lines.join("\n") + "\n";
}
