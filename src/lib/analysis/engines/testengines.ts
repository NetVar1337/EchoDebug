// Test helpers: a synthetic IL2CPP global-metadata.dat and a Source engine client image. Used by
// the engine reader tests and the fuzz seeds.

/** A v29-shaped global-metadata.dat: one image, two types, three methods, two fields. */
export function il2cppMetadata(imageSlot = 0xa8) {
  const b = new Uint8Array(0x1000);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, 0xfab11baf, true);
  dv.setInt32(4, 29, true);
  // strings at 0x200
  let sp = 0;
  const strs = new Uint8Array(0x200);
  const s = (t: string) => { const i = sp; strs.set(new TextEncoder().encode(t + "\0"), i); sp += t.length + 1; return i; };
  const img = s("Assembly-CSharp.dll"), ns = s("Game"), player = s("Player"), enemy = s("Enemy");
  const update = s("Update"), takeDamage = s("TakeDamage"), ctor = s(".ctor"), hp = s("health"), spd = s("speed");
  b.set(strs, 0x200);
  const pair = (o: number, off: number, size: number) => { dv.setUint32(o, off, true); dv.setUint32(o + 4, size, true); };
  pair(0x18, 0x200, 0x200);
  // types (88 bytes): name 0, namespace 4, fieldStart size-56, methodStart size-52, method_count size-24, field_count size-20, token size-4
  const TS = 88;
  const type = (i: number, name: number, fieldStart: number, fc: number, methodStart: number, mc: number) => {
    const o = 0x400 + i * TS;
    dv.setInt32(o, name, true); dv.setInt32(o + 4, ns, true);
    dv.setInt32(o + TS - 56, fieldStart, true); dv.setInt32(o + TS - 52, methodStart, true);
    dv.setUint16(o + TS - 24, mc, true); dv.setUint16(o + TS - 20, fc, true);
    dv.setUint32(o + TS - 4, 0x02000002 + i, true);
  };
  type(0, player, 0, 2, 0, 2);
  type(1, enemy, -1, 0, 2, 1);
  pair(0xa0, 0x400, 2 * TS);
  // methods (32 bytes): name 0, token size-12, params size-2
  const MS = 32;
  [[update, 0], [takeDamage, 1], [ctor, 0]].forEach(([n, params], i) => {
    const o = 0x600 + i * MS;
    dv.setInt32(o, n, true); dv.setUint32(o + MS - 12, 0x06000001 + i, true); dv.setUint16(o + MS - 2, params, true);
  });
  pair(0x30, 0x600, 3 * MS);
  // fields (12 bytes): name 0, token 8
  [hp, spd].forEach((n, i) => { dv.setInt32(0x700 + i * 12, n, true); dv.setUint32(0x700 + i * 12 + 8, 0x04000001 + i, true); });
  pair(0x60, 0x700, 24);
  // image (40 bytes): name 0, typeStart 8, typeCount 12
  dv.setInt32(0x800, img, true); dv.setInt32(0x808, 0, true); dv.setUint32(0x80c, 2, true);
  pair(imageSlot, 0x800, 40);
  return b;
}

/** A tiny x64 client image: two ClientClasses, a derived table with a baseclass and a nested table. */
export function sourceImage() {
  const base = 0x180000000n;
  const img = new Uint8Array(0x4000);
  const dv = new DataView(img.buffer);
  let str = 0x100;
  const s = (t: string) => { const a = str; img.set(new TextEncoder().encode(t + "\0"), a); str += t.length + 1; return base + BigInt(a); };
  const p64 = (o: number, v: bigint) => dv.setBigUint64(o, v, true);
  // RecvProp x64 (0x60 bytes): name 0, type 8, datatable 0x40, offset 0x48, elements 0x50
  const prop = (o: number, name: string, type: number, offset: number, table = 0n) => { p64(o, s(name)); dv.setInt32(o + 8, type, true); p64(o + 0x40, table); dv.setInt32(o + 0x48, offset, true); dv.setInt32(o + 0x50, 1, true); };
  // RecvTable x64: props 0, count 8, name 0x18
  const table = (o: number, name: string, props: number, n: number) => { p64(o, base + BigInt(props)); dv.setInt32(o + 8, n, true); p64(o + 0x18, s(name)); return base + BigInt(o); };
  const dtLocal = table(0x2000, "DT_LocalData", 0x2100, 1);
  prop(0x2100, "m_vecVelocity", 2, 0x10);
  const dtBase = table(0x2200, "DT_BaseEntity", 0x2300, 2);
  prop(0x2300, "m_iTeamNum", 0, 0xf4);
  prop(0x2360, "m_vecOrigin", 2, 0x138);
  const dtPlayer = table(0x2400, "DT_BasePlayer", 0x2500, 3);
  prop(0x2500, "baseclass", 6, 0, dtBase);
  prop(0x2560, "m_iHealth", 0, 0x100);
  prop(0x25c0, "localdata", 6, 0x200, dtLocal);
  // ClientClass x64: name 0x10, table 0x18, next 0x20, id 0x28
  const cc = (o: number, name: string, t: bigint, next: bigint, id: number) => { p64(o + 0x10, s(name)); p64(o + 0x18, t); p64(o + 0x20, next); dv.setInt32(o + 0x28, id, true); return base + BigInt(o); };
  const c2 = cc(0x3040, "C_BaseEntity", dtBase, 0n, 1);
  cc(0x3000, "C_BasePlayer", dtPlayer, c2, 2);
  return { img, base };
}
