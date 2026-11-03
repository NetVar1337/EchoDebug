import { describe, expect, it } from "vitest";
import {
  decodeLegacyEntry, decodeNameHeader, decodePoolEntry, dumpObjects, findNamePools, findObjectArrays, fnameString, fullName, kDefaultOffsets as O,
  LegacyNames, listObjects, NamePool, ObjectArray, readStruct, ripTarget, sdkText, type Mem,
} from "./unreal";

/** Sparse fake process memory. */
class Fake implements Mem {
  m = new Map<bigint, number>();
  put(a: bigint, b: Uint8Array) { b.forEach((x, i) => this.m.set(a + BigInt(i), x)); }
  u64(a: bigint, v: bigint) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, v, true); this.put(a, b); }
  i32(a: bigint, v: number) { const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, v, true); this.put(a, b); }
  async read(a: bigint, n: number) {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      const v = this.m.get(a + BigInt(i));
      if (v === undefined) return null;
      out[i] = v;
    }
    return out;
  }
}

describe("unreal dumper", () => {
  it("finds GNames/GObjects by shape and dumps objects and an SDK class", async () => {
    const mem = new Fake();
    const modBase = 0x140000000n;
    const img = new Uint8Array(0x2000);
    const dv = new DataView(img.buffer);
    // --- FNamePool at module+0x100: CurrentBlock 0, cursor, Blocks[0] -> heap
    const block = 0x20000000n;
    dv.setUint32(0x108, 0, true);
    dv.setUint32(0x10c, 0x200, true);
    dv.setBigUint64(0x110, block, true);
    // --- FUObjectArray at module+0x1000: Objects -> chunk table, Max 0x20000, Num 6
    const chunkTbl = 0x21000000n, chunk = 0x22000000n;
    dv.setBigUint64(0x1010, chunkTbl, true);
    dv.setInt32(0x1020, 0x20000, true);
    dv.setInt32(0x1024, 70, true);
    dv.setInt32(0x1028, 2, true);
    dv.setInt32(0x102c, 1, true);
    mem.put(modBase, img);
    // names: entries are 2-byte headers (len << 6) + text, 2-byte aligned
    const names: Record<string, number> = {};
    let cur = 0;
    for (const n of ["None", "Class", "ScriptStruct", "Engine", "Object", "Actor", "Pawn", "Health", "IntProperty", "FloatProperty", "Speed", "bAlive", "BoolProperty"]) {
      const at = block + BigInt(cur);
      const h = new Uint8Array(2);
      new DataView(h.buffer).setUint16(0, n.length << 6, true);
      mem.put(at, h);
      mem.put(at + 2n, new TextEncoder().encode(n));
      names[n] = cur / 2;
      cur += (2 + n.length + 1) & ~1;
    }
    // objects: 0 Class(class of classes), 1 Engine (package), 2 Object, 3 Actor, 4 Pawn
    const obj = (i: number) => 0x30000000n + BigInt(i) * 0x200n;
    mem.put(chunk, new Uint8Array(70 * O.itemSize));
    const mk = (i: number, name: string, cls: number, outer: number) => {
      mem.u64(chunk + BigInt(i * O.itemSize), obj(i));
      mem.put(obj(i), new Uint8Array(0x60));
      mem.u64(obj(i) + BigInt(O.objClass), obj(cls));
      mem.i32(obj(i) + BigInt(O.objName), names[name]);
      mem.i32(obj(i) + BigInt(O.objName + 4), 0);
      mem.u64(obj(i) + BigInt(O.objOuter), outer < 0 ? 0n : obj(outer));
    };
    mk(0, "Class", 0, 1); mk(1, "Engine", 0, -1); mk(2, "Object", 0, 1); mk(3, "Actor", 0, 1); mk(4, "Pawn", 0, 1);
    for (let i = 5; i < 70; i++) mem.u64(chunk + BigInt(i * O.itemSize), 0n);
    mem.u64(chunkTbl, chunk);
    // Pawn : Actor, size 0x30, properties Health (int @0x28), Speed (float @0x2c), bAlive (bool @0x2f)
    mem.u64(obj(4) + BigInt(O.structSuper), obj(3));
    mem.u64(obj(3) + BigInt(O.structSuper), obj(2));
    mem.u64(obj(2) + BigInt(O.structSuper), 0n);
    mem.i32(obj(3) + BigInt(O.structSize), 0x28);
    mem.i32(obj(4) + BigInt(O.structSize), 0x30);
    const fieldClass = (n: string) => { const a = 0x40000000n + BigInt(names[n]) * 0x10n; mem.i32(a, names[n]); mem.i32(a + 4n, 0); return a; };
    const field = (a: bigint, name: string, cls: string, offset: number, size: number, next: bigint) => {
      mem.put(a, new Uint8Array(O.propInner + 8));
      mem.u64(a + BigInt(O.fieldClass), fieldClass(cls));
      mem.i32(a + BigInt(O.fieldName), names[name]);
      mem.i32(a + BigInt(O.propArrayDim), 1);
      mem.i32(a + BigInt(O.propElementSize), size);
      mem.i32(a + BigInt(O.propOffset), offset);
      mem.u64(a + BigInt(O.fieldNext), next);
    };
    field(0x50000200n, "bAlive", "BoolProperty", 0x2f, 1, 0n);
    mem.put(0x50000200n + BigInt(O.boolFieldMask), new Uint8Array([0x01]));
    field(0x50000100n, "Speed", "FloatProperty", 0x2c, 4, 0x50000200n);
    field(0x50000000n, "Health", "IntProperty", 0x28, 4, 0x50000100n);
    mem.u64(obj(4) + BigInt(O.structChildProps), 0x50000000n);

    const ranges = [{ rva: 0, size: img.length }];
    const pools = findNamePools(img, modBase, ranges);
    expect(pools.map((p) => p.address)).toContain(modBase + 0x100n);
    const arrays = findObjectArrays(img, modBase, ranges);
    expect(arrays.map((a) => a.address)).toEqual([modBase + 0x1000n]);

    const np = new NamePool(mem, modBase + 0x100n);
    expect(await np.init()).toBe(true);
    expect(await np.name(names.Pawn, 3)).toBe("Pawn_2");
    const oa = new ObjectArray(mem, modBase + 0x1000n);
    expect(await oa.init()).toBe(true);
    const d = await dumpObjects(np, oa);
    expect(d.objects.map((o) => `${o.className} ${o.name}`)).toEqual(["Class Class", "Class Engine", "Class Object", "Class Actor", "Class Pawn"]);
    expect(fullName(d.objects[4], d)).toBe("Engine.Pawn");
    const s = (await readStruct(mem, np, d, d.objects[4]))!;
    expect(s.cppName).toBe("APawn");
    expect(s.superName).toBe("AActor");
    expect(s.fields.map((f) => [f.name, f.type, f.offset])).toEqual([["Health", "int32", 0x28], ["Speed", "float", 0x2c], ["bAlive", "bool", 0x2f]]);
    const text = sdkText([s], new Map([["AActor", 0x28]]));
    expect(text).toContain("class APawn : public AActor {");
    expect(text).toContain("int32 Health; // 0x0028(0x0004)");
    expect(text).toContain("bool bAlive : 1; // mask 0x01 0x002F(0x0001)");
  });
});

const poolEntry = (s: string, wide = false) => {
  const b = new Uint8Array(2 + s.length * (wide ? 2 : 1));
  const dv = new DataView(b.buffer);
  dv.setUint16(0, (s.length << 6) | (wide ? 1 : 0), true);
  for (let i = 0; i < s.length; i++) wide ? dv.setUint16(2 + i * 2, s.charCodeAt(i), true) : (b[2 + i] = s.charCodeAt(i));
  return b;
};

describe("unreal names and object pages", () => {
  it("decodes FNameEntry headers, entries and display names", () => {
    expect(decodeNameHeader((4 << 6) | 1)).toEqual({ wide: true, len: 4 });
    expect(decodePoolEntry(poolEntry("None"))).toBe("None");
    expect(decodePoolEntry(poolEntry("Ünïcode", true))).toBe("Ünïcode");
    expect(decodePoolEntry(poolEntry("Truncated").subarray(0, 5))).toBeNull();
    expect(fnameString("Actor", 0)).toBe("Actor");
    expect(fnameString("Actor", 3)).toBe("Actor_2");
  });

  it("decodes legacy entries", () => {
    const b = new Uint8Array(0x20);
    new DataView(b.buffer).setInt32(0, 5 << 1, true);
    b.set(new TextEncoder().encode("ByteProperty"), 0x10);
    expect(decodeLegacyEntry(b)).toBe("ByteProperty");
  });

  it("resolves RIP-relative operands", () => {
    const d = new Uint8Array(4);
    new DataView(d.buffer).setInt32(0, -0x10, true);
    expect(ripTarget(0x140001000n, d, 7)).toBe(0x140000ff7n);
  });

  it("reads wide names out of a later FNamePool block", async () => {
    const mem = new Fake();
    const pool = 0x140100000n, block0 = 0x20000000n, block1 = 0x20100000n;
    mem.i32(pool + 8n, 1); // CurrentBlock
    mem.i32(pool + 12n, 0x10);
    mem.u64(pool + 16n, block0);
    mem.u64(pool + 24n, block1);
    mem.put(block0, poolEntry("None"));
    mem.put(block1 + 4n, poolEntry("Wïde", true));
    const np = new NamePool(mem, pool);
    expect(await np.init()).toBe(true);
    expect(await np.name((1 << 16) | 2)).toBe("Wïde");
    expect(await np.name(5 << 16)).toBe("name#327680"); // no such block
  });

  it("reads names out of legacy GNames", async () => {
    const mem = new Fake();
    const g = 0x20000000n, chunk = 0x20010000n;
    mem.u64(g, chunk);
    const entry = (i: number, s: string) => {
      const at = 0x20020000n + BigInt(i) * 0x200n;
      mem.u64(chunk + BigInt(i) * 8n, at);
      mem.put(at, new Uint8Array(0x10 + 0x100));
      mem.i32(at, i << 1);
      mem.put(at + 0x10n, new TextEncoder().encode(s + "\0"));
    };
    entry(0, "None");
    entry(7, "Object");
    const n = new LegacyNames(mem, g);
    expect(await n.init()).toBe(true);
    expect(await n.name(7)).toBe("Object");
    expect(await n.name(7, 2)).toBe("Object_1");
  });

  it("lists GUObjectArray pages with names and classes, skipping free slots", async () => {
    const mem = new Fake();
    const pool = 0x140100000n, block = 0x20000000n;
    mem.i32(pool + 8n, 0);
    mem.i32(pool + 12n, 0x40);
    mem.u64(pool + 16n, block);
    mem.put(block, poolEntry("None")); // 0
    mem.put(block + 0x10n, poolEntry("Class")); // 8
    mem.put(block + 0x20n, poolEntry("Package")); // 0x10
    mem.put(block + 0x30n, poolEntry("PlayerPawn")); // 0x18

    const gobj = 0x140200000n, chunks = 0x21000000n, items = 0x22000000n;
    mem.put(gobj, new Uint8Array(0x30));
    mem.u64(gobj + 0x10n, chunks);
    mem.i32(gobj + 0x24n, 3); // Num
    mem.i32(gobj + 0x2cn, 1); // NumChunks
    mem.u64(chunks, items);
    mem.put(items, new Uint8Array(3 * O.itemSize));
    const obj = (addr: bigint, cls: bigint, name: number, num = 0) => {
      mem.put(addr, new Uint8Array(0x28));
      mem.u64(addr + BigInt(O.objClass), cls); mem.i32(addr + BigInt(O.objName), name); mem.i32(addr + BigInt(O.objName + 4), num);
    };
    const classClass = 0x23000000n, pkgClass = 0x23000100n, pawn = 0x23000200n;
    obj(classClass, classClass, 8);
    obj(pkgClass, classClass, 0x10);
    obj(pawn, pkgClass, 0x18, 4);
    mem.u64(items, classClass);
    mem.u64(items + BigInt(2 * O.itemSize), pawn); // slot 1 is free

    const oa = new ObjectArray(mem, gobj);
    expect(await oa.init()).toBe(true);
    const np = new NamePool(mem, pool);
    expect(await np.init()).toBe(true);
    const rows = await listObjects(np, oa, 0, 10);
    expect(rows.map((x) => [x.index, x.name, x.className])).toEqual([
      [0, "Class", "Class"],
      [2, "PlayerPawn_3", "Package"],
    ]);
    expect(await listObjects(np, oa, 1, 1)).toEqual([]);
  });
});
