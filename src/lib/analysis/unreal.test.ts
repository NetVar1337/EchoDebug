import { describe, expect, it } from "vitest";
import {
  decodeLegacyEntry, decodeNameHeader, decodePoolEntry, fnameString, kLegacyNames, kNamePool, parseUObject, poolLocation,
  readNames, readObjects, ripTarget, type Reader,
} from "./unreal";

/** A sparse fake address space: writes go into 64 KiB pages, reads of unmapped pages fail. */
class Mem {
  pages = new Map<bigint, Uint8Array>();
  page(a: bigint) {
    const k = a & ~0xffffn;
    if (!this.pages.has(k)) this.pages.set(k, new Uint8Array(0x10000));
    return this.pages.get(k)!;
  }
  write(a: bigint, b: Uint8Array) { b.forEach((x, i) => (this.page(a + BigInt(i))[Number((a + BigInt(i)) & 0xffffn)] = x)); }
  u64(a: bigint, v: bigint) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, v, true); this.write(a, b); }
  i32(a: bigint, v: number) { const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, v, true); this.write(a, b); }
  reader: Reader = async (reads) => reads.map(({ address, size }) => {
    if (!this.pages.has(address & ~0xffffn)) return null;
    return Uint8Array.from({ length: size }, (_, i) => this.pages.get((address + BigInt(i)) & ~0xffffn)?.[Number((address + BigInt(i)) & 0xffffn)] ?? 0);
  });
}

const poolEntry = (s: string, wide = false) => {
  const h = (s.length << 6) | (wide ? 1 : 0);
  const b = new Uint8Array(2 + s.length * (wide ? 2 : 1));
  new DataView(b.buffer).setUint16(0, h, true);
  for (let i = 0; i < s.length; i++) wide ? new DataView(b.buffer).setUint16(2 + i * 2, s.charCodeAt(i), true) : (b[2 + i] = s.charCodeAt(i));
  return b;
};

describe("unreal names", () => {
  it("decodes FNameEntry headers and entries", () => {
    expect(decodeNameHeader((4 << 6) | 1)).toEqual({ wide: true, len: 4 });
    expect(decodePoolEntry(poolEntry("None"))).toBe("None");
    expect(decodePoolEntry(poolEntry("Ünïcode", true))).toBe("Ünïcode");
    expect(decodePoolEntry(poolEntry("Truncated").subarray(0, 5))).toBeNull();
    expect(poolLocation((3 << 16) | 0x10)).toEqual({ block: 3, offset: 0x20 });
    expect(fnameString("Actor", 0)).toBe("Actor");
    expect(fnameString("Actor", 3)).toBe("Actor_2");
  });

  it("decodes legacy entries", () => {
    const b = new Uint8Array(0x20);
    new DataView(b.buffer).setInt32(0, 5 << 1, true);
    b.set(new TextEncoder().encode("ByteProperty"), kLegacyNames.nameOffset);
    expect(decodeLegacyEntry(b)).toBe("ByteProperty");
  });

  it("resolves RIP-relative operands", () => {
    const d = new Uint8Array(4);
    new DataView(d.buffer).setInt32(0, -0x10, true);
    expect(ripTarget(0x140001000n, d, 7)).toBe(0x140000ff7n);
  });

  it("reads names out of an FNamePool, including long and wide ones", async () => {
    const m = new Mem();
    const pool = 0x140100000n, block0 = 0x20000000n, block1 = 0x20100000n;
    m.u64(pool + BigInt(kNamePool.blocksOffset), block0);
    m.u64(pool + BigInt(kNamePool.blocksOffset + 8), block1);
    m.write(block0, poolEntry("None")); // index 0
    m.write(block0 + 6n, poolEntry("ByteProperty")); // index 3
    const long = "A".repeat(200);
    m.write(block0 + 0x20n, poolEntry(long)); // index 0x10
    m.write(block1 + 4n, poolEntry("Wïde", true)); // index (1<<16)|2
    const names = await readNames(m.reader, { kind: "pool", address: pool, layout: kNamePool }, [0, 3, 0x10, (1 << 16) | 2, (5 << 16)]);
    expect(names.get(0)).toBe("None");
    expect(names.get(3)).toBe("ByteProperty");
    expect(names.get(0x10)).toBe(long);
    expect(names.get((1 << 16) | 2)).toBe("Wïde");
    expect(names.get(5 << 16)).toMatch(/^</); // block pointer is null
  });

  it("reads names out of legacy GNames", async () => {
    const m = new Mem();
    const g = 0x20000000n, chunk = 0x20010000n, entry = 0x20020000n;
    m.u64(g, chunk);
    m.u64(chunk + 7n * 8n, entry);
    m.i32(entry, 7 << 1);
    m.write(entry + 0x10n, new TextEncoder().encode("Object\0"));
    const names = await readNames(m.reader, { kind: "legacy", address: g, layout: kLegacyNames }, [7]);
    expect(names.get(7)).toBe("Object");
  });
});

describe("unreal objects", () => {
  it("parses a UObject header", () => {
    const b = new Uint8Array(0x28);
    const d = new DataView(b.buffer);
    d.setBigUint64(0, 0x140200000n, true); d.setInt32(0xc, 42, true); d.setBigUint64(0x10, 0x30000000n, true); d.setInt32(0x18, 7, true); d.setInt32(0x1c, 2, true);
    expect(parseUObject(b)).toMatchObject({ vtable: 0x140200000n, index: 42, cls: 0x30000000n, nameIndex: 7, nameNumber: 2 });
  });

  it("lists GUObjectArray pages with names and classes", async () => {
    const m = new Mem();
    const pool = 0x140100000n, block = 0x20000000n;
    m.u64(pool + 0x10n, block);
    m.write(block, poolEntry("Class")); // 0
    m.write(block + 0x10n, poolEntry("Package")); // 8
    m.write(block + 0x20n, poolEntry("PlayerPawn")); // 0x10

    const gobj = 0x140200000n, chunks = 0x21000000n, items = 0x22000000n;
    m.u64(gobj + 0x10n, chunks);
    m.i32(gobj + 0x24n, 3);
    m.u64(chunks, items);
    const obj = (addr: bigint, idx: number, cls: bigint, name: number, num = 0) => {
      m.u64(addr, 0x140001000n); m.i32(addr + 0xcn, idx); m.u64(addr + 0x10n, cls); m.i32(addr + 0x18n, name); m.i32(addr + 0x1cn, num);
    };
    const classClass = 0x23000000n, pkgClass = 0x23000100n, pawn = 0x23000200n;
    obj(classClass, 0, classClass, 0);
    obj(pkgClass, 1, classClass, 8);
    obj(pawn, 2, pkgClass, 0x10, 4);
    m.u64(items, classClass);
    m.u64(items + 0x18n, 0n); // freed slot
    m.u64(items + 0x30n, pawn);

    const r = await readObjects(m.reader, gobj, { kind: "pool", address: pool, layout: kNamePool }, 0, 10);
    expect(r.total).toBe(3);
    expect(r.rows.map((x) => [x.index, x.name, x.className])).toEqual([
      [0, "Class", "Class"],
      [2, "PlayerPawn_3", "Package"],
    ]);
  });
});
