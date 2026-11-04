// Tests for the game scanner: full netvar enumeration from descriptor structures,
// entity-list discovery by pointer-shape, view matrix by frame-diff.
import { describe, expect, it } from "vitest";
import { clusterAndConfirm, collectMemberNames, enumerateLiveNetvars, enumerateNetvars, findEntityList, findViewMatrix, offsetMap, type MemBatch, type MemReader } from "./apex";
import type { PeInfo } from "../pe";

const base = 0x140000000n;

// A synthetic module image: one DataDesc table (4+ entries), one compact RecvProp table,
// plus a PeInfo with one data section covering them.
function fixture() {
  const img = new Uint8Array(0x10000);
  const dv = new DataView(img.buffer);
  let strOff = 0x8000;
  const str = (t: string) => { const o = strOff; img.set(new TextEncoder().encode(t + "\0"), o); strOff += t.length + 1; return o; };
  const p64 = (o: number, v: bigint | number) => dv.setBigUint64(o, BigInt(v), true);
  const i32 = (o: number, v: number) => dv.setInt32(o, v, true);
  // DataDesc table @ 0x2000: type/offset/string(+0x28) entries
  const health = str("m_iHealth");
  const team = str("m_iTeamNum");
  const origin = str("m_vecAbsOrigin");
  const vel = str("m_vecVelocity");
  const zoom = str("m_bZooming");
  const rows: [string, number, number][] = [["", 0, 0]];
  void rows;
  const t2 = (o: number, nameRva: number, off: number, type = 0) => { i32(o, type); i32(o + 4, off); p64(o + 0x28, nameRva); };
  t2(0x2000, health, 0x330);
  t2(0x2040, team, 0x340);
  t2(0x2080, origin, 0x170, 1); // composite
  t2(0x20c0, vel, 0x384);
  t2(0x2100, zoom, 0x1cb1);
  // compact RecvProp-style table @ 0x3000: [string][offset@+8]
  p64(0x3000, health);
  i32(0x3008, 0x330); // agrees with the DataDesc offset → confirmed
  p64(0x3040, team);
  i32(0x3048, 0x340);
  p64(0x3080, origin);
  i32(0x3088, 0x170);
  p64(0x30c0, vel);
  i32(0x30c8, 0x384);
  const pe = {
    sections: [
      { name: ".data", rva: 0x2000, vsize: 0x2000, rawSize: 0x2000, chars: 0, r: true, w: true, x: false },
      { name: ".rdata", rva: 0x8000, vsize: 0x1000, rawSize: 0x1000, chars: 0, r: true, w: false, x: false },
    ],
  } as unknown as PeInfo;
  return { img, base, pe };
}

describe("enumerateNetvars", () => {
  it("finds both tables, cross-confirms shared offsets and maps canaries", () => {
    const { img, base: b, pe } = fixture();
    const scan = enumerateNetvars(img, b, pe);
    expect(scan.tables.length).toBe(2);
    expect(scan.confirmed).toBeGreaterThanOrEqual(4);
    const map = offsetMap(scan);
    expect(map.get("m_iHealth")).toBe(0x330);
    expect(map.get("m_vecAbsOrigin")).toBe(0x170);
    const t2 = scan.tables.find((t) => t.entries.some((e) => e.type === 1))!;
    expect(t2.entries.find((e) => e.name === "m_vecAbsOrigin")!.type).toBe(1);
    const health = scan.tables.flatMap((t) => t.entries).filter((e) => e.name === "m_iHealth");
    expect(health.some((e) => e.confirmed)).toBe(true);
  });

  it("ignores random pointer coincidences (no validated cluster, no tables)", () => {
    const img = new Uint8Array(0x4000);
    const dv = new DataView(img.buffer);
    img.set(new TextEncoder().encode("m_loner\0"), 0x3000);
    dv.setBigUint64(0x1000, 0x3000n, true); // one dangling pointer, no descriptor fields
    const pe = { sections: [{ name: ".data", rva: 0x1000, vsize: 0x2000, rawSize: 0x2000, chars: 0, r: true, w: true, x: false }] } as unknown as PeInfo;
    const scan = enumerateNetvars(img, 0x140000000n, pe);
    expect(scan.tables.length).toBe(0);
  });
});

// Synthetic process memory for the globals: a writable span holding the entity-list global,
// whose target block has CEntInfo-style slots (entity ptr + serial) with vtables in rdata.
function procMem() {
  const mem = new Uint8Array(0x40000);
  const dv = new DataView(mem.buffer);
  const WRIT = 0x10000, RDATA = 0x20000, ENT0 = 0x28000;
  const vt = RDATA + 0x800;
  // entity-list global at WRIT+0x800 points at ENT0 (a block of entity pointers)
  dv.setBigUint64(WRIT + 0x800, BigInt(ENT0), true);
  // entity block: 8 CEntInfo-ish slots at 0x20 stride, each holding an entity ptr (+ serial at +0x10)
  for (let i = 0; i < 8; i++) {
    dv.setBigUint64(ENT0 + i * 0x20, BigInt(0x2a000 + i * 0x1000), true);
    dv.setBigUint64(ENT0 + i * 0x20 + 0x10, 0x1000n + BigInt(i), true);
    dv.setBigUint64(0x2a000 + i * 0x1000, BigInt(vt), true); // entity head -> vtable in rdata
  }
  // a decoy: pointer to writable, but target's head is not an rdata vtable
  dv.setBigUint64(WRIT + 0x900, BigInt(WRIT + 0x1000), true);
  dv.setBigUint64(WRIT + 0x1000, BigInt(WRIT + 0x500), true);
  const read: MemReader = async (addr, size) => {
    const o = Number(addr);
    return o >= 0 && o + size <= mem.length ? mem.subarray(o, o + size) : null;
  };
  const batch: MemBatch = async (reads) => reads.map((r) => {
    const o = Number(r.addr);
    return o >= 0 && o + r.size <= mem.length ? mem.subarray(o, o + r.size) : null;
  });
  const writable = [{ addr: BigInt(WRIT), size: 0x1000 }];
  const rdata = [{ addr: BigInt(RDATA), size: 0x1000 }];
  return { read, batch, writable, rdata };
}

describe("enumerateLiveNetvars", () => {
  // member strings in an "image"; descriptor tables in a heap outside it holding ABSOLUTE pointers
  it("finds runtime-built tables by their absolute pointers to module strings", async () => {
    const base = 0x7ff600000000n;
    const img = new Uint8Array(0x10000);
    const str = (o: number, t: string) => img.set(new TextEncoder().encode(t + "\0"), o);
    str(0x5000, "m_iHealth");
    str(0x5100, "m_iTeamNum");
    const names = new Map<string, number[]>([["m_iHealth", [0x5000]], ["m_iTeamNum", [0x5100]]]);
    const HEAP = 0x1a0000000n;
    const heap = new Uint8Array(0x40000);
    const dv = new DataView(heap.buffer);
    const t2 = (o: number, rva: number, off: number) => {
      dv.setUint32(o, 0, true);
      dv.setUint32(o + 4, off, true);
      dv.setBigUint64(o + 0x28, base + BigInt(rva), true);
    };
    t2(0x8000, 0x5000, 0x330);
    t2(0x8040, 0x5100, 0x340);
    t2(0x9000, 0x5000, 0x331); // a second table, far enough to cluster separately
    t2(0x9040, 0x5100, 0x341);
    const read: MemReader = async (addr, size) => {
      const o = Number(addr - HEAP);
      return o >= 0 && o + size <= heap.length ? heap.subarray(o, o + size) : null;
    };
    const r = await enumerateLiveNetvars(read, [{ addr: HEAP, size: heap.length }], base, names, { chunkBytes: 0x8000 });
    expect(r.found.length).toBe(4);
    const scan = clusterAndConfirm(r.found, 2);
    expect(scan.tables.length).toBe(2);
    const map = offsetMap(scan);
    expect(map.get("m_iHealth")).toBe(0x330);
    expect(map.get("m_iTeamNum")).toBe(0x340);
  });

  it("stops early once enoughNames distinct members validated", async () => {
    const base = 0x7ff600000000n;
    const img = new Uint8Array(0x10000);
    img.set(new TextEncoder().encode("m_one\0"), 0x5000);
    img.set(new TextEncoder().encode("m_two\0"), 0x5100);
    const names = new Map<string, number[]>([["m_one", [0x5000]], ["m_two", [0x5100]]]);
    const HEAP = 0x1a0000000n;
    const heap = new Uint8Array(0x40000);
    const dv = new DataView(heap.buffer);
    // table at the very start, then a huge empty span that should never be fully read
    dv.setUint32(0x100, 0, true);
    dv.setUint32(0x104, 0x10, true);
    dv.setBigUint64(0x128, base + 0x5000n, true);
    dv.setUint32(0x140, 0, true);
    dv.setUint32(0x144, 0x20, true);
    dv.setBigUint64(0x168, base + 0x5100n, true);
    let reads = 0;
    const read: MemReader = async (addr, size) => {
      reads++;
      const o = Number(addr - HEAP);
      return o >= 0 && o + size <= heap.length ? heap.subarray(o, o + size) : null;
    };
    const r = await enumerateLiveNetvars(read, [{ addr: HEAP, size: heap.length }], base, names, { chunkBytes: 0x1000, enoughNames: 2 });
    expect(r.found.length).toBe(2);
    expect(reads).toBeLessThan(5);
  });
});

describe("collectMemberNames", () => {
  it("collects identifier strings and never drops a canary to the cap", () => {
    const img = new Uint8Array(0x10000);
    // fill the image with many decoy identifiers so the cap is hit
    let o = 0x100;
    for (let i = 0; i < 5000 && o < 0x8000; i++) {
      img.set(new TextEncoder().encode(`decoy_name_${i}\0`), o);
      o += 16;
    }
    img.set(new TextEncoder().encode("m_iHealth\0"), 0x9000);
    const names = collectMemberNames(img, 100);
    expect(names.get("m_iHealth")).toEqual([0x9000]);
  });
});

describe("findEntityList", () => {
  it("finds the global by pointer shape and scores sibling slots", async () => {
    const { read, batch, writable, rdata } = procMem();
    const hits = await findEntityList(read, batch, writable, rdata);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].address).toBe(0x10800n);
    expect(hits[0].score).toBeGreaterThanOrEqual(8); // head + 7 valid siblings
  });
});

describe("findViewMatrix", () => {
  it("frame-diffs a live camera matrix out of a writable span", async () => {
    const mem = new Uint8Array(0x20000);
    const dv = new DataView(mem.buffer);
    const MAT = 0x18000;
    const writeMat = (yaw: number) => {
      const c = Math.cos(yaw), s = Math.sin(yaw);
      const m = [c, s * 0.5, -s, 0, -s * 0.3, c, s * 0.2, 0, s, -s * 0.2, c, 0, 10 + 5 * yaw, 20 - 3 * yaw, 30 + yaw, 1];
      m.forEach((v, i) => dv.setFloat32(MAT + i * 4, v, true));
    };
    writeMat(0.3);
    const spans = [{ addr: BigInt(MAT - 0x4000), size: 0x8000 }];
    let call = 0;
    const read: MemReader = async (addr, size) => {
      call++;
      if (call > 1 && addr === BigInt(MAT - 0x4000)) writeMat(0.9); // "next frame"
      const o = Number(addr);
      return mem.slice(o, o + size); // copies: a and b must be independent snapshots
    };
    const hit = await findViewMatrix(read, spans, { delayMs: 0 });
    expect(hit).not.toBeNull();
    expect(hit!.address).toBe(BigInt(MAT));
  });

  it("rejects static memory (nothing changes between reads)", async () => {
    const mem = new Uint8Array(0x2000);
    const read: MemReader = async (addr, size) => mem.subarray(Number(addr), Number(addr) + size);
    expect(await findViewMatrix(read, [{ addr: 0n, size: 0x2000 }], { delayMs: 0 })).toBeNull();
  });
});
