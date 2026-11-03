// Fuzz / property tests for the game-engine readers (IL2CPP metadata, Source netvars, Unreal
// scanners and name decoders) and the small byte decoders the views use.
import { describe, expect, it } from "vitest";
import { clean, fc, inputs, kTimeout, params, randomBytes } from "./harness";
import { applyMethodPointers, dumpCs, parseMetadata, scriptJson } from "../engines/il2cpp";
import { dumpNetvars, netvarText } from "../engines/source";
import { decodeLegacyEntry, decodePoolEntry, findNamePools, findObjectArrays } from "../engines/unreal";
import { il2cppMetadata, sourceImage } from "../engines/testengines";
import { inspect } from "../bytes";
import { decode, type ValueType } from "../values";
import { fieldValue, kFieldSizes, type FieldType } from "../struct";
import { readNum } from "../scancmp";
import { decodeStub } from "../hooks";
import { resolveSwitch } from "../jumptables";

const kBase = 0x180000000n;

describe("engine readers under random and mutated input", () => {
  it("IL2CPP metadata: parse, dump, apply method pointers", () => {
    const seeds = [0xa8, 0xb0].map((slot) => ({ bytes: il2cppMetadata(slot), regions: [[0, 0x100], [0x400, 0x4b0], [0x600, 0x660], [0x700, 0x718], [0x800, 0x828]] as [number, number][] }));
    const ga = new Uint8Array(0x3000);
    fc.assert(
      fc.property(inputs(seeds), (b) => {
        const md = clean(() => parseMetadata(b));
        if (!md) return;
        clean(() => dumpCs(md));
        clean(() => scriptJson(md));
        clean(() => applyMethodPointers(md, b, kBase, [{ rva: 0, size: b.length }]));
        clean(() => applyMethodPointers(md, ga, kBase, [{ rva: 0x2000, size: 0x1000 }]));
      }),
      params(),
    );
  }, kTimeout);

  it("Source netvars", () => {
    const { img } = sourceImage();
    const seeds = [{ bytes: img, regions: [[0x2000, 0x2620], [0x3000, 0x3080]] as [number, number][] }];
    fc.assert(
      fc.property(inputs(seeds), fc.boolean(), (b, is64) => {
        const d = clean(() => dumpNetvars(b, kBase, is64));
        if (d) clean(() => netvarText(d));
      }),
      params(),
    );
  }, kTimeout);

  it("Unreal scanners and name entries", () => {
    fc.assert(
      fc.property(randomBytes(8192), fc.nat({ max: 8192 }), fc.nat({ max: 8192 }), (b, rva, size) => {
        clean(() => findNamePools(b, kBase, [{ rva, size }, { rva: 0, size: b.length }]));
        clean(() => findObjectArrays(b, kBase, [{ rva, size }, { rva: 0, size: b.length }]));
        clean(() => decodePoolEntry(b.subarray(0, 64)));
        clean(() => decodeLegacyEntry(b.subarray(0, 64)));
      }),
      params(),
    );
  }, kTimeout);
});

describe("small byte decoders on random input", () => {
  const valueTypes: ValueType[] = ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "ptr", "ascii", "utf16"];
  it("inspect / decode / fieldValue / readNum / decodeStub", () => {
    fc.assert(
      fc.property(randomBytes(80), fc.integer({ min: -4, max: 90 }), fc.boolean(), (b, off, le) => {
        clean(() => inspect(b, le));
        for (const t of valueTypes) clean(() => decode(b, off, t));
        for (const t of Object.keys(kFieldSizes) as FieldType[]) clean(() => fieldValue(b, off, t));
        for (const t of ["u8", "i16", "u32", "i64", "f32", "f64"] as const) clean(() => readNum(b, off, t));
        clean(() => decodeStub(b, 0x1000n, () => null));
      }),
      params(),
    );
  }, kTimeout);

  it("jump table recovery reads only inside the image", () => {
    const lines = (n: number, t: string) => [
      { address: "0x140001000", length: 3, text: `cmp eax, ${n}` },
      { address: "0x140001003", length: 2, text: "ja 0x140001100" },
      { address: "0x140001005", length: 7, text: "lea rdx, [rip+0x1000]" },
      { address: "0x14000100c", length: 4, text: "movsxd rax, dword ptr [rdx+rax*4]" },
      { address: "0x140001010", length: 3, text: "add rax, rdx" },
      { address: "0x140001013", length: 2, text: t },
    ];
    fc.assert(
      fc.property(randomBytes(0x3000), fc.constantFrom("0x7fffffff", "0xffffffff", "4", "0"), fc.constantFrom("jmp rax", "jmp qword ptr [rax*8+0x140002000]"), (img, n, t) => {
        const r = clean(() => resolveSwitch(lines(n as unknown as number, t), 5, img, 0x140000000n));
        if (r) expect(r.count).toBeLessThanOrEqual(1 << 16);
      }),
      params(),
    );
  }, kTimeout);
});
