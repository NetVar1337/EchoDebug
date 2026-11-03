// Fuzz / property tests for the CLR metadata reader and the CIL disassembler.
import { describe, expect, it } from "vitest";
import { clean, fc, inputs, kTimeout, params, randomBytes } from "./harness";
import { dotnetSeeds } from "./seeds";
import { compressedUInt, openMetadata, parseDotnet } from "../dotnet";
import { disassembleIl, formatIl, userStringRefs } from "../cil";

function analyse(img: Uint8Array, tokens: number[]): void {
  clean(() => parseDotnet(img));
  const md = clean(() => openMetadata(img));
  if (!md) return;
  for (const t of tokens) {
    clean(() => md.tokenName(t));
    clean(() => md.userString(t));
  }
  clean(() => userStringRefs(img, md.methods));
  for (const m of md.methods.slice(0, 8)) {
    const body = clean(() => disassembleIl(img, m.rva, md.tokenName));
    if (body) clean(() => formatIl(body));
  }
}

const token = fc.oneof(
  fc.integer({ min: 0, max: 0xffffffff }),
  fc.tuple(fc.constantFrom(0x01, 0x02, 0x04, 0x06, 0x0a, 0x11, 0x1a, 0x1b, 0x2b, 0x70), fc.nat({ max: 8 })).map(([t, r]) => ((t << 24) | r) >>> 0),
);

describe(".NET metadata and IL under random and mutated input", () => {
  const seeds = dotnetSeeds();

  it("seeds parse", () => {
    for (const s of seeds) expect(parseDotnet(s.bytes), s.name).not.toBeNull();
  });

  it("parseDotnet / openMetadata / tokenName / IL of every method", () => {
    fc.assert(fc.property(inputs(seeds), fc.array(token, { maxLength: 16 }), (img, tokens) => analyse(img, tokens)), params());
  }, kTimeout);

  it("disassembleIl on random method bodies", () => {
    fc.assert(
      fc.property(randomBytes(512), fc.nat({ max: 600 }), (b, rva) => {
        const body = clean(() => disassembleIl(b, rva));
        if (body) clean(() => formatIl(body));
      }),
      params(),
    );
  }, kTimeout);

  it("compressedUInt never reads past the buffer", () => {
    fc.assert(
      fc.property(randomBytes(8), fc.integer({ min: -2, max: 10 }), (b, at) => {
        const [v, n] = compressedUInt(b, at);
        expect(Number.isInteger(v) && v >= 0 && [1, 2, 4].includes(n)).toBe(true);
      }),
      params(),
    );
  }, kTimeout);
});
