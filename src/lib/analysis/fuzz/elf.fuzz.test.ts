// Fuzz / property tests for the ELF64 parser and the mapped-ELF helpers.
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { clean, fc, inputs, kTimeout, params } from "./harness";
import { elfFile, elfRegions, fixture, type Seed } from "./seeds";
import { detectArch } from "../arch";
import { a64Refs } from "../a64";
import { elfBias, isElf, parseElf } from "../elf";
import { buildXrefIndex, elfExecutableRanges, executableRanges } from "../xrefindex";

function analyse(b: Uint8Array): void {
  const info = clean(() => parseElf(b));
  if (info) clean(() => elfBias(info, 0x7f0000000000n));
  const ranges = clean(() => elfExecutableRanges(b)) ?? [];
  clean(() => buildXrefIndex(b, ranges));
  clean(() => executableRanges(b));
  clean(() => detectArch(b, false));
  clean(() => a64Refs(b, ranges, 10_000));
}

describe("ELF parser under random and mutated input", () => {
  const a64 = fixture("fix-a64.elf");
  const seeds: Seed[] = [{ name: "synthetic", bytes: elfFile(), regions: elfRegions() }, { name: "fix-a64.elf", bytes: a64, regions: [[0, 64], [64, 64 + 8 * 56]] }];
  // a real ELF from the host, cut to its first 64 KiB (section headers are dropped, the rest stays)
  const host = ["/bin/true", "/usr/bin/true"].find((p) => existsSync(p) && isElf(new Uint8Array(readFileSync(p).subarray(0, 4))));
  if (host) {
    const bytes = new Uint8Array(readFileSync(host));
    seeds.push({ name: host, bytes: bytes.subarray(0, Math.min(bytes.length, 0x10000)), regions: [[0, 64], [64, 64 + 13 * 56]] });
  }

  it("the synthetic seed parses", () => {
    const info = parseElf(seeds[0].bytes);
    expect(info.symbols.map((s) => s.name)).toEqual(["main", "helper"]);
    expect(info.needed).toEqual(["libc.so.6"]);
    expect(info.soname).toBe("libx.so");
    expect(info.interp).toBe("/lib/ld.so");
    expect(info.buildId).toBe("0102030405060708");
    expect(info.relocs).toEqual([{ section: ".rela.dyn", offset: 0x2000n, type: 7, symbol: "main", addend: 0n }]);
  });

  it("parseElf / executable ranges / xref index", () => {
    fc.assert(fc.property(inputs(seeds), (b) => analyse(b)), params());
  }, kTimeout);
});
