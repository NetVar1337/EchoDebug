// Fuzz / property tests for everything that reads PE bytes: headers, sections, imports, exports,
// .pdata, Rich/TLS/relocations/debug, resources, RTTI, Authenticode, unpacking, hook scans and the
// byte scanners that walk the section table.
import { describe, expect, it } from "vitest";
import { clean, cleanAsync, fc, inputs, kTimeout, params, randomBytes } from "./harness";
import { peSeeds } from "./seeds";
import { mapPeFile, parsePe, parseRuntimeFunctions, type PeInfo } from "../pe";
import { imphash, parseDebug, parseRelocs, parseRich, parseTls } from "../peextra";
import { summarizeResources, resourceTree, parseVersionInfo, parseDialog, parseStringTable, buildIco } from "../resources";
import { buildRtti, findVftables } from "../rtti";
import { buildExports } from "../exports";
import { buildIat } from "../iat";
import { authenticodeHash, certificateTable, parseDer, parseSignature } from "../authenticode";
import { buildDumpPe, findIat, type ExportIndex } from "../unpack";
import { diffCode, iatHooks, inlineHooks, rebase } from "../hooks";
import { detectPacker, sectionEntropies } from "../entropy";
import { scanAntiDebug } from "../antidebug";
import { scanCrypto } from "../crypto";
import { buildXrefIndex, executableRanges } from "../xrefindex";
import { findXrefs } from "../xrefs";
import { extractStrings } from "../strings";
import { stringAt } from "../annotate";
import { parseDotnet } from "../dotnet";
import { dumpNetvars } from "../engines/source";
import { findNamePools, findObjectArrays } from "../engines/unreal";
import { listExceptionHandlers, parseUnwindInfo, tlsCallbacks } from "../seh";
import { detectArch } from "../arch";
import { a64Refs } from "../a64";

const kBase = 0x140000000n;

/** Every analysis that takes a mapped image, each under the robustness property. */
function analyseImage(img: Uint8Array): void {
  const pe = clean(() => parsePe(img));
  clean(() => parseRich(img));
  clean(() => executableRanges(img));
  clean(() => buildExports(img, kBase));
  clean(() => buildIat(img, kBase));
  clean(() => buildRtti(img, kBase));
  clean(() => sectionEntropies(img));
  clean(() => detectPacker(img));
  clean(() => scanAntiDebug(img, kBase));
  clean(() => parseDotnet(img));
  clean(() => detectArch(img, true));
  clean(() => detectArch(img, false));
  clean(() => listExceptionHandlers(img));
  if (!pe) return;
  clean(() => tlsCallbacks(img, pe.imageBase, pe));
  for (const f of (clean(() => parseRuntimeFunctions(img, pe)) ?? []).slice(0, 16)) clean(() => parseUnwindInfo(img, f.unwind));
  clean(() => parseRuntimeFunctions(img, pe));
  clean(() => parseTls(img, pe.imageBase, pe));
  clean(() => parseRelocs(img, pe));
  clean(() => parseDebug(img, pe));
  clean(() => imphash(pe));
  clean(() => resourceTree(img, pe));
  clean(() => summarizeResources(img, pe));
  const rtti = clean(() => buildRtti(img, kBase, pe));
  for (const c of rtti?.classes.slice(0, 4) ?? []) clean(() => findVftables(img, kBase, c, pe));
  const ranges = clean(() => executableRanges(img, pe)) ?? [];
  clean(() => a64Refs(img, ranges, 10_000));
  clean(() => buildXrefIndex(img, ranges));
  clean(() => findXrefs(img, ranges, pe.entryRva));
  clean(() => findIat(img, exportIndex(pe)));
  clean(() => diffCode(img, rebase(img, pe, kBase + 0x10000n), pe, kBase));
  clean(() => inlineHooks(img, pe, kBase, img.length, [{ name: "a.dll", base: kBase, size: img.length }]));
  clean(() => iatHooks(img, pe, [{ name: "kernel32.dll", base: 0x7ff800000000n, size: 0x100000 }]));
  clean(() => buildDumpPe(img, kBase, pe.entryRva, findIat(img, exportIndex(pe)), pe));
  clean(() => dumpNetvars(img, kBase, pe.is64, pe.sections.map((s) => ({ rva: s.rva, size: s.vsize }))));
  clean(() => findNamePools(img, kBase, pe.sections.map((s) => ({ rva: s.rva, size: s.vsize }))));
  clean(() => findObjectArrays(img, kBase, pe.sections.map((s) => ({ rva: s.rva, size: s.vsize }))));
}

/** An export index that makes every qword equal to one of a few values look like an import. */
function exportIndex(pe: PeInfo): ExportIndex {
  const m: ExportIndex = new Map();
  m.set(0x7ff800001000n, { dll: "kernel32.dll", name: "Sleep" });
  m.set(0x7ff800002000n, { dll: "kernel32.dll", name: "ExitProcess" });
  m.set(0x7ff900001000n, { dll: "user32.dll", name: "", ordinal: 7 });
  m.set(kBase + BigInt(pe.entryRva), { dll: "self.dll", name: "Entry" });
  return m;
}

describe("PE parsers under random and mutated input", () => {
  const { files, images } = peSeeds();

  it("seeds parse", () => {
    for (const s of images) expect(() => parsePe(s.bytes), s.name).not.toThrow();
  });

  it("mapped images: every analysis returns or fails cleanly, within budget", () => {
    fc.assert(fc.property(inputs(images), (img) => analyseImage(img)), params());
  }, kTimeout);

  it("files: mapPeFile, Authenticode and the analyses of the mapped result", async () => {
    await fc.assert(
      fc.asyncProperty(inputs(files), async (file) => {
        clean(() => certificateTable(file));
        clean(() => parseSignature(file));
        clean(() => parseRich(file));
        await cleanAsync(() => authenticodeHash(file));
        const img = clean(() => mapPeFile(file));
        if (img) analyseImage(img);
      }),
      params(),
    );
  }, kTimeout);

  it("resource leaf decoders on random bytes", () => {
    fc.assert(
      fc.property(randomBytes(1024), fc.nat({ max: 0xffff }), (b, id) => {
        clean(() => parseVersionInfo(b));
        clean(() => parseDialog(b));
        clean(() => parseStringTable(id, b));
        clean(() => buildIco(b, new Map([[1, b], [id, b.subarray(1)]])));
      }),
      params(),
    );
  }, kTimeout);

  it("DER decoder on random bytes", () => {
    fc.assert(fc.property(randomBytes(512), (b) => { clean(() => parseDer(b)); }), params());
  }, kTimeout);

  it("byte scanners on random buffers", () => {
    fc.assert(
      fc.property(randomBytes(8192), fc.nat({ max: 8192 }), (b, at) => {
        clean(() => scanCrypto(b, kBase));
        clean(() => extractStrings(b));
        clean(() => stringAt(b, at));
        clean(() => buildXrefIndex(b, [{ rva: 0, size: b.length }]));
        clean(() => findXrefs(b, [{ rva: 0, size: b.length }], at));
        clean(() => findXrefs(b, [{ rva: 0, size: b.length }], at, 100, "arm64"));
        clean(() => a64Refs(b, [{ rva: 0, size: b.length }]));
        clean(() => parseUnwindInfo(b, at));
        clean(() => detectArch(b));
      }),
      params(),
    );
  }, kTimeout);
});
