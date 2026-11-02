import { describe, expect, it } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { mapPeFile, parsePe } from "./pe";
import { buildDumpPe, findIat, findOep, type ExportIndex } from "./unpack";

const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));

describe("unpacking", () => {
  it("finds the OEP from a trace and the emulator's writes", () => {
    const sections = [{ start: 0x1000n, end: 0x2000n, name: ".text" }, { start: 0x5000n, end: 0x6000n, name: "UPX0" }];
    // stub in UPX0 writes 0x1000-0x1fff, then jumps there
    const trace = [0x5000n, 0x5004n, 0x5008n, 0x1234n, 0x1238n];
    const c = findOep(trace, [{ address: 0x1000n, size: 0x1000 }], [sections[1], sections[0]]);
    expect(c[0]).toEqual({ address: 0x1234n, step: 3, reason: "written-then-executed" });
    expect(c.map((x) => x.reason)).toContain("section-change");
  });

  it("recovers the IAT of a loaded image and writes a PE whose imports parse back", () => {
    const base = 0x140000000n;
    const img = mapPeFile(fixture("fix.exe"));
    const pe = parsePe(img);
    // simulate the loader: the IAT slots hold the resolved kernel32 addresses
    const exp: ExportIndex = new Map();
    const dv = new DataView(img.buffer);
    const k32 = pe.imports[0];
    k32.funcs.forEach((f, i) => {
      const addr = 0x7ffa00001000n + BigInt(i * 0x40);
      exp.set(addr, { dll: "KERNEL32.dll", name: f.name! });
      dv.setBigUint64(f.iatRva, addr, true);
    });
    const blocks = findIat(img, exp);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].rva).toBe(k32.funcs[0].iatRva);
    expect(blocks[0].thunks.map((t) => t.name)).toEqual(k32.funcs.map((f) => f.name));

    const out = buildDumpPe(img, base, 0x1030, blocks, pe);
    if (process.env.ECHODEBUG_KEEP_DUMP) writeFileSync(process.env.ECHODEBUG_KEEP_DUMP, out);
    const re = parsePe(mapPeFile(out));
    expect(re.entryRva).toBe(0x1030);
    expect(re.imageBase).toBe(base);
    expect(re.sections.map((s) => s.name)).toContain(".edimp");
    expect(re.imports.map((d) => [d.dll, d.funcs.map((f) => f.name)])).toEqual([["KERNEL32.dll", k32.funcs.map((f) => f.name)]]);
    // the descriptors' FirstThunk is the original IAT
    expect(re.imports[0].funcs[0].iatRva).toBe(k32.funcs[0].iatRva);
  });
});
