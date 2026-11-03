import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { mapPeFile, parsePe } from "./analysis/pe";
import { readHeaders } from "./analysis/dumper";

// a fake target: fix-seh.exe mapped at 0x140000000, one page that is not resident, a stack region
const file = new Uint8Array(readFileSync(new URL("./analysis/fixtures/fix-seh.exe", import.meta.url)));
const image = mapPeFile(file);
const kBase = 0x140000000n;
const mem = new Map<bigint, Uint8Array>([[kBase, image], [0x7ff0_0000n, new Uint8Array(0x3000).fill(0xab)]]);
const unreadable = new Set<bigint>([0x7ff0_1000n]);
let wipeHeaders = false;
const calls: number[] = [];

function readAt(addr: bigint, size: number): Uint8Array | null {
  for (let p = addr & ~0xfffn; p < addr + BigInt(size); p += 0x1000n) if (unreadable.has(p)) return null;
  for (const [b, bytes] of mem) {
    if (addr >= b && addr + BigInt(size) <= b + BigInt(bytes.length)) {
      const out = bytes.slice(Number(addr - b), Number(addr - b) + size);
      if (wipeHeaders && b === kBase && addr === kBase) out.fill(0, 0, Math.min(size, 0x400));
      return out;
    }
  }
  return null;
}
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

vi.mock("./client", () => ({
  request: async (type: string, f: Record<string, unknown>) => {
    if (type === "read_batch") {
      const reads = f.reads as { address: string; size: number }[];
      calls.push(reads.length);
      return { results: reads.map((r) => { const b = readAt(BigInt(r.address), r.size); return b ? { success: true, address: r.address, data: hex(b) } : { success: false, address: r.address, data: "" }; }) };
    }
    if (type === "regions") return { regions: [{ base: "0x140000000", size: image.length, present: true, executable: true }, { base: "0x7ff00000", size: 0x3000, present: true, writable: true }] };
    throw new Error(`unexpected ${type}`);
  },
}));
vi.mock("./modfile", () => ({ readModuleFileBytes: async () => ({ bytes: file, path: "C:\\fix-seh.exe" }) }));
vi.mock("./unpacklive", () => ({ exportIndex: async () => new Map() }));
vi.mock("./tauri", () => ({ isTauri: () => false }));

const { dumpImage, dumpName, dumpTarget, findHiddenImages, isDriverFile, probeKernelReads, readSalvaged } = await import("./dumplive");
const mod = { name: "fix-seh.exe", base: "0x140000000", size: image.length };

describe("live dumps", () => {
  it("salvages every readable page around one that is not resident", async () => {
    const r = await readSalvaged(0x7ff0_0000n, 0x3000);
    expect(r.badPages).toEqual([0x1000]);
    expect(r.bytes[0]).toBe(0xab);
    expect(r.bytes[0x1000]).toBe(0);
    expect(r.bytes[0x2fff]).toBe(0xab);
  });

  it("dumps a module into a loadable file-layout PE at its runtime base", async () => {
    const d = await dumpImage({ name: mod.name, base: kBase, size: mod.size, module: mod }, [mod], { layout: "file", headers: "auto" });
    expect(d.report.headerSource).toBe("memory");
    expect(d.report.badPages).toBe(0);
    const pe = parsePe(mapPeFile(d.bytes));
    expect(pe.imageBase).toBe(kBase);
    expect(mapPeFile(d.bytes).subarray(0x1000, 0x10c6)).toEqual(image.subarray(0x1000, 0x10c6));
    expect(dumpName(d.name)).toBe("fix-seh_dump.exe");
  });

  it("takes wiped headers from the file on disk", async () => {
    wipeHeaders = true;
    try {
      const d = await dumpImage({ name: mod.name, base: kBase, size: mod.size, module: mod }, [mod], { layout: "virtual", headers: "auto" });
      expect(d.report.headerSource).toBe("disk");
      expect(d.report.warnings[0]).toMatch(/broken.*disk/);
      expect(readHeaders(d.bytes).fileAlign).toBe(0x1000);
      await expect(dumpImage({ name: "x", base: kBase, size: mod.size }, [mod], { layout: "file", headers: "memory" })).rejects.toThrow(/MZ/);
    } finally {
      wipeHeaders = false;
    }
  });

  it("reads the size from the headers and explains unreadable kernel images", async () => {
    const d = await dumpImage({ name: "", base: kBase }, [], { layout: "file", headers: "memory" });
    expect(d.report.size).toBeGreaterThan(0);
    await expect(dumpImage({ name: "ntoskrnl.exe", base: 0xfffff800_00000000n, size: 0x2000 }, [], { layout: "file", headers: "memory" })).rejects.toThrow(/kernel memory/);
  });

  it("finds images the module list does not show", async () => {
    const found = await findHiddenImages([]);
    expect(found).toEqual([expect.objectContaining({ base: kBase, kind: "pe", listed: false })]);
    expect(await findHiddenImages([mod])).toEqual([expect.objectContaining({ kind: "pe", listed: true })]);
  });

  it("streams the whole target as a MINIDUMP", async () => {
    const chunks: Uint8Array[] = [];
    const sink = { write: async (b: Uint8Array) => { chunks.push(b.slice()); }, close: async () => "out.dmp" };
    const phases = new Set<string>();
    const r = await dumpTarget([mod], { pid: 7, name: "fix-seh.exe" }, { format: "minidump", include: "all", maxRegionMiB: 0, sink, onProgress: (_d, _t, p) => phases.add(p) });
    const out = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
    expect(r).toMatchObject({ regions: 2, badPages: 1, skipped: 0, modules: 1, path: "out.dmp" });
    expect(out.length).toBe(r.bytes);
    const dv = new DataView(out.buffer);
    expect(dv.getUint32(0, true)).toBe(0x504d444d);
    // find Memory64List and check the stack region's data landed at its offset
    const n = dv.getUint32(8, true);
    const dir = dv.getUint32(12, true);
    let m64 = 0;
    for (let i = 0; i < n; i++) if (dv.getUint32(dir + i * 12, true) === 9) m64 = dv.getUint32(dir + i * 12 + 8, true);
    const baseRva = Number(dv.getBigUint64(m64 + 8, true));
    expect(out.subarray(baseRva, baseRva + 2)).toEqual(image.subarray(0, 2));
    const stack = baseRva + image.length;
    expect(out[stack]).toBe(0xab);
    expect(out[stack + 0x1000]).toBe(0);
    expect([...phases]).toContain("reading memory");
  });

  it("leaves out regions over the size limit and read-only mappings when asked", async () => {
    const sink = { write: async () => {}, close: async () => "x" };
    const r = await dumpTarget([], {}, { format: "elf", include: "writable+images", maxRegionMiB: 0, sink });
    expect(r).toMatchObject({ regions: 2, skipped: 0 });
    const r2 = await dumpTarget([], {}, { format: "elf", include: "all", maxRegionMiB: 0.013, sink });
    expect(r2).toMatchObject({ regions: 1, skipped: 1 });
  });

  it("tests kernel reads on a .sys driver", async () => {
    expect(isDriverFile({ name: "ACPI.sys" })).toBe(true);
    expect(isDriverFile({ name: "ntoskrnl.exe" })).toBe(false);
    // a "driver" whose image the fake backend can read (headers there) and one it cannot
    const readable = await probeKernelReads([
      { name: "ntoskrnl.exe", path: "", base: "0x7ff00000", size: 0x1000 },
      { name: "fake.sys", path: "", base: "0x140000000", size: image.length },
    ]);
    expect(readable).toMatchObject({ ok: true, driver: "fake.sys" });
    const unreadable = await probeKernelReads([{ name: "ACPI.sys", path: "", base: "0xfffff80000000000", size: 0x1000 }]);
    expect(unreadable.ok).toBe(false);
    expect(unreadable.detail).toMatch(/cannot read kernel memory/);
    const garbage = await probeKernelReads([{ name: "x.sys", path: "", base: "0x7ff00000", size: 0x1000 }]);
    expect(garbage.detail).toMatch(/without valid PE headers/);
    expect((await probeKernelReads([{ name: "x.sys", path: "", base: "0x0", size: 1 }])).detail).toMatch(/elevated/);
  });
});
