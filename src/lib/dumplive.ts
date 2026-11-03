// Live dumping on top of the backend's reads (read_batch), so it works the same over the Echo
// agent, the local /proc backend or any other: module images rebuilt into loadable PEs, images
// the loader does not list, kernel drivers, and the whole target as a MINIDUMP or ELF core
// streamed to disk. See analysis/dumper.ts for the format work.
import { invoke } from "@tauri-apps/api/core";
import { request } from "./client";
import { readMany } from "./batch";
import { fmtAddr, toBig, type Module } from "./hex";
import { isTauri } from "./tauri";
import { readModuleFileBytes } from "./modfile";
import { exportIndex } from "./unpacklive";
import { buildDumpPe, findIat } from "./analysis/unpack";
import {
  codeViewRecord, dumpSize, elfCorePrefix, findImages, fixDump, headerProblem, minidumpPrefix, readHeaders, recoverHeaders, updateChecksum,
  type DumpLayout, type DumpRegion, type DumpReport, type FoundImage, type MdModule,
} from "./analysis/dumper";

const kPage = 0x1000;
const kEntry = 0x10000; // Echo caps one read_batch entry at 64 KiB
const kRound = 128; // 8 MiB per round trip

export type Progress = (done: number, total: number) => void;
export type Cancel = { aborted: boolean };

/**
 * [base, base+size) with every readable page: 64 KiB entries first, and a failed entry is read
 * again page by page so one missing page does not cost the whole 64 KiB. Echo reads physical
 * memory and the local backend /proc/<pid>/mem, so page protections (guard, no-access) do not stop
 * either: what fails are pages that are not resident (paged out, never touched, decommitted).
 * Those stay zero and are listed (as offsets from `base`).
 */
export async function readSalvaged(base: bigint, size: number, onProgress?: Progress, cancel?: Cancel): Promise<{ bytes: Uint8Array; badPages: number[] }> {
  const out = new Uint8Array(size);
  const bad: number[] = [];
  const offsets: number[] = [];
  for (let off = 0; off < size; off += kEntry) offsets.push(off);
  for (let i = 0; i < offsets.length; i += kRound) {
    if (cancel?.aborted) throw new Error("cancelled");
    const round = offsets.slice(i, i + kRound);
    const reads = round.map((off) => ({ address: fmtAddr(base + BigInt(off)), size: Math.min(kEntry, size - off) }));
    const bufs = await readMany(reads).catch(() => reads.map(() => null));
    const retry: number[] = [];
    bufs.forEach((b, j) => {
      if (b && b.length >= reads[j].size) out.set(b.subarray(0, reads[j].size), round[j]);
      else for (let p = round[j]; p < round[j] + reads[j].size; p += kPage) retry.push(p);
    });
    for (let k = 0; k < retry.length; k += 1024) {
      const pages = retry.slice(k, k + 1024);
      const preads = pages.map((p) => ({ address: fmtAddr(base + BigInt(p)), size: Math.min(kPage, size - p) }));
      const pb = await readMany(preads).catch(() => preads.map(() => null));
      pb.forEach((b, j) => {
        if (b && b.length >= preads[j].size) out.set(b.subarray(0, preads[j].size), pages[j]);
        else bad.push(pages[j]);
      });
    }
    onProgress?.(Math.min(offsets.length, i + kRound), offsets.length);
  }
  return { bytes: out, badPages: bad };
}

export type ImageTarget = { name: string; base: bigint; size?: number; module?: Module };
export type ModuleDumpOptions = {
  layout: DumpLayout;
  /** "auto": memory, else the file on disk when the headers in memory are broken */
  headers: "auto" | "memory" | "disk";
  /** rebuild the import table from the live IAT (PE32+, forces the virtual layout) */
  rebuildImports?: boolean;
  oepRva?: number;
  onProgress?: Progress;
  cancel?: Cancel;
};
export type ModuleDump = { name: string; bytes: Uint8Array; report: DumpReport & { headerSource: "memory" | "disk"; imports?: number } };

/** A loaded image (module, driver, or a PE found at an address) rebuilt into a loadable PE. */
export async function dumpImage(t: ImageTarget, modules: readonly Module[], o: ModuleDumpOptions): Promise<ModuleDump> {
  let size = t.size ?? 0;
  if (!size) {
    const head = (await readMany([{ address: fmtAddr(t.base), size: kPage }]))[0];
    if (!head) throw new Error(`cannot read the headers at ${fmtAddr(t.base)}`);
    size = readHeaders(head).sizeOfImage;
  }
  if (size <= 0 || size > 0x4000_0000) throw new Error(`implausible image size 0x${size.toString(16)}`);
  const { bytes, badPages } = await readSalvaged(t.base, size, o.onProgress, o.cancel);
  const pages = Math.ceil(size / kPage);
  if (badPages.length === pages) throw new Error(`no page of ${t.name} at ${fmtAddr(t.base)} could be read${t.base >= 0xffff_8000_0000_0000n ? " (kernel memory: this backend cannot read it here — Echo documents no kernel-memory access, and the local /proc backend has none)" : ""}`);
  let disk: Uint8Array | null = null;
  if (o.headers === "disk" || (o.headers === "auto" && headerProblem(bytes))) {
    if (t.module) disk = await readModuleFileBytes(t.module).then((f) => f.bytes).catch(() => null);
  }
  const rec = recoverHeaders(bytes, disk, o.headers === "disk" ? "disk" : "memory");
  const problem = headerProblem(rec.img);
  if (problem) throw new Error(`${t.name}: ${problem}${rec.note ? ` (${rec.note})` : ""}`);
  const layout: DumpLayout = o.rebuildImports ? "virtual" : o.layout;
  let { bytes: out, report } = fixDump(rec.img, { layout, base: t.base, oepRva: o.oepRva, badPages });
  let imports: number | undefined;
  if (o.rebuildImports) {
    const self = t.module ?? { name: t.name, base: fmtAddr(t.base), size };
    const idx = await exportIndex(modules, self);
    const blocks = findIat(rec.img, idx);
    if (blocks.length) {
      out = buildDumpPe(out, t.base, o.oepRva ?? readHeaders(out).entryRva, blocks);
      report = { ...report, size: out.length, checksum: updateChecksum(out), warnings: [...report.warnings] };
      imports = blocks.reduce((a, b) => a + b.thunks.length, 0);
    } else report.warnings.push("no IAT found to rebuild: the import table is the one in memory");
  }
  if (rec.note) report.warnings.unshift(rec.note);
  if (badPages.length) report.warnings.push("unreadable pages are usually not resident (paged out or never touched): touching that code or data in the target before dumping brings them in");
  return { name: t.name, bytes: out, report: { ...report, headerSource: rec.source, imports } };
}

/** File name for a dump: game.exe → game_dump.exe (`_<base>` for images without a name). */
export function dumpName(name: string, base?: bigint): string {
  const n = name || `image_${base?.toString(16) ?? "0"}.bin`;
  return /\.[^.\\/]+$/.test(n) ? n.replace(/(\.[^.\\/]+)$/, "_dump$1") : `${n}_dump`;
}

// ---- images the loader does not list ------------------------------------------------------------

type Region = { base: string; size: number; present: boolean; writable?: boolean; executable?: boolean };

export async function regions(range?: { start?: string; end?: string }): Promise<Region[]> {
  const r = await request<{ regions: Region[] }>("regions", { max: 200000, ...(range ?? {}) });
  return r.regions.filter((x) => x.present !== false);
}

/** PE images and executable memory the module list does not explain (manual maps, payloads). */
export async function findHiddenImages(modules: readonly Module[], onProgress?: Progress): Promise<FoundImage[]> {
  const rs = await regions();
  const heads: (Uint8Array | null)[] = [];
  for (let i = 0; i < rs.length; i += 512) {
    const part = rs.slice(i, i + 512);
    heads.push(...(await readMany(part.map((r) => ({ address: r.base, size: Math.min(kPage, r.size) }))).catch(() => part.map(() => null))));
    onProgress?.(Math.min(rs.length, i + 512), rs.length);
  }
  const mods = modules.map((m) => ({ base: toBig(m.base), size: m.size }));
  return findImages(rs.map((r, i) => ({ base: toBig(r.base), size: r.size, executable: !!r.executable, head: heads[i] })), mods);
}

// ---- kernel drivers -----------------------------------------------------------------------------

export type KernelModule = { name: string; path: string; base: string; size: number };
export async function kernelModules(): Promise<{ modules: KernelModule[]; source: string; note?: string }> {
  return request("kernel_modules", {});
}

// ---- the whole target ---------------------------------------------------------------------------

/** Where a streamed dump goes: a file through the app, or a download in the browser. */
export type Sink = { write(b: Uint8Array): Promise<void>; close(): Promise<string> };

export function fileSink(path: string): Sink {
  let first = true;
  return {
    async write(b) {
      // 8 MiB per IPC call; the first call creates (truncates) the file
      const kChunk = 8 << 20;
      let off = 0;
      do {
        await invoke("append_file_raw", b.subarray(off, off + kChunk), { headers: { "x-path": encodeURIComponent(path), "x-truncate": first ? "1" : "0" } });
        first = false;
        off += kChunk;
      } while (off < b.length);
    },
    async close() { return path; },
  };
}

export function downloadSink(name: string): Sink {
  const parts: BlobPart[] = [];
  return {
    async write(b) { parts.push(b.slice() as BlobPart); },
    async close() {
      const url = URL.createObjectURL(new Blob(parts, { type: "application/octet-stream" }));
      const a = Object.assign(document.createElement("a"), { href: url, download: name });
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
      return name;
    },
  };
}

/** A sink at a path the user picks (the app's save dialog), or a download. */
export async function pickSink(defaultName: string): Promise<Sink | null> {
  if (!isTauri()) return downloadSink(defaultName);
  const { save } = await import("@tauri-apps/plugin-dialog");
  const path = await save({ defaultPath: defaultName });
  return path ? fileSink(path) : null;
}

export type TargetDumpOptions = {
  format: "minidump" | "elf";
  /** which regions: everything readable, or skip big read-only mappings (mapped files) */
  include: "all" | "writable+images";
  /** regions larger than this are left out (MiB; 0: no limit) */
  maxRegionMiB: number;
  sink: Sink;
  onProgress?: (done: number, total: number, phase: string) => void;
  cancel?: Cancel;
};
export type TargetDumpReport = { format: string; path: string; regions: number; bytes: number; skipped: number; badPages: number; modules: number };

/** The whole target from memory, streamed region by region (never held in memory at once). */
export async function dumpTarget(modules: readonly Module[], target: { pid?: number; name?: string; arch?: string }, o: TargetDumpOptions): Promise<TargetDumpReport> {
  o.onProgress?.(0, 1, "walking regions");
  const all = await regions();
  const inImage = (a: bigint) => modules.some((m) => a >= toBig(m.base) && a < toBig(m.base) + BigInt(m.size));
  const limit = o.maxRegionMiB > 0 ? o.maxRegionMiB * 1024 * 1024 : Infinity;
  let skipped = 0;
  const picked: (DumpRegion & { src: Region })[] = [];
  for (const r of all) {
    const base = toBig(r.base);
    const keep = r.size <= limit && (o.include === "all" || r.writable || r.executable || inImage(base));
    if (!keep) { skipped++; continue; }
    picked.push({ base, size: r.size, writable: r.writable, executable: r.executable, src: r });
  }
  const arch = target.arch === "arm64" ? "arm64" : "x64";
  let prefix: Uint8Array;
  if (o.format === "minidump") {
    o.onProgress?.(0, 1, "reading module headers");
    const heads = await readMany(modules.map((m) => ({ address: m.base, size: Math.min(m.size, kPage) }))).catch(() => modules.map(() => null));
    const md: MdModule[] = modules.map((m, i) => {
      const h = heads[i];
      let ts = 0, cs = 0;
      if (h) {
        try {
          const hd = readHeaders(h);
          ts = hd.timestamp;
          cs = new DataView(h.buffer, h.byteOffset).getUint32(hd.checksumOff, true);
        } catch { /* not a PE */ }
      }
      return { name: m.name, base: toBig(m.base), size: m.size, timestamp: ts, checksum: cs };
    });
    // CodeView records need the debug directory, which may sit past the first page: read the images' first 64 KiB
    const cvs = await readMany(modules.map((m) => ({ address: m.base, size: Math.min(m.size, kEntry) }))).catch(() => modules.map(() => null));
    cvs.forEach((b, i) => { const r = b ? codeViewRecord(b) : null; if (r) md[i].cv = r; });
    prefix = minidumpPrefix({ arch, pid: target.pid, modules: md, regions: picked });
  } else {
    prefix = elfCorePrefix({ arch, regions: picked, pid: target.pid, name: target.name });
  }
  const total = dumpSize(prefix, picked);
  await o.sink.write(prefix);
  let done = prefix.length;
  let badPages = 0;
  for (const r of picked) {
    for (let off = 0; off < r.size; off += kEntry * kRound) {
      if (o.cancel?.aborted) throw new Error("cancelled");
      const len = Math.min(kEntry * kRound, r.size - off);
      const { bytes, badPages: bad } = await readSalvaged(r.base + BigInt(off), len, undefined, o.cancel);
      badPages += bad.length;
      await o.sink.write(bytes);
      done += len;
      o.onProgress?.(done, total, "reading memory");
    }
  }
  const path = await o.sink.close();
  return { format: o.format, path, regions: picked.length, bytes: done, skipped, badPages, modules: modules.length };
}

/** ELF targets get a core file by default, PE targets a MINIDUMP (sniffed at the target's own image). */
export async function defaultFormat(modules: readonly Module[], imageBase?: string): Promise<"minidump" | "elf"> {
  const at = imageBase ?? modules[0]?.base;
  if (!at) return "minidump";
  const b = (await readMany([{ address: at, size: 4 }]).catch(() => [null]))[0];
  return b && b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46 ? "elf" : "minidump";
}
