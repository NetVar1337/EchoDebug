// x64dbg's patch workflow on EchoDebug's patch journal:
//
// * the `.1337` patch file x64dbg's Patches dialog exports and imports (PatchDialog::saveAs1337):
//   a `>module` line, then one `RVA:OLD->NEW` line per byte — the RVA as a zero-padded pointer
//   (16 hex digits on x64), the bytes as two hex digits, upper case, lines joined with "\n";
// * "Patch file": the journalled patches written into a copy of the module's file on disk, at the
//   file offset each RVA maps to through the section table.
import { readHeaders } from "./dumper";

export type BytePatch = { module: string; rva: number; old: number; new: number };

/** Journal entries (address, original hex, written hex) as one byte patch per changed byte. */
export function bytePatches(patches: readonly { module: string; rva: number; before: string; written: string }[]): BytePatch[] {
  const out = new Map<string, BytePatch>();
  for (const p of patches) {
    for (let i = 0; i * 2 < p.written.length; i++) {
      const nb = parseInt(p.written.slice(2 * i, 2 * i + 2), 16);
      const ob = parseInt(p.before.slice(2 * i, 2 * i + 2), 16);
      if (Number.isNaN(nb) || Number.isNaN(ob)) continue;
      const key = `${p.module.toLowerCase()}:${p.rva + i}`;
      const prev = out.get(key);
      // a byte patched twice keeps its first original and its last value
      out.set(key, { module: p.module, rva: p.rva + i, old: prev ? prev.old : ob, new: nb });
    }
  }
  return [...out.values()].filter((b) => b.old !== b.new).sort((a, b) => a.module.localeCompare(b.module) || a.rva - b.rva);
}

const h2 = (v: number) => v.toString(16).toUpperCase().padStart(2, "0");

export function to1337(patches: readonly BytePatch[], ptrDigits = 16): string {
  const lines: string[] = [];
  let mod = "";
  for (const p of patches) {
    if (p.module !== mod) {
      lines.push(`>${p.module}`);
      mod = p.module;
    }
    lines.push(`${p.rva.toString(16).toUpperCase().padStart(ptrDigits, "0")}:${h2(p.old)}->${h2(p.new)}`);
  }
  return lines.join("\n");
}

export function parse1337(text: string): { patches: BytePatch[]; errors: string[] } {
  const patches: BytePatch[] = [];
  const errors: string[] = [];
  let mod = "";
  text.replace(/\r\n/g, "\n").split("\n").forEach((raw, i) => {
    const line = raw.trim();
    if (!line) return;
    if (line.startsWith(">")) {
      mod = line.slice(1).trim();
      return;
    }
    const m = /^([0-9a-f]+):([0-9a-f]{1,2})->([0-9a-f]{1,2})$/i.exec(line);
    if (!m) return void errors.push(`line ${i + 1}: cannot read "${line}"`);
    if (!mod) return void errors.push(`line ${i + 1}: a patch before any ">module" line`);
    patches.push({ module: mod, rva: parseInt(m[1], 16), old: parseInt(m[2], 16), new: parseInt(m[3], 16) });
  });
  return { patches, errors };
}

/** File offset of an RVA through the section table (headers map 1:1); null when not in the file. */
export function rvaToOffset(file: Uint8Array, rva: number): number | null {
  const h = readHeaders(file);
  const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
  const hdrEnd = Math.max(h.sizeOfHeaders, h.st + h.nsec * 40);
  let best: number | null = rva < hdrEnd ? rva : null;
  for (let i = 0; i < h.nsec; i++) {
    const o = h.st + i * 40;
    const vsize = dv.getUint32(o + 8, true);
    const va = dv.getUint32(o + 12, true);
    const rawSize = dv.getUint32(o + 16, true);
    const raw = dv.getUint32(o + 20, true);
    if (rva >= va && rva < va + Math.max(vsize, rawSize)) {
      best = rva - va < rawSize && raw ? raw + (rva - va) : null;
    }
  }
  return best !== null && best < file.length ? best : null;
}

export type PatchFileReport = {
  applied: number;
  /** the file's byte differed from the original byte in memory (usually a relocated address) */
  differed: { rva: number; offset: number; file: number; memory: number }[];
  /** no file data at this RVA (.bss, beyond the raw data) */
  outside: number[];
};

/** The patches of one module written into a copy of its file. */
export function patchFile(file: Uint8Array, patches: readonly BytePatch[]): { bytes: Uint8Array; report: PatchFileReport } {
  const bytes = file.slice();
  const report: PatchFileReport = { applied: 0, differed: [], outside: [] };
  for (const p of patches) {
    const off = rvaToOffset(file, p.rva);
    if (off === null) {
      report.outside.push(p.rva);
      continue;
    }
    if (file[off] !== p.old) report.differed.push({ rva: p.rva, offset: off, file: file[off], memory: p.old });
    bytes[off] = p.new;
    report.applied++;
  }
  return { bytes, report };
}
