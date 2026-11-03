// Target architecture: detection from PE / ELF headers, display names and register sets.
// x86-64 is the default everywhere; "arm64" selects the AArch64 decoder, branch classifier,
// xref scanner, signature wildcarding and emulator register set.

export type Arch = "x86_64" | "x86" | "arm64";
export type ArchInfo = {
  arch: Arch;
  format: "pe" | "elf";
  /** PE Machine or ELF e_machine */
  machine: number;
  /**
   * Windows-on-ARM hybrids. "arm64x": an ARM64 image that also carries x64-compatible (ARM64EC)
   * code; "arm64ec": an x64-compatible image (Machine is AMD64) holding ARM64EC code. Both are
   * recognised by the load config's CHPE metadata pointer.
   */
  hybrid?: "arm64ec" | "arm64x";
};

export const IMAGE_FILE_MACHINE_I386 = 0x014c;
export const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
export const IMAGE_FILE_MACHINE_ARM64 = 0xaa64;
/** ARM64EC / ARM64X object files (linked images use AMD64 / ARM64 in the header) */
export const IMAGE_FILE_MACHINE_ARM64EC = 0xa641;
export const IMAGE_FILE_MACHINE_ARM64X = 0xa64e;
export const EM_386 = 3;
export const EM_X86_64 = 62;
export const EM_AARCH64 = 183;

export function peMachineArch(machine: number): Arch | null {
  switch (machine) {
    case IMAGE_FILE_MACHINE_AMD64: return "x86_64";
    case IMAGE_FILE_MACHINE_I386: return "x86";
    case IMAGE_FILE_MACHINE_ARM64:
    case IMAGE_FILE_MACHINE_ARM64EC:
    case IMAGE_FILE_MACHINE_ARM64X: return "arm64";
    default: return null;
  }
}

export function elfMachineArch(eMachine: number): Arch | null {
  return eMachine === EM_X86_64 ? "x86_64" : eMachine === EM_386 ? "x86" : eMachine === EM_AARCH64 ? "arm64" : null;
}

/** Accepts the usual spellings ("aarch64", "x64", ...). */
export function parseArch(s: string | undefined | null): Arch | null {
  switch ((s ?? "").trim().toLowerCase()) {
    case "x86_64": case "x86-64": case "x64": case "amd64": return "x86_64";
    case "x86": case "i386": case "i686": return "x86";
    case "arm64": case "aarch64": case "a64": case "arm64ec": case "arm64x": return "arm64";
    default: return null;
  }
}

/**
 * Detects the architecture from the start of a PE or ELF image. `mapped` says whether `img` is a
 * loaded image (RVAs index it; only then is the load config read for the hybrid flag) or a file.
 */
export function detectArch(img: Uint8Array, mapped = true): ArchInfo | null {
  if (img.length < 20) return null;
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  if (img[0] === 0x7f && img[1] === 0x45 && img[2] === 0x4c && img[3] === 0x46) {
    const machine = dv.getUint16(18, img[5] !== 2);
    const arch = elfMachineArch(machine);
    return arch ? { arch, format: "elf", machine } : null;
  }
  if (img[0] !== 0x4d || img[1] !== 0x5a || img.length < 0x40) return null;
  const nt = dv.getUint32(0x3c, true);
  if (nt + 24 > img.length || dv.getUint32(nt, true) !== 0x4550) return null;
  const machine = dv.getUint16(nt + 4, true);
  const arch = peMachineArch(machine);
  if (!arch) return null;
  const info: ArchInfo = { arch, format: "pe", machine };
  if (machine === IMAGE_FILE_MACHINE_ARM64EC) info.hybrid = "arm64ec";
  if (machine === IMAGE_FILE_MACHINE_ARM64X) info.hybrid = "arm64x";
  if (mapped && (machine === IMAGE_FILE_MACHINE_AMD64 || machine === IMAGE_FILE_MACHINE_ARM64) && chpeMetadata(img, nt) !== 0n) {
    info.hybrid = machine === IMAGE_FILE_MACHINE_ARM64 ? "arm64x" : "arm64ec";
  }
  return info;
}

/** IMAGE_LOAD_CONFIG_DIRECTORY64.CHPEMetadataPointer (offset 200), 0 when absent. */
function chpeMetadata(img: Uint8Array, nt: number): bigint {
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const oh = nt + 24;
  if (oh + 112 + 11 * 8 > img.length || dv.getUint16(oh, true) !== 0x20b) return 0n;
  if (dv.getUint32(oh + 108, true) <= 10) return 0n;
  const rva = dv.getUint32(oh + 112 + 10 * 8, true);
  if (!rva || rva + 208 > img.length) return 0n;
  if (dv.getUint32(rva, true) < 208) return 0n; // the directory's Size field
  return dv.getBigUint64(rva + 200, true);
}

/** Short badge text. */
export function archLabel(a: Arch | null | undefined): string {
  return a === "arm64" ? "ARM64" : a === "x86" ? "x86" : "x64";
}

const kX64Regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"];
const kA64Regs = [...Array.from({ length: 31 }, (_, i) => `x${i}`), "sp", "pc", "nzcv"];

/** General registers in display order. */
export function registerNames(arch: Arch | null | undefined): string[] {
  return arch === "arm64" ? kA64Regs : kX64Regs;
}

/** The program counter, stack pointer and first argument register. */
export function pcReg(arch: Arch | null | undefined): string {
  return arch === "arm64" ? "pc" : "rip";
}
export function spReg(arch: Arch | null | undefined): string {
  return arch === "arm64" ? "sp" : "rsp";
}
/** Integer argument registers (Windows x64 convention for x86-64, AAPCS64 for arm64). */
export function argRegs(arch: Arch | null | undefined): string[] {
  return arch === "arm64" ? ["x0", "x1", "x2", "x3"] : ["rcx", "rdx", "r8", "r9"];
}
