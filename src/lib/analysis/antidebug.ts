// Anti-debug and anti-tamper scanner.
//
// Two halves that work on the same module image:
//   - the byte patterns a debugger or virtual-machine check compiles into
//     (INT 2D, SIDT/SGDT, VMCALL, CPUID, RDTSC, PEB reads, ...)
//   - the imports a binary uses to ask the operating system whether it is
//     being debugged
//
// Both halves are heuristics: a hit is a place worth looking at, not proof.
import { parsePe, type PeInfo } from "./pe";

export type AntiKind =
  | "int2d"
  | "icebp"
  | "sidt"
  | "sgdt"
  | "sldt"
  | "vmcall"
  | "vmclear"
  | "xgetbv"
  | "cpuid"
  | "rdtsc"
  | "rdtscp"
  | "peb"
  | "teb"
  | "debug-api"
  | "debugger-window";

export type AntiHit = {
  kind: AntiKind;
  /** RVA of the match */
  rva: number;
  /** absolute address of the match */
  address: string;
  /** the matched bytes, lowercase hex */
  bytes: string;
  /** what it is and why it matters */
  detail: string;
  /** how sure we are that this is a deliberate check */
  confidence: number;
};

type Pattern = {
  kind: AntiKind;
  bytes: number[];
  /** the byte at this index may differ */
  mask?: number[];
  detail: string;
  confidence: number;
};

const kPatterns: Pattern[] = [
  { kind: "int2d", bytes: [0xcd, 0x2d], detail: "INT 2Dh raises a breakpoint exception; a kernel debugger handles it, a user-mode one does not", confidence: 0.95 },
  { kind: "icebp", bytes: [0xf1], detail: "ICEBP traps to the debugger; commonly used as a single-step trap", confidence: 0.9 },
  { kind: "sidt", bytes: [0x0f, 0x01, 0x0d], detail: "SIDT reads the interrupt descriptor table; the 'red pill' check compares it against the expected base", confidence: 0.9 },
  { kind: "sgdt", bytes: [0x0f, 0x01, 0x04], detail: "SGDT reads the global descriptor table; the base is compared against the expected value", confidence: 0.8 },
  { kind: "sldt", bytes: [0x0f, 0x00, 0x00], detail: "SLDT reads the local descriptor table register, another red-pill variant", confidence: 0.7 },
  { kind: "vmcall", bytes: [0x0f, 0x01, 0xc1], detail: "VMCALL traps into the hypervisor; an anti-VM check", confidence: 0.9 },
  { kind: "vmclear", bytes: [0x0f, 0x01, 0xc2], detail: "VMCLEAR is a virtualisation instruction; an anti-VM check", confidence: 0.85 },
  { kind: "xgetbv", bytes: [0x0f, 0x01, 0xd0], detail: "XGETBV reads the extended control registers; the debug-enable bit is checked for a debugger", confidence: 0.75 },
  { kind: "cpuid", bytes: [0x0f, 0xa2], detail: "CPUID is checked for hypervisor presence (leaf 1 ECX bit 31)", confidence: 0.55 },
  { kind: "rdtsc", bytes: [0x0f, 0x31], detail: "RDTSC reads the timestamp counter; two readings around a block measure how long it took", confidence: 0.45 },
  { kind: "rdtscp", bytes: [0x0f, 0x01, 0xf9], detail: "RDTSCP reads the timestamp counter with the processor id", confidence: 0.45 },
  // mov eax, fs:[30h] / mov ecx, fs:[30h] and the 64-bit forms
  { kind: "peb", bytes: [0x64, 0xa1, 0x30, 0x00, 0x00, 0x00], detail: "reads the PEB through fs:[30h]; the BeingDebugged flag lives there", confidence: 0.9 },
  { kind: "peb", bytes: [0x64, 0x8b, 0x0d, 0x30, 0x00, 0x00, 0x00], detail: "reads the PEB through fs:[30h]; the BeingDebugged flag lives there", confidence: 0.9 },
  { kind: "peb", bytes: [0x64, 0x8b, 0x15, 0x30, 0x00, 0x00, 0x00], detail: "reads the PEB through fs:[30h]; the BeingDebugged flag lives there", confidence: 0.9 },
  { kind: "peb", bytes: [0x64, 0x8b, 0x35, 0x30, 0x00, 0x00, 0x00], detail: "reads the PEB through fs:[30h]; the BeingDebugged flag lives there", confidence: 0.9 },
  { kind: "peb", bytes: [0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00], detail: "reads the PEB through gs:[60h] in 64-bit code; the BeingDebugged flag lives there", confidence: 0.9 },
  // mov rax, gs:[60h] written as a REX-prefixed mov
  { kind: "peb", bytes: [0x65, 0x48, 0x8b, 0x0c, 0x25, 0x60, 0x00, 0x00, 0x00], detail: "reads the PEB through gs:[60h] in 64-bit code; the BeingDebugged flag lives there", confidence: 0.9 },
  { kind: "teb", bytes: [0x64, 0xa1, 0x18, 0x00, 0x00, 0x00], detail: "reads the TEB through fs:[18h]; the debugger notification fields live there", confidence: 0.85 },
];

/** The APIs a binary asks when it wants to know whether it is debugged. */
const kDebugApis = [
  { name: "IsDebuggerPresent", detail: "the operating system reports whether a debugger is attached" },
  { name: "CheckRemoteDebuggerPresent", detail: "reports whether a debugger is attached to another process" },
  { name: "NtQueryInformationProcess", detail: "ProcessDebugPort and ProcessDebugObjectHandle answer the debugger question" },
  { name: "NtQuerySystemInformation", detail: "SystemKernelDebuggerInformation reveals a kernel debugger" },
  { name: "NtSetInformationThread", detail: "ThreadHideFromDebugger hides the thread from a debugger" },
  { name: "OutputDebugString", detail: "raises an exception when no debugger catches it, which reveals the debugger" },
  { name: "SetUnhandledExceptionFilter", detail: "an exception filter can tell a debugger apart from the normal path" },
  { name: "GetTickCount", detail: "a timing check around a block of code" },
  { name: "GetTickCount64", detail: "a timing check around a block of code" },
  { name: "QueryPerformanceCounter", detail: "a timing check around a block of code" },
  { name: "QueryPerformanceFrequency", detail: "the denominator of a timing check" },
];

/** Window classes and titles a binary looks for when hunting for a debugger UI. */
const kDebuggerWindows = [
  "ollydbg",
  "x64dbg",
  "x32dbg",
  "windbg",
  "ida",
  "immunity",
  "cheat engine",
  "processhacker",
  "dnspy",
  "fiddler",
  "wireshark",
  "httpdebugger",
  "charles",
];

function hex(b: Uint8Array, rva: number, len: number): string {
  let s = "";
  for (let i = 0; i < len && rva + i < b.length; i++) s += b[rva + i].toString(16).padStart(2, "0");
  return s;
}

/**
 * Scans the executable sections of a module image for the byte patterns.
 * `base` is the module's absolute base so the hits carry absolute addresses.
 */
export function scanAntiDebug(img: Uint8Array, base?: bigint, pe?: PeInfo): AntiHit[] {
  let info = pe;
  if (!info) {
    try {
      info = parsePe(img);
    } catch {
      return [];
    }
  }
  const hits: AntiHit[] = [];
  for (const s of info.sections) {
    if (!s.x) continue;
    const start = s.rva;
    const end = Math.min(img.length, s.rva + s.vsize);
    for (let i = start; i < end; i++) {
      for (const p of kPatterns) {
        if (i + p.bytes.length > end) continue;
        let ok = true;
        for (let k = 0; k < p.bytes.length; k++) {
          if (p.mask && (p.mask[k] & img[i + k]) !== (p.mask[k] & p.bytes[k])) { ok = false; break; }
          if (!p.mask && img[i + k] !== p.bytes[k]) { ok = false; break; }
        }
        if (!ok) continue;
        hits.push({
          kind: p.kind,
          rva: i,
          address: "0x" + ((base ?? 0n) + BigInt(i)).toString(16),
          bytes: hex(img, i, p.bytes.length),
          detail: p.detail,
          confidence: p.confidence,
        });
      }
    }
  }
  hits.sort((a, b) => b.confidence - a.confidence || a.rva - b.rva);
  return hits;
}

/**
 * Scans the import names of a module for the debugger-detection APIs.
 * `imports` is a list of { name } records.
 */
export function scanAntiImports(imports: readonly { name: string }[], base?: bigint): AntiHit[] {
  const out: AntiHit[] = [];
  for (const imp of imports) {
    const lower = imp.name.toLowerCase();
    for (const api of kDebugApis) {
      if (!lower.includes(api.name.toLowerCase())) continue;
      out.push({
        kind: "debug-api",
        rva: -1,
        address: "0x" + ((base ?? 0n) + BigInt(0)).toString(16),
        bytes: "",
        detail: `${imp.name}: ${api.detail}`,
        confidence: 0.95,
      });
      break;
    }
  }
  return out;
}

/**
 * Scans the strings of a module for the window titles and class names a
 * binary looks for when it hunts for a debugger UI.
 * `strings` is a list of { rva, text } records.
 */
export function scanAntiStrings(strings: readonly { rva: number; text: string }[], base?: bigint): AntiHit[] {
  const out: AntiHit[] = [];
  for (const s of strings) {
    const lower = s.text.toLowerCase();
    for (const w of kDebuggerWindows) {
      if (!lower.includes(w)) continue;
      out.push({
        kind: "debugger-window",
        rva: s.rva,
        address: "0x" + ((base ?? 0n) + BigInt(s.rva)).toString(16),
        bytes: "",
        detail: `"${s.text}": looks for a debugger window named "${w}"`,
        confidence: 0.9,
      });
      break;
    }
  }
  return out;
}

/** The rule tables, exposed so the UI can explain what it looks for. */
export function antiPatterns(): { kind: AntiKind; bytes: string; detail: string }[] {
  return kPatterns.map((p) => ({ kind: p.kind, bytes: p.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" "), detail: p.detail }));
}
