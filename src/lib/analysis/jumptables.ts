// Switch jump-table recovery from a disassembly listing plus the mapped module image.
//
// Recognised shapes (Intel syntax; AT&T text from the local backend is normalised first):
//   MSVC x64     cmp ecx, N ; ja def ; lea rdx, [imagebase] ; mov ecx, dword ptr [rdx+rax*4+TABLE_RVA] ; add rcx, rdx ; jmp rcx
//   GCC / Clang  cmp eax, N ; ja def ; lea rdx, [rip+T] ; movsxd rax, dword ptr [rdx+rax*4] ; add rax, rdx ; jmp rax
//   absolute     cmp eax, N ; ja def ; jmp qword ptr [rax*8+TABLE]
// Entries are read from the image (indexed by RVA); targets outside the image end the table.

export type SwitchLine = { address: string; length: number; text: string };
export type JumpTable = { jumpAt: bigint; table: bigint; kind: "msvc-rva" | "relative" | "absolute"; count: number; targets: bigint[]; bounded: boolean };

const kMaxCases = 1024;
/** Largest case count taken from a `cmp` (the immediate is target-controlled: `cmp eax, -1`). */
const kMaxBound = 1 << 16;

/** AT&T → Intel for the operand forms the switch shapes use. Intel text passes through. */
export function toIntel(text: string): string {
  const t = text.trim().replace(/^(?:(?:notrack|bnd) )+/i, "");
  if (!t.includes("%")) return t;
  const sp = t.indexOf(" ");
  if (sp < 0) return t.replace(/%/g, "");
  let mn = t.slice(0, sp).replace(/^(mov|add|sub|cmp|lea|jmp|call)[qlwb]$/, "$1");
  if (mn === "movslq") mn = "movsxd";
  const rest = t.slice(sp + 1).split(";")[0].trim();
  const conv = (op: string): string => {
    op = op.trim();
    const indirect = op.startsWith("*");
    if (indirect) op = op.slice(1);
    const m = /^(-?0x[0-9a-f]+|-?\d+)?\((%?\w*)(?:,%?(\w+)(?:,(\d))?)?\)$/i.exec(op);
    if (m) {
      const [, disp, base, idx, scale] = m;
      const parts: string[] = [];
      if (base) parts.push(base.replace("%", ""));
      if (idx) parts.push(`${idx}*${scale ?? 1}`);
      let s = parts.join("+");
      if (disp) s += disp.startsWith("-") ? disp : (s ? "+" : "") + disp;
      return `${indirect ? "qword ptr " : ""}[${s}]`;
    }
    return op.replace(/^\$/, "").replace(/^%/, "").replace(/ ;.*$/, "");
  };
  const ops: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of rest) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) {
      ops.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (cur) ops.push(cur);
  return `${mn} ${ops.map(conv).reverse().join(", ")}`;
}

const reg64 = (r: string): string => {
  const x = r.toLowerCase();
  const map: Record<string, string> = { eax: "rax", ebx: "rbx", ecx: "rcx", edx: "rdx", esi: "rsi", edi: "rdi", ebp: "rbp", esp: "rsp" };
  if (map[x]) return map[x];
  const m = /^r(\d+)[dwb]?$/.exec(x);
  return m ? `r${m[1]}` : x;
};

function num(s: string): bigint {
  const t = s.trim().toLowerCase();
  const neg = t.startsWith("-");
  const v = BigInt(neg ? t.slice(1) : t);
  return neg ? -v : v;
}

/** Address a `lea R, [...]` loads: `[rip+X]` (relative to the next instruction) or an absolute. */
function leaTarget(l: SwitchLine, mem: string): bigint | null {
  const m = /^\s*rip\s*([+-])\s*(0x[0-9a-f]+|\d+)\s*$/i.exec(mem);
  if (m) {
    const d = num(m[2]);
    return BigInt(l.address) + BigInt(l.length) + (m[1] === "-" ? -d : d);
  }
  const abs = /^\s*\[?\s*(0x[0-9a-f]+)\s*\]?\s*$/i.exec(mem);
  return abs ? BigInt(abs[1]) : null;
}

/** Upper bound from `cmp IDX, N` + `ja`/`jae`/`jbe` before `upto`. */
function caseCount(lines: readonly SwitchLine[], upto: number, idx: string): number | null {
  for (let i = upto; i >= Math.max(0, upto - 12); i--) {
    const t = toIntel(lines[i].text).toLowerCase();
    const m = /^cmp\s+(\w+),\s*(0x[0-9a-f]+|\d+)$/.exec(t);
    if (!m || reg64(m[1]) !== idx) continue;
    const next = toIntel(lines[i + 1]?.text ?? "").toLowerCase();
    const n = Math.min(Number(num(m[2])), kMaxBound - 1);
    if (/^ja\b|^jnbe\b/.test(next)) return n + 1;
    if (/^jae\b|^jnb\b|^jnc\b/.test(next)) return n;
    if (/^jbe\b|^jna\b/.test(next)) return n + 1;
    return n + 1;
  }
  return null;
}

function readI32(img: Uint8Array, rva: number): number | null {
  if (rva < 0 || rva + 4 > img.length) return null;
  return new DataView(img.buffer, img.byteOffset + rva, 4).getInt32(0, true);
}

function readU64(img: Uint8Array, rva: number): bigint | null {
  if (rva < 0 || rva + 8 > img.length) return null;
  return new DataView(img.buffer, img.byteOffset + rva, 8).getBigUint64(0, true);
}

/**
 * Recovers the jump table behind the indirect `jmp` at `lines[at]`. `img` is the module image
 * indexed by RVA, `base` its load address.
 */
export function resolveSwitch(lines: readonly SwitchLine[], at: number, img: Uint8Array, base: bigint): JumpTable | null {
  const jl = lines[at];
  const jt = toIntel(jl.text).toLowerCase();
  const inImage = (a: bigint) => a >= base && a < base + BigInt(img.length);
  const rvaOf = (a: bigint) => Number(a - base);

  // absolute: jmp qword ptr [IDX*8+TABLE]
  let m = /^jmp\s+qword ptr \[(\w+)\*8\+(0x[0-9a-f]+)\]$/.exec(jt);
  if (m) {
    const idx = reg64(m[1]);
    const table = BigInt(m[2]);
    if (!inImage(table)) return null;
    const bound = caseCount(lines, at - 1, idx);
    const targets: bigint[] = [];
    for (let i = 0; i < (bound ?? kMaxCases); i++) {
      const v = readU64(img, rvaOf(table) + i * 8);
      if (v === null || !inImage(v)) break;
      targets.push(v);
    }
    return targets.length ? { jumpAt: BigInt(jl.address), table, kind: "absolute", count: targets.length, targets, bounded: bound !== null } : null;
  }

  // jmp REG ; preceded by add REG, B ; load REG, dword ptr [B+IDX*4(+DISP)]
  m = /^jmp\s+(?:qword ptr )?(\w+)$/.exec(jt);
  if (!m) return null;
  const jr = reg64(m[1]);
  let addB: string | null = null;
  let loadAt = -1;
  let idx = "";
  let disp: bigint | null = null;
  for (let i = at - 1; i >= Math.max(0, at - 10); i--) {
    const t = toIntel(lines[i].text).toLowerCase();
    const a = /^add\s+(\w+),\s*(\w+)$/.exec(t);
    if (a && reg64(a[1]) === jr && !addB) {
      addB = reg64(a[2]);
      continue;
    }
    const ld = /^(?:mov|movsxd|movsx)\s+(\w+),\s*(?:dword ptr )?\[(\w+)\+(\w+)\*4(?:\+(0x[0-9a-f]+))?\]$/.exec(t);
    if (ld && addB && reg64(ld[1]) === jr && reg64(ld[2]) === addB) {
      idx = reg64(ld[3]);
      disp = ld[4] ? BigInt(ld[4]) : null;
      loadAt = i;
      break;
    }
  }
  if (!addB || loadAt < 0) return null;
  let bVal: bigint | null = null;
  for (let i = loadAt - 1; i >= Math.max(0, loadAt - 12); i--) {
    const t = toIntel(lines[i].text).toLowerCase();
    // `lea rdx, [rip+X]`, `lea rdx, [0x...]`, or GAS's resolved `lea rdx, 0x...`
    const lea = /^lea\s+(\w+),\s*(\[[^\]]+\]|0x[0-9a-f]+)/.exec(t);
    if (lea && reg64(lea[1]) === addB) {
      bVal = leaTarget(lines[i], lea[2].replace(/^\[|\]$/g, ""));
      break;
    }
  }
  if (bVal === null) return null;
  const bound = caseCount(lines, loadAt, idx) ?? caseCount(lines, loadAt, reg64(idx.replace(/^r/, "e")));
  const targets: bigint[] = [];
  const kind: JumpTable["kind"] = disp !== null ? "msvc-rva" : "relative";
  const table = disp !== null ? bVal + disp : bVal;
  if (!inImage(table)) return null;
  for (let i = 0; i < (bound ?? kMaxCases); i++) {
    const e = readI32(img, rvaOf(table) + i * 4);
    if (e === null) break;
    const target = kind === "msvc-rva" ? bVal + BigInt(e >>> 0) : bVal + BigInt(e);
    if (!inImage(target)) break;
    targets.push(target);
  }
  return targets.length ? { jumpAt: BigInt(jl.address), table, kind, count: targets.length, targets, bounded: bound !== null } : null;
}
