/**
 * Lightweight call-graph builder for a mapped module image.
 *
 * `img` is a mapped PE image indexed by RVA (`img[rva]` is the byte at RVA
 * `rva`).  `fns` carries the module functions as *absolute* addresses; they are
 * converted to RVAs by subtracting the module base.
 */

export type GraphNode = {
  address: string;
  rva: number;
  label: string;
  kind: "function" | "import" | "unknown";
  /** distance from the root function list; column 0 holds the roots */
  depth: number;
};

export type GraphEdge = {
  from: string;
  to: string;
  kind: "call" | "jmp" | "jcc" | "rip";
  fromRva: number;
  toRva: number;
};

export type CallGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

const kDefaultMaxDepth = 1;
const kDefaultMaxNodes = 512;

function parseAbsoluteAddress(text: string): bigint | null {
  const t = text.trim();
  if (!t) return null;
  try {
    if (/^0x[0-9a-f]+$/i.test(t)) return BigInt(t);
    if (/^[0-9a-f]+$/i.test(t)) return BigInt(`0x${t}`);
  } catch {
    return null;
  }
  return null;
}

function formatAddress(rva: number, base: bigint): string {
  return `0x${(base + BigInt(rva)).toString(16)}`;
}

function labelFor(rva: number): string {
  return `sub_${rva.toString(16).toUpperCase()}`;
}

function readInt32LE(img: Uint8Array, off: number): number {
  return (
    (img[off] | (img[off + 1] << 8) | (img[off + 2] << 16) | (img[off + 3] << 24)) | 0
  );
}

/** One-byte opcodes that are followed by a ModRM byte. */
function isModrmOpcode(op: number): boolean {
  if (op >= 0x00 && op <= 0x03) return true;
  if (op >= 0x08 && op <= 0x0b) return true;
  if (op >= 0x10 && op <= 0x13) return true;
  if (op >= 0x18 && op <= 0x1b) return true;
  if (op >= 0x20 && op <= 0x23) return true;
  if (op >= 0x28 && op <= 0x2b) return true;
  if (op >= 0x30 && op <= 0x33) return true;
  if (op >= 0x38 && op <= 0x3b) return true;
  if (op === 0x62 || op === 0x63 || op === 0x69 || op === 0x6b) return true;
  if (op >= 0x80 && op <= 0x8f) return true;
  if (op === 0xc0 || op === 0xc1 || op === 0xc6 || op === 0xc7) return true;
  if (op >= 0xd0 && op <= 0xdf) return true;
  if (op === 0xf6 || op === 0xf7 || op === 0xfe || op === 0xff) return true;
  return false;
}

/** Immediate bytes that follow the ModRM/displacement of a one-byte opcode. */
function oneByteImmediateSize(op: number, modrm: number): number {
  const reg = (modrm >> 3) & 0x07;
  switch (op) {
    case 0x69:
      return 4;
    case 0x6b:
      return 1;
    case 0x80:
    case 0x82:
    case 0x83:
    case 0xc0:
    case 0xc1:
      return 1;
    case 0x81:
    case 0xc7:
      return 4;
    case 0xf6:
      return reg === 0x00 || reg === 0x01 ? 1 : 0;
    case 0xf7:
      return reg === 0x00 || reg === 0x01 ? 4 : 0;
    default:
      return 0;
  }
}

/** 0F-escaped opcodes that are followed by a ModRM byte. */
function isTwoByteModrmOpcode(op2: number): boolean {
  if (op2 >= 0x80 && op2 <= 0x8f) return false; // jcc rel32
  switch (op2) {
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0b:
    case 0x0e:
      return false;
    default:
      break;
  }
  if (op2 >= 0x30 && op2 <= 0x37) return false;
  if (op2 === 0xa0 || op2 === 0xa1 || op2 === 0xa2) return false;
  if (op2 === 0xa8 || op2 === 0xa9 || op2 === 0xaa) return false;
  if (op2 >= 0xc8 && op2 <= 0xcf) return false; // bswap
  return true;
}

/** Immediate bytes following the ModRM/displacement of a 0F-escaped opcode. */
function twoByteImmediateSize(op2: number): number {
  if (op2 === 0x0f) return 1; // 3DNow!
  if (op2 >= 0x70 && op2 <= 0x73) return 1;
  if (op2 === 0xa4 || op2 === 0xc2 || op2 === 0xc4 || op2 === 0xc5 || op2 === 0xc6) return 1;
  return 0;
}

type RipCandidate = {
  /** Image index of the ModRM byte. */
  modrmOffset: number;
  /** RVA of the instruction that follows the RIP-relative operand. */
  nextInstructionRva: number;
  /** The 32-bit displacement. */
  displacement: number;
};

/**
 * Finds RIP-relative memory operands (ModRM mod=00, rm=101) inside the byte
 * range.  The ModRM byte must be preceded by an opcode that actually consumes
 * a ModRM byte (optionally behind a REX prefix or a 0F escape) so that data
 * bytes are not mistaken for operands.
 */
function findRipRelative(img: Uint8Array, start: number, end: number): RipCandidate[] {
  const out: RipCandidate[] = [];

  for (let p = start + 1; p < end; p++) {
    const modrm = img[p];
    // ModRM with mod=00 and rm=101 -> RIP-relative in 64-bit mode.
    if ((modrm & 0xc7) !== 0x05) continue;
    if (p + 4 >= end) continue;

    const opPos = p - 1;
    if (opPos < start) continue;

    const opcode = img[opPos];
    let immediate = 0;

    if (opcode === 0x0f) {
      if (opPos - 1 < start) continue;
      const op2 = img[opPos - 1];
      if (!isTwoByteModrmOpcode(op2)) continue;
      immediate = twoByteImmediateSize(op2);
    } else {
      if (!isModrmOpcode(opcode)) continue;
      // A 0x67 prefix switches to 32-bit addressing, where rm=101 is absolute.
      if (opPos - 1 >= start && img[opPos - 1] === 0x67) continue;
      immediate = oneByteImmediateSize(opcode, modrm);
    }

    // ModRM (1 byte) + disp32 (4 bytes) + trailing immediate bytes.
    const nextInstructionRva = p + 5 + immediate;
    out.push({ modrmOffset: p, nextInstructionRva, displacement: readInt32LE(img, p + 1) });
  }

  return out;
}

/**
 * Builds a call graph over the supplied functions.
 *
 * Limit semantics:
 * - `maxDepth` (default 1) bounds how many call-graph levels are expanded.
 *   Level 1 is the set of functions passed in `fns`; their outgoing edges are
 *   always emitted.  A larger value additionally expands known functions that
 *   are reached through those edges (level 2, 3, ...).  `maxDepth <= 0`
 *   produces an empty graph.
 * - `maxNodes` (default 512) caps the number of graph nodes (functions plus
 *   unknown targets) so that scanning a large module stays bounded.  Once the
 *   budget is exhausted, no further functions are scanned.
 */
export function buildCallGraph(
  img: Uint8Array,
  fns: readonly { address: string; size: number }[],
  base: bigint,
  opts?: { maxDepth?: number; maxNodes?: number },
): CallGraph {
  const maxDepth = opts?.maxDepth ?? kDefaultMaxDepth;
  const maxNodes = Math.max(0, opts?.maxNodes ?? kDefaultMaxNodes);

  if (maxDepth <= 0 || maxNodes === 0) return { nodes: [], edges: [] };

  type FnInfo = { rva: number; size: number };
  const functions: FnInfo[] = [];
  for (const fn of fns) {
    const abs = parseAbsoluteAddress(fn.address);
    if (abs === null) continue;
    const delta = abs - base;
    if (delta < 0n || delta > BigInt(Number.MAX_SAFE_INTEGER)) continue;
    const rva = Number(delta);
    if (rva >= img.length) continue;
    functions.push({ rva, size: Math.max(0, Math.min(fn.size, img.length - rva)) });
  }
  functions.sort((a, b) => a.rva - b.rva);

  const known = new Map<number, FnInfo>();
  for (const fn of functions) if (!known.has(fn.rva)) known.set(fn.rva, fn);

  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();

  const addNode = (rva: number, kind: GraphNode["kind"], depth: number): GraphNode | null => {
    const address = formatAddress(rva, base);
    const existing = nodes.get(address);
    if (existing) {
      // A node reached through a shorter path keeps the smaller depth.
      if (depth < existing.depth) existing.depth = depth;
      return existing;
    }
    if (nodes.size >= maxNodes) return null;
    const node: GraphNode = { address, rva, label: labelFor(rva), kind, depth };
    nodes.set(address, node);
    return node;
  };

  const addEdge = (fromRva: number, toRva: number, kind: GraphEdge["kind"]): void => {
    const from = formatAddress(fromRva, base);
    const to = formatAddress(toRva, base);
    const key = `${from}|${to}|${kind}`;
    if (edges.has(key)) return;
    if (!nodes.has(to)) return;
    edges.set(key, { from, to, kind, fromRva, toRva });
  };

  // Level 1 is the supplied function list.
  const queue: { fn: FnInfo; level: number }[] = functions.map((fn) => ({ fn, level: 1 }));
  const scanned = new Set<number>();

  while (queue.length > 0) {
    const current = queue.shift() as { fn: FnInfo; level: number };
    const { fn, level } = current;
    if (level > maxDepth) continue;
    if (scanned.has(fn.rva)) continue;
    scanned.add(fn.rva);

    if (nodes.size >= maxNodes) break;
    if (!addNode(fn.rva, "function", level - 1)) break;

    const start = fn.rva;
    const end = fn.rva + fn.size;

    // Direct relative branches: E8 (call), E9 (jmp), 0F 8x (jcc).
    for (let i = start; i + 5 <= end; i++) {
      const op = img[i];
      let kind: GraphEdge["kind"] | null = null;
      let rel = 0;
      let next = i + 5;
      if (op === 0xe8) {
        kind = "call";
        rel = readInt32LE(img, i + 1);
      } else if (op === 0xe9) {
        kind = "jmp";
        rel = readInt32LE(img, i + 1);
      } else if (op === 0x0f && i + 6 <= end && (img[i + 1] & 0xf0) === 0x80) {
        kind = "jcc";
        rel = readInt32LE(img, i + 2);
        next = i + 6;
      }
      if (!kind) continue;
      const targetRva = next + rel;
      if (targetRva < 0 || targetRva >= img.length) continue;
      const knownFn = known.get(targetRva);
      addNode(targetRva, knownFn ? "function" : "unknown", level);
      addEdge(fn.rva, targetRva, kind);
      if (knownFn && level + 1 <= maxDepth) queue.push({ fn: knownFn, level: level + 1 });
    }

    // RIP-relative memory operands.
    for (const cand of findRipRelative(img, start, end)) {
      const targetRva = cand.nextInstructionRva + cand.displacement;
      if (targetRva < 0 || targetRva >= img.length) continue;
      const knownFn = known.get(targetRva);
      addNode(targetRva, knownFn ? "function" : "unknown", level);
      addEdge(fn.rva, targetRva, "rip");
    }
  }

  const nodeList = [...nodes.values()].sort((a, b) => a.rva - b.rva);
  const edgeList = [...edges.values()].sort(
    (a, b) => a.fromRva - b.fromRva || a.toRva - b.toRva || a.kind.localeCompare(b.kind),
  );

  return { nodes: nodeList, edges: edgeList };
}
