// A YARA engine for module images and memory ranges.
//
// Supported: rules with tags and meta, `private`/`global`; text strings with nocase, wide, ascii,
// fullword and xor[(a-b)]; hex strings with ??, nibble wildcards (?A, A?), jumps [n] [n-m] [n-],
// alternatives (aa | bb cc); regex strings /…/is with nocase/wide/ascii; conditions with and, or,
// not, parentheses, $a, #a, @a[i], !a[i], `$a at x`, `$a in (a..b)`, `N|any|all of them`,
// `N of ($a*, $b)`, comparisons, + - * / % & | ^ << >>, filesize, entrypoint (when known),
// uint8/16/32 (le) and the be variants, int8/16/32, true/false, KB/MB suffixes, references to
// earlier rules. `import` and `for` loops are rejected with a clear message.
//
// Strings compile to JavaScript RegExps over a latin1 view of the bytes (one char per byte).

export class YaraError extends Error {}

type Mods = { nocase: boolean; wide: boolean; ascii: boolean; fullword: boolean; xor: [number, number] | null; private: boolean };
type YString = { id: string; kind: "text" | "hex" | "regex"; source: string; mods: Mods; res: RegExp[]; chain?: Chain };
type Expr =
  | { t: "bool"; v: boolean }
  | { t: "num"; v: number }
  | { t: "str"; id: string }
  | { t: "count"; id: string }
  | { t: "offset"; id: string; index: Expr | null }
  | { t: "length"; id: string; index: Expr | null }
  | { t: "at"; id: string; at: Expr }
  | { t: "in"; id: string; lo: Expr; hi: Expr }
  | { t: "of"; quant: "any" | "all" | Expr; ids: string[] }
  | { t: "not"; e: Expr }
  | { t: "bin"; op: string; a: Expr; b: Expr }
  | { t: "neg"; e: Expr }
  | { t: "filesize" }
  | { t: "entrypoint" }
  | { t: "read"; fn: string; at: Expr }
  | { t: "rule"; name: string };

export type YaraRule = { name: string; tags: string[]; meta: Record<string, string | number | boolean>; strings: YString[]; condition: Expr; private: boolean; global: boolean };
export type YaraStringMatch = { id: string; offset: number; length: number; data: string };
export type YaraMatch = { rule: string; tags: string[]; meta: Record<string, string | number | boolean>; strings: YaraStringMatch[] };

// ------------------------------------------------------------------------------------------------
// Lexer
// ------------------------------------------------------------------------------------------------

type Tok = { k: "id" | "str" | "num" | "sym" | "hex" | "re" | "var"; v: string; n?: number; line: number };

function lex(src: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  let line = 1;
  const err = (m: string) => { throw new YaraError(`line ${line}: ${m}`); };
  while (i < src.length) {
    const c = src[i];
    if (c === "\n") { line++; i++; continue; }
    if (/\s/.test(c)) { i++; continue; }
    if (src.startsWith("//", i)) { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (src.startsWith("/*", i)) {
      const e = src.indexOf("*/", i + 2);
      if (e < 0) err("unterminated comment");
      line += (src.slice(i, e).match(/\n/g) ?? []).length;
      i = e + 2;
      continue;
    }
    if (c === '"') {
      let s = "";
      i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === "\\") {
          const n = src[i + 1];
          if (n === "n") s += "\n";
          else if (n === "t") s += "\t";
          else if (n === "r") s += "\r";
          else if (n === "x") { s += String.fromCharCode(parseInt(src.slice(i + 2, i + 4), 16)); i += 2; }
          else s += n;
          i += 2;
        } else {
          // literal characters are UTF-8 in a rules file: one latin1 char per byte
          const ch = String.fromCodePoint(src.codePointAt(i)!);
          s += ch.charCodeAt(0) < 0x80 ? ch : String.fromCharCode(...new TextEncoder().encode(ch));
          i += ch.length;
        }
      }
      if (src[i] !== '"') err("unterminated string");
      i++;
      toks.push({ k: "str", v: s, line });
      continue;
    }
    if (c === "{" && toks.length && toks[toks.length - 1].v === "=") {
      const e = src.indexOf("}", i);
      if (e < 0) err("unterminated hex string");
      toks.push({ k: "hex", v: src.slice(i + 1, e), line });
      line += (src.slice(i, e).match(/\n/g) ?? []).length;
      i = e + 1;
      continue;
    }
    if (c === "/" && toks.length && toks[toks.length - 1].v === "=") {
      let j = i + 1;
      let body = "";
      while (j < src.length && src[j] !== "/") {
        if (src[j] === "\\") { body += src[j] + src[j + 1]; j += 2; } else body += src[j++];
      }
      j++;
      let flags = "";
      while (/[is]/.test(src[j] ?? "")) flags += src[j++];
      toks.push({ k: "re", v: body, line, n: 0 });
      toks.push({ k: "id", v: `__reflags:${flags}`, line });
      i = j;
      continue;
    }
    if ("$#@!".includes(c) && /[A-Za-z0-9_*]/.test(src[i + 1] ?? "") || (c === "$" )) {
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_*]/.test(src[j])) j++;
      toks.push({ k: "var", v: src.slice(i, j), line });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      const m = /^(0x[0-9a-fA-F]+|0o[0-7]+|\d+)(KB|MB)?/.exec(src.slice(i))!;
      let n = m[1].startsWith("0x") ? parseInt(m[1], 16) : m[1].startsWith("0o") ? parseInt(m[1].slice(2), 8) : Number(m[1]);
      if (m[2] === "KB") n *= 1024;
      if (m[2] === "MB") n *= 1024 * 1024;
      toks.push({ k: "num", v: m[0], n, line });
      i += m[0].length;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_.]/.test(src[j])) j++;
      toks.push({ k: "id", v: src.slice(i, j), line });
      i = j;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (["==", "!=", "<=", ">=", "<<", ">>", ".."].includes(two)) { toks.push({ k: "sym", v: two, line }); i += 2; continue; }
    if ("{}()[]:=<>+-*/%&|^~,\\".includes(c)) { toks.push({ k: "sym", v: c, line }); i++; continue; }
    err(`unexpected character '${c}'`);
  }
  return toks;
}

// ------------------------------------------------------------------------------------------------
// String compilation
// ------------------------------------------------------------------------------------------------

const byteRe = (b: number) => `\\x${b.toString(16).padStart(2, "0")}`;

function textRes(s: string, m: Mods): RegExp[] {
  const out: string[] = [];
  const asciiToo = m.ascii || !m.wide;
  const variants: string[] = [];
  if (m.xor) {
    for (let k = m.xor[0]; k <= m.xor[1]; k++) variants.push(Array.from(s, (c) => String.fromCharCode(c.charCodeAt(0) ^ k)).join(""));
  } else variants.push(s);
  for (const v of variants) {
    // the lexer already turned the text into bytes (one latin1 char each)
    const chars = Array.from(v, (c) => {
      if (m.nocase && /[a-z]/i.test(c)) return `[${byteRe(c.toLowerCase().charCodeAt(0))}${byteRe(c.toUpperCase().charCodeAt(0))}]`;
      return byteRe(c.charCodeAt(0) & 0xff);
    });
    if (asciiToo) out.push(chars.join(""));
    if (m.wide) out.push(chars.map((c) => `${c}\\x00`).join(""));
  }
  const word = (body: string) => (m.fullword ? `(?<![A-Za-z0-9_])(?:${body})(?![A-Za-z0-9_])` : body);
  return out.map((b) => new RegExp(word(b), "gs"));
}

// Hex strings are parsed into a small tree first. They compile to one RegExp, except when a
// top-level jump has a range ([2-40], [0-], [8-]): a lazy `[\s\S]{lo,hi}?` makes the regex
// engine retry every jump length from every start, which is quadratic on bytes a target controls
// (`{ 4D 5A [0-] 50 45 }` over a module full of "MZ" and no "PE" took 1.6 s per 128 KiB). Such
// patterns are matched as a chain of fixed-length fragments instead (see `chainMatches`), with
// the same results the regex would give.

type HexNode = { t: "byte"; re: string } | { t: "jump"; lo: number; hi: number; range: boolean } | { t: "alt"; alts: HexNode[][] };

/** Deepest ( … ) nesting a hex string may use, and the largest jump. */
const kHexDepth = 32;
const kMaxJump = 0x7fffffff;

function parseHex(hex: string): HexNode[] {
  const src = hex.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, " ");
  let i = 0;
  const parse = (depth: number): HexNode[] => {
    if (depth > kHexDepth) throw new YaraError("hex string alternatives nested too deeply");
    const out: HexNode[] = [];
    while (i < src.length) {
      const c = src[i];
      if (/\s/.test(c)) { i++; continue; }
      if (c === "(") {
        i++;
        const alts = [parse(depth + 1)];
        while (src[i] === "|") { i++; alts.push(parse(depth + 1)); }
        if (src[i] !== ")") throw new YaraError("unbalanced ( in hex string");
        i++;
        out.push({ t: "alt", alts });
        continue;
      }
      if (c === "|" || c === ")") return out;
      if (c === "[") {
        const e = src.indexOf("]", i);
        if (e < 0) throw new YaraError("unterminated jump in hex string");
        const body = src.slice(i + 1, e).replace(/\s/g, "");
        i = e + 1;
        const m = /^(\d*)(-?)(\d*)$/.exec(body);
        if (!m) throw new YaraError(`bad jump [${body}]`);
        const lo = m[1] ? Number(m[1]) : 0;
        const hi = !m[2] ? lo : m[3] ? Number(m[3]) : Infinity;
        if (lo > kMaxJump || (hi !== Infinity && hi > kMaxJump) || hi < lo) throw new YaraError(`bad jump [${body}]`);
        out.push({ t: "jump", lo, hi, range: Boolean(m[2]) });
        continue;
      }
      const pair = src.slice(i, i + 2);
      if (!/^[0-9a-fA-F?]{2}$/.test(pair)) throw new YaraError(`bad hex token '${pair}'`);
      i += 2;
      let re: string;
      if (pair === "??") re = "[\\s\\S]";
      else if (pair[0] === "?") {
        const lo = parseInt(pair[1], 16);
        re = `[${Array.from({ length: 16 }, (_, h) => byteRe((h << 4) | lo)).join("")}]`;
      } else if (pair[1] === "?") {
        const hi = parseInt(pair[0], 16);
        re = `[${byteRe(hi << 4)}-${byteRe((hi << 4) | 15)}]`;
      } else re = byteRe(parseInt(pair, 16));
      out.push({ t: "byte", re });
    }
    return out;
  };
  const r = parse(0);
  if (i < src.length) throw new YaraError("unexpected ) or | in hex string");
  if (!r.length) throw new YaraError("empty hex string");
  return r;
}

const isRange = (n: HexNode): boolean => n.t === "jump" && n.range;

function hexSource(nodes: readonly HexNode[]): string {
  return nodes.map((n) => {
    if (n.t === "byte") return n.re;
    if (n.t === "alt") return `(?:${n.alts.map(hexSource).join("|")})`;
    if (!n.range) return `[\\s\\S]{${n.lo}}`;
    return `[\\s\\S]{${n.lo},${n.hi === Infinity ? "" : n.hi}}?`;
  }).join("");
}

export function hexToRegex(hex: string): string {
  return hexSource(parseHex(hex));
}

/** Byte length of a node sequence when every way of matching it has the same length, else null. */
function fixedLength(nodes: readonly HexNode[]): number | null {
  let n = 0;
  for (const x of nodes) {
    if (x.t === "byte") n++;
    else if (x.t === "jump") {
      if (x.range) return null;
      n += x.lo;
    } else {
      const lens = x.alts.map(fixedLength);
      if (lens.some((l) => l === null || l !== lens[0])) return null;
      n += lens[0]!;
    }
  }
  return n;
}

/** One fixed-length piece of a chained hex string and the jump range that precedes it. */
type Fragment = { re: RegExp; len: number; lo: number; hi: number };
type Chain = Fragment[];

/** Splits a hex string at its top-level ranged jumps; null when the regex is safe or the pattern does not split cleanly. */
function hexChain(nodes: readonly HexNode[]): Chain | null {
  if (!nodes.some(isRange)) return null;
  const chain: Chain = [];
  let cur: HexNode[] = [];
  let lo = 0;
  let hi = 0;
  const flush = () => {
    const len = fixedLength(cur);
    if (len === null || len === 0) return false;
    chain.push({ re: compileRe(hexSource(cur), "gs", "hex string"), len, lo, hi });
    cur = [];
    lo = 0;
    hi = 0;
    return true;
  };
  for (const n of nodes) {
    if (n.t === "jump" && n.range) {
      if (!cur.length) return null; // a leading jump, or two in a row: leave it to the regex
      if (!flush()) return null;
      lo = n.lo;
      hi = n.hi;
    } else cur.push(n);
  }
  if (!cur.length || !flush()) return null;
  return chain;
}

/**
 * The matches of a chained hex string: for every start where fragment 0 matches and the rest of
 * the chain completes, the match the lazy regex would report (the smallest jump at each step).
 * Each later fragment keeps a forward cursor: the positions asked about only ever increase (they
 * follow the starts, which increase), so every fragment occurrence is examined once per level and
 * the whole scan is linear in the buffer, whatever the jump ranges.
 */
function chainMatches(chain: Chain, text: string, limit: number): { offset: number; length: number }[] {
  type Level = { f: Fragment; cand: number; candEnd: number; asked: number };
  const levels: Level[] = chain.map((f) => ({ f, cand: -2, candEnd: 0, asked: -1 }));
  /** Smallest q >= x where level k matches and the chain after it completes (-1: none). */
  const nextOk = (k: number, x: number): number => {
    const L = levels[k];
    if (L.asked >= 0 && x >= L.asked && (L.cand === -1 || L.cand >= x)) return L.cand;
    L.asked = x;
    const re = L.f.re;
    for (let from = x; from <= text.length;) {
      re.lastIndex = from;
      const m = re.exec(text);
      if (!m) break;
      const q = m.index;
      if (k + 1 === levels.length) {
        L.cand = q;
        L.candEnd = q + L.f.len;
        return q;
      }
      const nf = levels[k + 1].f;
      const y = q + L.f.len + nf.lo;
      const r = nextOk(k + 1, y);
      if (r < 0) break; // nothing completes after y, so nothing completes after any later q either
      if (r - y <= nf.hi - nf.lo) {
        L.cand = q;
        L.candEnd = levels[k + 1].candEnd;
        return q;
      }
      from = q + 1;
    }
    L.cand = -1;
    return -1;
  };
  const out: { offset: number; length: number }[] = [];
  const first = levels[0].f;
  const second = levels[1].f;
  first.re.lastIndex = 0;
  for (let m = first.re.exec(text); m && out.length < limit; m = first.re.exec(text)) {
    const p = m.index;
    const y = p + first.len + second.lo;
    const r = nextOk(1, y);
    if (r < 0) break;
    if (r - y <= second.hi - second.lo) out.push({ offset: p, length: levels[1].candEnd - p });
    first.re.lastIndex = p + 1;
  }
  return out;
}

/** Test hook: the matches of one hex string with the chained matcher, or with the plain regex. */
export function hexMatches(hex: string, buf: Uint8Array, engine: "auto" | "regex" = "auto", limit = 1000): { offset: number; length: number }[] {
  const nodes = parseHex(hex);
  const chain = engine === "auto" ? hexChain(nodes) : null;
  const s: YString = { id: "$", kind: "hex", source: hex, mods: { nocase: false, wide: false, ascii: false, fullword: false, xor: null, private: false }, res: chain ? [] : [new RegExp(hexSource(nodes), "gs")], chain: chain ?? undefined };
  return stringMatches(s, latin1(buf), limit);
}

/** A RegExp from rule text: a bad pattern is the rule's YaraError, not an engine SyntaxError. */
function compileRe(src: string, flags: string, id: string): RegExp {
  try {
    return new RegExp(src, flags);
  } catch (e) {
    throw new YaraError(`${id}: ${(e as Error).message}`);
  }
}

function regexRes(body: string, flags: string, m: Mods, id: string): RegExp[] {
  const f = "g" + (flags.includes("s") ? "s" : "") + (flags.includes("i") || m.nocase ? "i" : "");
  const out = [compileRe(m.fullword ? `(?<![A-Za-z0-9_])(?:${body})(?![A-Za-z0-9_])` : body, f, id)];
  if (m.wide) out.push(compileRe(body.replace(/(\\.|[^\\])/g, "$1\\x00"), f, id));
  return m.wide && !m.ascii ? out.slice(1) : out;
}

// ------------------------------------------------------------------------------------------------
// Parser
// ------------------------------------------------------------------------------------------------

/** Deepest parenthesis / not / minus nesting while parsing, and deepest finished condition tree. */
const kMaxNesting = 256;
const kMaxExprDepth = 2000;

/** Depth of an expression tree, without recursion. */
function exprDepth(root: Expr): number {
  let max = 0;
  const stack: [Expr, number][] = [[root, 1]];
  while (stack.length) {
    const [e, d] = stack.pop()!;
    if (d > max) max = d;
    for (const v of Object.values(e)) if (v && typeof v === "object" && "t" in v) stack.push([v as Expr, d + 1]);
  }
  return max;
}

export function parseYara(src: string): YaraRule[] {
  const t = lex(src);
  let p = 0;
  let nesting = 0;
  const peek = (o = 0) => t[p + o];
  const err = (m: string): never => { throw new YaraError(`line ${peek()?.line ?? t[t.length - 1]?.line ?? 0}: ${m}`); };
  const eat = (v?: string) => {
    const x = t[p];
    if (!x) err(`unexpected end of rules${v ? `, expected '${v}'` : ""}`);
    if (v !== undefined && x.v !== v) err(`expected '${v}', got '${x.v}'`);
    p++;
    return x;
  };
  const is = (v: string) => peek()?.v === v;

  const rules: YaraRule[] = [];
  while (p < t.length) {
    if (is("import") || is("include")) err(`'${peek().v}' is not supported (no YARA modules here)`);
    let isPrivate = false;
    let isGlobal = false;
    while (is("private") || is("global")) {
      if (eat().v === "private") isPrivate = true;
      else isGlobal = true;
    }
    eat("rule");
    const name = eat().v;
    const tags: string[] = [];
    if (is(":")) {
      eat(":");
      while (peek() && !is("{")) tags.push(eat().v);
    }
    eat("{");
    const meta: YaraRule["meta"] = {};
    const strings: YString[] = [];
    let condition: Expr | null = null;
    while (!is("}")) {
      const section = eat().v;
      eat(":");
      if (section === "meta") {
        while (peek() && peek(1)?.v === "=" && !["strings", "condition"].includes(peek().v)) {
          const k = eat().v;
          eat("=");
          const v = eat();
          meta[k] = v.k === "num" ? v.n! : v.v === "true" ? true : v.v === "false" ? false : v.k === "sym" && v.v === "-" ? -eat().n! : v.v;
        }
      } else if (section === "strings") {
        while (peek()?.k === "var") {
          const id = eat().v;
          eat("=");
          const body = eat();
          let reFlags = "";
          if (body.k === "re") reFlags = eat().v.slice("__reflags:".length);
          const mods: Mods = { nocase: false, wide: false, ascii: false, fullword: false, xor: null, private: false };
          while (peek()?.k === "id" && ["nocase", "wide", "ascii", "fullword", "xor", "private"].includes(peek().v)) {
            const m = eat().v;
            if (m === "xor") {
              mods.xor = [0, 255];
              if (is("(")) {
                eat("(");
                const a = eat().n!;
                let b = a;
                if (is("-")) { eat("-"); b = eat().n!; }
                eat(")");
                // a bad range would otherwise spin over millions of keys (xor(5-1000000))
                if (!(Number.isInteger(a) && Number.isInteger(b) && a >= 0 && a <= b && b <= 255)) err(`bad xor range for ${id}: (${a}-${b})`);
                mods.xor = [a, b];
              }
            } else (mods as Record<string, unknown>)[m] = true;
          }
          let res: RegExp[];
          let kind: YString["kind"];
          let chain: Chain | null = null;
          if (body.k === "str") { kind = "text"; res = textRes(body.v, mods); }
          else if (body.k === "hex") {
            kind = "hex";
            const nodes = parseHex(body.v);
            chain = hexChain(nodes);
            res = chain ? [] : [compileRe(hexSource(nodes), "gs", id)];
          } else if (body.k === "re") { kind = "regex"; res = regexRes(body.v, reFlags, mods, id); }
          else return err(`bad string value for ${id}`);
          if (strings.some((s) => s.id === id) && id !== "$") err(`duplicate string ${id}`);
          strings.push({ id, kind, source: body.v, mods, res, ...(chain ? { chain } : {}) });
        }
      } else if (section === "condition") {
        condition = parseExpr();
      } else err(`unknown section '${section}'`);
    }
    eat("}");
    if (!condition) err(`rule ${name} has no condition`);
    rules.push({ name, tags, meta, strings, condition: condition!, private: isPrivate, global: isGlobal });
  }
  return rules;

  // Nesting is bounded while parsing (parentheses, "not not …", "- - …") and the finished tree's
  // depth is checked too (a chain of 10000 "and"s is 10000 deep), so neither the parser nor the
  // evaluator can overflow the stack.
  function nested<T>(f: () => T): T {
    if (++nesting > kMaxNesting) err("condition nested too deeply");
    try {
      return f();
    } finally {
      nesting--;
    }
  }
  function parseExpr(): Expr {
    const e = nested(parseOr);
    if (nesting === 0 && exprDepth(e) > kMaxExprDepth) err("condition nested too deeply");
    return e;
  }
  function parseOr(): Expr {
    let a = parseAnd();
    while (is("or")) { eat(); a = { t: "bin", op: "or", a, b: parseAnd() }; }
    return a;
  }
  function parseAnd(): Expr {
    let a = parseNot();
    while (is("and")) { eat(); a = { t: "bin", op: "and", a, b: parseNot() }; }
    return a;
  }
  function parseNot(): Expr {
    if (is("not")) { eat(); return { t: "not", e: nested(parseNot) }; }
    return parseCmp();
  }
  function parseCmp(): Expr {
    const a = parseBits();
    const op = peek()?.v;
    if (op && ["==", "!=", "<", "<=", ">", ">="].includes(op)) { eat(); return { t: "bin", op, a, b: parseBits() }; }
    return a;
  }
  function parseBits(): Expr {
    let a = parseShift();
    while (is("&") || is("|") || is("^")) { const op = eat().v; a = { t: "bin", op, a, b: parseShift() }; }
    return a;
  }
  function parseShift(): Expr {
    let a = parseAdd();
    while (is("<<") || is(">>")) { const op = eat().v; a = { t: "bin", op, a, b: parseAdd() }; }
    return a;
  }
  function parseAdd(): Expr {
    let a = parseMul();
    while (is("+") || is("-")) { const op = eat().v; a = { t: "bin", op, a, b: parseMul() }; }
    return a;
  }
  function parseMul(): Expr {
    let a = parseUnary();
    while (is("*") || is("\\") || is("%") || (is("/"))) { const op = eat().v; a = { t: "bin", op: op === "\\" ? "/" : op, a, b: parseUnary() }; }
    return a;
  }
  function parseUnary(): Expr {
    if (is("-")) { eat(); return { t: "neg", e: nested(parseUnary) }; }
    if (is("~")) { eat(); return { t: "bin", op: "^", a: nested(parseUnary), b: { t: "num", v: -1 } }; }
    return parsePrimary();
  }
  function idList(): string[] {
    if (is("them")) { eat(); return ["$*"]; }
    eat("(");
    const ids = [eat().v];
    while (is(",")) { eat(","); ids.push(eat().v); }
    eat(")");
    return ids;
  }
  function parsePrimary(): Expr {
    const x = peek();
    if (!x) return err("unexpected end of condition");
    if (x.v === "for") return err("'for' loops are not supported");
    if (x.v === "(") { eat(); const e = parseExpr(); eat(")"); return e; }
    if (x.v === "true" || x.v === "false") { eat(); return { t: "bool", v: x.v === "true" }; }
    if (x.v === "filesize") { eat(); return { t: "filesize" }; }
    if (x.v === "entrypoint") { eat(); return { t: "entrypoint" }; }
    if (x.v === "any" || x.v === "all" || x.k === "num" && peek(1)?.v === "of") {
      eat();
      const quant = x.v === "any" || x.v === "all" ? (x.v as "any" | "all") : ({ t: "num", v: x.n! } as Expr);
      eat("of");
      return { t: "of", quant, ids: idList() };
    }
    if (x.k === "num") { eat(); return { t: "num", v: x.n! }; }
    if (x.k === "id" && /^u?int(8|16|32)(be)?$/.test(x.v)) {
      eat();
      eat("(");
      const at = parseExpr();
      eat(")");
      return { t: "read", fn: x.v, at };
    }
    if (x.k === "var") {
      eat();
      const sigil = x.v[0];
      const id = "$" + x.v.slice(1);
      if (sigil === "#") return { t: "count", id };
      if (sigil === "@" || sigil === "!") {
        let index: Expr | null = null;
        if (is("[")) { eat("["); index = parseExpr(); eat("]"); }
        return sigil === "@" ? { t: "offset", id, index } : { t: "length", id, index };
      }
      if (is("at")) { eat(); return { t: "at", id, at: parseAdd() }; }
      if (is("in")) {
        eat();
        eat("(");
        const lo = parseExpr();
        eat("..");
        const hi = parseExpr();
        eat(")");
        return { t: "in", id, lo, hi };
      }
      return { t: "str", id };
    }
    if (x.k === "id") {
      eat();
      if (x.v.includes(".")) return err(`'${x.v}': YARA modules are not supported`);
      return { t: "rule", name: x.v };
    }
    return err(`unexpected '${x.v}' in condition`);
  }
}

// ------------------------------------------------------------------------------------------------
// Scanning
// ------------------------------------------------------------------------------------------------

export function latin1(buf: Uint8Array): string {
  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < buf.length; i += chunk) s += String.fromCharCode(...buf.subarray(i, i + chunk));
  return s;
}

function stringMatches(s: YString, text: string, limit: number): { offset: number; length: number }[] {
  if (s.chain) return chainMatches(s.chain, text, limit);
  const out: { offset: number; length: number }[] = [];
  const seen = new Set<number>();
  for (const re of s.res) {
    re.lastIndex = 0;
    for (let m = re.exec(text); m; m = re.exec(text)) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      if (!seen.has(m.index)) {
        seen.add(m.index);
        out.push({ offset: m.index, length: m[0].length });
      }
      re.lastIndex = m.index + 1; // overlapping matches, like YARA
      if (out.length >= limit) break;
    }
  }
  return out.sort((a, b) => a.offset - b.offset);
}

function expand(ids: string[], all: YString[]): YString[] {
  const out = new Set<YString>();
  for (const id of ids) {
    if (id.endsWith("*")) {
      const pre = id.slice(0, -1);
      for (const s of all) if (s.id.startsWith(pre)) out.add(s);
    } else {
      const s = all.find((x) => x.id === id);
      if (!s) throw new YaraError(`undefined string ${id}`);
      out.add(s);
    }
  }
  return [...out];
}

export type ScanOptions = { entrypoint?: number; limitPerString?: number };

/** Runs compiled rules over `buf`. Offsets are relative to the buffer. */
export function scanYara(rules: readonly YaraRule[], buf: Uint8Array, opts: ScanOptions = {}): YaraMatch[] {
  const text = latin1(buf);
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const results = new Map<string, boolean>();
  const out: YaraMatch[] = [];
  const limit = opts.limitPerString ?? 1000;
  const globalsOk = () => rules.filter((r) => r.global).every((r) => results.get(r.name) !== false);
  for (const rule of rules) {
    const hits = new Map<string, { offset: number; length: number }[]>();
    const get = (id: string) => {
      let h = hits.get(id);
      if (!h) {
        const s = rule.strings.find((x) => x.id === id);
        if (!s) throw new YaraError(`rule ${rule.name}: undefined string ${id}`);
        h = stringMatches(s, text, limit);
        hits.set(id, h);
      }
      return h;
    };
    const num = (e: Expr): number => {
      const v = ev(e);
      return typeof v === "boolean" ? (v ? 1 : 0) : v;
    };
    const ev = (e: Expr): number | boolean => {
      switch (e.t) {
        case "bool": return e.v;
        case "num": return e.v;
        case "filesize": return buf.length;
        case "entrypoint":
          if (opts.entrypoint === undefined) throw new YaraError("entrypoint is unknown for this scan");
          return opts.entrypoint;
        case "str": return get(e.id).length > 0;
        case "count": return get(e.id).length;
        case "offset": { const h = get(e.id); const i = e.index ? num(e.index) : 1; return h[i - 1]?.offset ?? NaN; }
        case "length": { const h = get(e.id); const i = e.index ? num(e.index) : 1; return h[i - 1]?.length ?? NaN; }
        case "at": { const a = num(e.at); return get(e.id).some((h) => h.offset === a); }
        case "in": { const lo = num(e.lo); const hi = num(e.hi); return get(e.id).some((h) => h.offset >= lo && h.offset <= hi); }
        case "of": {
          const set = expand(e.ids, rule.strings);
          const n = set.filter((s) => get(s.id).length > 0).length;
          if (e.quant === "any") return n >= 1;
          if (e.quant === "all") return n === set.length;
          return n >= num(e.quant);
        }
        case "not": return !ev(e.e);
        case "neg": return -num(e.e);
        case "rule": {
          if (!results.has(e.name)) throw new YaraError(`rule ${rule.name}: '${e.name}' is not an earlier rule`);
          return results.get(e.name)!;
        }
        case "read": {
          const at = num(e.at);
          const w = Number(/\d+/.exec(e.fn)![0]) / 8;
          if (!(at >= 0 && at + w <= buf.length)) return NaN;
          const be = e.fn.endsWith("be");
          const signed = !e.fn.startsWith("u");
          if (w === 1) return signed ? dv.getInt8(at) : dv.getUint8(at);
          if (w === 2) return signed ? dv.getInt16(at, !be) : dv.getUint16(at, !be);
          return signed ? dv.getInt32(at, !be) : dv.getUint32(at, !be);
        }
        case "bin": {
          if (e.op === "and") return Boolean(ev(e.a)) && Boolean(ev(e.b));
          if (e.op === "or") return Boolean(ev(e.a)) || Boolean(ev(e.b));
          const a = num(e.a);
          const b = num(e.b);
          switch (e.op) {
            case "==": return a === b;
            case "!=": return a !== b;
            case "<": return a < b;
            case "<=": return a <= b;
            case ">": return a > b;
            case ">=": return a >= b;
            case "+": return a + b;
            case "-": return a - b;
            case "*": return a * b;
            case "/": return b === 0 ? NaN : Math.trunc(a / b);
            case "%": return b === 0 ? NaN : a % b;
            case "&": return a & b;
            case "|": return a | b;
            case "^": return a ^ b;
            case "<<": return a << b;
            case ">>": return a >>> b;
          }
        }
      }
      throw new YaraError(`cannot evaluate ${e.t}`);
    };
    const ok = Boolean(ev(rule.condition)) && (rule.global || globalsOk());
    results.set(rule.name, ok);
    if (ok && !rule.private) {
      const strings: YaraStringMatch[] = [];
      for (const s of rule.strings) {
        if (s.mods.private) continue;
        for (const h of get(s.id)) strings.push({ id: s.id, offset: h.offset, length: h.length, data: Array.from(buf.subarray(h.offset, h.offset + Math.min(h.length, 64)), (x) => x.toString(16).padStart(2, "0")).join("") });
      }
      out.push({ rule: rule.name, tags: rule.tags, meta: rule.meta, strings });
    }
  }
  return out;
}
