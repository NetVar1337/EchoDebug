// A small Markdown parser for the assistant's replies: headings, paragraphs, lists, block quotes,
// tables, rules and fenced code (an unterminated fence while streaming renders as open code), with
// inline code, bold, italic, links and addresses (0x… and module+0x…) that the panel links into
// the disassembly. No HTML is ever produced from the text: the panel renders the tree as React
// elements.

export type Inline =
  | { t: "text"; v: string }
  | { t: "code"; v: string }
  | { t: "b"; c: Inline[] }
  | { t: "i"; c: Inline[] }
  | { t: "link"; href: string; c: Inline[] }
  | { t: "addr"; v: string };

export type MdBlock =
  | { t: "p"; c: Inline[] }
  | { t: "h"; level: number; c: Inline[] }
  | { t: "code"; lang: string; code: string; open: boolean }
  | { t: "list"; ordered: boolean; start: number; items: { level: number; c: Inline[] }[] }
  | { t: "quote"; blocks: MdBlock[] }
  | { t: "table"; head: Inline[][]; rows: Inline[][][] }
  | { t: "hr" };

/** 0x-addresses of 4+ digits, and module+0x offsets (game.exe+0x1a2b, libc.so.6+0x10). */
export const kAddrRe = /\b0x[0-9a-fA-F]{4,16}\b|\b[A-Za-z_][\w.-]*\.(?:exe|dll|sys|so(?:\.\d+)*|dylib|bin)\+0x[0-9a-fA-F]+\b/g;

function splitAddrs(s: string, out: Inline[]): void {
  let last = 0;
  for (const m of s.matchAll(kAddrRe)) {
    if (m.index! > last) out.push({ t: "text", v: s.slice(last, m.index) });
    out.push({ t: "addr", v: m[0] });
    last = m.index! + m[0].length;
  }
  if (last < s.length) out.push({ t: "text", v: s.slice(last) });
}

export function parseInline(s: string): Inline[] {
  const out: Inline[] = [];
  let buf = "";
  const flush = () => { if (buf) { splitAddrs(buf, out); buf = ""; } };
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "\\" && i + 1 < s.length && /[\\`*_[\]()#>|-]/.test(s[i + 1])) { buf += s[i + 1]; i += 2; continue; }
    if (c === "`") {
      const n = /^`+/.exec(s.slice(i))![0].length;
      const end = s.indexOf("`".repeat(n), i + n);
      if (end > 0) { flush(); out.push({ t: "code", v: s.slice(i + n, end).replace(/^ (.*) $/, "$1") }); i = end + n; continue; }
    }
    if ((c === "*" || c === "_") && s[i + 1] === c) {
      const end = s.indexOf(c + c, i + 2);
      if (end > i + 2) { flush(); out.push({ t: "b", c: parseInline(s.slice(i + 2, end)) }); i = end + 2; continue; }
    }
    if ((c === "*" || c === "_") && s[i + 1] !== " " && s[i + 1] !== c && (c === "*" || i === 0 || /\W/.test(s[i - 1]))) {
      let end = i + 1;
      while ((end = s.indexOf(c, end)) > 0 && (s[end + 1] === c || s[end - 1] === " ")) end++;
      if (end > i + 1 && (c === "*" || end + 1 >= s.length || /\W/.test(s[end + 1]))) { flush(); out.push({ t: "i", c: parseInline(s.slice(i + 1, end)) }); i = end + 1; continue; }
    }
    if (c === "[") {
      const m = /^\[([^\]]+)\]\(([^)\s]+)\)/.exec(s.slice(i));
      if (m) { flush(); out.push({ t: "link", href: m[2], c: parseInline(m[1]) }); i += m[0].length; continue; }
    }
    buf += c;
    i++;
  }
  flush();
  return out;
}

const cells = (line: string) => line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((x) => parseInline(x.trim()));

export function parseMarkdown(src: string): MdBlock[] {
  const lines = src.replace(/\r\n/g, "\n").split("\n");
  const out: MdBlock[] = [];
  let para: string[] = [];
  const endPara = () => { if (para.length) { out.push({ t: "p", c: parseInline(para.join("\n")) }); para = []; } };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fence = /^\s*(```+|~~~+)\s*([\w+#.-]*)/.exec(line);
    if (fence) {
      endPara();
      const close = fence[1];
      const body: string[] = [];
      let j = i + 1;
      while (j < lines.length && !lines[j].trim().startsWith(close)) body.push(lines[j++]);
      out.push({ t: "code", lang: fence[2] ?? "", code: body.join("\n"), open: j >= lines.length });
      i = j;
      continue;
    }
    if (!line.trim()) { endPara(); continue; }
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) { endPara(); out.push({ t: "h", level: h[1].length, c: parseInline(h[2].replace(/\s+#+\s*$/, "")) }); continue; }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { endPara(); out.push({ t: "hr" }); continue; }
    if (/^\s*>/.test(line)) {
      endPara();
      const q: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) q.push(lines[i++].replace(/^\s*>\s?/, ""));
      i--;
      out.push({ t: "quote", blocks: parseMarkdown(q.join("\n")) });
      continue;
    }
    if (line.includes("|") && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(lines[i + 1])) {
      endPara();
      const head = cells(line);
      const rows: Inline[][][] = [];
      i += 2;
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) rows.push(cells(lines[i++]));
      i--;
      out.push({ t: "table", head, rows });
      continue;
    }
    const li = /^(\s*)([-*+]|(\d+)[.)])\s+(.*)$/.exec(line);
    if (li) {
      endPara();
      const ordered = !!li[3];
      const items: { level: number; c: Inline[] }[] = [];
      let start = ordered ? Number(li[3]) : 1;
      while (i < lines.length) {
        const m = /^(\s*)([-*+]|(\d+)[.)])\s+(.*)$/.exec(lines[i]);
        if (m) {
          if (!items.length && m[3]) start = Number(m[3]);
          items.push({ level: Math.floor(m[1].replace(/\t/g, "  ").length / 2), c: parseInline(m[4]) });
          i++;
        } else if (lines[i].trim() && /^\s{2,}/.test(lines[i]) && items.length) {
          // a continuation line of the previous item
          const last = items[items.length - 1];
          last.c = [...last.c, { t: "text", v: " " }, ...parseInline(lines[i].trim())];
          i++;
        } else break;
      }
      i--;
      out.push({ t: "list", ordered, start, items });
      continue;
    }
    para.push(line);
  }
  endPara();
  return out;
}

/** The plain text of inline nodes (for copying and tests). */
export function inlineText(c: readonly Inline[]): string {
  return c.map((x) => (x.t === "text" || x.t === "code" || x.t === "addr" ? x.v : inlineText(x.c))).join("");
}
