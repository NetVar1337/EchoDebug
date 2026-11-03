// Renders the assistant's Markdown as React elements (never as HTML), with copyable code blocks
// and addresses that jump to the disassembly.
import { Fragment, memo, useMemo, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import { fmtAddr, parseAddress } from "@/lib/hex";
import { openUrl } from "@/lib/tauri";
import { inlineText, kAddrRe, parseInline, parseMarkdown, type Inline, type MdBlock } from "@/lib/assistant/markdown";
import { useConn } from "@/store/conn";
import { useUi } from "@/store/ui";
import { useCopy } from "../../ui";

function goTo(expr: string): void {
  const v = parseAddress(expr, useConn.getState().modules);
  if (v !== null) useUi.getState().goDisasm(fmtAddr(v));
}

function Addr({ v }: { v: string }) {
  return <span className="link mono" title="Open in Disassembly" onClick={() => goTo(v)}>{v}</span>;
}

/** Text with addresses turned into links (used inside code). */
function linkify(s: string, key = 0): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  for (const m of s.matchAll(kAddrRe)) {
    if (m.index! > last) out.push(s.slice(last, m.index));
    out.push(<Addr key={`${key}-${m.index}`} v={m[0]} />);
    last = m.index! + m[0].length;
  }
  if (last < s.length) out.push(s.slice(last));
  return out;
}

function Inl({ c }: { c: readonly Inline[] }) {
  return (
    <>
      {c.map((x, i) => {
        switch (x.t) {
          case "text": return <Fragment key={i}>{x.v}</Fragment>;
          case "addr": return <Addr key={i} v={x.v} />;
          case "code": return <code key={i}>{linkify(x.v, i)}</code>;
          case "b": return <b key={i}><Inl c={x.c} /></b>;
          case "i": return <em key={i}><Inl c={x.c} /></em>;
          case "link": {
            const safe = /^https?:\/\//i.test(x.href);
            return safe ? <span key={i} className="link" title={x.href} onClick={() => void openUrl(x.href)}><Inl c={x.c} /></span> : <Fragment key={i}><Inl c={x.c} /> ({x.href})</Fragment>;
          }
        }
      })}
    </>
  );
}

function CodeBlock({ lang, code, open }: { lang: string; code: string; open: boolean }) {
  const [copied, copy] = useCopy();
  const lines = code.split("\n");
  return (
    <div className="as-code">
      <div className="as-code-head">
        <span className="faint mono">{lang || "code"}{open ? " …" : ""}</span>
        <span className="grow" />
        <button className="as-code-copy" title="Copy code" aria-label="Copy code" onClick={() => copy(code)}>{copied === code ? <Check size={11} /> : <Copy size={11} />}</button>
      </div>
      <pre className="mono">{lines.map((l, i) => <Fragment key={i}>{linkify(l, i)}{i < lines.length - 1 ? "\n" : ""}</Fragment>)}</pre>
    </div>
  );
}

function Blocks({ blocks }: { blocks: MdBlock[] }) {
  return (
    <>
      {blocks.map((b, i) => {
        switch (b.t) {
          case "p": return <p key={i}><Inl c={b.c} /></p>;
          case "h": { const H = `h${Math.min(6, b.level + 2)}` as "h3"; return <H key={i}><Inl c={b.c} /></H>; }
          case "code": return <CodeBlock key={i} lang={b.lang} code={b.code} open={b.open} />;
          case "hr": return <hr key={i} />;
          case "quote": return <blockquote key={i}><Blocks blocks={b.blocks} /></blockquote>;
          case "list": {
            const L = b.ordered ? "ol" : "ul";
            return <L key={i} start={b.ordered ? b.start : undefined}>{b.items.map((it, j) => <li key={j} style={it.level ? { marginLeft: it.level * 14 } : undefined}><Inl c={it.c} /></li>)}</L>;
          }
          case "table": return (
            <div key={i} className="as-table-wrap">
              <table className="as-table">
                <thead><tr>{b.head.map((h, j) => <th key={j}><Inl c={h} /></th>)}</tr></thead>
                <tbody>{b.rows.map((r, j) => <tr key={j}>{r.map((c, k) => <td key={k}><Inl c={c} /></td>)}</tr>)}</tbody>
              </table>
            </div>
          );
        }
      })}
    </>
  );
}

export const Markdown = memo(function Markdown({ text }: { text: string }) {
  const blocks = useMemo(() => parseMarkdown(text), [text]);
  return <div className="as-md">{<Blocks blocks={blocks} />}</div>;
});

/** Plain text with links (thinking summaries). */
export function PlainLinked({ text }: { text: string }) {
  return <div className="as-text">{<Inl c={parseInline(text)} />}</div>;
}

export { inlineText };
