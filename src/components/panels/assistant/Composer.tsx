// The assistant's message box: Enter sends, Shift+Enter adds a line, Esc stops, ↑ in an empty box
// edits the last message; `/` opens the command list and `@` the mention list (Tab or Enter
// picks); mentions in the text show as chips above it.
import { useEffect, useMemo, useRef, useState } from "react";
import { AtSign, Send, Square, X } from "lucide-react";
import { insertMention, mentionAt, mentionCompletions, mentionToken, parseMentions, slashCompletions, type MentionItem, type SlashDef } from "@/lib/assistant/commands";
import { estimateTokens } from "@/lib/assistant/cost";
import { useAssistant } from "@/store/assistant";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { useTypes } from "@/store/types";
import { useUi } from "@/store/ui";

type Item = { key: string; label: string; detail: string; apply: () => void };

export function Composer({ disabled, placeholder }: { disabled: boolean; placeholder: string }) {
  const a = useAssistant();
  const [text, setText] = useState("");
  const [caret, setCaret] = useState(0);
  const [sel, setSel] = useState(0);
  const [dismissed, setDismissed] = useState<string | null>(null);
  const ta = useRef<HTMLTextAreaElement>(null);
  const modules = useConn((s) => s.modules);
  const ui = useUi();

  // focus requests (Ctrl+L) and drafts handed over by "edit last message"
  const firstFocus = useRef(true);
  useEffect(() => {
    if (firstFocus.current) { firstFocus.current = false; return; }
    ta.current?.focus();
  }, [a.focusTick]);
  useEffect(() => {
    if (!a.draft) return;
    setText(a.draft.text);
    requestAnimationFrame(() => { ta.current?.focus(); ta.current?.setSelectionRange(a.draft!.text.length, a.draft!.text.length); });
  }, [a.draft]);

  const setAt = (t: string, c: number) => {
    setText(t);
    setCaret(c);
    requestAnimationFrame(() => { ta.current?.focus(); ta.current?.setSelectionRange(c, c); });
  };

  const items: Item[] = useMemo(() => {
    const slash: SlashDef[] = caret === text.length || !text.slice(caret).trim() ? slashCompletions(text.slice(0, caret)) : [];
    if (slash.length) {
      return slash.map((d) => ({ key: `/${d.name}`, label: `/${d.name}${d.args ? " " + d.args : ""}`, detail: d.help, apply: () => setAt(`/${d.name}${d.args ? " " : ""}`, d.name.length + 1 + (d.args ? 1 : 0)) }));
    }
    const at = mentionAt(text, caret);
    if (!at) return [];
    const names = useNames.getState().list().filter((n) => n.name).map((n) => ({ address: n.address, name: n.name }));
    const list: MentionItem[] = mentionCompletions(at.query, {
      names, modules, structs: useTypes.getState().types, cursor: ui.disasmAt ?? ui.selected,
      selection: ui.memSel ? `memory ${ui.memSel.from}…${ui.memSel.to}` : null,
    });
    return list.map((m) => ({ key: m.label, label: m.label, detail: m.detail, apply: () => { const r = insertMention(text, at.start, caret, m.mention); setAt(r.text, r.caret); } }));
  }, [text, caret, modules, ui.disasmAt, ui.selected, ui.memSel]);

  const popKey = items.map((i) => i.key).join("|");
  const showPop = items.length > 0 && dismissed !== popKey;
  useEffect(() => { setSel(0); }, [popKey]);

  const chips = useMemo(() => parseMentions(text), [text]);

  const submit = () => {
    const t = text;
    if (!t.trim() || a.busy) return;
    setText("");
    setCaret(0);
    void a.submit(t);
  };

  const onKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (showPop) {
      if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => (s + 1) % items.length); return; }
      if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => (s - 1 + items.length) % items.length); return; }
      if (e.key === "Tab" || (e.key === "Enter" && !e.shiftKey)) {
        const it = items[sel];
        // Enter on a complete command runs it rather than re-completing it
        if (!(e.key === "Enter" && it && text.trim() === it.key)) { e.preventDefault(); it?.apply(); return; }
      }
      if (e.key === "Escape") { e.preventDefault(); setDismissed(popKey); return; }
    }
    if (e.key === "Escape" && a.busy) { e.preventDefault(); a.stop(); return; }
    if (e.key === "ArrowUp" && !text && !a.busy) { e.preventDefault(); a.editLast(); return; }
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); submit(); }
  };

  const removeChip = (tok: string) => {
    const re = new RegExp(`(^|\\s)${tok.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?=\\s|$)`, "g");
    setText((t) => t.replace(re, "$1").replace(/\s{2,}/g, " "));
  };

  return (
    <div className="panel-section as-input">
      {chips.length > 0 && (
        <div className="as-chips">
          {chips.map((m) => { const tok = mentionToken(m); return <span key={tok} className="as-chip mono" title="Attached when you send"><AtSign size={10} />{tok.slice(1)}<button aria-label={`Remove ${tok}`} onClick={() => removeChip(tok)}><X size={10} /></button></span>; })}
        </div>
      )}
      {showPop && (
        <div className="as-pop as-complete" role="listbox">
          {items.map((it, i) => (
            <div key={it.key} role="option" aria-selected={i === sel} className="as-complete-item" data-active={i === sel} onMouseDown={(e) => { e.preventDefault(); it.apply(); }} onMouseEnter={() => setSel(i)}>
              <span className="mono">{it.label}</span><span className="faint ellipsis">{it.detail}</span>
            </div>
          ))}
        </div>
      )}
      <div className="row as-input-row">
        <textarea
          ref={ta}
          className="input"
          rows={3}
          aria-label="Message the assistant"
          placeholder={placeholder}
          value={text}
          disabled={disabled}
          onChange={(e) => { setText(e.target.value); setCaret(e.target.selectionStart ?? e.target.value.length); setDismissed(null); }}
          onSelect={(e) => setCaret((e.target as HTMLTextAreaElement).selectionStart ?? 0)}
          onKeyDown={onKey}
        />
        <div className="as-input-side">
          {a.busy
            ? <button className="btn small" title="Stop (Esc)" onClick={() => a.stop()}><Square size={11} /> Stop</button>
            : <button className="btn small primary" title="Send (Enter)" disabled={disabled || !text.trim()} onClick={submit}><Send size={11} /> Send</button>}
          {text.length > 200 && <span className="faint as-est">~{estimateTokens(text)} tok</span>}
        </div>
      </div>
    </div>
  );
}
