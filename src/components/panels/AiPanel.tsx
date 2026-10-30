import { Fragment, useEffect, useRef, useState } from "react";
import { Eraser, Send, Square } from "lucide-react";
import { chat, type ChatLine } from "@/lib/ai";
import { useUi } from "@/store/ui";
import { IconButton, Panel } from "../ui";

/** Tiny formatter: ``` fences, `inline code`, paragraphs. No HTML injection: everything is text nodes. */
function Rich({ text }: { text: string }) {
  const parts = text.split(/```[a-z0-9]*\n?/i);
  return (
    <>
      {parts.map((p, i) =>
        i % 2 === 1 ? <pre key={i}>{p.replace(/\n$/, "")}</pre> : p.split(/\n{2,}/).filter(Boolean).map((para, j) => (
          <p key={`${i}-${j}`}>{para.split(/(`[^`]+`)/).map((s, k) => (s.startsWith("`") && s.endsWith("`") && s.length > 1 ? <code key={k}>{s.slice(1, -1)}</code> : <Fragment key={k}>{s}</Fragment>))}</p>
        )),
      )}
    </>
  );
}

export default function AiPanel() {
  const ai = useUi((s) => s.ai);
  const set = useUi((s) => s.set);
  const [lines, setLines] = useState<ChatLine[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const history = useRef<unknown[]>([]);
  const abort = useRef<AbortController | null>(null);
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { end.current?.scrollIntoView({ block: "end" }); }, [lines.length]);

  const send = async () => {
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    setLines((l) => [...l, { role: "user", text }]);
    setBusy(true);
    abort.current = new AbortController();
    try {
      await chat(ai, history.current, text, (l) => setLines((x) => [...x, l]), abort.current.signal);
    } catch (e) {
      setLines((x) => [...x, { role: "assistant", text: `⚠ ${e instanceof Error ? e.message : String(e)}` }]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title={<>AI Assistant <span className="faint">{ai.model}</span></>}
      actions={<IconButton tip="New conversation" onClick={() => { history.current = []; setLines([]); }}><Eraser size={14} /></IconButton>}
    >
      <div className="panel-body">
        <div className="chat">
          {lines.length === 0 && (
            <div className="faint" style={{ fontSize: 12.5 }}>
              Ask about the attached process: "what does the function at game.exe+0x1234 do?", "find the string 'PlayerController' and its xrefs".
              {!ai.apiKey && <> <span className="link" onClick={() => set({ settingsOpen: true })}>Set an API key</span> first.</>}
            </div>
          )}
          {lines.map((l, i) => (
            <div key={i} className="msg" data-role={l.role}>{l.role === "tool" ? `→ ${l.text}` : <Rich text={l.text} />}</div>
          ))}
          {busy && <div className="faint">thinking…</div>}
          <div ref={end} />
        </div>
      </div>
      <div className="chat-input">
        <textarea className="textarea grow" rows={3} value={input} placeholder="Ask… (Enter to send, Shift+Enter for newline)" onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(); } }} />
        {busy ? <IconButton tip="Stop" onClick={() => abort.current?.abort()}><Square size={14} /></IconButton> : <IconButton tip="Send" onClick={() => void send()}><Send size={14} /></IconButton>}
      </div>
    </Panel>
  );
}
