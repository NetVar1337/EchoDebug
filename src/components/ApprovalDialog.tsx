// MCP policy "ask": approve or deny a tool call that would change the target (writes, freezes,
// attach/detach, dumps…). One dialog per queued call, oldest first; unanswered calls are denied.
import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { kApprovalTimeoutMs, useMcp } from "@/store/mcp";

export default function ApprovalDialog() {
  const queue = useMcp((s) => s.queue);
  const answer = useMcp((s) => s.answer);
  const setPolicy = useMcp((s) => s.setPolicy);
  const [now, setNow] = useState(Date.now());
  const a = queue[0];
  useEffect(() => {
    if (!a) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [a?.id]);
  if (!a) return null;
  const left = Math.max(0, Math.ceil((a.at + kApprovalTimeoutMs - now) / 1000));
  const args = JSON.stringify(a.args, null, 2);
  return (
    <div className="modal-scrim">
      <div className="modal" role="alertdialog" aria-label="Approve MCP tool call" style={{ width: 520 }}>
        <div className="modal-body">
          <div className="row"><ShieldAlert size={16} /><span className="label grow">An MCP client wants to run <span className="mono">{a.tool}</span></span>{queue.length > 1 && <span className="faint">+{queue.length - 1} more</span>}</div>
          <div className="faint" style={{ fontSize: 12 }}>This call changes the target (verb <span className="mono">{a.verb}</span>). The policy is set to ask (Settings → MCP). It is denied automatically in {left}s.</div>
          <pre className="mcp-result" style={{ maxHeight: 240 }}>{args.length > 4000 ? args.slice(0, 4000) + "…" : args}</pre>
          <div className="row">
            <button className="btn primary" autoFocus onClick={() => answer(a.id, true)}>Allow</button>
            <button className="btn" onClick={() => answer(a.id, false)}>Deny</button>
            <span className="grow" />
            <button className="btn small" title="Add this tool to the deny list" onClick={() => { setPolicy({ deny: [...new Set([...useMcp.getState().deny, a.tool])] }); answer(a.id, false); }}>Always deny {a.tool}</button>
          </div>
        </div>
      </div>
    </div>
  );
}
