// shared primitives: panel chrome, tabs, empty states, small inputs
import { Component, type ReactNode, Suspense, useEffect, useState } from "react";
import { Check, Copy, PlugZap } from "lucide-react";
import { useConn } from "@/store/conn";

export function Panel({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {title !== undefined && (
        <div className="panel-head">
          <div className="panel-title">{title}</div>
          <div className="grow" />
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function Tabs<T extends string>({ tabs, active, onSelect, right }: { tabs: readonly { id: T; label: string }[]; active: T; onSelect: (t: T) => void; right?: ReactNode }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={active === t.id} className="tab" data-active={active === t.id} onClick={() => onSelect(t.id)}>
          {t.label}
        </button>
      ))}
      <div className="tab-spacer" />
      {right}
    </div>
  );
}

export function Empty({ icon, title, hint }: { icon?: ReactNode; title: string; hint?: ReactNode }) {
  return (
    <div className="empty">
      {icon && <div className="empty-glyph">{icon}</div>}
      <div className="empty-title">{title}</div>
      {hint && <div className="empty-hint">{hint}</div>}
    </div>
  );
}

/** Renders children only when a memory backend is up (Echo server on Windows, /proc on Linux). */
export function NeedsAgent({ children, ext = false }: { children: ReactNode; ext?: boolean }) {
  const { relay, agent, backend, ext: extUp, os } = useConn();
  if (!relay) return <Empty icon={<PlugZap size={26} strokeWidth={1.5} />} title="Relay not reachable." hint="The EchoDebug relay is not running. Restart the app or check the port in Settings." />;
  if (!agent && backend !== "local") {
    return os === "linux"
      ? <Empty icon={<PlugZap size={26} strokeWidth={1.5} />} title="No process attached." hint="Attach to a process from the Targets panel — on Linux the relay reads it via /proc (same user, or ptrace_scope=0)." />
      : <Empty icon={<PlugZap size={26} strokeWidth={1.5} />} title="Echo memory server not connected." hint="Load echo_debug.as in Echo, then attach to a process from the Targets panel." />;
  }
  if (ext && !extUp) return <Empty icon={<PlugZap size={26} strokeWidth={1.5} />} title="EchoDebug agent not connected." hint={os === "linux" ? "This feature needs the Windows Echo agent (write / freeze / emulate / pointer scan). The local Linux backend covers read, modules, sig/string scan, disassembly, scanner and writes." : "This view needs the echo_debug.as agent (write / scan / emulate verbs). Load it in Echo."} />;
  return <>{children}</>;
}

export function IconButton({ tip, onClick, children, disabled }: { tip: string; onClick: (e: React.MouseEvent<HTMLButtonElement>) => void; children: ReactNode; disabled?: boolean }) {
  return (
    <button className="icon-button" data-tip={tip} aria-label={tip} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}

/** Text input that only commits on Enter/blur, for address boxes. */
export function CommitInput({ value, onCommit, placeholder, className = "input mono", width }: { value: string; onCommit: (v: string) => void; placeholder?: string; className?: string; width?: number }) {
  const [v, setV] = useState(value);
  useEffect(() => { setV(value); }, [value]);
  return (
    <input
      className={className}
      style={width ? { width } : undefined}
      value={v}
      placeholder={placeholder}
      spellCheck={false}
      onChange={(e) => setV(e.target.value)}
      onKeyDown={(e) => e.key === "Enter" && onCommit(v)}
      onBlur={() => v !== value && onCommit(v)}
    />
  );
}

export function Progress({ value }: { value: number }) {
  return (
    <div className="progress">
      <div className="progress-fill" style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }} />
    </div>
  );
}

export async function copy(text: string): Promise<void> {
  await navigator.clipboard.writeText(text).catch(() => undefined);
}

export function useCopy(): [string | null, (text: string) => void] {
  const [copied, setCopied] = useState<string | null>(null);
  return [copied, (text) => {
    void navigator.clipboard?.writeText(text).catch(() => undefined);
    setCopied(text);
    setTimeout(() => setCopied((c) => (c === text ? null : c)), 1200);
  }];
}

export function CopyChip({ text, copied, onCopy }: { text: string; copied: string | null; onCopy: (t: string) => void }) {
  return (
    <button className="mono selectable chip" data-copied={copied === text} onClick={() => onCopy(text)} title="Copy">
      <span className="ellipsis">{text}</span>
      {copied === text ? <Check size={11} /> : <Copy size={11} />}
    </button>
  );
}

/** Suspense wrapper for React.lazy views / panels, styled like an empty state. */
export function Lazy({ children }: { children: ReactNode }) {
  return <Suspense fallback={<Empty title="Loading…" />}>{children}</Suspense>;
}

/** Keeps one broken view from blanking the whole window. */
export class Boundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (this.state.error)
      return <Empty title="This view crashed." hint={<><span className="mono">{this.state.error.message}</span> <span className="link" onClick={() => this.setState({ error: null })}>retry</span></>} />;
    return this.props.children;
  }
}
