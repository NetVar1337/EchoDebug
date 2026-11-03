// TLS callbacks and structured exception handlers of a PE module, read statically from the loaded
// image (TLS directory; .pdata + UNWIND_INFO handler RVAs and C scope tables). Every backend.
import { Fragment, useEffect, useMemo, useState } from "react";
import { fmtAddr } from "@/lib/hex";
import { sehReport, tlsReport } from "@/lib/threadslive";
import { useNames } from "@/store/names";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

type Tls = Awaited<ReturnType<typeof tlsReport>>;
type Seh = Awaited<ReturnType<typeof sehReport>>;

export default function HandlersView() {
  const m = useFocusedModule();
  const ui = useUi();
  useNames((s) => s.names);
  const [tls, setTls] = useState<Tls | null>(null);
  const [seh, setSeh] = useState<Seh | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const [notPe, setNotPe] = useState("");

  const load = async () => {
    if (!m) return;
    setBusy(true);
    const [t, s] = await Promise.allSettled([tlsReport(m), sehReport(m)]);
    const fail = [t, s].find((x) => x.status === "rejected");
    const why = fail ? String(fail.reason instanceof Error ? fail.reason.message : fail.reason) : "";
    // ELF / Mach-O modules have neither a TLS directory nor .pdata
    setNotPe(/MZ header|PE signature|optional header/.test(why) ? m.name : "");
    if (why && !/MZ header|PE signature|optional header/.test(why)) log("error", "tls/seh", `${m.name}: ${why}`);
    setTls(t.status === "fulfilled" ? t.value : null);
    setSeh(s.status === "fulfilled" ? s.value : null);
    setOpen(null);
    setBusy(false);
  };
  useEffect(() => { void load(); }, [m?.name, m?.base]); // eslint-disable-line react-hooks/exhaustive-deps

  const at = (rva: number) => (seh ? fmtAddr(seh.base + BigInt(rva)) : "");
  const nameOf = useNames((s) => s.nameOf);
  const rows = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return (seh?.handlers ?? []).filter((h) => !f || h.address.includes(f) || (h.handlerName ?? "").toLowerCase().includes(f) || h.kindLabel.toLowerCase().includes(f) || nameOf(h.address).toLowerCase().includes(f));
  }, [seh, filter, nameOf]);

  return (
    <NeedsAgent>
      <div className="vlist">
        <div className="toolbar">
          <ModulePicker />
          <button className="btn small" disabled={busy || !m} onClick={() => void load()}>Reload</button>
          {busy && <span className="faint">reading the image…</span>}
        </div>
        {notPe && <div className="empty"><div className="empty-title">{notPe} is not a PE module.</div><div className="empty-hint">TLS callbacks and .pdata exception handlers are Windows PE structures. Pick a PE module, or use the Threads view for call stacks of ELF code (.eh_frame).</div></div>}

        {!notPe && <div className="panel-section">
          <div className="label">TLS callbacks <span className="faint">(run before the entry point, and on every thread attach / detach)</span></div>
          {tls && !tls.directory && <div className="faint">no TLS directory</div>}
          {tls?.directory && tls.callbacks.length === 0 && <div className="faint">TLS directory without callbacks (index {tls.directory.index})</div>}
          {tls && tls.callbacks.length > 0 && (
            <table className="table mono"><thead><tr><th style={{ width: 40 }}>#</th><th style={{ width: 170 }}>address</th><th>name</th><th style={{ width: 200 }}>where</th></tr></thead><tbody>
              {tls.callbacks.map((c) => (
                <tr key={c.index}>
                  <td className="faint">{c.index}</td>
                  <td className="link" onClick={() => ui.goDisasm(c.address)}>{c.address}</td>
                  <td className="ellipsis">{c.name ?? <span className="faint">{c.label}</span>}</td>
                  <td className={c.inModule && c.executable ? "faint" : "danger"}>{c.inModule ? `${c.section ?? "?"}${c.executable ? "" : " (not executable)"}` : "outside the module"}</td>
                </tr>
              ))}
            </tbody></table>
          )}
        </div>}

        {!notPe && <div className="panel-section">
          <div className="label">Exception handlers <span className="faint">(.pdata + UNWIND_INFO)</span></div>
          {seh && (
            <>
              <div className="faint">{seh.functions} functions with unwind info{seh.chained ? `, ${seh.chained} chained fragments` : ""}; {seh.handlers.length} with a language handler</div>
              {seh.routines.length > 0 && (
                <table className="table mono"><thead><tr><th style={{ width: 170 }}>handler</th><th>routine</th><th style={{ width: 220 }}>kind</th><th style={{ width: 90 }}>functions</th></tr></thead><tbody>
                  {seh.routines.map((r) => (
                    <tr key={r.rva}>
                      <td className="link" onClick={() => ui.goDisasm(r.address)}>{r.address}</td>
                      <td className="ellipsis">{r.name ?? <span className="faint">unnamed</span>}</td>
                      <td>{r.kindLabel}</td>
                      <td className="link" onClick={() => setFilter(r.name ?? r.address)}>{r.count}</td>
                    </tr>
                  ))}
                </tbody></table>
              )}
              {seh.handlers.length > 0 && (
                <>
                  <input className="input" placeholder="filter by address, handler or kind" value={filter} onChange={(e) => setFilter(e.target.value)} />
                  <table className="table mono"><thead><tr><th style={{ width: 170 }}>function</th><th>name</th><th style={{ width: 150 }}>flags</th><th style={{ width: 220 }}>handler</th><th style={{ width: 70 }}>scopes</th></tr></thead><tbody>
                    {rows.slice(0, 3000).map((h) => (
                      <Fragment key={h.begin}>
                        <tr data-selected={open === h.begin}>
                          <td className="link" onClick={() => ui.goDisasm(h.address)}>{h.address}</td>
                          <td className="ellipsis">{nameOf(h.address) || <span className="faint">size 0x{(h.end - h.begin).toString(16)}</span>}</td>
                          <td className="faint">{h.flags.join(" ")}</td>
                          <td className="ellipsis link" onClick={() => ui.goDisasm(h.handlerAddress)}>{h.handlerName ?? h.handlerAddress}</td>
                          <td>{h.scopes?.length ? <span className="link" onClick={() => setOpen(open === h.begin ? null : h.begin)}>{h.scopes.length}{h.scopesHeuristic ? "?" : ""}</span> : <span className="faint">—</span>}</td>
                        </tr>
                        {open === h.begin && h.scopes?.map((s, i) => (
                          <tr key={`${h.begin}:${i}`}>
                            <td colSpan={5} className="faint">
                              {"  "}__try <span className="link" onClick={() => ui.goDisasm(at(s.begin))}>{at(s.begin)}</span>…{at(s.end)}{" "}
                              {s.kind === "finally"
                                ? <>__finally <span className="link" onClick={() => ui.goDisasm(at(s.handler))}>{at(s.handler)}</span></>
                                : <>__except({s.filter === "rva" ? <span className="link" onClick={() => ui.goDisasm(at(s.handler))}>filter {at(s.handler)}</span> : s.filter === "EXCEPTION_EXECUTE_HANDLER" ? "EXCEPTION_EXECUTE_HANDLER" : s.handler}) → <span className="link" onClick={() => ui.goDisasm(at(s.target))}>{at(s.target)}</span></>}
                              {h.scopesHeuristic ? " (scope table guessed: handler not identified)" : ""}
                            </td>
                          </tr>
                        ))}
                      </Fragment>
                    ))}
                  </tbody></table>
                </>
              )}
            </>
          )}
          <div className="faint" style={{ fontSize: 12 }}>
            Vectored handlers (AddVectoredExceptionHandler) are not listed: ntdll keeps them in a private list (LdrpVectorHandlerList) with pointers encoded by a per-process cookie, so they cannot be enumerated reliably without undocumented internals.
          </div>
        </div>}
      </div>
    </NeedsAgent>
  );
}
