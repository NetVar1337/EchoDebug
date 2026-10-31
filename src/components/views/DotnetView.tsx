// .NET / CLR assembly explorer: namespace -> type -> member tree, with the
// metadata parsed straight out of the loaded module image.
import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Search } from "lucide-react";
import { loadImage } from "@/lib/memory";
import { parseDotnet, type DotnetInfo, type DotnetType } from "@/lib/analysis/dotnet";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent, Progress } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";

type Node = { key: string; label: string; kind: "ns" | "type" | "method" | "field"; type?: DotnetType };

export default function DotnetView() {
  const m = useFocusedModule();
  const ui = useUi();
  const [info, setInfo] = useState<DotnetInfo | null>(null);
  const [progress, setProgress] = useState(1);
  const [filter, setFilter] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [sel, setSel] = useState<string | null>(null);

  useEffect(() => {
    if (!m) return;
    let live = true;
    setInfo(null);
    setProgress(0);
    void attempt("dotnet", loadImage(m, (d, t) => live && setProgress(d / t))).then((img) => {
      if (!live || !img) return;
      setProgress(1);
      const info = parseDotnet(img);
      setInfo(info);
      log("info", "dotnet", info ? `${info.types.length} types in ${m.name}` : `${m.name} is not a managed assembly`);
    });
    return () => { live = false; };
  }, [m?.name, m?.base]);

  const tree = useMemo(() => {
    if (!info) return [] as Node[];
    const f = filter.toLowerCase();
    const byNs = new Map<string, DotnetType[]>();
    for (const t of info.types) {
      if (f && !t.fullName.toLowerCase().includes(f)) continue;
      const ns = t.namespace || "(global)";
      const list = byNs.get(ns) ?? [];
      list.push(t);
      byNs.set(ns, list);
    }
    const out: Node[] = [];
    for (const ns of [...byNs.keys()].sort()) {
      out.push({ key: `ns:${ns}`, label: ns, kind: "ns" });
      for (const t of byNs.get(ns)!) out.push({ key: `t:${t.fullName}`, label: t.name, kind: "type", type: t });
    }
    return out;
  }, [info, filter]);

  const toggle = (key: string) =>
    setExpanded((s) => {
      const n = new Set(s);
      if (n.has(key)) n.delete(key);
      else n.add(key);
      return n;
    });

  const typeOf = (key: string) => info?.types.find((t) => `t:${t.fullName}` === key);

  return (
    <NeedsAgent>
      <div className="split-h" style={{ ["--fn-w" as string]: "340px" }}>
        <div className="list-col">
          <div className="toolbar">
            <ModulePicker />
            <label className="search grow"><Search size={13} /><input placeholder="Filter types…" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
          </div>
          {progress < 1 && <Progress value={progress} />}
          <div className="vlist">
            {info === null && progress >= 1 && <div className="panel-section faint">Not a managed (.NET) assembly.</div>}
            {tree.map((n) => {
              const open = expanded.has(n.key);
              if (n.kind === "ns") {
                return (
                  <div key={n.key} className="fn-row" onClick={() => toggle(n.key)}>
                    {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    <span className="grow ellipsis" style={{ color: "var(--text)" }}>{n.label}</span>
                  </div>
                );
              }
              const t = n.type!;
              const kids: Node[] = [
                ...t.methods.map((mm) => ({ key: `${n.key}:m:${mm.name}`, label: mm.name, kind: "method" as const, type: t })),
                ...t.fields.map((ff) => ({ key: `${n.key}:f:${ff.name}`, label: ff.name, kind: "field" as const, type: t })),
              ];
              return (
                <div key={n.key}>
                  <div className="fn-row" data-selected={sel === n.key} onClick={() => { setSel(n.key); toggle(n.key); }} style={{ paddingLeft: 16 }}>
                    {kids.length ? (open ? <ChevronDown size={12} /> : <ChevronRight size={12} />) : <span style={{ width: 12 }} />}
                    <span className="grow ellipsis" style={{ color: "var(--text)" }} title={t.fullName}>{t.name}</span>
                    <span className="faint">{t.methods.length}m</span>
                  </div>
                  {open && kids.map((k) => (
                    <div key={k.key} className="fn-row" data-selected={sel === k.key} onClick={() => setSel(k.key)} style={{ paddingLeft: 36 }}>
                      <span className="faint" style={{ width: 14 }}>{k.kind === "method" ? "M" : "F"}</span>
                      <span className="grow ellipsis">{k.label}</span>
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </div>
        <div className="list-col" style={{ borderRight: "none" }}>
          {!info ? (
            <div className="empty"><div className="empty-title">No CLR metadata.</div><div className="empty-hint">This module is not a managed assembly, or it has no CLR header.</div></div>
          ) : (
            <div className="vlist">
              <div className="panel-section">
                <div className="label">Assembly</div>
                <div className="kv">
                  <span>runtime</span><span>{info.runtimeVersion}</span>
                  <span>metadata</span><span>{info.metadataVersion}</span>
                  <span>types</span><span>{info.types.length}</span>
                  <span>entry token</span><span>{info.entryPointToken ? `0x${info.entryPointToken.toString(16)}` : "—"}</span>
                </div>
              </div>
              {sel && typeOf(sel) && (
                <div className="panel-section">
                  <div className="label">{typeOf(sel)!.fullName}</div>
                  <div className="faint" style={{ fontSize: 12 }}>base: {typeOf(sel)!.baseType || "—"}</div>
                  <table className="table mono">
                    <thead><tr><th>Method</th><th>RVA</th><th>Address</th></tr></thead>
                    <tbody>
                      {typeOf(sel)!.methods.map((mm) => {
                        const base = m ? BigInt(m.base) : 0n;
                        const addr = "0x" + (base + BigInt(mm.rva)).toString(16);
                        return (
                          <tr key={mm.name} onClick={() => ui.goDisasm(addr)}>
                            <td className="link">{mm.name}</td>
                            <td className="faint">0x{mm.rva.toString(16)}</td>
                            <td className="dim">{addr}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
