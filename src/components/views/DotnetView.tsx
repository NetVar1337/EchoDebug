// .NET / CLR assembly explorer: namespace -> type -> member tree, with the
// metadata parsed straight out of the loaded module image.
import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Search } from "lucide-react";
import { loadImage } from "@/lib/memory";
import { openMetadata, parseDotnet, type DotnetInfo, type DotnetMetadata, type DotnetType } from "@/lib/analysis/dotnet";
import { disassembleIl, formatIl, userStringRefs, type IlBody } from "@/lib/analysis/cil";
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
  const [img, setImg] = useState<Uint8Array | null>(null);
  const [md, setMd] = useState<DotnetMetadata | null>(null);
  const [il, setIl] = useState<{ name: string; rva: number; body: IlBody | null; error: string } | null>(null);
  const [pane, setPane] = useState<"type" | "strings">("type");
  const [usFilter, setUsFilter] = useState("");

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
      setImg(img);
      setMd(info ? openMetadata(img) : null);
      setIl(null);
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
  const showIl = (t: DotnetType, name: string, rva: number) => {
    if (!img || !md) return;
    try {
      setIl({ name: `${t.fullName}::${name}`, rva, body: disassembleIl(img, rva, md.tokenName), error: "" });
    } catch (e) {
      setIl({ name: `${t.fullName}::${name}`, rva, body: null, error: String(e instanceof Error ? e.message : e) });
    }
  };
  const refs = useMemo(() => (pane === "strings" && img && md ? userStringRefs(img, md.methods) : new Map()), [pane, img, md]);
  const strings = useMemo(() => {
    const f = usFilter.toLowerCase();
    return (md?.userStrings ?? []).filter((u) => !f || u.text.toLowerCase().includes(f));
  }, [md, usFilter]);

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
                    <div key={k.key} className="fn-row" data-selected={sel === k.key} onClick={() => {
                      setSel(k.key);
                      const mm = k.kind === "method" ? t.methods.find((x) => x.name === k.label) : undefined;
                      if (mm) { setPane("type"); showIl(t, mm.name, mm.rva); }
                    }} style={{ paddingLeft: 36 }}>
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
              <div className="toolbar">
                <button className="btn small" data-active={pane === "type"} onClick={() => setPane("type")}>Type & IL</button>
                <button className="btn small" data-active={pane === "strings"} onClick={() => setPane("strings")}>User strings ({md?.userStrings.length ?? 0})</button>
              </div>
              {pane === "strings" ? (
                <div className="panel-section">
                  <label className="search"><Search size={13} /><input placeholder="Filter strings…" value={usFilter} onChange={(e) => setUsFilter(e.target.value)} /></label>
                  <table className="table mono"><tbody>
                    {strings.slice(0, 3000).map((u) => {
                      const r = refs.get(u.token) ?? [];
                      return (
                        <tr key={u.token}>
                          <td className="ellipsis" title={u.text}>{JSON.stringify(u.text)}</td>
                          <td className="faint" style={{ width: "40%" }}>{r.length ? r.slice(0, 3).map((x: { method: string; offset: number }) => `${x.method}+IL_${x.offset.toString(16).padStart(4, "0")}`).join(", ") + (r.length > 3 ? ` +${r.length - 3}` : "") : "unreferenced"}</td>
                        </tr>
                      );
                    })}
                  </tbody></table>
                </div>
              ) : <>
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
                          <tr key={mm.name} onClick={() => showIl(typeOf(sel)!, mm.name, mm.rva)} onDoubleClick={() => ui.goMemory(addr)} title="click: IL · double-click: bytes in memory">
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
              {il && (
                <div className="panel-section">
                  <div className="label">IL · {il.name}</div>
                  {il.error ? <div className="faint">{il.error}</div> : il.body && (
                    <>
                      <div className="faint" style={{ fontSize: 12 }}>{il.body.headerSize === 1 ? "tiny" : "fat"} header · {il.body.codeSize} bytes · maxstack {il.body.maxStack}{il.body.localsToken ? ` · locals ${md?.tokenName(il.body.localsToken)}` : ""}</div>
                      <pre className="mcp-result" style={{ maxHeight: "none" }}>{formatIl(il.body).join("\n")}</pre>
                    </>
                  )}
                </div>
              )}
              </>}
            </div>
          )}
        </div>
      </div>
    </NeedsAgent>
  );
}
