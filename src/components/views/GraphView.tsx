// Call graph: the function under the cursor plus its direct callers and
// callees, drawn as a small SVG graph. Edges come from Echo's own
// disassembly, so they are exact.
//
// The module mode builds the same picture for every function of a module at
// once, from the mapped image, which is how a whole binary is surveyed. The
// CFG and Pseudocode modes look inside the function instead (CfgPanel).
import { useCallback, useEffect, useMemo, useState } from "react";
import { request } from "@/lib/client";
import { labelAddr, toBig } from "@/lib/hex";
import { xrefsTo } from "@/lib/live";
import { loadImage } from "@/lib/memory";
import { addEdge, addNode, calleesOf, layout, type CallGraph } from "@/lib/analysis/callgraph";
import { buildCallGraph } from "@/lib/analysis/graph";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { NeedsAgent } from "../ui";
import ModulePicker, { useFocusedModule } from "../ModulePicker";
import CfgPanel from "./CfgPanel";

type Line = { address: string; length: number; bytes: string; text: string };

const kMaxCallees = 48;

export default function GraphView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const names = useNames();
  const focused = useFocusedModule();
  const root = ui.disasmAt ?? ui.selected;
  const [mode, setMode] = useState<"function" | "module" | "cfg" | "pseudo">("function");
  const [graph, setGraph] = useState<CallGraph>({ nodes: [], edges: [], visited: [] });
  const [busy, setBusy] = useState(false);

  const build = useCallback(async () => {
    if (!root) return;
    setBusy(true);
    const g: CallGraph = { nodes: [], edges: [], visited: [] };
    const rootLabel = names.nameOf(root) || `sub_${toBig(root).toString(16)}`;
    addNode(g, root, rootLabel, "function", 0);

    const listing = await attempt("graph", request<{ results: Line[] }>("disassemble", { address: root, size: 0 }));
    if (!listing) {
      setBusy(false);
      return;
    }
    g.visited.push(root);

    // Callees: direct call targets of the root function.
    const callees = calleesOf(listing.results).slice(0, kMaxCallees);
    for (const c of callees) {
      addNode(g, c, names.nameOf(c) || `sub_${toBig(c).toString(16)}`, "function", 1);
      addEdge(g, root, c, "call");
    }

    // Callers: direct references into the root, found by scanning the module image.
    const refs = await attempt("graph", xrefsTo(root, modules));
    const callRefs = (refs ?? []).filter((x) => x.kind === "call").slice(0, kMaxCallees);
    for (const r of callRefs) {
      const from = "0x" + r.address.toString(16);
      addNode(g, from, names.nameOf(from) || `sub_${toBig(from).toString(16)}`, "unknown", 2);
      addEdge(g, from, root, "call");
    }

    setGraph(g);
    setBusy(false);
    log("info", "graph", `${callees.length} callees, ${callRefs.length} callers of ${labelAddr(root, modules)}`);
  }, [root, modules, names]);

  /** The whole module at once: every function, with the calls between them. */
  const buildModule = useCallback(async () => {
    if (!focused) return;
    setBusy(true);
    const fns = await attempt("graph", request<{ results: { address: string; size: number }[] }>("enumerate_functions", { module: focused.name }));
    if (!fns) { setBusy(false); return; }
    const img = await attempt("graph", loadImage(focused));
    if (!img) { setBusy(false); return; }
    const built = buildCallGraph(img, fns.results, toBig(focused.base), { maxDepth: 2, maxNodes: 900 });
    const g: CallGraph = { nodes: [], edges: [], visited: [] };
    for (const n of built.nodes) {
      addNode(g, n.address, names.nameOf(n.address) || n.label, n.kind === "function" ? "function" : "unknown", n.depth);
    }
    for (const e of built.edges) {
      if (e.kind === "rip") continue;
      addEdge(g, e.from, e.to, e.kind);
    }
    setGraph(g);
    setBusy(false);
    log("info", "graph", `${built.nodes.length} functions, ${built.edges.length} edges in ${focused.name}`);
  }, [focused, names]);

  useEffect(() => {
    if (mode === "module") void buildModule();
    else if (mode === "function") void build();
  }, [mode, build, buildModule]);

  const pos = useMemo(() => layout(graph), [graph]);

  const width = useMemo(() => {
    let max = 400;
    for (const p of pos.values()) max = Math.max(max, p.x + 180);
    return max;
  }, [pos]);
  const height = useMemo(() => {
    let max = 200;
    for (const p of pos.values()) max = Math.max(max, p.y + 30);
    return max;
  }, [pos]);

  if (!root && mode !== "module") {
    return (
      <NeedsAgent>
        <div className="empty">
          <div className="empty-title">No function selected.</div>
          <div className="empty-hint">Pick a function in the disassembly view, then open the Graph tab to see what it calls.</div>
        </div>
      </NeedsAgent>
    );
  }

  const modes = (
    <>
      <button className="btn small" data-active={mode === "function"} onClick={() => setMode("function")}>Function</button>
      <button className="btn small" data-active={mode === "module"} onClick={() => setMode("module")}>Module</button>
      <button className="btn small" data-active={mode === "cfg"} onClick={() => setMode("cfg")}>CFG</button>
      <button className="btn small" data-active={mode === "pseudo"} onClick={() => setMode("pseudo")}>Pseudocode</button>
    </>
  );

  if (root && (mode === "cfg" || mode === "pseudo")) {
    return (
      <NeedsAgent>
        <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
          <CfgPanel mode={mode} root={root} modes={modes} />
        </div>
      </NeedsAgent>
    );
  }

  return (
    <NeedsAgent>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          {modes}
          {mode === "module" && <ModulePicker />}
          <span className="mono faint ellipsis grow">
            {mode === "function" ? labelAddr(root ?? "", modules) : focused?.name} · {graph.nodes.length} nodes · {graph.edges.length} edges
          </span>
          <button className="btn small" disabled={busy} onClick={() => void (mode === "module" ? buildModule() : build())}>{busy ? "Building…" : "Rebuild"}</button>
        </div>
        <div className="vlist" style={{ overflow: "auto" }}>
          <svg width={width} height={height} style={{ display: "block" }}>
            <defs>
              <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                <path d="M0,0 L0,6 L7,3 z" fill="var(--text-faint)" />
              </marker>
            </defs>
            {graph.edges.map((e) => {
              const a = pos.get(e.from);
              const b = pos.get(e.to);
              if (!a || !b) return null;
              return (
                <line
                  key={`${e.from}->${e.to}:${e.kind}`}
                  x1={a.x + 170} y1={a.y + 9} x2={b.x} y2={b.y + 9}
                  stroke="var(--border)" strokeWidth={1}
                  markerEnd="url(#arrow)"
                />
              );
            })}
            {graph.nodes.map((n) => {
              const p = pos.get(n.address)!;
              const isRoot = n.depth === 0;
              return (
                <g key={n.address} transform={`translate(${p.x}, ${p.y})`} onClick={() => ui.goDisasm(n.address)} style={{ cursor: "pointer" }}>
                  <rect width={170} height={19} rx={3} fill={isRoot ? "var(--selection)" : "var(--bg-2)"} stroke="var(--border)" />
                  <text x={6} y={13} fill={isRoot ? "var(--accent)" : "var(--text-dim)"} fontSize={11.5} fontFamily="var(--font-mono)">
                    {n.label.length > 24 ? n.label.slice(0, 23) + "…" : n.label}
                  </text>
                </g>
              );
            })}
          </svg>
          <div className="panel-section">
            <div className="label">{mode === "module" ? "Functions" : "Callees"}</div>
            {graph.nodes.filter((n) => n.depth === (mode === "module" ? 0 : 1)).length === 0 ? (
              <div className="faint">{mode === "module" ? "No functions found in this module." : "No direct calls found in this function."}</div>
            ) : (
              <table className="table mono">
                <thead><tr><th>Target</th><th>Name</th></tr></thead>
                <tbody>
                  {graph.nodes.filter((n) => n.depth === (mode === "module" ? 0 : 1)).map((n) => (
                    <tr key={n.address} onClick={() => ui.goDisasm(n.address)}>
                      <td className="link">{labelAddr(n.address, modules)}</td>
                      <td className="faint">{n.label}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </NeedsAgent>
  );
}
