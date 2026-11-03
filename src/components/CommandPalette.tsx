// Ctrl+K / Ctrl+Shift+P command palette: one searchable list of every action in the app.
import { useEffect, useMemo, useRef, useState } from "react";
import { useUi, kTabs, kTabHints, kViewGroups, type Theme, type ViewGroup } from "@/store/ui";
import { togglePanel } from "@/lib/layout";
import { useConn } from "@/store/conn";
import { useUpdate } from "@/store/update";
import { openUrl } from "@/lib/tauri";
import { exportProjects, importProjects, useProjects } from "@/lib/projects";
import { saveText } from "@/lib/save";
import { redo, undo } from "@/lib/history";
import { log } from "@/store/output";

async function pickJson(): Promise<unknown> {
  const input = Object.assign(document.createElement("input"), { type: "file", accept: ".json,.edproj" });
  const { promise, resolve } = Promise.withResolvers<File | null>();
  input.onchange = () => resolve(input.files?.[0] ?? null);
  input.click();
  const f = await promise;
  return f ? JSON.parse(await f.text()) : null;
}

type Cmd = { id: string; label: string; group: string; hint?: string; run: () => void };

const kThemes: [Theme, string][] = [["obsidian", "Obsidian"], ["nord", "Nord"], ["blood-orange", "Blood Orange"]];

/** Subsequence match: "gsx" matches "Go to Signature". Returns a score, or -1. */
function fuzzy(needle: string, hay: string): number {
  if (!needle) return 0;
  const n = needle.toLowerCase();
  const h = hay.toLowerCase();
  let hi = 0;
  let score = 0;
  let streak = 0;
  for (const ch of n) {
    const at = h.indexOf(ch, hi);
    if (at < 0) return -1;
    score += at === hi ? 3 + streak : 1;
    streak = at === hi ? streak + 1 : 0;
    hi = at + 1;
  }
  return score + (h.startsWith(n) ? 20 : 0);
}

export default function CommandPalette() {
  const ui = useUi();
  const conn = useConn();
  const upd = useUpdate();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  const cmds = useMemo<Cmd[]>(() => {
    const out: Cmd[] = [];
    const groupOf = (id: string) => (Object.entries(kViewGroups) as [ViewGroup, { tabs: string[] }][]).find(([, g]) => g.tabs.includes(id))?.[0] ?? "View";
    for (const t of kTabs) out.push({ id: `tab:${t.id}`, label: t.label, group: `View · ${groupOf(t.id)}`, hint: kTabHints[t.id], run: () => ui.setTab(t.id) });
    out.push(
      { id: "views", label: "All views…", group: "View", hint: "Ctrl+Shift+V", run: () => ui.set({ viewsOpen: true }) },
      { id: "close-tab", label: "Close current tab", group: "View", hint: "Ctrl+W", run: () => ui.closeTab(ui.tab) },
      { id: "p-left", label: "Toggle side panel", group: "Panels", hint: "Ctrl+B", run: () => togglePanel("left") },
      { id: "p-scan", label: "Toggle scanner", group: "Panels", hint: "Ctrl+Alt+S", run: () => togglePanel("scanner") },
      { id: "p-out", label: "Toggle output", group: "Panels", hint: "Ctrl+J", run: () => togglePanel("output") },
      { id: "p-insp", label: "Toggle inspector", group: "Panels", hint: "Ctrl+Alt+I", run: () => togglePanel("inspector") },
      { id: "shortcuts", label: "Keyboard shortcuts", group: "App", hint: "F1", run: () => ui.set({ shortcutsOpen: true }) },
    );
    out.push(
      { id: "goto", label: "Go to address", group: "Navigate", hint: "Ctrl+G", run: () => ui.set({ gotoOpen: true }) },
      { id: "search", label: "Search everything (names, comments, bookmarks, signatures, types, exports, strings)", group: "Navigate", hint: "Ctrl+Shift+F", run: () => ui.set({ searchOpen: true }) },
      { id: "disasm", label: "Disassemble selection", group: "Navigate", run: () => ui.selected && ui.goDisasm(ui.selected) },
      { id: "memory", label: "Show selection in memory", group: "Navigate", run: () => ui.selected && ui.goMemory(ui.selected) },
      { id: "struct", label: "Show selection in struct view", group: "Navigate", run: () => ui.selected && ui.goStruct(ui.selected) },
      { id: "sig", label: "Make signature at selection", group: "Navigate", run: () => ui.selected && ui.goSig(ui.selected) },
      { id: "lift", label: "Lift / deobfuscate / devirtualize at selection", group: "Navigate", hint: "Lifter", run: () => ui.setTab("lifter") },
    );
    // Every loaded module is a jump target.
    for (const m of conn.modules) {
      out.push({
        id: `mod:${m.base}`,
        label: `Module: ${m.name}`,
        group: "Module",
        run: () => {
          ui.set({ module: m.name });
          ui.goDisasm(m.base);
        },
      });
    }
    out.push(
      { id: "attach", label: "Attach to a process", group: "Target", run: () => ui.setRail("targets") },
      { id: "detach", label: "Detach from target", group: "Target", run: () => void conn.detach() },
      { id: "modules", label: "Refresh module list", group: "Target", run: () => void conn.refreshModules() },
      { id: "watch", label: "Open watchlist", group: "Target", run: () => ui.setRail("watch") },
      { id: "names", label: "Open names & comments", group: "Target", run: () => ui.setRail("names") },
      { id: "mcp", label: "Open MCP server panel", group: "Target", run: () => ui.setRail("mcp") },
      { id: "export", label: "Export session to file", group: "Session", run: () => ui.set({ sessionExportOpen: true }) },
      { id: "undo", label: "Undo last name / comment / type edit", group: "Session", hint: "Ctrl+Z", run: () => log("info", "edit", `undo: ${undo() ?? "nothing"}`) },
      { id: "redo", label: "Redo", group: "Session", hint: "Ctrl+Y", run: () => log("info", "edit", `redo: ${redo() ?? "nothing"}`) },
      { id: "proj-export", label: "Export module projects (names, comments, bookmarks by RVA)", group: "Session", run: () => void saveText("echodebug-projects.edproj", JSON.stringify(exportProjects(), null, 1)) },
      { id: "proj-import", label: "Import module projects", group: "Session", run: () => void pickJson().then((f) => f && log("info", "project", `imported ${importProjects(f as never)} module projects`)).catch((e) => log("error", "project", String(e))) },
      { id: "proj-toggle", label: `${useProjects.getState().enabled ? "Disable" : "Enable"} automatic module projects`, group: "Session", run: () => useProjects.getState().setEnabled(!useProjects.getState().enabled) },
      { id: "import", label: "Import session from file", group: "Session", run: () => ui.set({ sessionImportOpen: true }) },
      { id: "settings", label: "Open settings", group: "App", run: () => ui.set({ settingsOpen: true }) },
      { id: "update", label: "Check for updates", group: "App", run: () => void upd.check({ manual: true }) },
      { id: "docs", label: "Open Echo API docs", group: "App", run: () => void openUrl("https://echo-23.gitbook.io/angel") },
      { id: "protocol", label: "Open protocol reference", group: "App", run: () => void openUrl("https://github.com/NetVar1337/EchoDebug/blob/main/PROTOCOL.md") },
      { id: "releases", label: "Open GitHub releases", group: "App", run: () => void openUrl("https://github.com/NetVar1337/EchoDebug/releases") },
    );
    for (const [id, label] of kThemes) out.push({ id: `theme:${id}`, label: `Theme: ${label}`, group: "App", run: () => ui.set({ theme: id }) });
    return out;
  }, [ui, conn, upd]);

  const shown = useMemo(() => {
    const scored = cmds
      .map((c) => ({ c, s: Math.max(fuzzy(q, c.label), c.hint && q.length > 2 && c.hint.toLowerCase().includes(q.toLowerCase()) ? 5 : -1) + (q ? Math.max(0, fuzzy(q, c.group)) * 0.25 : 0) }))
      .filter((x) => x.s >= 0)
      .sort((a, b) => b.s - a.s);
    return scored.slice(0, 60).map((x) => x.c);
  }, [cmds, q]);

  useEffect(() => setSel(0), [q]);

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key === "Escape") ui.set({ paletteOpen: false });
      else if (e.key === "ArrowDown") {
        e.preventDefault();
        setSel((s) => Math.min(shown.length - 1, s + 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSel((s) => Math.max(0, s - 1));
      } else if (e.key === "Enter") {
        const c = shown[sel];
        if (c) {
          ui.set({ paletteOpen: false });
          c.run();
        }
      }
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [shown, sel, ui]);

  useEffect(() => {
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const run = (c: Cmd) => {
    ui.set({ paletteOpen: false });
    c.run();
  };

  let lastGroup = "";
  return (
    <div className="modal-scrim" onMouseDown={(e) => e.target === e.currentTarget && ui.set({ paletteOpen: false })}>
      <div className="modal palette" role="dialog" aria-label="Command palette">
        <input
          autoFocus
          className="palette-input"
          placeholder="Type a command…"
          value={q}
          spellCheck={false}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              const c = shown[sel];
              if (c) run(c);
            } else if (e.key === "Escape") ui.set({ paletteOpen: false });
          }}
        />
        <div className="palette-list" ref={listRef}>
          {shown.length === 0 && <div className="empty-hint" style={{ padding: "var(--pad-md)" }}>No matching command.</div>}
          {shown.map((c, i) => {
            const head = c.group !== lastGroup ? c.group : null;
            lastGroup = c.group;
            return (
              <div key={c.id}>
                {head && <div className="palette-group">{head}</div>}
                <button className="palette-item" data-active={i === sel} onMouseEnter={() => setSel(i)} onClick={() => run(c)}>
                  <span className="grow ellipsis">{c.label}</span>
                  {c.hint && <span className="faint">{c.hint}</span>}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
