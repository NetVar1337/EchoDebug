// Frameless title bar: brand, dropdown menus, drag region and window buttons.
// The window is undecorated (tauri.conf.json -> decorations: false), so the
// controls here replace the OS caption buttons.
import { useEffect, useRef, useState } from "react";
import { Minus, Square, X } from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import iconUrl from "@/assets/icon.png";
import { useUi, kTabs, type Theme } from "@/store/ui";
import { useUpdate } from "@/store/update";
import { useConn } from "@/store/conn";
import { openUrl } from "@/lib/tauri";

type MenuName = "File" | "View" | "Window" | "Theme" | "Help";
type Item = { label: string; hint?: string; run: () => void; checked?: boolean } | "sep";

const kRepo = "https://github.com/NetVar1337/EchoDebug";
const kThemes: [Theme, string][] = [["obsidian", "Obsidian"], ["nord", "Nord"], ["blood-orange", "Blood Orange"]];

async function windowAction(action: "minimize" | "toggleMaximize" | "close") {
  try {
    const win = getCurrentWindow();
    if (action === "minimize") await win.minimize();
    else if (action === "toggleMaximize") await win.toggleMaximize();
    else await win.close();
  } catch {
    // Running in a plain browser (npm run dev): there is no window to drive.
  }
}

export default function TitleBar() {
  const ui = useUi();
  const upd = useUpdate();
  const target = useConn((s) => s.target);
  const version = useConn((s) => s.appVersion);
  const [open, setOpen] = useState<MenuName | null>(null);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(null);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(null);
    window.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const menu = (name: MenuName, items: Item[]) => (
    <div className="menu-root" key={name}>
      <button className="menu-button" data-open={open === name} onClick={() => setOpen(open === name ? null : name)}>
        {name}
      </button>
      {open === name && (
        <div className="menu-pop" role="menu">
          {items.map((it, i) =>
            it === "sep" ? (
              <div key={i} className="menu-sep" />
            ) : (
              <button key={i} role="menuitem" className="menu-item" data-checked={it.checked} onClick={() => { setOpen(null); it.run(); }}>
                <span className="grow ellipsis">{it.label}</span>
                {it.hint && <span className="faint menu-hint">{it.hint}</span>}
              </button>
            ),
          )}
        </div>
      )}
    </div>
  );

  return (
    <header className="titlebar" ref={root}>
      <div className="brand"><img src={iconUrl} alt="" />EchoDebug</div>
      {menu("File", [
        { label: "Go to address…", hint: "Ctrl+G", run: () => ui.set({ gotoOpen: true }) },
        { label: "Command palette…", hint: "Ctrl+Shift+P", run: () => ui.set({ paletteOpen: true }) },
        "sep",
        { label: "Export session…", run: () => ui.set({ sessionExportOpen: true }) },
        { label: "Import session…", run: () => ui.set({ sessionImportOpen: true }) },
        "sep",
        { label: "Exit", hint: "Alt+F4", run: () => void windowAction("close") },
      ])}
      {menu("View", [
        ...kTabs.map((t) => ({ label: t.label, run: () => ui.setTab(t.id), checked: ui.tab === t.id })),
        "sep",
        { label: "Go to address…", hint: "Ctrl+G", run: () => ui.set({ gotoOpen: true }) },
        { label: "Command palette…", hint: "Ctrl+Shift+P", run: () => ui.set({ paletteOpen: true }) },
        { label: "Settings…", run: () => ui.set({ settingsOpen: true }) },
      ])}
      {menu("Window", [
        { label: "Minimize", run: () => void windowAction("minimize") },
        { label: "Maximize / restore", run: () => void windowAction("toggleMaximize") },
        "sep",
        { label: "Reload interface", run: () => window.location.reload() },
      ])}
      {menu("Theme", kThemes.map(([id, label]) => ({ label, run: () => ui.set({ theme: id }), checked: ui.theme === id })))}
      {menu("Help", [
        upd.phase === "ready"
          ? { label: `Restart to update (v${upd.version})`, run: () => void upd.restart() }
          : { label: "Check for updates…", run: () => void upd.check({ manual: true }) },
        { label: "Releases", run: () => void openUrl(`${kRepo}/releases`) },
        { label: "Protocol reference", run: () => void openUrl(`${kRepo}/blob/main/PROTOCOL.md`) },
        { label: "Echo API docs", run: () => void openUrl("https://echo-23.gitbook.io/angel") },
        "sep",
        { label: `EchoDebug v${version}`, run: () => void openUrl(kRepo) },
      ])}
      <div className="titlebar-drag" data-tauri-drag-region />
      <div className="topbar-title">{target ? `${target.name ?? "target"} (${target.pid})` : ""}</div>
      <div className="win-controls">
        <button className="win-button" data-tip="Minimize" aria-label="Minimize" onClick={() => void windowAction("minimize")}><Minus size={14} /></button>
        <button className="win-button" data-tip="Maximize / restore" aria-label="Maximize" onClick={() => void windowAction("toggleMaximize")}><Square size={11} /></button>
        <button className="win-button" data-close="true" data-tip="Close" aria-label="Close" onClick={() => void windowAction("close")}><X size={14} /></button>
      </div>
    </header>
  );
}
