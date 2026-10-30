import { useEffect, useRef, useState } from "react";
import iconUrl from "@/assets/icon.png";
import { useUi, type TabId, type Theme } from "@/store/ui";
import { useUpdate } from "@/store/update";
import { openUrl } from "@/lib/tauri";
import { useConn } from "@/store/conn";

type Item = { label: string; run: () => void; checked?: boolean } | "sep";

const kRepo = "https://github.com/NetVar1337/EchoDebug";
const kTabs: [TabId, string][] = [
  ["disassembly", "Disassembly"], ["memory", "Memory"], ["structs", "Structs"], ["strings", "Strings"],
  ["pe", "PE Browser"], ["signatures", "Signatures"], ["pointers", "Pointers"], ["emulator", "Emulator"],
];
const kThemes: [Theme, string][] = [["obsidian", "Obsidian"], ["nord", "Nord"], ["blood-orange", "Blood Orange"]];

function Menu({ label, items }: { label: string; items: Item[] }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [open]);
  return (
    <div className="menu-root" ref={ref}>
      <button className="menu-button" data-open={open} onClick={() => setOpen(!open)}>{label}</button>
      {open && (
        <div className="menu-pop" role="menu">
          {items.map((it, i) =>
            it === "sep" ? <div key={i} className="menu-sep" /> : (
              <button key={i} role="menuitem" className="menu-item" data-checked={it.checked} onClick={() => { setOpen(false); it.run(); }}>
                {it.label}
              </button>
            ),
          )}
        </div>
      )}
    </div>
  );
}

export default function TopBar() {
  const ui = useUi();
  const upd = useUpdate();
  const target = useConn((s) => s.target);
  const version = useConn((s) => s.appVersion);
  return (
    <header className="topbar">
      <div className="brand"><img src={iconUrl} alt="" />EchoDebug</div>
      <Menu
        label="View"
        items={[
          ...kTabs.map(([id, label]) => ({ label, run: () => ui.setTab(id), checked: ui.tab === id })),
          "sep",
          { label: "Go to address…  Ctrl+G", run: () => ui.set({ gotoOpen: true }) },
          { label: "Settings…", run: () => ui.set({ settingsOpen: true }) },
        ]}
      />
      <Menu label="Theme" items={kThemes.map(([id, label]) => ({ label, run: () => ui.set({ theme: id }), checked: ui.theme === id }))} />
      <Menu
        label="Help"
        items={[
          upd.phase === "ready"
            ? { label: `Restart to update (v${upd.version})`, run: () => void upd.restart() }
            : { label: "Check for updates…", run: () => void upd.check({ manual: true }) },
          { label: "Releases", run: () => void openUrl(`${kRepo}/releases`) },
          { label: "Protocol reference", run: () => void openUrl(`${kRepo}/blob/main/PROTOCOL.md`) },
          { label: "Echo API docs", run: () => void openUrl("https://echo-23.gitbook.io/angel") },
          "sep",
          { label: `EchoDebug v${version}`, run: () => void openUrl(kRepo) },
        ]}
      />
      <div className="topbar-title">{target ? `${target.name ?? "target"} (${target.pid})` : ""}</div>
    </header>
  );
}
