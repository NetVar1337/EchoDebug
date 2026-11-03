// F1 / Ctrl+/ : every keyboard shortcut in one place.
import { useEffect } from "react";
import { useUi } from "@/store/ui";

const kGroups: [string, [string, string][]][] = [
  ["Navigate", [["Ctrl+G", "Go to an address (module+0x… works)"], ["Ctrl+K · Ctrl+Shift+P", "Command palette"], ["Ctrl+Shift+F", "Search everything: names, comments, bookmarks, signatures, types, exports, strings"], ["Ctrl+Shift+V", "All views"], ["Ctrl+W", "Close the current tab"], ["Middle-click a tab", "Close it"], ["Mouse wheel over tabs", "Scroll the tab strip"]]],
  ["Panels", [["Ctrl+B", "Side panel (or click the active rail icon)"], ["Ctrl+Alt+S", "Scanner"], ["Ctrl+J", "Output"], ["Ctrl+Alt+I", "Inspector"]]],
  ["Edit", [["Ctrl+Z", "Undo a name / comment / type edit"], ["Ctrl+Y · Ctrl+Shift+Z", "Redo"]]],
  ["Disassembly", [["F3", "Next search match"], ["Enter · Shift+Enter", "In the go-to box: disassembly · memory"], ["Double-click", "Follow / edit"]]],
  ["Memory", [["Click · Shift+click", "Select · extend the selection"], ["Double-click a byte", "Edit it"]]],
  ["Help", [["F1 · Ctrl+/", "This list"], ["Esc", "Close a dialog or menu"]]],
];

export default function ShortcutsDialog() {
  const set = useUi((s) => s.set);
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && set({ shortcutsOpen: false });
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);
  return (
    <div className="modal-scrim" onMouseDown={(e) => e.target === e.currentTarget && set({ shortcutsOpen: false })}>
      <div className="modal" role="dialog" aria-label="Keyboard shortcuts" style={{ width: 640 }}>
        <div className="modal-body">
          <div className="label">Keyboard shortcuts</div>
          <div className="shortcut-grid">
            {kGroups.map(([g, rows]) => (
              <div key={g}>
                <div className="label faint">{g}</div>
                {rows.map(([k, d]) => (
                  <div key={k} className="shortcut-row">
                    <span className="row wrap" style={{ gap: 3 }}>
                      {/^[A-Z][a-z]*\+|^F\d|^Esc/.test(k)
                        ? k.split(" · ").map((x) => <span key={x} className="kbd">{x}</span>)
                        : <span className="faint">{k}</span>}
                    </span>
                    <span className="faint">{d}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
          <div className="faint" style={{ fontSize: 12 }}>On macOS, Cmd works wherever Ctrl is listed.</div>
        </div>
      </div>
    </div>
  );
}
