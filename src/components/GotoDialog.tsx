import { useState } from "react";
import { fmtAddr, parseAddress } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { useUi } from "@/store/ui";

export default function GotoDialog() {
  const modules = useConn((s) => s.modules);
  const ui = useUi();
  const [v, setV] = useState("");
  const addr = parseAddress(v, modules);
  const go = (where: "disasm" | "memory" | "struct") => {
    if (addr === null) return;
    const a = fmtAddr(addr);
    ui.set({ gotoOpen: false });
    if (where === "disasm") ui.goDisasm(a);
    else if (where === "memory") ui.goMemory(a);
    else ui.goStruct(a);
  };
  return (
    <div className="modal-scrim" onMouseDown={(e) => e.target === e.currentTarget && ui.set({ gotoOpen: false })}>
      <div className="modal" role="dialog" aria-label="Go to address" style={{ width: 460 }}>
        <div className="modal-body">
          <div className="label">Go to address</div>
          <input
            autoFocus
            className="input mono"
            placeholder="0x7ff6… · game.exe+0x1234"
            value={v}
            spellCheck={false}
            onChange={(e) => setV(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") go(e.shiftKey ? "memory" : "disasm");
              if (e.key === "Escape") ui.set({ gotoOpen: false });
            }}
          />
          <div className="row">
            <span className="mono faint grow">{addr === null ? (v ? "unparseable" : "") : fmtAddr(addr)}</span>
            <button className="btn primary" disabled={addr === null} onClick={() => go("disasm")}>Disassembly</button>
            <button className="btn" disabled={addr === null} onClick={() => go("memory")}>Memory</button>
            <button className="btn" disabled={addr === null} onClick={() => go("struct")}>Struct</button>
          </div>
        </div>
      </div>
    </div>
  );
}
