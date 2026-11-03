// Right-click menu on an address (disassembly rows, names): a few built-in actions plus the
// address actions plugins registered.
import { useEffect } from "react";
import { create } from "zustand";
import { usePluginRegistry } from "@/lib/plugins/registry";
import { labelAddr } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { copy } from "./ui";

type MenuState = { at: { x: number; y: number; address: string } | null };
const useAddressMenu = create<MenuState>(() => ({ at: null }));

/** onContextMenu handler factory: `onContextMenu={addressMenu(addr)}`. */
export function addressMenu(address: string) {
  return (e: React.MouseEvent) => {
    e.preventDefault();
    useAddressMenu.setState({ at: { x: e.clientX, y: e.clientY, address } });
  };
}

export default function AddressMenu() {
  const at = useAddressMenu((s) => s.at);
  const actions = usePluginRegistry((s) => s.actions);
  const modules = useConn((s) => s.modules);
  useEffect(() => {
    if (!at) return;
    const close = () => useAddressMenu.setState({ at: null });
    const key = (e: KeyboardEvent) => e.key === "Escape" && close();
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", key);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", key);
      window.removeEventListener("blur", close);
    };
  }, [at]);
  if (!at) return null;
  const ui = useUi.getState();
  const a = at.address;
  const run = (f: () => unknown) => () => {
    useAddressMenu.setState({ at: null });
    void Promise.resolve().then(f).catch((e) => log("error", "plugin", e instanceof Error ? e.message : String(e)));
  };
  const shown = actions.filter((x) => {
    try {
      return !x.when || x.when(a);
    } catch {
      return false;
    }
  });
  return (
    <div className="menu-pop address-menu" role="menu" style={{ position: "fixed", left: Math.min(at.x, window.innerWidth - 240), top: Math.min(at.y, window.innerHeight - 40 - 26 * (shown.length + 4)) }} onMouseDown={(e) => e.stopPropagation()}>
      <div className="faint mono" style={{ fontSize: 11, padding: "2px 10px" }}>{labelAddr(a, modules)}</div>
      <button className="menu-item" onClick={run(() => copy(a))}>Copy address</button>
      <button className="menu-item" onClick={run(() => ui.goDisasm(a))}>Disassemble</button>
      <button className="menu-item" onClick={run(() => ui.goMemory(a))}>Show in memory</button>
      <button className="menu-item" onClick={run(() => ui.goSig(a))}>Make signature</button>
      {shown.length > 0 && <div className="menu-sep" />}
      {shown.map((x) => (
        <button key={x.key} className="menu-item" title={`from ${x.pluginName}`} onClick={run(() => x.run(a))}>{x.label}</button>
      ))}
    </div>
  );
}
