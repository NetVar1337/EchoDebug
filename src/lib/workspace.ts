// Workspace restore: splitter sizes, the last place in each view (module + RVA, so it survives
// ASLR) and, when enabled, reattaching to the last target by name.
import { request } from "./client";
import { fmtAddr, moduleOf, toBig } from "./hex";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";

const kViews = [["disasm", "disasmAt"], ["memory", "memoryAt"], ["struct", "structAt"]] as const;

export function applyLayout(root: HTMLElement): void {
  for (const [k, v] of Object.entries(useUi.getState().layout)) root.style.setProperty(k, v);
}

let started = false;

export function startWorkspace(): void {
  if (started) return;
  started = true;
  let restoredFor = -1;
  // remember places
  useUi.subscribe((s, prev) => {
    const mods = useConn.getState().modules;
    for (const [view, field] of kViews) {
      const at = s[field];
      if (!at || at === prev[field]) continue;
      const m = moduleOf(toBig(at), mods);
      if (m) useUi.getState().set({ places: { ...useUi.getState().places, [view]: { module: m.name, rva: Number(toBig(at) - toBig(m.base)) } } });
    }
  });
  // restore them once per target, when its modules are known
  useConn.subscribe((s, prev) => {
    if (s.target?.name && s.target.name !== useUi.getState().lastTarget) {
      const name = s.target.name;
      useUi.getState().set({ lastTarget: name, recentTargets: [name, ...useUi.getState().recentTargets.filter((x) => x.toLowerCase() !== name.toLowerCase())].slice(0, 8) });
    }
    if (s.modules === prev.modules || !s.modules.length || !s.target || restoredFor === s.target.pid) return;
    restoredFor = s.target.pid;
    const ui = useUi.getState();
    const patch: Record<string, string> = {};
    for (const [view, field] of kViews) {
      const p = ui.places[view];
      if (!p || ui[field]) continue;
      const m = s.modules.find((x) => x.name.toLowerCase() === p.module.toLowerCase());
      if (m && p.rva < m.size) patch[field] = fmtAddr(toBig(m.base) + BigInt(p.rva));
    }
    if (Object.keys(patch).length) ui.set(patch);
  });
  // reattach by name
  const tryReattach = async () => {
    const ui = useUi.getState();
    const c = useConn.getState();
    if (!ui.reattach || !ui.lastTarget || c.target || !(c.ext || c.localAvailable)) return;
    const r = await request<{ processes: { pid: number; name: string }[] }>("processes").catch(() => null);
    const p = r?.processes.find((x) => x.name.toLowerCase() === ui.lastTarget!.toLowerCase());
    if (!p) return log("info", "workspace", `${ui.lastTarget} is not running; not reattaching`);
    await c.attach({ pid: p.pid }).catch((e) => log("warn", "workspace", `reattach failed: ${e}`));
  };
  let tried = false;
  useConn.subscribe((s) => {
    if (!tried && s.relay && (s.ext || s.localAvailable)) {
      tried = true;
      void tryReattach();
    }
  });
}
