import { useConn } from "@/store/conn";
import { useUi } from "@/store/ui";

/** Module focused for PE / strings / functions; falls back to the main executable. */
export function useFocusedModule() {
  const { modules, target } = useConn();
  const name = useUi((s) => s.module);
  return modules.find((m) => m.name === name) ?? modules.find((m) => m.base === target?.base) ?? modules[0];
}

export default function ModulePicker() {
  const modules = useConn((s) => s.modules);
  const m = useFocusedModule();
  const set = useUi((s) => s.set);
  return (
    <select className="select" style={{ width: 220 }} value={m?.name ?? ""} onChange={(e) => set({ module: e.target.value })}>
      {modules.map((x) => <option key={x.base}>{x.name}</option>)}
    </select>
  );
}
