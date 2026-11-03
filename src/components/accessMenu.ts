// "Find what writes / accesses this address" entries for the Memory view and Watchlist menus.
import { startTrace, type TraceKind } from "@/lib/debugger";
import { labelAddr } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import type { MenuItem } from "./ui";

export async function findAccesses(address: string, size: number, kind: TraceKind): Promise<void> {
  const r = await attempt("access finder", startTrace(address, size, kind));
  if (!r) return;
  const what = kind === "write" ? "writes" : "accesses";
  log("info", "access finder", `DR${r.slot} watches ${labelAddr(address, useConn.getState().modules)} (${r.watch.len} bytes at ${r.watch.address}): collecting what ${what} it${r.auto ? "; the debugger attached for it and detaches when the trace stops" : ""}`);
  useUi.getState().setTab("accesses");
}

export function accessMenuItems(address: string, size: number): MenuItem[] {
  const dbg = useConn.getState().debugger;
  const hint = dbg ? undefined : "needs a native debugger";
  return [
    { label: "Find what writes this address", onClick: () => void findAccesses(address, size, "write"), disabled: !dbg, hint },
    { label: "Find what accesses this address", onClick: () => void findAccesses(address, size, "access"), disabled: !dbg, hint },
  ];
}
