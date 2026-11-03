// Disassembler sync state for the Sync panel, and the wiring between the relay's /sync hub and
// the app: the disassembly cursor follows the tools (and they follow it), names and comments
// travel both ways. Directions and the module map are kept here and pushed to the relay.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { client, request, type Frame } from "@/lib/client";
import { fmtAddr } from "@/lib/hex";
import { diffNames, fromModuleRva, onSyncEvent, structDecls, syncSend, toModuleRva, trailing } from "@/lib/sync";
import { useConn } from "./conn";
import { useNames } from "./names";
import { log } from "./output";
import { useTypes } from "./types";
import { useUi } from "./ui";

export type Direction = "cursor_in" | "cursor_out" | "names_in" | "names_out" | "comments_in" | "comments_out" | "types_out";
export type Directions = Record<Direction, boolean>;
export type SyncPeer = { id: number; tool: string; version: string; file: string; modules: { name: string; base?: string | null; size?: number | null; live: string }[]; connected_at: number; last_seen: number };
export type SyncLogEntry = { seq: number; ts: number; kind: string; dir: "in" | "out" | "conflict" | "info"; from: string; module: string; rva: string | null; text: string };
type Status = { peers: SyncPeer[]; directions: Directions; map: Record<string, string>; cursor: { module: string; rva: string; from: string } | null; log: SyncLogEntry[] };

export const kDefaultDirections: Directions = { cursor_in: true, cursor_out: true, names_in: true, names_out: true, comments_in: true, comments_out: true, types_out: true };

type SyncStore = {
  directions: Directions;
  /** disassembler module name (lowercase) → live module name */
  map: Record<string, string>;
  peers: SyncPeer[];
  log: SyncLogEntry[];
  cursor: Status["cursor"];
  setDirection: (d: Direction, on: boolean) => void;
  setMapping: (toolModule: string, live: string) => void;
  refresh: () => Promise<void>;
};

export const useSync = create<SyncStore>()(
  persist(
    (set, get) => ({
      directions: kDefaultDirections,
      map: {},
      peers: [],
      log: [],
      cursor: null,
      setDirection: (d, on) => {
        set({ directions: { ...get().directions, [d]: on } });
        void pushConfig();
      },
      setMapping: (toolModule, live) => {
        const map = { ...get().map };
        if (live) map[toolModule.toLowerCase()] = live;
        else delete map[toolModule.toLowerCase()];
        set({ map });
        void request("sync_config", { map: { [toolModule]: live } }, true).catch(() => undefined);
      },
      refresh: async () => {
        if (!client.connected) return;
        const r = await request<Status>("sync_status", { log_limit: 300 }, true).catch(() => null);
        if (r?.peers) set({ peers: r.peers, log: r.log ?? [], cursor: r.cursor ?? null });
      },
    }),
    { name: "echodebug.sync", partialize: (s) => ({ directions: s.directions, map: s.map }) },
  ),
);

async function pushConfig(): Promise<void> {
  if (!client.connected) return;
  const { directions, map } = useSync.getState();
  await request("sync_config", { directions, map, replace_map: true }, true).catch(() => undefined);
  await useSync.getState().refresh();
}

/** Struct catalog → every connected tool as C declarations. */
export async function pushTypes(): Promise<number> {
  const { decls, names } = structDecls(useTypes.getState().types);
  if (!names.length) throw new Error("the struct catalog has no named types with fields");
  return syncSend("types", { decls, names });
}

/** Every name and comment inside a loaded module → the tools (they missed what was named before they connected). */
export async function pushAllNames(): Promise<number> {
  const mods = useConn.getState().modules;
  let sent = 0;
  for (const n of useNames.getState().names) {
    const at = toModuleRva("0x" + n.address.replace(/^0x/, ""), mods);
    if (!at) continue;
    if (n.name) { await syncSend("name", { ...at, name: n.name }); sent++; }
    if (n.comment) { await syncSend("comment", { ...at, comment: n.comment }); sent++; }
  }
  return sent;
}

/** True while the app applies a frame from a tool, so the store subscriptions don't send it back. */
let applying = false;
/** the last address a tool moved us to: our own cursor update for it is not sent back */
let followed: string | null = null;
let started = false;

function note(text: string, extra: Record<string, unknown> = {}): void {
  void request("sync_log", { text, ...extra }, true).catch(() => undefined);
}

function onEvent(f: Frame): void {
  const s = useSync.getState();
  switch (f.kind) {
    case "log": {
      const e = f.entry as SyncLogEntry;
      useSync.setState({ log: [...s.log.slice(-299), e] });
      if (e.dir === "conflict") log("warn", "sync", e.text);
      return;
    }
    case "peers":
    case "config":
      void s.refresh();
      return;
    case "cursor": {
      const addr = fromModuleRva(String(f.module), String(f.rva), useConn.getState().modules);
      useSync.setState({ cursor: { module: String(f.module), rva: String(f.rva), from: String(f.from) } });
      if (addr === null) return;
      followed = fmtAddr(addr);
      useUi.getState().goDisasm(followed);
      return;
    }
    case "name":
    case "comment": {
      const kind = f.kind;
      const value = String(f[kind] ?? "");
      const addr = fromModuleRva(String(f.module), String(f.rva), useConn.getState().modules);
      if (addr === null) {
        note(`${kind} from ${f.from} at ${f.module}+${f.rva} not applied: module not loaded in the target`, { kind, module: f.module, rva: f.rva });
        return;
      }
      const names = useNames.getState();
      const a = fmtAddr(addr);
      const cur = kind === "name" ? names.nameOf(a) : names.commentOf(a);
      if (cur === value.trim()) return;
      if (cur) note(`${kind} '${cur}' in EchoDebug replaced by '${value}' from ${f.from} (last writer wins)`, { kind, dir: "conflict", module: f.module, rva: f.rva });
      applying = true;
      try {
        if (kind === "name") names.rename(a, value);
        else names.comment(a, value);
      } finally {
        applying = false;
      }
      return;
    }
  }
}

/** Wires the hub to the app; call once at boot. */
export function startSync(): void {
  if (started) return;
  started = true;
  onSyncEvent(onEvent);
  client.onState((up) => up && void pushConfig());
  void pushConfig();

  const sendCursor = trailing(80, (addr: string) => {
    const at = toModuleRva(addr, useConn.getState().modules);
    if (at) void syncSend("cursor", at).catch(() => undefined);
  });
  useUi.subscribe((st, prev) => {
    const at = st.selected ?? st.disasmAt;
    if (!at || at === (prev.selected ?? prev.disasmAt)) return;
    if (followed && at === followed) return;
    followed = null;
    if (useSync.getState().peers.length) sendCursor(at);
  });
  useNames.subscribe((st, prev) => {
    if (applying || st.names === prev.names || !useSync.getState().peers.length) return;
    const mods = useConn.getState().modules;
    for (const c of diffNames(prev.names, st.names)) {
      const at = toModuleRva(c.address, mods);
      if (!at) continue;
      if (c.name !== undefined) void syncSend("name", { ...at, name: c.name }).catch((e) => log("warn", "sync", String(e)));
      if (c.comment !== undefined) void syncSend("comment", { ...at, comment: c.comment }).catch((e) => log("warn", "sync", String(e)));
    }
  });
}
