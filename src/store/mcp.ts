// MCP call policy (pushed to the relay, which enforces it) and the queue of calls waiting for the
// user's approval in "ask" mode.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { client, request } from "@/lib/client";
import { kPresets, type PolicyMode, type PresetId } from "@/lib/mcppresets";

export type { PolicyMode };
export type Approval = { id: number; tool: string; verb: string; args: Record<string, unknown>; at: number; resolve: (ok: boolean) => void };

type McpStore = {
  mode: PolicyMode;
  allow: string[];
  deny: string[];
  audit: boolean;
  /** "ask": clients with form elicitation ask their own user; otherwise this window asks */
  elicit: boolean;
  /** the MCP panel's first-run card was dismissed */
  onboarded: boolean;
  queue: Approval[];
  setPolicy: (p: Partial<Pick<McpStore, "mode" | "allow" | "deny" | "audit" | "elicit">>) => void;
  /** a tool profile: its mode and allow/deny lists */
  applyPreset: (id: PresetId) => void;
  setOnboarded: (v: boolean) => void;
  enqueue: (a: Omit<Approval, "id" | "at">) => void;
  answer: (id: number, ok: boolean) => void;
};

let nextId = 1;
/** An unanswered prompt is denied after this long (the relay gives up at 120 s). */
export const kApprovalTimeoutMs = 100_000;

export const useMcp = create<McpStore>()(
  persist(
    (set, get) => ({
      mode: "allow",
      allow: [],
      deny: [],
      audit: false,
      elicit: true,
      onboarded: false,
      queue: [],
      setPolicy: (p) => {
        set(p);
        void pushPolicy();
      },
      applyPreset: (id) => {
        const p = kPresets.find((x) => x.id === id);
        if (p) get().setPolicy({ mode: p.policy.mode, allow: [...p.policy.allow], deny: [...p.policy.deny] });
      },
      setOnboarded: (v) => set({ onboarded: v }),
      enqueue: (a) => {
        const id = nextId++;
        set((s) => ({ queue: [...s.queue, { ...a, id, at: Date.now() }] }));
        setTimeout(() => get().answer(id, false), kApprovalTimeoutMs);
      },
      answer: (id, ok) => {
        const a = get().queue.find((x) => x.id === id);
        if (!a) return;
        set((s) => ({ queue: s.queue.filter((x) => x.id !== id) }));
        a.resolve(ok);
      },
    }),
    { name: "echodebug.mcp", partialize: (s) => ({ mode: s.mode, allow: s.allow, deny: s.deny, audit: s.audit, elicit: s.elicit, onboarded: s.onboarded }) },
  ),
);

export async function pushPolicy(): Promise<void> {
  if (!client.connected) return;
  const { mode, allow, deny, audit, elicit } = useMcp.getState();
  await request("mcp_policy", { mode, allow, deny, audit, elicit }, true).catch(() => undefined);
}

/** Pushes the policy whenever the relay connection comes up. */
export function startMcpPolicy(): void {
  client.onState((up) => up && void pushPolicy());
  void pushPolicy();
}

/** "a, b\nc" → ["a","b","c"] */
export function parseList(s: string): string[] {
  return [...new Set(s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean))];
}
