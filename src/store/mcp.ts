// MCP call policy (pushed to the relay, which enforces it) and the queue of calls waiting for the
// user's approval in "ask" mode.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { client, request } from "@/lib/client";

export type PolicyMode = "allow" | "ask" | "readonly";
export type Approval = { id: number; tool: string; verb: string; args: Record<string, unknown>; at: number; resolve: (ok: boolean) => void };

type McpStore = {
  mode: PolicyMode;
  allow: string[];
  deny: string[];
  audit: boolean;
  queue: Approval[];
  setPolicy: (p: Partial<Pick<McpStore, "mode" | "allow" | "deny" | "audit">>) => void;
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
      queue: [],
      setPolicy: (p) => {
        set(p);
        void pushPolicy();
      },
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
    { name: "echodebug.mcp", partialize: (s) => ({ mode: s.mode, allow: s.allow, deny: s.deny, audit: s.audit }) },
  ),
);

export async function pushPolicy(): Promise<void> {
  if (!client.connected) return;
  const { mode, allow, deny, audit } = useMcp.getState();
  await request("mcp_policy", { mode, allow, deny, audit }, true).catch(() => undefined);
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
