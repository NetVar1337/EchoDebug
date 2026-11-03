// The assistant panel's state: the transcript, the conversation sent to the Messages API, the
// tool-use loop (read-only tools only), and the review lists for suggested names and fields.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import * as api from "@/lib/assistant/api";
import { MessageAccumulator, echoContent, toolsMayRun, type Block, type Usage } from "@/lib/assistant/stream";
import { runTool } from "@/lib/assistant/exec";
import { functionContext, moduleContext, structContext } from "@/lib/assistant/context";
import {
  applyFieldAt, buildRequest, explainFunctionPrompt, kDefaultModel, kModels, parseNameSuggestions, parseStructFields, suggestNamesPrompt,
  suggestStructPrompt, summariseModulePrompt, type Effort, type FieldSuggestion, type Msg, type NameSuggestion,
} from "@/lib/assistant/prompts";
import { useNames } from "./names";
import { useStructCtx } from "./structctx";
import { useUi } from "./ui";
import { log } from "./output";

export type Entry =
  | { kind: "user"; id: string; text: string; /** short title for a generated prompt; the full text is expandable */ title?: string }
  | { kind: "assistant"; id: string; blocks: Block[]; model: string; streaming: boolean; usage?: Usage }
  | { kind: "tool"; id: string; name: string; input: unknown; result?: string; isError?: boolean; running: boolean }
  | { kind: "note"; id: string; text: string; level: "info" | "warn" | "error" };

type AssistantStore = {
  model: string;
  effort: Effort;
  entries: Entry[];
  messages: Msg[];
  busy: boolean;
  names: NameSuggestion[];
  fields: FieldSuggestion[];
  /** struct address the field suggestions were made for */
  fieldsFor: string | null;
  keyInfo: api.KeyInfo | null;
  set: (p: Partial<Pick<AssistantStore, "model" | "effort">>) => void;
  refreshKey: () => Promise<void>;
  send: (text: string, title?: string) => Promise<void>;
  stop: () => void;
  clear: () => void;
  explainFunction: () => Promise<void>;
  suggestNames: () => Promise<void>;
  suggestFields: () => Promise<void>;
  summariseModule: (name?: string) => Promise<void>;
  acceptName: (id: string) => void;
  rejectName: (id: string) => void;
  acceptField: (id: string) => void;
  rejectField: (id: string) => void;
};

const uid = () => Math.random().toString(36).slice(2, 10);
const kMaxTurns = 16;
let streamId: number | null = null;
let cancelled = false;

export const useAssistant = create<AssistantStore>()(
  persist(
    (set, get) => {
      const push = (e: Entry) => set((s) => ({ entries: [...s.entries, e] }));
      const patch = (id: string, p: Partial<Entry>) => set((s) => ({ entries: s.entries.map((e) => (e.id === id ? ({ ...e, ...p } as Entry) : e)) }));
      const note = (text: string, level: "info" | "warn" | "error" = "info") => push({ kind: "note", id: uid(), text, level });

      /** submit_* review tools: fill the review lists, change nothing */
      const local = (name: string, input: unknown): string => {
        if (name === "submit_name_suggestions") {
          const list = parseNameSuggestions(input);
          set((s) => ({ names: [...s.names, ...list] }));
          return `Recorded ${list.length} name suggestion(s) for the user to review; nothing is renamed until they accept.`;
        }
        const list = parseStructFields(input);
        set({ fields: list, fieldsFor: useStructCtx.getState().base });
        return `Recorded ${list.length} field suggestion(s) for the user to review; the layout changes only for the fields they accept.`;
      };

      /** One Messages API round trip, streamed into a transcript entry. */
      const turn = async (): Promise<MessageAccumulator | null> => {
        const { model, effort, messages } = get();
        const acc = new MessageAccumulator();
        const id = uid();
        push({ kind: "assistant", id, blocks: [], model, streaming: true });
        let timer: ReturnType<typeof setTimeout> | null = null;
        const flush = () => { timer = null; patch(id, { blocks: [...acc.content], model: acc.model || model }); };
        const req = api.send(buildRequest({ model, effort, messages }), (ev) => {
          acc.apply(ev);
          if (!timer) timer = setTimeout(flush, 60);
        });
        streamId = req.id;
        try {
          await req.done;
        } catch (e) {
          if (timer) clearTimeout(timer);
          flush();
          patch(id, { streaming: false });
          if (!cancelled) note(String(e instanceof Error ? e.message : e), "error");
          // keep what was said so far (text only: partial thinking / tool calls cannot be replayed)
          const text = acc.content.filter((b) => b?.type === "text" && (b as { text: string }).text);
          if (text.length) set((s) => ({ messages: [...s.messages, { role: "assistant", content: text }] }));
          return null;
        } finally {
          streamId = null;
        }
        if (timer) clearTimeout(timer);
        flush();
        patch(id, { streaming: false, usage: acc.usage });
        if (acc.error) {
          note(acc.error, "error");
          return null;
        }
        set((s) => ({ messages: [...s.messages, { role: "assistant", content: echoContent(acc.content) }] }));
        return acc;
      };

      const run = async () => {
        cancelled = false;
        set({ busy: true });
        try {
          for (let i = 0; i < kMaxTurns; i++) {
            const acc = await turn();
            if (!acc) return;
            // a tool_use left without a result would make the next request invalid
            const closeTools = (why: string) => {
              const open = acc.toolUses();
              if (open.length) set((s) => ({ messages: [...s.messages, { role: "user", content: open.map((t) => ({ type: "tool_result", tool_use_id: t.id, content: why, is_error: true })) }] }));
            };
            if (cancelled) return closeTools("not run: the user stopped the assistant");
            if (acc.stopReason === "refusal") {
              // a declined reply is discarded, not replayed
              set((s) => ({ messages: s.messages.slice(0, -1) }));
              const d = acc.stopDetails as { category?: string; explanation?: string } | null;
              note(`The model declined this request${d?.category ? ` (${d.category})` : ""}.${d?.explanation ? ` ${d.explanation}` : ""}`, "warn");
              return;
            }
            if (acc.stopReason === "max_tokens") {
              closeTools("not run: the reply hit the output limit before this call was complete");
              note("The reply hit the output limit; tool calls in it were not run. Ask to continue.", "warn");
              return;
            }
            if (!toolsMayRun(acc.stopReason)) return;
            const results: unknown[] = [];
            for (const t of acc.toolUses()) {
              if (cancelled) {
                results.push({ type: "tool_result", tool_use_id: t.id, content: "not run: the user stopped the assistant", is_error: true });
                continue;
              }
              const eid = uid();
              push({ kind: "tool", id: eid, name: t.name, input: t.input, running: true });
              const r = await runTool(t.name, t.input, (t as { invalid?: string }).invalid, local);
              patch(eid, { running: false, result: r.content, isError: r.isError });
              results.push({ type: "tool_result", tool_use_id: t.id, content: r.content, ...(r.isError ? { is_error: true } : {}) });
            }
            // every tool_use gets its result, even after Stop, so the conversation stays valid
            set((s) => ({ messages: [...s.messages, { role: "user", content: results }] }));
            if (cancelled) return;
          }
          note(`Stopped after ${kMaxTurns} rounds of tool calls. Send a message to continue.`, "warn");
        } finally {
          set({ busy: false });
        }
      };

      const action = async (title: string, build: () => Promise<string> | string) => {
        if (get().busy) return;
        let text: string;
        try {
          text = await build();
        } catch (e) {
          note(`${title}: ${e instanceof Error ? e.message : String(e)}`, "error");
          return;
        }
        await get().send(text, title);
      };

      const cursor = () => {
        const ui = useUi.getState();
        const at = ui.disasmAt ?? ui.selected;
        if (!at) throw new Error("put the disassembly cursor on a function first");
        return at;
      };

      return {
        model: kDefaultModel,
        effort: "medium",
        entries: [],
        messages: [],
        busy: false,
        names: [],
        fields: [],
        fieldsFor: null,
        keyInfo: null,
        set: (p) => set(p),
        refreshKey: async () => { set({ keyInfo: await api.keyStatus().catch(() => null) }); },
        send: async (text, title) => {
          if (get().busy || !text.trim()) return;
          push({ kind: "user", id: uid(), text, title });
          set((s) => ({ messages: [...s.messages, { role: "user", content: text }] }));
          await run();
        },
        stop: () => {
          cancelled = true;
          if (streamId !== null) void api.cancel(streamId);
        },
        clear: () => {
          if (get().busy) get().stop();
          set({ entries: [], messages: [] });
        },
        explainFunction: () => action("Explain function", async () => explainFunctionPrompt(await functionContext(cursor()))),
        suggestNames: () => action("Suggest names", async () => suggestNamesPrompt(await functionContext(cursor()))),
        suggestFields: () => action("Suggest struct fields", () => suggestStructPrompt(structContext())),
        summariseModule: (name) => action("Summarise module", async () => summariseModulePrompt(await moduleContext(name ?? useUi.getState().module ?? undefined))),
        acceptName: (id) => {
          const s = get().names.find((x) => x.id === id);
          if (!s) return;
          const names = useNames.getState();
          if (s.kind === "local" || s.kind === "argument") {
            const prev = names.commentOf(s.address);
            const add = `${s.current || s.kind}: ${s.name}`;
            names.comment(s.address, prev ? `${prev}; ${add}` : add);
          } else names.rename(s.address, s.name);
          log("info", "assistant", `${s.kind === "local" || s.kind === "argument" ? "noted" : "named"} ${s.address} ${s.name}`);
          set((st) => ({ names: st.names.filter((x) => x.id !== id) }));
        },
        rejectName: (id) => set((st) => ({ names: st.names.filter((x) => x.id !== id) })),
        acceptField: (id) => {
          const f = get().fields.find((x) => x.id === id);
          if (!f) return;
          const ctx = useStructCtx.getState();
          if (get().fieldsFor && ctx.base !== get().fieldsFor) {
            log("warn", "assistant", `these fields were suggested for ${get().fieldsFor}; the Structs view now shows ${ctx.base ?? "nothing"}`);
            return;
          }
          const next = applyFieldAt(ctx.pending ?? ctx.fields, f.offset, f.type, f.name);
          useStructCtx.setState({ pending: next, fields: next });
          useUi.getState().setTab("structs");
          set((st) => ({ fields: st.fields.filter((x) => x.id !== id) }));
        },
        rejectField: (id) => set((st) => ({ fields: st.fields.filter((x) => x.id !== id) })),
      };
    },
    {
      name: "echodebug.assistant",
      // only preferences persist: the conversation (code and data from the target) does not
      partialize: (s) => ({ model: kModels.some((m) => m.id === s.model) ? s.model : kDefaultModel, effort: s.effort }),
    },
  ),
);
