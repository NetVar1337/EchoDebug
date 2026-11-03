// The assistant panel's state: providers and models, saved conversations (transcript + the
// messages sent to the model), the tool-use loop (read-only tools only, for every provider), slash
// commands, @-mentions, usage and cost, and the review lists for suggested names and fields.
import { create } from "zustand";
import { persist } from "zustand/middleware";
import * as api from "@/lib/assistant/api";
import { isTauri } from "@/lib/tauri";
import { saveText } from "@/lib/save";
import { request } from "@/lib/client";
import { fmtAddr, labelAddr, parseAddress, toBig } from "@/lib/hex";
import { MessageAccumulator, echoContent, toolsMayRun } from "@/lib/assistant/stream";
import { runTool } from "@/lib/assistant/exec";
import { functionContext, moduleContext, structContext } from "@/lib/assistant/context";
import { apiTools, assistantTools, kLocalTools } from "@/lib/assistant/tools";
import {
  applyFieldAt, buildRequest, explainFunctionPrompt, kSystemPrompt, parseNameSuggestions, parseStructFields, suggestNamesPrompt,
  suggestStructPrompt, summariseModulePrompt, type FieldSuggestion, type Msg, type NameSuggestion,
} from "@/lib/assistant/prompts";
import {
  builtinModels, defaultSettings, findModel, fmtTokens, kKindLabels, kModelCacheMs, usable, withKnownPrices,
  type ModelInfo, type ModelSettings, type ProviderInfo, type ProviderKind,
} from "@/lib/assistant/providers";
import { helpText, parseMentions, parseSlash } from "@/lib/assistant/commands";
import { resolveMention, withAttachments, type MentionDeps } from "@/lib/assistant/mentions";
import { addUsage, estimateRequest, fmtCost, fmtUsage, totalCost, usageCost } from "@/lib/assistant/cost";
import { errorHint } from "@/lib/assistant/errors";
import {
  autoTitle, compactedMessages, deserialize, exportMarkdown, kCompactPrompt, lastUserTurn, newConversation, serialize,
  type Conversation, type Entry,
} from "@/lib/assistant/conversations";
import { useConn } from "./conn";
import { useNames } from "./names";
import { useStructCtx } from "./structctx";
import { useTypes } from "./types";
import { useUi } from "./ui";
import { log } from "./output";
import { layout as structLayout } from "@/lib/analysis/struct";

export type { Entry } from "@/lib/assistant/conversations";

type ModelCache = { at: number; models: ModelInfo[]; error?: string };

type AssistantStore = {
  /** active provider id */
  provider: string;
  model: string;
  /** per model: `${provider}/${model}` */
  settings: Record<string, ModelSettings>;
  modelCache: Record<string, ModelCache>;
  /** the model last used with each provider */
  lastModel: Record<string, string>;
  /** keep conversations on disk */
  saveHistory: boolean;

  providers: ProviderInfo[] | null;
  storage: { storage: "dpapi" | "file"; note: string; conversations: string } | null;
  conv: Conversation;
  convs: api.ConvSummary[];
  busy: boolean;
  /** text the composer should take over (edit last message), with a counter to notice repeats */
  draft: { text: string; n: number } | null;
  /** Ctrl+L / focus requests */
  focusTick: number;
  pickerOpen: boolean;
  systemEditing: boolean;
  names: NameSuggestion[];
  fields: FieldSuggestion[];
  /** struct address the field suggestions were made for */
  fieldsFor: string | null;

  set: (p: Partial<Pick<AssistantStore, "pickerOpen" | "systemEditing" | "saveHistory">>) => void;
  refreshProviders: () => Promise<void>;
  refreshModels: (provider: string, force?: boolean) => Promise<void>;
  /** every model of every usable provider (live where fetched, else built in) */
  allModels: () => ModelInfo[];
  activeProvider: () => ProviderInfo | undefined;
  activeModel: () => ModelInfo | undefined;
  modelSettings: () => ModelSettings & ReturnType<typeof defaultSettings>;
  setModelSettings: (p: ModelSettings) => void;
  select: (provider: string, model?: string) => void;
  /** composer input: slash commands, else a message with its @-mentions */
  submit: (text: string) => Promise<void>;
  send: (text: string, title?: string, opts?: { tools?: boolean; mentions?: boolean }) => Promise<boolean>;
  stop: () => void;
  retry: () => Promise<void>;
  editLast: () => void;
  compact: () => Promise<void>;
  clear: () => void;
  newConversation: () => void;
  listConversations: () => Promise<void>;
  openConversation: (id: string) => Promise<void>;
  renameConversation: (id: string, title: string) => Promise<void>;
  deleteConversation: (id: string) => Promise<void>;
  exportConversation: () => Promise<void>;
  setSystem: (text: string | null) => void;
  explainFunction: (addr?: string) => Promise<void>;
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
let backend: api.ConvBackend = isTauri() ? api.tauriConvs : api.memoryConvs();
/** for tests */
export function setConvBackend(b: api.ConvBackend): void {
  backend = b;
}
let saveTimer: ReturnType<typeof setTimeout> | null = null;

const settingsKey = (provider: string, model: string) => `${provider}/${model}`;

/** Live data sources for @-mentions. */
function mentionDeps(): MentionDeps {
  const { modules } = useConn.getState();
  const ui = useUi.getState();
  return {
    cursor: () => ui.disasmAt ?? ui.selected,
    parse: (e) => { const v = parseAddress(e, modules); return v === null ? null : fmtAddr(v); },
    functionAt: (a) => functionContext(a),
    read: async (a, size) => {
      const r = await request<{ data: string; success: boolean }>("read", { address: a, size }, true);
      if (!r.success || !r.data) throw new Error(`cannot read ${a}`);
      return r.data;
    },
    disasm: async (a, count) => ((await request<{ results: { address: string; text: string }[] }>("disassemble", { address: a, size: count * 8 }, true)).results ?? []).slice(0, count).map((l) => `${l.address}  ${l.text}`),
    label: (a) => useNames.getState().nameOf(a) || labelAddr(toBig(a), modules),
    struct: (name) => {
      const t = useTypes.getState().find(name) ?? useTypes.getState().types.find((x) => x.name.toLowerCase() === name.toLowerCase());
      if (!t) return undefined;
      const lay = structLayout(t.fields);
      return { name: t.name, fields: t.fields.map((f, i) => ({ offset: lay[i].offset, type: f.type, name: f.name || `field_${lay[i].offset.toString(16)}` })) };
    },
    module: (name) => moduleContext(name),
    memorySelection: () => useUi.getState().memSel,
  };
}

export const useAssistant = create<AssistantStore>()(
  persist(
    (set, get) => {
      const upd = (f: (c: Conversation) => Partial<Conversation>) => set((s) => ({ conv: { ...s.conv, ...f(s.conv), updated: Date.now() } }));
      const push = (e: Entry) => upd((c) => ({ entries: [...c.entries, e] }));
      const patch = (id: string, p: Partial<Entry>) => upd((c) => ({ entries: c.entries.map((e) => (e.id === id ? ({ ...e, ...p } as Entry) : e)) }));
      const addMsg = (m: Msg) => upd((c) => ({ messages: [...c.messages, m] }));
      const note = (text: string, level: "info" | "warn" | "error" = "info", extra: { pre?: boolean; actions?: string[] } = {}) => push({ kind: "note", id: uid(), text, level, ...extra });
      const errNote = (msg: string) => note(msg, "error", { actions: errorHint(msg).actions });

      const persistNow = async () => {
        const c = get().conv;
        if (!get().saveHistory || !c.entries.length || !isTauri()) return;
        try {
          await backend.save(c.id, serialize(c));
          void get().listConversations();
        } catch (e) {
          log("warn", "assistant", `could not save the conversation: ${e instanceof Error ? e.message : String(e)}`);
        }
      };
      const persistSoon = () => {
        if (saveTimer) clearTimeout(saveTimer);
        saveTimer = setTimeout(() => { saveTimer = null; void persistNow(); }, 400);
      };

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

      /** One round trip to the active provider, streamed into a transcript entry. */
      const turn = async (tools: boolean): Promise<MessageAccumulator | null> => {
        const p = get().activeProvider();
        const { provider, model, conv } = get();
        if (!p || !usable(p)) {
          errNote(`${p ? p.name : provider} is not set up: add a key or sign in in Settings → Assistant.`);
          return null;
        }
        const mi = get().activeModel();
        const settings = get().settings[settingsKey(provider, model)] ?? {};
        const acc = new MessageAccumulator();
        const id = uid();
        const started = Date.now();
        push({ kind: "assistant", id, blocks: [], model, provider, streaming: true, started });
        let timer: ReturnType<typeof setTimeout> | null = null;
        const flush = () => { timer = null; patch(id, { blocks: [...acc.content], model: acc.model || model }); };
        const body = buildRequest({ kind: p.kind, modelId: model, model: mi, settings, messages: conv.messages, tools, system: conv.system ?? kSystemPrompt });
        const req = api.send(provider, body, (ev) => {
          acc.apply(ev);
          if (!timer) timer = setTimeout(flush, 50);
        });
        streamId = req.id;
        const finish = () => {
          if (timer) clearTimeout(timer);
          flush();
          const cost = usageCost(acc.usage, settings.price ?? mi?.price);
          patch(id, { streaming: false, usage: acc.usage, cost, ms: Date.now() - started });
        };
        try {
          await req.done;
        } catch (e) {
          finish();
          if (!cancelled) errNote(String(e instanceof Error ? e.message : e));
          // keep what was said so far (text only: partial thinking / tool calls cannot be replayed)
          const text = acc.content.filter((b) => b?.type === "text" && (b as { text: string }).text);
          if (text.length) addMsg({ role: "assistant", content: text });
          return null;
        } finally {
          streamId = null;
        }
        finish();
        if (acc.error) {
          errNote(acc.error);
          return null;
        }
        addMsg({ role: "assistant", content: echoContent(acc.content) });
        return acc;
      };

      const run = async (tools: boolean): Promise<boolean> => {
        cancelled = false;
        set({ busy: true });
        try {
          for (let i = 0; i < kMaxTurns; i++) {
            const acc = await turn(tools);
            if (!acc) return false;
            // a tool_use left without a result would make the next request invalid
            const closeTools = (why: string) => {
              const open = acc.toolUses();
              if (open.length) addMsg({ role: "user", content: open.map((t) => ({ type: "tool_result", tool_use_id: t.id, content: why, is_error: true })) });
            };
            if (cancelled) { closeTools("not run: the user stopped the assistant"); return false; }
            if (acc.stopReason === "refusal") {
              // a declined reply is discarded, not replayed
              upd((c) => ({ messages: c.messages.slice(0, -1) }));
              const d = acc.stopDetails as { category?: string; explanation?: string } | null;
              note(`The model declined this request${d?.category ? ` (${d.category})` : ""}.${d?.explanation ? ` ${d.explanation}` : ""}`, "warn");
              return false;
            }
            if (acc.stopReason === "max_tokens") {
              closeTools("not run: the reply hit the output limit before this call was complete");
              note("The reply hit the output limit; tool calls in it were not run. Ask to continue, or raise max output tokens in the model settings.", "warn");
              return true;
            }
            if (!toolsMayRun(acc.stopReason)) return true;
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
            addMsg({ role: "user", content: results });
            if (cancelled) return false;
          }
          note(`Stopped after ${kMaxTurns} rounds of tool calls. Send a message to continue.`, "warn");
          return true;
        } finally {
          set({ busy: false });
          persistSoon();
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
        await get().send(text, title, { mentions: false });
      };

      const cursor = () => {
        const ui = useUi.getState();
        const at = ui.disasmAt ?? ui.selected;
        if (!at) throw new Error("put the disassembly cursor on a function first");
        return at;
      };

      const fresh = () => newConversation(get().provider, get().model);

      const commands: Record<string, (args: string) => unknown> = {
        help: () => note(helpText(), "info", { pre: true }),
        explain: (args) => {
          if (!args) return get().explainFunction();
          const v = parseAddress(args.replace(/^@/, ""), useConn.getState().modules);
          if (v === null) return note(`/explain: cannot parse ${args}`, "error");
          return get().explainFunction(fmtAddr(v));
        },
        names: () => get().suggestNames(),
        struct: () => get().suggestFields(),
        summary: (args) => get().summariseModule(args.replace(/^@?(module:)?/, "") || undefined),
        model: (args) => {
          if (!args) return set({ pickerOpen: true });
          const m = findModel(get().allModels(), args, get().provider);
          if (!m) return note(`/model: no model matches "${args}". Open the picker (/model) or refresh the list.`, "warn");
          get().select(m.provider, m.id);
          note(`Model: ${m.name} (${m.provider})`);
        },
        provider: (args) => {
          const ps = (get().providers ?? []).filter(usable);
          if (!args) return note(ps.length ? `Providers set up: ${ps.map((p) => `${p.id} (${p.name})`).join(", ")}. Use /provider <name>.` : "No provider is set up yet: open Settings → Assistant.", "info");
          const q = args.toLowerCase();
          const p = ps.find((x) => x.id === q) ?? ps.find((x) => x.name.toLowerCase() === q) ?? ps.find((x) => x.id.includes(q) || x.name.toLowerCase().includes(q) || kKindLabels[x.kind].toLowerCase().includes(q));
          if (!p) return note(`/provider: "${args}" is not set up. Providers: ${ps.map((x) => x.id).join(", ") || "none"}.`, "warn");
          get().select(p.id);
          note(`Provider: ${p.name}, model ${get().model}`);
        },
        clear: () => get().clear(),
        new: () => get().newConversation(),
        compact: () => get().compact(),
        retry: () => get().retry(),
        export: () => get().exportConversation(),
        tools: () => {
          const ts = [...assistantTools(), ...kLocalTools];
          const first = (d: string) => d.split(/(?<=\.)\s/)[0].slice(0, 110);
          note(`${ts.length} read-only tools (the same for every provider; writes, freezes, dumps, patches, renames, emulation and debugger control are never offered):\n${ts.map((t) => `  ${t.name.padEnd(26)} ${first(t.description)}`).join("\n")}`, "info", { pre: true });
        },
        context: () => {
          const { conv } = get();
          const p = get().activeProvider();
          const mi = get().activeModel();
          const est = estimateRequest(conv.system ?? kSystemPrompt, mi?.tools === false ? null : apiTools(), conv.messages);
          const lastIn = [...conv.entries].reverse().find((e) => e.kind === "assistant" && e.usage) as Extract<Entry, { kind: "assistant" }> | undefined;
          const used = lastIn?.usage ? (lastIn.usage.input_tokens ?? 0) + (lastIn.usage.cache_read_input_tokens ?? 0) + (lastIn.usage.cache_creation_input_tokens ?? 0) + (lastIn.usage.output_tokens ?? 0) : null;
          const atts = conv.entries.flatMap((e) => (e.kind === "user" ? e.attachments ?? [] : []));
          const ctx = mi?.context ?? null;
          note([
            `Provider ${p?.name ?? get().provider} · model ${get().model} · context window ${fmtTokens(ctx)}`,
            `Estimated next request: ~${est.total} tokens (system ~${est.system}, tools ~${est.tools}, ${conv.messages.length} messages ~${est.messages})${ctx ? ` = ${Math.round((est.total / ctx) * 1000) / 10}% of the window` : ""}`,
            used !== null ? `Last reply reported ${used} tokens in context.` : "",
            `Attached in this conversation: ${atts.length ? [...new Set(atts)].join(", ") : "nothing"}`,
            ctx && est.total > ctx * 0.7 ? "That is getting close to the limit: /compact summarises the history." : "",
          ].filter(Boolean).join("\n"), "info", { pre: true });
        },
        cost: () => {
          const as = get().conv.entries.filter((e): e is Extract<Entry, { kind: "assistant" }> => e.kind === "assistant" && !!e.usage);
          const by = new Map<string, { usage: typeof as[number]["usage"]; cost: number; unknown: boolean; n: number }>();
          for (const e of as) {
            const k = `${e.provider}/${e.model}`;
            const cur = by.get(k) ?? { usage: {}, cost: 0, unknown: false, n: 0 };
            cur.usage = addUsage(cur.usage ?? {}, e.usage);
            if (e.cost == null) cur.unknown = true; else cur.cost += e.cost;
            cur.n++;
            by.set(k, cur);
          }
          const t = totalCost(as);
          note([
            ...[...by].map(([k, v]) => `${k}: ${v.n} replies, ${fmtUsage(v.usage)}, ${v.unknown && !v.cost ? "price unknown" : fmtCost(v.cost) + (v.unknown ? " + unknown" : "")}`),
            `Total: ${fmtCost(t.usd)}${t.complete ? "" : " (some replies have no known price: set one in the model settings)"}`,
          ].join("\n") || "No replies yet.", "info", { pre: true });
        },
        system: (args) => {
          if (!args) return set({ systemEditing: true });
          if (args === "reset") { get().setSystem(null); return note("System prompt reset to the default."); }
          get().setSystem(args);
          note("System prompt replaced for this conversation (/system reset restores the default).");
        },
      };

      return {
        provider: "anthropic",
        model: "claude-opus-5-5",
        settings: {},
        modelCache: {},
        lastModel: {},
        saveHistory: true,
        providers: null,
        storage: null,
        conv: newConversation("anthropic", "claude-opus-5-5"),
        convs: [],
        busy: false,
        draft: null,
        focusTick: 0,
        pickerOpen: false,
        systemEditing: false,
        names: [],
        fields: [],
        fieldsFor: null,
        set: (p) => set(p),

        refreshProviders: async () => {
          const r = await api.providers().catch(() => null);
          if (!r) return;
          set({ providers: r.providers, storage: { storage: r.storage, note: r.note, conversations: r.conversations } });
          const ok = r.providers.filter(usable);
          // keep the active provider if it is usable, else switch to the first one that is
          if (ok.length && !ok.some((p) => p.id === get().provider)) get().select(ok[0].id);
          for (const p of ok) void get().refreshModels(p.id);
        },

        refreshModels: async (provider, force = false) => {
          const cached = get().modelCache[provider];
          if (!force && cached && !cached.error && Date.now() - cached.at < kModelCacheMs) return;
          const p = get().providers?.find((x) => x.id === provider);
          if (!p || !usable(p)) return;
          try {
            const list = withKnownPrices(p.kind, await api.listModels(provider));
            set((s) => ({ modelCache: { ...s.modelCache, [provider]: { at: Date.now(), models: list } } }));
            // a model this provider does not have (e.g. after switching to a local server): its first one
            const cur = get().model;
            if (get().provider === provider && list.length && !list.some((x) => x.id === cur) && !builtinModels(p).some((x) => x.id === cur)) get().select(provider, list[0].id);
          } catch (e) {
            const error = e instanceof Error ? e.message : String(e);
            set((s) => ({ modelCache: { ...s.modelCache, [provider]: { at: Date.now(), models: s.modelCache[provider]?.models ?? [], error } } }));
            if (force) log("warn", "assistant", `${p.name} models: ${error}`);
          }
        },

        allModels: () => {
          const out: ModelInfo[] = [];
          for (const p of (get().providers ?? []).filter(usable)) {
            const live = get().modelCache[p.id]?.models;
            out.push(...(live?.length ? live : builtinModels(p)));
          }
          return out;
        },
        activeProvider: () => get().providers?.find((p) => p.id === get().provider),
        activeModel: () => {
          const { provider, model } = get();
          const live = get().modelCache[provider]?.models ?? [];
          const p = get().activeProvider();
          return live.find((m) => m.id === model) ?? (p ? builtinModels(p).find((m) => m.id === model) : undefined);
        },
        modelSettings: () => {
          const p = get().activeProvider();
          const d = defaultSettings((p?.kind ?? "anthropic") as ProviderKind, get().activeModel());
          const s = get().settings[settingsKey(get().provider, get().model)] ?? {};
          return { ...d, ...Object.fromEntries(Object.entries(s).filter(([, v]) => v !== undefined)) } as ModelSettings & typeof d;
        },
        setModelSettings: (p) => set((s) => {
          const k = settingsKey(s.provider, s.model);
          return { settings: { ...s.settings, [k]: { ...s.settings[k], ...p } } };
        }),
        select: (provider, model) => {
          const p = get().providers?.find((x) => x.id === provider);
          let m = model;
          if (!m) {
            const live = get().modelCache[provider]?.models ?? [];
            const builtin = p ? builtinModels(p) : [];
            // the last model used with this provider, else its first
            const prev = get().lastModel[provider];
            m = (prev && [...live, ...builtin].some((x) => x.id === prev) ? prev : undefined) ?? builtin[0]?.id ?? live[0]?.id ?? get().model;
          }
          set((s) => ({ provider, model: m!, pickerOpen: false, lastModel: { ...s.lastModel, [provider]: m! } }));
          upd(() => ({ provider, model: m! }));
          void get().refreshModels(provider);
        },

        submit: async (raw) => {
          const text = raw.trim();
          if (!text) return;
          const s = parseSlash(text);
          if (!s) { await get().send(text); return; }
          if (!s.def) { note(`Unknown command /${s.name}. /help lists the commands.`, "warn"); return; }
          if (get().busy && !["help", "tools", "context", "cost"].includes(s.name)) { note("Wait for the reply (or press Esc to stop) first.", "warn"); return; }
          await commands[s.name](s.args);
        },

        send: async (text, title, opts = {}) => {
          if (get().busy || !text.trim()) return false;
          const c = get().conv;
          const mentions = opts.mentions === false ? [] : parseMentions(text);
          set({ busy: true });
          let content = text;
          let attachments: string[] | undefined;
          if (mentions.length) {
            const deps = mentionDeps();
            const atts = await Promise.all(mentions.map((m) => resolveMention(m, deps)));
            for (const a of atts) if (a.error) note(`${a.token}: ${a.error}`, "warn");
            attachments = atts.filter((a) => !a.error).map((a) => a.title);
            content = withAttachments(text, atts);
          }
          set({ busy: false });
          const at = c.messages.length;
          push({ kind: "user", id: uid(), text, title, at, ...(attachments?.length ? { attachments } : {}) });
          if (!c.title) upd(() => ({ title: title ?? autoTitle(text) }));
          upd(() => ({ provider: get().provider, model: get().model }));
          addMsg({ role: "user", content });
          return run(opts.tools !== false);
        },

        stop: () => {
          cancelled = true;
          if (streamId !== null) void api.cancel(streamId);
        },

        retry: async () => {
          if (get().busy) return;
          const last = lastUserTurn(get().conv);
          if (!last) { note("Nothing to retry yet.", "info"); return; }
          upd((c) => ({ messages: last.before, entries: c.entries.slice(0, last.entryIndex) }));
          await get().send(last.text, last.title, { mentions: !last.title });
        },

        editLast: () => {
          if (get().busy) return;
          const last = lastUserTurn(get().conv);
          if (!last || last.title) return;
          upd((c) => ({ messages: last.before, entries: c.entries.slice(0, last.entryIndex) }));
          set((s) => ({ draft: { text: last.text, n: (s.draft?.n ?? 0) + 1 } }));
        },

        compact: async () => {
          if (get().busy) return;
          const before = get().conv.messages;
          if (before.length < 2) { note("Nothing to compact yet.", "info"); return; }
          const estBefore = estimateRequest("", null, before).messages;
          const ok = await get().send(kCompactPrompt, "Compact conversation", { tools: false, mentions: false });
          const last = [...get().conv.entries].reverse().find((e) => e.kind === "assistant") as Extract<Entry, { kind: "assistant" }> | undefined;
          const summary = last?.blocks.filter((b) => b?.type === "text").map((b) => (b as { text: string }).text).join("").trim();
          if (!ok || !summary) { note("Compaction did not finish; the history is unchanged.", "warn"); upd(() => ({ messages: before })); return; }
          const next = compactedMessages(summary);
          upd((c) => ({ messages: next, entries: c.entries.map((e) => (e.kind === "user" ? { ...e, at: undefined } : e)) }));
          note(`Compacted ${before.length} messages (~${estBefore} tokens) into a summary (~${estimateRequest("", null, next).messages} tokens).`);
          persistSoon();
        },

        clear: () => {
          if (get().busy) get().stop();
          upd(() => ({ entries: [], messages: [], title: "" }));
          set({ names: [], fields: [] });
          persistSoon();
        },

        newConversation: () => {
          if (get().busy) get().stop();
          void persistNow();
          set({ conv: fresh(), names: [], fields: [], systemEditing: false });
        },

        listConversations: async () => {
          if (!isTauri()) return;
          set({ convs: await backend.list().catch(() => []) });
        },

        openConversation: async (id) => {
          if (get().busy) return;
          try {
            await persistNow();
            const c = deserialize(await backend.load(id));
            set({ conv: c, names: [], fields: [] });
            if (c.provider && get().providers?.some((p) => p.id === c.provider && usable(p))) {
              set({ provider: c.provider, model: c.model || get().model });
            }
          } catch (e) {
            note(`Could not open the conversation: ${e instanceof Error ? e.message : String(e)}`, "error");
          }
        },

        renameConversation: async (id, title) => {
          const t = title.trim().slice(0, 120);
          if (!t) return;
          if (get().conv.id === id) { upd(() => ({ title: t })); await persistNow(); return; }
          try {
            const c = deserialize(await backend.load(id));
            await backend.save(id, serialize({ ...c, title: t, updated: Date.now() }));
            await get().listConversations();
          } catch (e) {
            log("warn", "assistant", `rename: ${e instanceof Error ? e.message : String(e)}`);
          }
        },

        deleteConversation: async (id) => {
          await backend.remove(id).catch((e) => log("warn", "assistant", `delete: ${String(e)}`));
          if (get().conv.id === id) set({ conv: fresh() });
          await get().listConversations();
        },

        exportConversation: async () => {
          const c = get().conv;
          if (!c.entries.length) { note("Nothing to export yet.", "info"); return; }
          const name = `${(c.title || "assistant").replace(/[^\w.-]+/g, "_").slice(0, 60)}.md`;
          const path = await saveText(name, exportMarkdown(c), { name: "Markdown", extensions: ["md"] });
          if (path) note(`Exported to ${path}`);
        },

        setSystem: (text) => { upd(() => ({ system: text })); set({ systemEditing: false }); persistSoon(); },

        explainFunction: (addr) => action("Explain function", async () => explainFunctionPrompt(await functionContext(addr ?? cursor()))),
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
      version: 2,
      // preferences and model lists persist here; conversations (code and data from the target)
      // are saved by the desktop app in their own 0600 files, and only when saveHistory is on
      partialize: (s) => ({ provider: s.provider, model: s.model, settings: s.settings, modelCache: s.modelCache, lastModel: s.lastModel, saveHistory: s.saveHistory }),
      migrate: (old) => {
        const o = (old ?? {}) as { model?: string; effort?: string };
        return { provider: "anthropic", model: typeof o.model === "string" ? o.model : "claude-opus-5-5", settings: o.effort && o.model ? { [`anthropic/${o.model}`]: { effort: o.effort as ModelSettings["effort"] } } : {}, modelCache: {}, lastModel: {}, saveHistory: true } as never;
      },
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Partial<AssistantStore>;
        const merged = { ...current, ...p };
        return { ...merged, conv: newConversation(merged.provider, merged.model) };
      },
    },
  ),
);
