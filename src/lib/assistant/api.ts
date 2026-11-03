// The desktop side of the assistant (src-tauri/src/lib.rs → relay/src/assistant/). Credentials stay
// there: the web view can list providers (without keys), store or remove a credential, run
// OpenRouter's sign-in, list models, and send a provider-neutral request that the desktop checks,
// turns into the provider's own request, signs and streams back as normalised events.
import { Channel, invoke } from "@tauri-apps/api/core";
import { isTauri, openUrl } from "../tauri";
import type { ModelInfo, ProviderInfo } from "./providers";
import type { StreamEvent } from "./stream";

export type ProvidersReply = { storage: "dpapi" | "file"; note: string; providers: ProviderInfo[]; conversations: string };

export const available = (): boolean => isTauri();

export async function providers(): Promise<ProvidersReply | null> {
  if (!isTauri()) return null;
  return invoke<ProvidersReply>("assistant_providers");
}

/** `{id, kind?, name?, base_url?, api_key?, headers?, clear_key?}`; an empty api_key keeps the stored key. */
export async function saveProvider(cred: Record<string, unknown>): Promise<ProviderInfo> {
  return invoke<ProviderInfo>("assistant_save_provider", { cred });
}

export async function removeProvider(id: string): Promise<ProviderInfo> {
  return invoke<ProviderInfo>("assistant_remove_provider", { id });
}

export async function listModels(provider: string): Promise<ModelInfo[]> {
  return invoke<ModelInfo[]>("assistant_models", { provider });
}

export async function testProvider(provider: string): Promise<{ ok: boolean; models: number; ms: number; host: string }> {
  return invoke("assistant_test", { provider });
}

let nextId = 1;

/** OpenRouter's OAuth PKCE sign-in: opens the browser and resolves once the key is stored. */
export function signInOpenRouter(): { id: number; done: Promise<ProviderInfo> } {
  const id = nextId++;
  const done = (async () => {
    const url = await invoke<string>("assistant_signin_begin", { id });
    await openUrl(url);
    return invoke<ProviderInfo>("assistant_signin_finish", { id });
  })();
  return { id, done };
}

export async function cancelSignIn(id: number): Promise<void> {
  if (isTauri()) await invoke("assistant_signin_cancel", { id });
}

/** Streams one request; resolves when the stream ends, rejects with the provider's error text. */
export function send(provider: string, body: Record<string, unknown>, onEvent: (ev: StreamEvent) => void): { id: number; done: Promise<void> } {
  const id = nextId++;
  if (!isTauri()) return { id, done: Promise.reject(new Error("the assistant runs in the desktop app only")) };
  const ch = new Channel<StreamEvent>();
  ch.onmessage = onEvent;
  return { id, done: invoke<void>("assistant_send", { id, provider, body, onEvent: ch }) };
}

export async function cancel(id: number): Promise<void> {
  if (isTauri()) await invoke("assistant_cancel", { id });
}

export type ConvSummary = { id: string; title: string; updated: number; provider: string | null; model: string | null; count: number };

/** Where saved conversations live: the desktop's config directory, or (in a browser) nowhere. */
export interface ConvBackend {
  list(): Promise<ConvSummary[]>;
  load(id: string): Promise<string>;
  save(id: string, body: string): Promise<void>;
  remove(id: string): Promise<void>;
}

export const tauriConvs: ConvBackend = {
  list: () => invoke<ConvSummary[]>("assistant_conv_list"),
  load: (id) => invoke<string>("assistant_conv_load", { id }),
  save: (id, body) => invoke<void>("assistant_conv_save", { id, body }),
  remove: (id) => invoke<void>("assistant_conv_delete", { id }),
};

/** In-memory backend (browser preview and tests). */
export function memoryConvs(): ConvBackend & { files: Map<string, string> } {
  const files = new Map<string, string>();
  return {
    files,
    list: async () =>
      [...files.values()]
        .map((b) => JSON.parse(b) as ConvSummary)
        .map(({ id, title, updated, provider, model, count }) => ({ id, title, updated, provider, model, count }))
        .sort((a, b) => b.updated - a.updated),
    load: async (id) => {
      const b = files.get(id);
      if (b === undefined) throw new Error(`no conversation ${id}`);
      return b;
    },
    save: async (id, body) => { files.set(id, body); },
    remove: async (id) => { files.delete(id); },
  };
}
