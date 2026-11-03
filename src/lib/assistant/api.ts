// The desktop side of the assistant (src-tauri/src/lib.rs → relay/src/assistant.rs). The API key
// stays there: the web view can only ask whether one is stored, replace or remove it, and send a
// request body that the desktop checks, signs with the key and streams from api.anthropic.com.
import { Channel, invoke } from "@tauri-apps/api/core";
import { isTauri } from "../tauri";
import type { StreamEvent } from "./stream";

export type KeyInfo = { present: boolean; storage: "dpapi" | "file"; path: string; note: string };

export const available = (): boolean => isTauri();

export async function keyStatus(): Promise<KeyInfo | null> {
  if (!isTauri()) return null;
  return invoke<KeyInfo>("assistant_key_status");
}

export async function setKey(key: string): Promise<KeyInfo> {
  return invoke<KeyInfo>("assistant_set_key", { key });
}

export async function clearKey(): Promise<KeyInfo> {
  return invoke<KeyInfo>("assistant_clear_key");
}

let nextId = 1;

/** Streams one request; resolves when the stream ends, rejects with the API's error text. */
export function send(body: Record<string, unknown>, onEvent: (ev: StreamEvent) => void): { id: number; done: Promise<void> } {
  const id = nextId++;
  if (!isTauri()) return { id, done: Promise.reject(new Error("the assistant runs in the desktop app only")) };
  const ch = new Channel<StreamEvent>();
  ch.onmessage = onEvent;
  return { id, done: invoke<void>("assistant_send", { id, body, onEvent: ch }) };
}

export async function cancel(id: number): Promise<void> {
  if (isTauri()) await invoke("assistant_cancel", { id });
}
