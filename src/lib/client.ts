// One WebSocket to the relay's /client endpoint. Native Echo verbs, ext agent verbs and
// relay-local verbs all travel the same way (see PROTOCOL.md); the relay routes by "type".

export type Frame = { type: string; id?: unknown; [k: string]: unknown };

export class EchoError extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly detail = "",
  ) {
    super(detail ? `${message} (${detail})` : message);
    this.name = "EchoError";
  }
}

type Pending = { resolve: (f: Frame) => void; reject: (e: Error) => void; type: string; allowFail: boolean };
type Listener = (f: Frame) => void;
type StateListener = (connected: boolean) => void;

const kTimeoutMs = 130_000; // relay times out at 120 s, keep ours just above

class Client {
  private ws: WebSocket | null = null;
  private url = "";
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private listeners = new Set<Listener>();
  private stateListeners = new Set<StateListener>();
  private retry = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  connected = false;

  /** `token` is the relay's bearer token; browsers can't set WebSocket headers, so it goes in the query. */
  connect(port: number, token = ""): void {
    this.url = `ws://127.0.0.1:${port}/client`;
    this.setToken(token);
    this.open();
  }

  /** Used for the next (re)connect; the open socket stays authorized. */
  setToken(token: string): void {
    this.url = this.url.split("?")[0] + (token ? `?token=${encodeURIComponent(token)}` : "");
  }

  /** Fire-and-forget frame (replies to relay-initiated `ui_call`s). */
  send(frame: Record<string, unknown>): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(frame));
  }

  private open(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    let ws: WebSocket;
    try {
      ws = new WebSocket(this.url);
    } catch {
      this.schedule();
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      this.retry = 0;
      this.setConnected(true);
    };
    ws.onmessage = (ev) => {
      let f: Frame;
      try {
        f = JSON.parse(String(ev.data)) as Frame;
      } catch {
        return;
      }
      const id = typeof f.id === "number" ? f.id : undefined;
      const p = id !== undefined ? this.pending.get(id) : undefined;
      if (p && id !== undefined) {
        this.pending.delete(id);
        if (f.type === "error" || (f.success === false && !p.allowFail)) {
          p.reject(new EchoError(Number(f.code ?? 0), String(f.message ?? f.error ?? `${p.type} failed`), String(f.detail ?? "")));
        } else p.resolve(f);
        return;
      }
      for (const l of this.listeners) l(f);
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.setConnected(false);
      for (const p of this.pending.values()) p.reject(new EchoError(2004, "relay connection lost"));
      this.pending.clear();
      this.schedule();
    };
  }

  private schedule(): void {
    const delay = Math.min(5000, 250 * 2 ** this.retry++);
    this.timer = setTimeout(() => this.open(), delay);
  }

  private setConnected(v: boolean): void {
    if (this.connected === v) return; // a never-opened socket closes on every retry
    this.connected = v;
    for (const l of this.stateListeners) l(v);
  }

  /**
   * Send one request; resolves with the reply frame. Native Echo replies report failure via
   * `success:false` (e.g. sig_scan with no hit) — pass allowFail to receive those instead of throwing.
   */
  request<T = Frame>(type: string, fields: Record<string, unknown> = {}, allowFail = false): Promise<T & Frame> {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) return Promise.reject(new EchoError(2000, "relay not connected"));
    const id = this.nextId++;
    return new Promise<T & Frame>((resolve, reject) => {
      const t = setTimeout(() => {
        if (this.pending.delete(id)) reject(new EchoError(2003, `${type} timed out`));
      }, kTimeoutMs);
      this.pending.set(id, {
        type,
        allowFail,
        resolve: (f) => {
          clearTimeout(t);
          resolve(f as T & Frame);
        },
        reject: (e) => {
          clearTimeout(t);
          reject(e);
        },
      });
      ws.send(JSON.stringify({ ...fields, type, id }));
    });
  }

  on(l: Listener): () => void {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  }

  onState(l: StateListener): () => void {
    this.stateListeners.add(l);
    return () => this.stateListeners.delete(l);
  }
}

export const client = new Client();
export const request = client.request.bind(client);
