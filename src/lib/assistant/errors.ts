// What the panel offers next to an error from the desktop side. The desktop's messages
// (relay/src/assistant.rs `error_message`) carry the hints this keys off.

export type ErrorAction = "settings" | "retry" | "compact" | "models";
export type ErrorHint = { actions: ErrorAction[]; retryAfter?: number };

export function errorHint(msg: string): ErrorHint {
  const m = msg.toLowerCase();
  const actions: ErrorAction[] = [];
  let retryAfter: number | undefined;
  if (/\/compact|too long|context length|context_length|maximum context/.test(m)) actions.push("compact");
  if (/settings|api key|not set up|sign in|no endpoint|credential|401|403/.test(m)) actions.push("settings");
  if (/unknown model|refresh the model list|404/.test(m)) actions.push("models");
  const ra = /retry after (\d+)s/.exec(m);
  if (ra) retryAfter = Number(ra[1]);
  if (/\/retry|rate limit|429|overloaded|timed out|5\d\d|cannot reach|stream interrupted|ended before/.test(m)) actions.push("retry");
  return { actions: [...new Set(actions)], ...(retryAfter !== undefined ? { retryAfter } : {}) };
}
