// Dangerous-API triage: flags the imports a binary uses that are worth a
// second look (memory tampering, process injection, anti-analysis), so a
// reviewer can triage a module in one pass.
import type { IatEntry, IatMap } from "./iat";

export type RiskLevel = "high" | "medium" | "low";

export type RiskRule = {
  /** substring matched against the imported function name, case-insensitive */
  match: string;
  level: RiskLevel;
  why: string;
};

/** The rule table. Names are the common spellings across the Windows API. */
export const kRiskRules: RiskRule[] = [
  { match: "VirtualAlloc", level: "high", why: "allocates executable memory" },
  { match: "VirtualProtect", level: "medium", why: "changes page permissions" },
  { match: "WriteProcessMemory", level: "high", why: "writes another process's memory" },
  { match: "ReadProcessMemory", level: "medium", why: "reads another process's memory" },
  { match: "CreateRemoteThread", level: "high", why: "runs code in another process" },
  { match: "CreateRemoteThreadEx", level: "high", why: "runs code in another process" },
  { match: "NtCreateThreadEx", level: "high", why: "runs code in another process" },
  { match: "QueueUserAPC", level: "high", why: "queues code in another thread" },
  { match: "SetWindowsHookEx", level: "high", why: "installs a hook into other processes" },
  { match: "LoadLibrary", level: "medium", why: "loads a library at runtime" },
  { match: "GetProcAddress", level: "low", why: "resolves an API dynamically" },
  { match: "OpenProcess", level: "medium", why: "opens another process" },
  { match: "AdjustTokenPrivileges", level: "medium", why: "raises its own privileges" },
  { match: "IsDebuggerPresent", level: "medium", why: "anti-analysis" },
  { match: "CheckRemoteDebuggerPresent", level: "medium", why: "anti-analysis" },
  { match: "NtQueryInformationProcess", level: "low", why: "often used to detect a debugger" },
  { match: "OutputDebugString", level: "low", why: "often used to detect a debugger" },
  { match: "GetTickCount", level: "low", why: "often used for timing checks" },
  { match: "QueryPerformanceCounter", level: "low", why: "often used for timing checks" },
  { match: "rdtsc", level: "low", why: "often used for timing checks" },
  { match: "CreateToolhelp32Snapshot", level: "medium", why: "enumerates processes" },
  { match: "DeviceIoControl", level: "medium", why: "talks to a device driver" },
  { match: "WinHttpOpen", level: "low", why: "makes network requests" },
  { match: "InternetOpen", level: "low", why: "makes network requests" },
  { match: "URLDownloadToFile", level: "medium", why: "downloads a file" },
  { match: "ShellExecute", level: "medium", why: "runs another program" },
  { match: "RegSetValue", level: "low", why: "writes the registry" },
  { match: "CryptEncrypt", level: "medium", why: "encrypts data" },
  { match: "CryptDecrypt", level: "medium", why: "decrypts data" },
];

export type RiskHit = {
  entry: IatEntry;
  level: RiskLevel;
  why: string;
};

/** Classifies every import in the map against the rule table. */
export function classifyImports(iat: IatMap): RiskHit[] {
  const out: RiskHit[] = [];
  for (const entry of iat.entries) {
    const name = entry.name.toLowerCase();
    let best: RiskRule | null = null;
    for (const rule of kRiskRules) {
      if (!name.includes(rule.match.toLowerCase())) continue;
      // The most severe rule wins when several match.
      if (!best || rank(rule.level) > rank(best.level)) best = rule;
    }
    if (best) out.push({ entry, level: best.level, why: best.why });
  }
  const order: Record<RiskLevel, number> = { high: 0, medium: 1, low: 2 };
  return out.sort((a, b) => order[a.level] - order[b.level] || a.entry.name.localeCompare(b.entry.name));
}

function rank(l: RiskLevel): number {
  return l === "high" ? 3 : l === "medium" ? 2 : 1;
}
