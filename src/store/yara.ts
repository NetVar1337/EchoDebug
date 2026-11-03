// The YARA rules the user is editing, kept between runs.
import { create } from "zustand";
import { persist } from "zustand/middleware";

export const kSampleRules = `rule anti_debug_apis {
  meta: description = "debugger detection imports or strings"
  strings:
    $a = "IsDebuggerPresent" ascii wide
    $b = "CheckRemoteDebuggerPresent" ascii wide
    $c = "NtQueryInformationProcess" ascii wide
  condition: any of them
}

rule msvc_x64_prologue {
  strings: $p = { 48 89 5C 24 ?? 57 48 83 EC ?? }
  condition: #p > 10
}
`;

type YaraStore = { rules: string; setRules: (r: string) => void };

export const useYara = create<YaraStore>()(
  persist((set) => ({ rules: kSampleRules, setRules: (rules) => set({ rules }) }), { name: "echodebug.yara" }),
);
