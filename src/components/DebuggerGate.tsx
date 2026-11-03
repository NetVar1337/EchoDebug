// Gate for the native-debugger views (Debugger, Access Finder, API Monitor): the relay's ptrace
// debugger on Linux (local backend), or its Win32 debugger on Windows (a process on this machine).
import type { ReactNode } from "react";
import { Bug, PlugZap } from "lucide-react";
import { useConn } from "@/store/conn";
import { Empty } from "./ui";

export function DebuggerGate({ children }: { children: ReactNode }) {
  const { relay, debugger: dbg, backend, os, target } = useConn();
  if (!relay) return <Empty icon={<PlugZap size={26} strokeWidth={1.5} />} title="Relay not reachable." hint="The EchoDebug relay is not running. Restart the app or check the port in Settings." />;
  if (!dbg)
    return (
      <Empty icon={<Bug size={26} strokeWidth={1.5} />} title="No native debugger on this relay."
        hint={os === "windows"
          ? "The native Windows debugger is turned off (ECHODEBUG_NATIVE_DEBUGGER=0). Echo's Universal API itself has no breakpoint or thread-context API."
          : "The relay debugs local processes itself: with ptrace on Linux (local backend) and with the Win32 debug API in Windows builds. Echo's Universal API has no debugger."} />
    );
  if (dbg === "ptrace" && backend !== "local") return <Empty icon={<Bug size={26} strokeWidth={1.5} />} title="Attach to a process first." hint="Pick a process in the Targets panel; the ptrace debugger works on the attached process." />;
  if (dbg === "ptrace" && target?.arch === "arm64")
    return <Empty icon={<Bug size={26} strokeWidth={1.5} />} title="The native debugger is x86-64 only." hint={`${target.name ?? "The attached process"} is an ARM64 (AArch64) process. Breakpoints, stepping, the access finder and the API monitor need an x86-64 target; disassembly and the emulator work on ARM64.`} />;
  return <>{children}</>;
}
