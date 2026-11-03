import { useEffect, useState } from "react";
import type { Module } from "@/lib/hex";
import { archLabel, type Arch } from "@/lib/analysis/arch";
import { knownArch, moduleArch } from "@/lib/archlive";

/** The module's architecture: known at once when the backend reports it, else after a header read. */
export function useModuleArch(m: Module | undefined): Arch | null {
  const [arch, setArch] = useState<Arch | null>(() => knownArch(m));
  useEffect(() => {
    setArch(knownArch(m));
    if (!m) return;
    let live = true;
    void moduleArch(m).then((a) => live && setArch(a));
    return () => {
      live = false;
    };
  }, [m?.name, m?.base, m?.arch]);
  return arch;
}

/** "ARM64" / "x86" pill; x86-64 (the default) shows nothing unless `always`. */
export function ArchBadge({ arch, always = false }: { arch: Arch | null | undefined; always?: boolean }) {
  if (!arch || (arch === "x86_64" && !always)) return null;
  return (
    <span className={arch === "arm64" ? "pill accent" : "pill"} style={{ marginLeft: 6 }} data-tip={arch === "arm64" ? "AArch64 code: decoded by the relay's arm64 disassembler" : undefined}>
      {archLabel(arch)}
    </span>
  );
}

/** Badge for one module (reads its header once when the backend did not say). */
export function ModuleArchBadge({ module, always = false }: { module: Module | undefined; always?: boolean }) {
  return <ArchBadge arch={useModuleArch(module)} always={always} />;
}
