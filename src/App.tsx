import { lazy, useEffect, useRef } from "react";
import ActivityRail from "@/components/ActivityRail";
import CommandPalette from "@/components/CommandPalette";
import GotoDialog from "@/components/GotoDialog";
import InspectorPanel from "@/components/InspectorPanel";
import OutputPanel from "@/components/OutputPanel";
import ScannerPanel from "@/components/ScannerPanel";
import Splash from "@/components/Splash";
import Splitter from "@/components/Splitter";
import StatusBar from "@/components/StatusBar";
import TitleBar from "@/components/TitleBar";
import TooltipLayer from "@/components/TooltipLayer";
import WorkspacePanel from "@/components/WorkspacePanel";
import { hostOs, installAgent, isTauri } from "@/lib/tauri";
import { exportSession, importSession } from "@/lib/session";
import { useConn } from "@/store/conn";
import { applyMotion, useMotion } from "@/store/motion";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { startUpdateLoop } from "@/store/update";
import { Boundary, Lazy } from "@/components/ui";
import { startProvider } from "@/lib/provider";
import { startMcpPolicy } from "@/store/mcp";
import { startMonitors } from "@/store/monitors";
import { startSync } from "@/store/sync";
import ApprovalDialog from "@/components/ApprovalDialog";
import { redo, undo } from "@/lib/history";
import { startProjects } from "@/lib/projects";
import { applyLayout, startWorkspace } from "@/lib/workspace";
import { startAutoPatches } from "@/lib/patchsets";
import { togglePanel, useVisiblePanels, useWindowWidth } from "@/lib/layout";
import ShortcutsDialog from "@/components/ShortcutsDialog";
import Toasts from "@/components/Toasts";

let booted = false;

// Rail panels and settings load on first use, like the workspace views (see WorkspacePanel).
const kLeft = {
  targets: lazy(() => import("@/components/panels/TargetsPanel")),
  modules: lazy(() => import("@/components/panels/ModulesPanel")),
  watch: lazy(() => import("@/components/panels/WatchPanel")),
  names: lazy(() => import("@/components/panels/NamesPanel")),
  mcp: lazy(() => import("@/components/panels/McpPanel")),
  sync: lazy(() => import("@/components/panels/SyncPanel")),
};
const SettingsModal = lazy(() => import("@/components/SettingsModal"));

export default function App() {
  const appRef = useRef<HTMLDivElement>(null);
  const ui = useUi();

  useWindowWidth();
  const vis = useVisiblePanels();

  useEffect(() => {
    // StrictMode runs effects twice in development: boot once
    if (booted) return;
    booted = true;
    log("info", "app", `EchoDebug v${useConn.getState().appVersion}${isTauri() ? "" : " (browser mode)"}`);
    void useConn.getState().init();
    startProvider();
    startMcpPolicy();
    startMonitors();
    startSync();
    startProjects();
    startWorkspace();
    startAutoPatches();
    if (appRef.current) applyLayout(appRef.current);
    if (isTauri()) {
      void hostOs().then((os) => {
        if (os !== "windows") {
          log("info", "agent", `host ${os}: the Echo agent is Windows-only; the relay serves a local /proc backend on Linux`);
          return;
        }
        return installAgent()
          .then((r) => r && log("info", "agent", `echo_debug.as ${r.changed ? "installed/updated" : "up to date"} at ${r.path}`))
          .catch((e) => log("error", "agent", `install failed: ${e}`));
      });
    }
    return startUpdateLoop(() => useUi.getState().autoUpdate);
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = ui.theme;
    if (ui.accent) root.style.setProperty("--accent", ui.accent);
    else root.style.removeProperty("--accent");
  }, [ui.theme, ui.accent]);

  useEffect(() => applyMotion(useMotion.getState().pref), []);

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.shiftKey && e.key.toLowerCase() === "p") {
        e.preventDefault();
        useUi.getState().set({ paletteOpen: !useUi.getState().paletteOpen });
        return;
      }
      if (mod && e.key.toLowerCase() === "g") {
        e.preventDefault();
        useUi.getState().set({ gotoOpen: true });
      }
      if (mod && !e.shiftKey && e.key.toLowerCase() === "k") {
        e.preventDefault();
        useUi.getState().set({ paletteOpen: !useUi.getState().paletteOpen });
        return;
      }
      if (mod && e.shiftKey && e.key.toLowerCase() === "v") {
        e.preventDefault();
        useUi.getState().set({ viewsOpen: !useUi.getState().viewsOpen });
        return;
      }
      // panel toggles: Ctrl+B left, Ctrl+J output, Ctrl+Alt+S scanner, Ctrl+Alt+I inspector
      if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "b") { e.preventDefault(); togglePanel("left"); return; }
      if (mod && !e.shiftKey && !e.altKey && e.key.toLowerCase() === "j") { e.preventDefault(); togglePanel("output"); return; }
      if (mod && e.altKey && e.key.toLowerCase() === "s") { e.preventDefault(); togglePanel("scanner"); return; }
      if (mod && e.altKey && e.key.toLowerCase() === "i") { e.preventDefault(); togglePanel("inspector"); return; }
      if (mod && e.key === "w" && !e.shiftKey) {
        e.preventDefault();
        useUi.getState().closeTab(useUi.getState().tab);
        return;
      }
      if (e.key === "F1" || (mod && e.key === "/")) {
        e.preventDefault();
        useUi.getState().set({ shortcutsOpen: !useUi.getState().shortcutsOpen });
        return;
      }
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement;
      if (mod && !typing && (e.key.toLowerCase() === "z" || e.key.toLowerCase() === "y")) {
        e.preventDefault();
        const isRedo = e.key.toLowerCase() === "y" || e.shiftKey;
        const label = isRedo ? redo() : undo();
        log("info", "edit", label ? `${isRedo ? "redo" : "undo"}: ${label}` : `nothing to ${isRedo ? "redo" : "undo"}`);
      }
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);

  // Session import / export are triggered from the File menu.
  useEffect(() => {
    if (ui.sessionExportOpen) {
      useUi.getState().set({ sessionExportOpen: false });
      void exportSession().catch((e) => log("error", "session", String(e)));
    }
    if (ui.sessionImportOpen) {
      useUi.getState().set({ sessionImportOpen: false });
      void importSession().catch((e) => log("error", "session", String(e)));
    }
  }, [ui.sessionExportOpen, ui.sessionImportOpen]);

  const Left = kLeft[ui.rail] ?? kLeft.targets;
  return (
    <div className="app" ref={appRef}>
      <TitleBar />
      {useConn((s) => s.splash) ? (
        <Splash />
      ) : (
        <div className="app-body" style={{ gridTemplateColumns: [
          "var(--rail-w)",
          vis.left ? "var(--left-w, 300px) 4px" : "",
          "minmax(0, 1fr)",
          vis.inspector ? "4px var(--right-w, 300px)" : "",
        ].filter(Boolean).join(" ") }}>
          <ActivityRail />
          {vis.left && (
            <>
              <Boundary key={ui.rail}><Lazy><Left /></Lazy></Boundary>
              <Splitter axis="x" variable="--left-w" target={appRef} min={220} max={700} />
            </>
          )}
          <div className="center-col" style={{ gridTemplateRows: vis.output ? "minmax(0, 1fr) 4px var(--bottom-h, 220px)" : "minmax(0, 1fr)" }}>
            <div className="center-top" style={{ gridTemplateColumns: vis.scanner ? "var(--scan-w, 320px) 4px minmax(0, 1fr)" : "minmax(0, 1fr)" }}>
              {vis.scanner && (
                <>
                  <ScannerPanel />
                  <Splitter axis="x" variable="--scan-w" target={appRef} min={240} max={640} />
                </>
              )}
              <WorkspacePanel />
            </div>
            {vis.output && (
              <>
                <Splitter axis="y" variable="--bottom-h" target={appRef} min={80} max={640} invert />
                <OutputPanel />
              </>
            )}
          </div>
          {vis.inspector && (
            <>
              <Splitter axis="x" variable="--right-w" target={appRef} min={220} max={620} invert />
              <InspectorPanel />
            </>
          )}
        </div>
      )}
      <StatusBar />
      <TooltipLayer />
      {ui.settingsOpen && <Boundary><Lazy><SettingsModal /></Lazy></Boundary>}
      {ui.gotoOpen && <GotoDialog />}
      {ui.paletteOpen && <CommandPalette />}
      <ApprovalDialog />
      {ui.shortcutsOpen && <ShortcutsDialog />}
      <Toasts />
    </div>
  );
}
