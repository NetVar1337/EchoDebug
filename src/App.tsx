import { useEffect, useRef } from "react";
import ActivityRail from "@/components/ActivityRail";
import CommandPalette from "@/components/CommandPalette";
import GotoDialog from "@/components/GotoDialog";
import InspectorPanel from "@/components/InspectorPanel";
import OutputPanel from "@/components/OutputPanel";
import ScannerPanel from "@/components/ScannerPanel";
import SettingsModal from "@/components/SettingsModal";
import Splash from "@/components/Splash";
import Splitter from "@/components/Splitter";
import StatusBar from "@/components/StatusBar";
import TitleBar from "@/components/TitleBar";
import TooltipLayer from "@/components/TooltipLayer";
import WorkspacePanel from "@/components/WorkspacePanel";
import AiPanel from "@/components/panels/AiPanel";
import ModulesPanel from "@/components/panels/ModulesPanel";
import NamesPanel from "@/components/panels/NamesPanel";
import TargetsPanel from "@/components/panels/TargetsPanel";
import WatchPanel from "@/components/panels/WatchPanel";
import { installAgent, isTauri } from "@/lib/tauri";
import { exportSession, importSession } from "@/lib/session";
import { useConn } from "@/store/conn";
import { applyMotion, useMotion } from "@/store/motion";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { startUpdateLoop } from "@/store/update";
import { Boundary } from "@/components/ui";

const kLeft = { targets: TargetsPanel, modules: ModulesPanel, watch: WatchPanel, names: NamesPanel, ai: AiPanel };

export default function App() {
  const appRef = useRef<HTMLDivElement>(null);
  const ui = useUi();

  useEffect(() => {
    log("info", "app", `EchoDebug v${useConn.getState().appVersion}${isTauri() ? "" : " (browser mode)"}`);
    void useConn.getState().init();
    if (isTauri()) {
      void installAgent()
        .then((r) => r && log("info", "agent", `echo_debug.as ${r.changed ? "installed/updated" : "up to date"} at ${r.path}`))
        .catch((e) => log("error", "agent", `install failed: ${e}`));
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

  const Left = kLeft[ui.rail] ?? TargetsPanel;
  return (
    <div className="app" ref={appRef}>
      <TitleBar />
      {useConn((s) => s.splash) ? (
        <Splash />
      ) : (
        <div className="app-body">
          <ActivityRail />
          <Boundary key={ui.rail}><Left /></Boundary>
          <Splitter axis="x" variable="--left-w" target={appRef} min={220} max={700} />
          <div className="center-col">
            <div className="center-top">
              <ScannerPanel />
              <Splitter axis="x" variable="--scan-w" target={appRef} min={240} max={640} />
              <WorkspacePanel />
            </div>
            <Splitter axis="y" variable="--bottom-h" target={appRef} min={80} max={640} invert />
            <OutputPanel />
          </div>
          <Splitter axis="x" variable="--right-w" target={appRef} min={220} max={620} invert />
          <InspectorPanel />
        </div>
      )}
      <StatusBar />
      <TooltipLayer />
      {ui.settingsOpen && <Boundary><SettingsModal /></Boundary>}
      {ui.gotoOpen && <GotoDialog />}
      {ui.paletteOpen && <CommandPalette />}
    </div>
  );
}
