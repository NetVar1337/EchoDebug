import { useEffect, useRef } from "react";
import ActivityRail from "@/components/ActivityRail";
import GotoDialog from "@/components/GotoDialog";
import InspectorPanel from "@/components/InspectorPanel";
import OutputPanel from "@/components/OutputPanel";
import ScannerPanel from "@/components/ScannerPanel";
import SettingsModal from "@/components/SettingsModal";
import Splitter from "@/components/Splitter";
import StatusBar from "@/components/StatusBar";
import TopBar from "@/components/TopBar";
import WorkspacePanel from "@/components/WorkspacePanel";
import AiPanel from "@/components/panels/AiPanel";
import ModulesPanel from "@/components/panels/ModulesPanel";
import TargetsPanel from "@/components/panels/TargetsPanel";
import WatchPanel from "@/components/panels/WatchPanel";
import { installAgent, isTauri } from "@/lib/tauri";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { startUpdateLoop } from "@/store/update";
import { Boundary } from "@/components/ui";

const kLeft = { targets: TargetsPanel, modules: ModulesPanel, watch: WatchPanel, ai: AiPanel };

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

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "g") {
        e.preventDefault();
        useUi.getState().set({ gotoOpen: true });
      }
    };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, []);

  const Left = kLeft[ui.rail] ?? TargetsPanel;
  return (
    <div className="app" ref={appRef}>
      <TopBar />
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
      <StatusBar />
      {ui.settingsOpen && <Boundary><SettingsModal /></Boundary>}
      {ui.gotoOpen && <GotoDialog />}
    </div>
  );
}
