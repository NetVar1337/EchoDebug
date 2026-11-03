// Status-bar update control: progress while downloading, then a "Restart to update" button
import { Download, RotateCw } from "lucide-react";
import { useUpdate } from "@/store/update";

export default function UpdatePill() {
  const u = useUpdate();
  switch (u.phase) {
    case "checking":
      return <span className="status-pill"><span className="dot" data-state="busy" />Checking for updates…</span>;
    case "downloading":
      return (
        <span className="status-pill" title={u.notes || undefined}>
          <span className="dot" data-state="busy" />
          Downloading v{u.version}{u.progress !== null ? ` ${Math.round(u.progress * 100)}%` : "…"}
        </span>
      );
    case "available":
      return (
        <button className="btn small primary" title={u.notes || undefined} onClick={() => void u.download()}>
          <Download size={12} /> Update to v{u.version}
        </button>
      );
    case "ready":
      return (
        <button className="btn small primary" title={u.error || u.notes || "Installs the update and restarts EchoDebug"} onClick={() => void u.restart()}>
          <RotateCw size={12} /> Restart to update (v{u.version})
        </button>
      );
    case "installing":
      return <span className="status-pill"><span className="dot" data-state="busy" />Installing v{u.version}…</span>;
    case "uptodate":
      return <span className="status-pill"><span className="dot" data-state="ok" />Up to date</span>;
    case "error":
      return (
        <button className="btn small" title={u.error} onClick={() => void u.check({ manual: true })}>
          <span className="dot" data-state="bad" /> Update failed, retry
        </button>
      );
    default:
      return null;
  }
}
