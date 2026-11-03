// YARA: write or load rules, run them over a module image, every module, or a memory range.
import { useMemo, useState } from "react";
import { Play, Upload } from "lucide-react";
import { fmtAddr, labelAddr, parseAddress, toBig, type Module } from "@/lib/hex";
import { loadImage, readRange } from "@/lib/memory";
import { parsePe } from "@/lib/analysis/pe";
import { parseYara, scanYara, YaraError, type YaraMatch } from "@/lib/analysis/yara";
import { useConn } from "@/store/conn";
import { log } from "@/store/output";
import { useUi } from "@/store/ui";
import { useYara } from "@/store/yara";
import { NeedsAgent, Progress } from "../ui";

type Hit = YaraMatch & { where: string; base: bigint };

async function scanModule(rules: ReturnType<typeof parseYara>, m: Module): Promise<Hit[]> {
  const img = await loadImage(m);
  let entrypoint: number | undefined;
  try { entrypoint = parsePe(img).entryRva; } catch { /* ELF / no headers */ }
  return scanYara(rules, img, { entrypoint }).map((h) => ({ ...h, where: m.name, base: toBig(m.base) }));
}

export default function YaraView() {
  const ui = useUi();
  const { modules } = useConn();
  const { rules, setRules } = useYara();
  const [target, setTarget] = useState<string>("__main");
  const [rangeAddr, setRangeAddr] = useState("");
  const [rangeSize, setRangeSize] = useState("0x10000");
  const [hits, setHits] = useState<Hit[]>([]);
  const [busy, setBusy] = useState(0);
  const [error, setError] = useState("");

  const parsed = useMemo(() => {
    try {
      const r = parseYara(rules);
      return { rules: r, error: "" };
    } catch (e) {
      return { rules: null, error: e instanceof YaraError ? e.message : String(e) };
    }
  }, [rules]);

  const run = async () => {
    if (!parsed.rules) return;
    setError("");
    setHits([]);
    setBusy(0.01);
    try {
      let out: Hit[] = [];
      if (target === "__range") {
        const a = parseAddress(rangeAddr, modules);
        const n = Number(rangeSize);
        if (a === null || !(n > 0 && n <= 256 * 1024 * 1024)) throw new Error("enter an address and a size up to 256 MiB");
        const buf = await readRange(a, n, (d, t) => setBusy(d / t));
        out = scanYara(parsed.rules, buf).map((h) => ({ ...h, where: fmtAddr(a), base: a }));
      } else {
        const main = modules.find((m) => m.base === useConn.getState().target?.base) ?? modules[0];
        const list = target === "__all" ? modules : target === "__main" ? (main ? [main] : []) : modules.filter((m) => m.name === target);
        for (const [i, m] of list.entries()) {
          out = out.concat(await scanModule(parsed.rules, m).catch((e) => { log("warn", "yara", `${m.name}: ${e}`); return []; }));
          setBusy((i + 1) / list.length);
        }
      }
      setHits(out);
      log("info", "yara", `${out.length} rule matches`);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
    setBusy(0);
  };
  const loadFile = async () => {
    const input = Object.assign(document.createElement("input"), { type: "file", accept: ".yar,.yara,.txt" });
    const { promise, resolve } = Promise.withResolvers<File | null>();
    input.onchange = () => resolve(input.files?.[0] ?? null);
    input.click();
    const f = await promise;
    if (f) setRules(await f.text());
  };

  return (
    <NeedsAgent>
      <div className="split-h" style={{ gridTemplateColumns: "minmax(320px, 45%) minmax(0, 1fr)" }}>
        <div className="list-col">
          <div className="toolbar">
            <span className="panel-title grow">Rules</span>
            <button className="btn small" onClick={() => void loadFile()}><Upload size={12} /> Load .yar</button>
          </div>
          <textarea className="textarea mono" style={{ flex: 1, resize: "none", border: "none", borderRadius: 0 }} spellCheck={false} value={rules} onChange={(e) => setRules(e.target.value)} />
          <div className="toolbar">
            <span className={parsed.error ? "danger" : "faint"} style={{ fontSize: 12 }}>{parsed.error || `${parsed.rules?.length ?? 0} rules compiled`}</span>
          </div>
        </div>
        <div className="list-col" style={{ borderRight: "none" }}>
          <div className="toolbar">
            <select className="select" value={target} onChange={(e) => setTarget(e.target.value)}>
              <option value="__main">main module</option>
              <option value="__all">every module</option>
              <option value="__range">memory range…</option>
              {modules.map((m) => <option key={m.base} value={m.name}>{m.name}</option>)}
            </select>
            {target === "__range" && <>
              <input className="input mono" style={{ width: 170 }} placeholder="address" value={rangeAddr} onChange={(e) => setRangeAddr(e.target.value)} />
              <input className="input mono" style={{ width: 90 }} placeholder="size" value={rangeSize} onChange={(e) => setRangeSize(e.target.value)} />
            </>}
            <button className="btn small primary" disabled={!parsed.rules || busy > 0} onClick={() => void run()}><Play size={12} /> Scan</button>
            <span className="grow" />
            <span className="faint" style={{ fontSize: 12 }}>{hits.length} matches</span>
          </div>
          {busy > 0 && <Progress value={busy} />}
          {error && <div className="panel-section danger">{error}</div>}
          <div className="vlist">
            {hits.map((h, i) => (
              <div key={i} className="panel-section">
                <div className="row">
                  <span className="accent mono">{h.rule}</span>
                  {h.tags.map((t) => <span key={t} className="pill">{t}</span>)}
                  <span className="grow" />
                  <span className="faint mono">{h.where}</span>
                </div>
                {Object.keys(h.meta).length > 0 && <div className="faint" style={{ fontSize: 12 }}>{Object.entries(h.meta).map(([k, v]) => `${k}: ${v}`).join(" · ")}</div>}
                <table className="table mono"><tbody>
                  {h.strings.slice(0, 50).map((s, j) => {
                    const a = fmtAddr(h.base + BigInt(s.offset));
                    return (
                      <tr key={j} onClick={() => ui.select(a)} onDoubleClick={() => ui.goMemory(a)}>
                        <td style={{ width: 80 }}>{s.id}</td><td className="link">{labelAddr(a, modules)}</td><td className="faint ellipsis">{s.data.replace(/(..)/g, "$1 ")}</td>
                      </tr>
                    );
                  })}
                  {h.strings.length > 50 && <tr><td colSpan={3} className="faint">{h.strings.length - 50} more</td></tr>}
                </tbody></table>
              </div>
            ))}
          </div>
        </div>
      </div>
    </NeedsAgent>
  );
}
