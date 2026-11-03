// Batch decryption: run a string-decryption routine at every call site in the emulator and list
// what each call produced.
import { useRef, useState } from "react";
import { labelAddr, parseAddress } from "@/lib/hex";
import { saveText } from "@/lib/save";
import { batchDecrypt, type DecryptRow } from "@/lib/unpacklive";
import { detectDecryptRoutine } from "@/lib/strdec";
import { request } from "@/lib/client";
import type { ListingLine } from "@/lib/analysis/listing";
import { fmtAddr } from "@/lib/hex";
import { useConn } from "@/store/conn";
import { useNames } from "@/store/names";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";
import { CommitInput, NeedsAgent, Progress } from "../ui";

export default function DecryptView() {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const names = useNames();
  const [routine, setRoutine] = useState(ui.selected ?? "");
  const [rows, setRows] = useState<DecryptRow[]>([]);
  const [busy, setBusy] = useState(0);
  const abort = useRef({ aborted: false });

  const run = async () => {
    const a = parseAddress(routine, modules);
    if (a === null) return log("warn", "decrypt", `cannot parse ${routine}`);
    abort.current = { aborted: false };
    setRows([]);
    setBusy(0.01);
    const r = await attempt("decrypt", batchDecrypt(a, modules, { onProgress: (d, t) => setBusy(d / Math.max(1, t)), signal: abort.current }));
    setBusy(0);
    if (r) {
      setRows(r);
      log("info", "decrypt", `${r.filter((x) => x.result).length} of ${r.length} call sites produced a string`);
    }
  };
  /** Auto-detect the decryption routine called from the function at the cursor (#16). */
  const detect = async () => {
    const a = parseAddress(ui.selected || routine, modules);
    if (a === null) return log("warn", "decrypt", "select a function in the disassembly first");
    const disasmOf = async (addr: string, size: number) =>
      (await request<{ results: ListingLine[] }>("disassemble", { address: addr, size }, true).catch(() => null))?.results ?? [];
    const funcLines = await disasmOf(fmtAddr(a), 0x800);
    const top = await detectDecryptRoutine(funcLines, disasmOf);
    if (!top) return log("warn", "decrypt", "no call in this function looks like a decryptor");
    setRoutine(top.target);
    log("info", "decrypt", `detected routine ${top.target} (score ${top.score}: ${top.reasons.join(", ")})`);
  };
  const comment = () => {
    let n = 0;
    for (const r of rows) if (r.result) { names.comment(r.site, `decrypted: ${r.result.text}`); n++; }
    log("info", "decrypt", `${n} comments added`);
  };

  return (
    <NeedsAgent ext>
      <div className="list-col" style={{ height: "100%", borderRight: "none" }}>
        <div className="toolbar">
          <span className="faint">routine</span>
          <CommitInput value={routine} placeholder="address of the decryption routine" onCommit={setRoutine} width={240} />
          <button className="btn small primary" disabled={!routine || busy > 0} onClick={() => void run()}>Decrypt every call site</button>
          <button className="btn small" disabled={busy > 0} title="Find the decryption routine called from the function at the cursor" onClick={() => void detect()}>Detect routine</button>
          {busy > 0 && <button className="btn small" onClick={() => { abort.current.aborted = true; }}>Stop</button>}
          <span className="grow" />
          <button className="btn small" disabled={!rows.some((r) => r.result)} onClick={comment}>Comment the call sites</button>
          <button className="btn small" disabled={!rows.length} onClick={() => void saveText("decrypted-strings.json", JSON.stringify(rows.map((r) => ({ ...r, result: r.result ? { ...r.result, address: "0x" + r.result.address.toString(16) } : null })), null, 2))}>Export</button>
        </div>
        {busy > 0 && <Progress value={busy} />}
        <div className="faint" style={{ fontSize: 12, padding: "4px 10px" }}>Each call site is emulated from the start of its function to the instruction after the call (the process is never modified); the decrypted text is read from the buffers the run wrote.</div>
        <div className="vlist">
          <table className="table mono">
            <thead><tr><th>Call site</th><th>Result</th><th>Run</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.site} onClick={() => ui.goDisasm(r.site)}>
                  <td className="link">{labelAddr(r.site, modules)}</td>
                  <td className={r.result ? "accent" : "faint"}>{r.result ? `${r.result.encoding === "utf16" ? "L" : ""}${JSON.stringify(r.result.text)}` : r.error ?? "no string written"}</td>
                  <td className="faint">{r.stop}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </NeedsAgent>
  );
}
