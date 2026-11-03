// PE Browser panes: Details (Rich, TLS, relocations, debug/PDB + symbol loading, imphash,
// Authenticode) and Resources (version, strings, manifest, dialogs, icons).
import { useEffect, useMemo, useState } from "react";
import { fmtAddr, labelAddr, toBig, type Module } from "@/lib/hex";
import { loadImage } from "@/lib/memory";
import { readModuleFileBytes } from "@/lib/modfile";
import { loadPdb } from "@/lib/pdb";
import { parsePe, type PeInfo } from "@/lib/analysis/pe";
import { imphash, parseDebug, parseRelocs, parseRich, parseTls } from "@/lib/analysis/peextra";
import { authenticodeHash, parseSignature, type SignatureInfo } from "@/lib/analysis/authenticode";
import { summarizeResources, type ResourceSummary } from "@/lib/analysis/resources";
import { useConn } from "@/store/conn";
import { attempt, log } from "@/store/output";
import { useUi } from "@/store/ui";

function useImage(m: Module) {
  const [state, setState] = useState<{ img: Uint8Array; pe: PeInfo } | null>(null);
  useEffect(() => {
    let live = true;
    setState(null);
    void loadImage(m).then((img) => {
      try { if (live) setState({ img, pe: parsePe(img) }); } catch { /* not PE */ }
    }).catch(() => undefined);
    return () => { live = false; };
  }, [m.name, m.base]);
  return state;
}

const hx = (n: number | bigint) => "0x" + n.toString(16).toUpperCase();

export function PeDetails({ m }: { m: Module }) {
  const ui = useUi();
  const modules = useConn((s) => s.modules);
  const st = useImage(m);
  const [sig, setSig] = useState<{ info: SignatureInfo | null; actual: string; path: string } | null>(null);
  const [busy, setBusy] = useState("");
  const d = useMemo(() => {
    if (!st) return null;
    const { img, pe } = st;
    return { rich: parseRich(img), tls: parseTls(img, toBig(m.base), pe), relocs: parseRelocs(img, pe, 2000), debug: parseDebug(img, pe), imphash: imphash(pe) };
  }, [st, m.base]);
  if (!st || !d) return <div className="empty"><div className="empty-title">Reading image…</div></div>;

  const loadSymbols = async () => {
    setBusy("symbols");
    // a click here is the user's go-ahead to ask the symbol servers
    const r = await attempt("symbols", loadPdb(m, { download: true }));
    setBusy("");
    if (r && r.status !== "loaded") log("warn", "symbols", `${m.name}: ${r.error ?? r.status}`);
  };
  const checkSig = async () => {
    setBusy("sig");
    const f = await attempt("signature", readModuleFileBytes(m));
    if (f) {
      try {
        const info = parseSignature(f.bytes);
        const alg = info?.digestAlgorithm === "sha1" ? "sha1" : "sha256";
        setSig({ info, actual: info ? await authenticodeHash(f.bytes, alg) : "", path: f.path });
      } catch (e) {
        log("error", "signature", String(e instanceof Error ? e.message : e));
      }
    }
    setBusy("");
  };
  const cv = d.debug.find((x) => x.codeview)?.codeview;

  return (
    <div className="vlist">
      <div className="panel-section">
        <div className="label">Identity</div>
        <div className="kv">
          <span>imphash</span><span className="mono selectable">{d.imphash || "—"}</span>
          {cv && <><span>PDB</span><span className="mono">{cv.path}</span><span>GUID / age</span><span className="mono">{cv.guid} / {cv.age}</span><span>symbol key</span><span className="mono selectable">{cv.symbolKey}</span></>}
        </div>
        <div className="row">
          <button className="btn small" disabled={!cv || busy !== ""} onClick={() => void loadSymbols()}>{busy === "symbols" ? "Loading…" : "Load PDB symbols"}</button>
          <button className="btn small" onClick={() => ui.setTab("symbols")}>Symbols view</button>
          <span className="faint" style={{ fontSize: 12 }}>local copies first (symbol path, cache), then the configured symbol servers; names every function and data symbol</span>
        </div>
      </div>

      <div className="panel-section">
        <div className="label">Authenticode</div>
        <div className="row">
          <button className="btn small" disabled={busy !== ""} onClick={() => void checkSig()}>{busy === "sig" ? "Reading file…" : "Check the signature (reads the file on disk)"}</button>
        </div>
        {sig && !sig.info && <div className="faint">{sig.path}: not signed (no certificate table).</div>}
        {sig?.info && (
          <>
            <div className="kv">
              <span>file</span><span className="mono">{sig.path}</span>
              <span>content</span><span>{sig.info.contentType} · {sig.info.digestAlgorithm}</span>
              <span>signed digest</span><span className="mono">{sig.info.signedDigest || "—"}</span>
              <span>file digest</span><span className={`mono ${sig.info.signedDigest && sig.actual === sig.info.signedDigest ? "ok" : "danger"}`}>{sig.actual} {sig.info.signedDigest ? (sig.actual === sig.info.signedDigest ? "(matches)" : "(DOES NOT MATCH)") : ""}</span>
              <span>signer</span><span>{sig.info.signer ? Object.entries(sig.info.signer.subject).map(([k, v]) => `${k}=${v}`).join(", ") : "—"}</span>
            </div>
            <table className="table"><thead><tr><th>Subject</th><th>Issuer</th><th>Valid</th></tr></thead><tbody>
              {sig.info.certificates.map((c, i) => <tr key={i}><td>{c.subject.CN ?? c.subject.O}</td><td className="faint">{c.issuer.CN ?? c.issuer.O}</td><td className="faint">{c.notBefore.slice(0, 10)} – {c.notAfter.slice(0, 10)}</td></tr>)}
            </tbody></table>
            <div className="faint" style={{ fontSize: 12 }}>Integrity check only: the chain and trust are not validated.</div>
          </>
        )}
      </div>

      <div className="panel-section">
        <div className="label">Rich header</div>
        {!d.rich ? <div className="faint">none (not linked by Microsoft's linker, or stripped)</div> : (
          <>
            <div className="faint">key {hx(d.rich.key)} · checksum {d.rich.checksumValid ? <span className="ok">valid</span> : <span className="danger">invalid (edited or forged)</span>}</div>
            <table className="table mono"><thead><tr><th>prodid</th><th>build</th><th>count</th></tr></thead><tbody>
              {d.rich.entries.map((e, i) => <tr key={i}><td>{hx(e.prodId)}</td><td>{e.build}</td><td>{e.count}</td></tr>)}
            </tbody></table>
          </>
        )}
      </div>

      <div className="panel-section">
        <div className="label">TLS</div>
        {!d.tls ? <div className="faint">no TLS directory</div> : (
          <>
            <div className="faint">callback array at {fmtAddr(d.tls.callbacksAddress)} · {d.tls.callbacks.length} callbacks (they run before the entry point)</div>
            {d.tls.callbacks.map((c) => <div key={String(c)} className="mono link" onClick={() => ui.goDisasm(fmtAddr(c))}>{labelAddr(c, modules)}</div>)}
          </>
        )}
      </div>

      <div className="panel-section">
        <div className="label">Relocations</div>
        <div className="faint">{d.relocs.total} fixups in {d.relocs.blocks.length} pages · {Object.entries(d.relocs.byType).map(([k, v]) => `${k} ${v}`).join(" · ") || "none (image cannot be rebased)"}</div>
      </div>

      <div className="panel-section">
        <div className="label">Debug directory</div>
        <table className="table mono"><tbody>
          {d.debug.map((e, i) => <tr key={i}><td>{e.typeName}</td><td className="faint">{e.size} bytes</td><td className="faint">{e.timestamp ? new Date(e.timestamp * 1000).toISOString().slice(0, 10) : ""}</td></tr>)}
        </tbody></table>
      </div>
    </div>
  );
}

function icoUrl(ico: Uint8Array): string {
  let s = "";
  for (const b of ico) s += String.fromCharCode(b);
  return `data:image/x-icon;base64,${btoa(s)}`;
}

export function PeResources({ m }: { m: Module }) {
  const st = useImage(m);
  const r: ResourceSummary | null = useMemo(() => (st ? summarizeResources(st.img, st.pe) : null), [st]);
  if (!r) return <div className="empty"><div className="empty-title">Reading image…</div></div>;
  if (!r.leaves.length) return <div className="empty"><div className="empty-title">No resources.</div></div>;
  return (
    <div className="vlist">
      {r.icons.length > 0 && (
        <div className="panel-section">
          <div className="label">Icons</div>
          <div className="row wrap">{r.icons.map((i) => <img key={String(i.name)} src={icoUrl(i.ico)} alt={`icon ${i.name}`} title={`group ${i.name}`} style={{ width: 32, height: 32, imageRendering: "pixelated" }} />)}</div>
        </div>
      )}
      {r.version && (
        <div className="panel-section">
          <div className="label">Version</div>
          <div className="kv">
            <span>file version</span><span>{r.version.fileVersion}</span>
            <span>product version</span><span>{r.version.productVersion}</span>
            {Object.entries(r.version.strings).flatMap(([lang, kv]) => Object.entries(kv).flatMap(([k, v]) => [<span key={lang + k + "k"}>{k}</span>, <span key={lang + k}>{v}</span>]))}
          </div>
        </div>
      )}
      {r.manifest && <div className="panel-section"><div className="label">Manifest</div><pre className="mcp-result">{r.manifest}</pre></div>}
      {r.dialogs.map((dl) => (
        <div key={String(dl.name)} className="panel-section">
          <div className="label">Dialog {String(dl.name)}: “{dl.dialog.title}” {dl.dialog.cx}×{dl.dialog.cy}</div>
          <table className="table mono"><tbody>{dl.dialog.controls.map((c, i) => <tr key={i}><td>{c.cls}</td><td>{c.text}</td><td className="faint">id {c.id}</td></tr>)}</tbody></table>
        </div>
      ))}
      {r.strings.length > 0 && (
        <div className="panel-section">
          <div className="label">String table ({r.strings.length})</div>
          <table className="table mono"><tbody>{r.strings.slice(0, 2000).map((s) => <tr key={s.id}><td className="faint" style={{ width: 70 }}>{s.id}</td><td>{s.text}</td></tr>)}</tbody></table>
        </div>
      )}
      <div className="panel-section">
        <div className="label">All resources ({r.leaves.length})</div>
        <table className="table mono"><tbody>{r.leaves.map((l, i) => <tr key={i}><td>{l.typeName}</td><td>{String(l.name)}</td><td className="faint">lang {l.lang}</td><td className="faint">{l.size} bytes @ {hx(l.rva)}</td></tr>)}</tbody></table>
      </div>
    </div>
  );
}
