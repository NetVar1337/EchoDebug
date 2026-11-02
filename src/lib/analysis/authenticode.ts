// Authenticode: the PKCS#7 SignedData in a PE file's certificate table (the Security data
// directory holds a *file* offset, so this works on the file on disk, not the mapped image).
// Lists the embedded certificates and the signer, reads the signed image digest, and recomputes
// the Authenticode hash of the file to check it still matches. It does not validate chains or trust.

export type Der = { tag: number; cls: number; constructed: boolean; start: number; hdr: number; len: number; children?: Der[] };

export class DerError extends Error {}

export function parseDer(b: Uint8Array, at = 0, end = b.length, depth = 0): Der[] {
  const out: Der[] = [];
  let p = at;
  while (p < end) {
    if (depth > 32) throw new DerError("DER nesting too deep");
    const t = b[p];
    const cls = t >> 6;
    const constructed = (t & 0x20) !== 0;
    let tag = t & 0x1f;
    let q = p + 1;
    if (tag === 0x1f) { tag = 0; while (b[q] & 0x80) tag = (tag << 7) | (b[q++] & 0x7f); tag = (tag << 7) | b[q++]; }
    let len = b[q++];
    if (len === undefined) throw new DerError("truncated DER");
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) throw new DerError("unsupported DER length");
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + b[q++];
    }
    const node: Der = { tag, cls, constructed, start: p, hdr: q - p, len };
    if (q + len > end) throw new DerError("DER element runs past its parent");
    if (constructed) node.children = parseDer(b, q, q + len, depth + 1);
    out.push(node);
    p = q + len;
  }
  return out;
}

const body = (b: Uint8Array, n: Der) => b.subarray(n.start + n.hdr, n.start + n.hdr + n.len);

export function oid(b: Uint8Array): string {
  const parts: number[] = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join(".");
}

const kOids: Record<string, string> = {
  "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
  "1.2.840.113549.1.7.2": "signedData", "1.3.6.1.4.1.311.2.1.4": "SPC_INDIRECT_DATA",
  "2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512",
  "1.3.14.3.2.26": "sha1", "1.2.840.113549.2.5": "md5",
  "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA", "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
};
export const oidName = (o: string) => kOids[o] ?? o;

function text(b: Uint8Array, n: Der): string {
  const v = body(b, n);
  if (n.tag === 0x1e) { // BMPString
    let s = "";
    for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]);
    return s;
  }
  return new TextDecoder().decode(v);
}

function nameOf(b: Uint8Array, n: Der): Record<string, string> {
  const out: Record<string, string> = {};
  for (const set of n.children ?? []) for (const atv of set.children ?? []) {
    const [o, v] = atv.children ?? [];
    if (o && v) out[oidName(oid(body(b, o)))] = text(b, v);
  }
  return out;
}

function time(b: Uint8Array, n: Der): string {
  const s = new TextDecoder().decode(body(b, n));
  const m = n.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s);
  if (!m) return s;
  const y = n.tag === 0x17 ? (Number(m[1]) >= 50 ? 1900 : 2000) + Number(m[1]) : Number(m[1]);
  return `${y}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? "00"}Z`;
}

const hex = (v: Uint8Array) => Array.from(v, (x) => x.toString(16).padStart(2, "0")).join("");

export type CertInfo = { subject: Record<string, string>; issuer: Record<string, string>; serial: string; notBefore: string; notAfter: string; signatureAlgorithm: string };
export type SignatureInfo = {
  certificateType: number;
  revision: number;
  contentType: string;
  digestAlgorithm: string;
  /** the image digest the signature covers (SPC_INDIRECT_DATA only) */
  signedDigest: string;
  certificates: CertInfo[];
  /** the certificate whose issuer + serial the SignerInfo names */
  signer: CertInfo | null;
};

function cert(b: Uint8Array, n: Der): CertInfo | null {
  const tbs = n.children?.[0];
  const f = tbs?.children ?? [];
  const off = f[0]?.cls === 2 && f[0].tag === 0 ? 1 : 0; // [0] version
  const [serial, sigAlg, issuer, validity, subject] = f.slice(off, off + 5);
  if (!serial || !issuer || !validity || !subject) return null;
  return {
    serial: hex(body(b, serial)).replace(/^00(?=[89a-f])/, ""),
    signatureAlgorithm: sigAlg?.children?.[0] ? oidName(oid(body(b, sigAlg.children[0]))) : "",
    issuer: nameOf(b, issuer),
    subject: nameOf(b, subject),
    notBefore: validity.children?.[0] ? time(b, validity.children[0]) : "",
    notAfter: validity.children?.[1] ? time(b, validity.children[1]) : "",
  };
}

/** The WIN_CERTIFICATE at the Security directory of a PE file, or null when unsigned. */
export function certificateTable(file: Uint8Array): { offset: number; size: number } | null {
  const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
  if (file.length < 0x40 || dv.getUint16(0, true) !== 0x5a4d) return null;
  const nt = dv.getUint32(0x3c, true);
  const oh = nt + 24;
  const is64 = dv.getUint16(oh, true) === 0x20b;
  const dd = oh + (is64 ? 112 : 96);
  const off = dv.getUint32(dd + 4 * 8, true);
  const size = dv.getUint32(dd + 4 * 8 + 4, true);
  return off && size && off + size <= file.length ? { offset: off, size } : null;
}

export function parseSignature(file: Uint8Array): SignatureInfo | null {
  const t = certificateTable(file);
  if (!t) return null;
  const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
  const length = dv.getUint32(t.offset, true);
  const revision = dv.getUint16(t.offset + 4, true);
  const certificateType = dv.getUint16(t.offset + 6, true);
  const blob = file.subarray(t.offset + 8, t.offset + Math.min(length, t.size));
  const [ci] = parseDer(blob);
  const [ctOid, wrapped] = ci?.children ?? [];
  if (!ctOid || oid(body(blob, ctOid)) !== "1.2.840.113549.1.7.2") throw new DerError("certificate table is not PKCS#7 SignedData");
  const sd = wrapped?.children?.[0];
  const parts = sd?.children ?? [];
  const digestAlgs = parts[1];
  const encap = parts[2];
  const certsNode = parts.find((p) => p.cls === 2 && p.tag === 0);
  const signerInfos = parts[parts.length - 1];
  const contentType = encap?.children?.[0] ? oidName(oid(body(blob, encap.children[0]))) : "";
  let signedDigest = "";
  let digestAlgorithm = digestAlgs?.children?.[0]?.children?.[0] ? oidName(oid(body(blob, digestAlgs.children[0].children[0]))) : "";
  if (contentType === "SPC_INDIRECT_DATA") {
    // [0] EXPLICIT SpcIndirectDataContent { data, DigestInfo { algorithm, digest } }
    // PKCS#7 (signtool) puts the SEQUENCE right under [0]; CMS (openssl) wraps it in an OCTET STRING
    let spc = encap?.children?.[1]?.children?.[0];
    let src = blob;
    if (spc && spc.tag === 4 && !spc.constructed) {
      src = body(blob, spc);
      spc = parseDer(src)[0];
    }
    const di = spc?.children?.[1];
    const alg = di?.children?.[0]?.children?.[0];
    const dig = di?.children?.[1];
    if (alg) digestAlgorithm = oidName(oid(body(src, alg)));
    if (dig) signedDigest = hex(body(src, dig));
  }
  const certificates = (certsNode?.children ?? []).map((c) => cert(blob, c)).filter((c): c is CertInfo => c !== null);
  let signer: CertInfo | null = null;
  const si = signerInfos?.children?.[0];
  const ias = si?.children?.[1];
  if (ias?.children?.length === 2) {
    const issuer = nameOf(blob, ias.children[0]);
    const serial = hex(body(blob, ias.children[1])).replace(/^00(?=[89a-f])/, "");
    signer = certificates.find((c) => c.serial === serial && JSON.stringify(c.issuer) === JSON.stringify(issuer)) ?? null;
  }
  return { certificateType, revision, contentType, digestAlgorithm, signedDigest, certificates, signer };
}

/**
 * The Authenticode image hash: every byte of the file except the checksum, the Security directory
 * entry and the certificate table itself (the common layout where the table is last).
 */
export async function authenticodeHash(file: Uint8Array, algorithm: "sha1" | "sha256" = "sha256"): Promise<string> {
  const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
  const nt = dv.getUint32(0x3c, true);
  const oh = nt + 24;
  const is64 = dv.getUint16(oh, true) === 0x20b;
  const checksum = oh + 64;
  const secDir = oh + (is64 ? 112 : 96) + 4 * 8;
  const t = certificateTable(file);
  const end = t ? t.offset : file.length;
  const parts = [file.subarray(0, checksum), file.subarray(checksum + 4, secDir), file.subarray(secDir + 8, end)];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { buf.set(p, o); o += p.length; }
  const d = await crypto.subtle.digest(algorithm === "sha1" ? "SHA-1" : "SHA-256", buf);
  return hex(new Uint8Array(d));
}
