import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { mapPeFile, parsePe } from "./pe";
import { imphash, parseDebug, parseRelocs, parseRich, parseTls } from "./peextra";
import { authenticodeHash, parseSignature } from "./authenticode";
import { buildTestPe } from "./testpe";

const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));

describe("PE details on an lld-link fixture (ground truth from pefile)", () => {
  const file = fixture("fix.exe");
  const img = mapPeFile(file);
  const pe = parsePe(img);

  it("maps the file and computes imphash", () => {
    expect(pe.imports.map((d) => d.dll.toLowerCase())).toEqual(["kernel32.dll"]);
    expect(imphash(pe)).toBe("855fe313bcb171bd90823be6a896a99c");
  });
  it("reads TLS callbacks, relocations and the CodeView entry", () => {
    expect(parseTls(img, pe.imageBase, pe)!.callbacks).toEqual([0x140001000n]);
    expect(parseRelocs(img, pe).total).toBe(7);
    const cv = parseDebug(img, pe).find((d) => d.codeview)!.codeview!;
    expect(cv).toMatchObject({ format: "RSDS", guid: "E5F4837E-BE62-2C4A-4C4C-44205044422E", age: 1, path: "fix.pdb" });
    expect(cv.symbolKey).toBe("E5F4837EBE622C4A4C4C44205044422E1");
  });
  it("has no Rich header (lld does not write one) and no signature", () => {
    expect(parseRich(img)).toBeNull();
    expect(parseSignature(file)).toBeNull();
  });
});

describe("Rich header", () => {
  it("decodes the entries and checks the checksum", () => {
    const entries = [[0x0104, 30148, 12], [0x0103, 30148, 3], [0x0001, 0, 87]];
    const img = buildTestPe([{ name: ".text", rva: 0x1000, bytes: new Uint8Array(16) }], {}, {
      headerBytes: (b) => {
        const dv = new DataView(b.buffer);
        // the DOS header up to e_lfanew, then the stub; DanS at 0x80, e_lfanew moved past the block
        const dans = 0x80;
        const rich = dans + 16 + entries.length * 8;
        const lfanew = 0x100;
        b.copyWithin(lfanew, 0x80, 0x80 + 0x200);
        dv.setUint32(0x3c, lfanew, true);
        let csum = dans;
        const rol = (v: number, n: number) => ((v << (n & 31)) | (v >>> (32 - (n & 31)))) >>> 0;
        for (let i = 0; i < dans; i++) if (i < 0x3c || i >= 0x40) csum = (csum + rol(b[i], i)) >>> 0;
        for (const [p, bld, c] of entries) csum = (csum + rol(((p << 16) | bld) >>> 0, c)) >>> 0;
        const key = csum;
        dv.setUint32(dans, 0x536e6144 ^ key, true);
        for (let i = 1; i < 4; i++) dv.setUint32(dans + i * 4, key, true);
        entries.forEach(([p, bld, c], i) => { dv.setUint32(dans + 16 + i * 8, (((p << 16) | bld) ^ key) >>> 0, true); dv.setUint32(dans + 20 + i * 8, (c ^ key) >>> 0, true); });
        dv.setUint32(rich, 0x68636952, true);
        dv.setUint32(rich + 4, key, true);
      },
    });
    const r = parseRich(img)!;
    expect(r.entries).toEqual(entries.map(([prodId, build, count]) => ({ prodId, build, count })));
    expect(r.checksumValid).toBe(true);
    img[0x10] ^= 1; // a DOS header byte changed: the checksum no longer matches
    expect(parseRich(img)!.checksumValid).toBe(false);
  });
});

describe("Authenticode", () => {
  const file = fixture("fix-signed.exe");
  it("lists the signer and the signed digest, and the digest matches the file", async () => {
    const s = parseSignature(file)!;
    expect(s.certificateType).toBe(2);
    expect(s.contentType).toBe("SPC_INDIRECT_DATA");
    expect(s.digestAlgorithm).toBe("sha256");
    expect(s.signedDigest).toBe("6b995689d9e5ef37dd42531159e1a41b7bd53b3a12d9d12ea5c858fa24510991");
    expect(s.certificates).toHaveLength(1);
    expect(s.signer?.subject).toEqual({ C: "NO", O: "EchoDebug Tests", CN: "EchoDebug Test Signer" });
    expect(s.signer?.serial).toBe("48d24d75efea085185cc135c51837e7ef561e3ff");
    expect(await authenticodeHash(file)).toBe(s.signedDigest);
    const tampered = file.slice();
    tampered[0x400] ^= 0xff;
    expect(await authenticodeHash(tampered)).not.toBe(s.signedDigest);
  });
});
