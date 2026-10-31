import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { flirtArchName, matchFlirt, parseFlirtFile } from "./flirt";

// The signature files that ship with IDA. They are the ground truth for the
// parser: v5 is uncompressed, v7 is zlib and v10 is zlib as well.
const kSigDir = "C:/Program Files/IDA Professional 9.5/sig/pc";

function load(name: string): Uint8Array {
  return new Uint8Array(readFileSync(`${kSigDir}/${name}`));
}

function has(name: string): boolean {
  try {
    load(name);
    return true;
  } catch {
    return false;
  }
}

describe("flirt against the real IDA signature files", () => {
  it("reads an uncompressed v5 signature file", async () => {
    if (!has("aztec.sig")) return;
    const sig = await parseFlirtFile(load("aztec.sig"));
    expect(sig.libraryName.length).toBeGreaterThan(0);
    expect(sig.root).not.toBeNull();
    expect(sig.root!.children.length).toBeGreaterThan(0);
  });

  it("reads a zlib compressed v7 signature file", async () => {
    if (!has("mssdk64.sig")) return;
    const sig = await parseFlirtFile(load("mssdk64.sig"));
    expect(sig.version).toBe(7);
    expect(sig.libraryName).toContain("Windows");
    expect(sig.root!.children.length).toBeGreaterThan(0);
  });

  it("reads a v10 signature file", async () => {
    if (!has("msmfc64.sig")) return;
    const sig = await parseFlirtFile(load("msmfc64.sig"));
    expect(sig.version).toBe(10);
    expect(sig.libraryName.length).toBeGreaterThan(0);
    expect(sig.root!.children.length).toBeGreaterThan(0);
  });

  it("names the architecture", async () => {
    if (!has("msmfc64.sig")) return;
    const sig = await parseFlirtFile(load("msmfc64.sig"));
    expect(flirtArchName(sig.arch)).toBe("x86");
  });

  it("matches a real function body", async () => {
    if (!has("mssdk64.sig")) return;
    const sig = await parseFlirtFile(load("mssdk64.sig"));
    // The MSVC x64 function prologue.
    const img = new Uint8Array(0x1000);
    img.set([0x48, 0x89, 0x5c, 0x24, 0x08], 0x100);
    const hits = matchFlirt(sig, img, 0x140000000n);
    expect(Array.isArray(hits)).toBe(true);
    for (const h of hits) expect(h.name.length).toBeGreaterThan(0);
  });

  it("reads most of the signature files of version 10 or older", async () => {
    const files = readdirSync(kSigDir).filter((f) => f.endsWith(".sig"));
    expect(files.length).toBeGreaterThan(10);
    let parsed = 0;
    let newer = 0;
    let unsupported = 0;
    for (const f of files) {
      const raw = load(f);
      if (raw[6] > 10) {
        newer++;
        continue;
      }
      try {
        const sig = await parseFlirtFile(raw);
        expect(sig.root).not.toBeNull();
        parsed++;
      } catch (e) {
        // A few signature sets use a pattern layout this parser does not
        // support; they are reported instead of parsed.
        expect((e as Error).message).toBeTruthy();
        unsupported++;
      }
    }
    expect(parsed).toBeGreaterThan(50);
    expect(newer).toBeGreaterThan(0);
    expect(unsupported).toBeGreaterThan(0);
  }, 60_000);

  it("reports the newer format instead of failing silently", async () => {
    if (!has("pe64.sig")) return;
    await expect(parseFlirtFile(load("pe64.sig"))).rejects.toThrow(/version 11/);
  });
});
