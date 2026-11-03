import { describe, expect, it } from "vitest";
import { antiPatterns, scanAntiDebug, scanAntiImports, scanAntiStrings } from "./antidebug";
import { parsePe } from "./pe";

/** A mapped PE with one executable section holding the given bytes. */
function buildPe(body: Uint8Array): Uint8Array {
  const image = new Uint8Array(0x1000 + body.length);
  const dv = new DataView(image.buffer);
  image[0] = 0x4d; image[1] = 0x5a;
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x4550, true);
  const fh = 0x84;
  dv.setUint16(fh, 0x8664, true);
  dv.setUint16(fh + 2, 1, true);
  dv.setUint16(fh + 16, 0xf0, true);
  const oh = fh + 20;
  dv.setUint16(oh, 0x20b, true);
  dv.setUint32(oh + 16, 0x1000, true);
  dv.setBigUint64(oh + 24, 0x140000000n, true);
  dv.setUint32(oh + 56, image.length, true);
  dv.setUint16(oh + 68, 3, true);
  dv.setUint32(oh + 108, 16, true);
  const st = oh + 0xf0;
  image.set(new TextEncoder().encode(".text"), st);
  dv.setUint32(st + 8, 0x1000, true);
  dv.setUint32(st + 12, body.length, true);
  dv.setUint32(st + 16, 0x1000, true);
  dv.setUint32(st + 36, 0x60000020, true);
  image.set(body, 0x1000);
  return image;
}

describe("anti-debug scanner", () => {
  it("finds the INT 2D breakpoint check", () => {
    const body = new Uint8Array(0x100);
    body.set([0xcd, 0x2d], 0x10);
    const hits = scanAntiDebug(buildPe(body), 0x140000000n);
    const hit = hits.find((h) => h.kind === "int2d");
    expect(hit).toBeDefined();
    expect(hit!.rva).toBe(0x1010);
    expect(hit!.address).toBe("0x140001010");
    expect(hit!.bytes).toBe("cd2d");
  });

  it("finds the red-pill descriptor table reads", () => {
    const body = new Uint8Array(0x100);
    body.set([0x0f, 0x01, 0x0d], 0x20); // sidt
    body.set([0x0f, 0x01, 0x04], 0x30); // sgdt
    const hits = scanAntiDebug(buildPe(body));
    expect(hits.some((h) => h.kind === "sidt")).toBe(true);
    expect(hits.some((h) => h.kind === "sgdt")).toBe(true);
  });

  it("finds a PEB read", () => {
    const body = new Uint8Array(0x100);
    body.set([0x64, 0xa1, 0x30, 0x00, 0x00, 0x00], 0x40);
    const hits = scanAntiDebug(buildPe(body));
    const hit = hits.find((h) => h.kind === "peb");
    expect(hit).toBeDefined();
    expect(hit!.rva).toBe(0x1040);
  });

  it("finds the hypervisor check", () => {
    const body = new Uint8Array(0x100);
    body.set([0x0f, 0x01, 0xc1], 0x08);
    expect(scanAntiDebug(buildPe(body)).some((h) => h.kind === "vmcall")).toBe(true);
  });

  it("returns nothing for a section without checks", () => {
    const body = new Uint8Array(0x100).fill(0x90);
    expect(scanAntiDebug(buildPe(body))).toHaveLength(0);
  });

  it("ignores non-executable sections", () => {
    const img = buildPe(new Uint8Array(0x100));
    const dv = new DataView(img.buffer);
    dv.setUint32(0x84 + 20 + 0xf0 + 36, 0x40000040, true);
    expect(scanAntiDebug(img)).toHaveLength(0);
  });

  it("flags the debugger-detection imports", () => {
    const hits = scanAntiImports([
      { name: "IsDebuggerPresent" },
      { name: "kernel32.dll" },
      { name: "FindWindowA" },
      { name: "NtSetInformationThread" },
    ]);
    const kinds = hits.map((h) => h.kind);
    expect(kinds.filter((k) => k === "debug-api")).toHaveLength(2);
    expect(kinds).not.toContain("debugger-window");
  });

  it("finds a debugger window name in the strings", () => {
    const hits = scanAntiStrings([{ rva: 0x2000, text: "OllyDbg" }], 0x140000000n);
    expect(hits).toHaveLength(1);
    expect(hits[0].kind).toBe("debugger-window");
    expect(hits[0].detail).toContain("ollydbg");
    expect(hits[0].address).toBe("0x140002000");
  });

  it("ignores ordinary strings", () => {
    expect(scanAntiStrings([{ rva: 0, text: "hello world" }])).toHaveLength(0);
  });

  it("has no empty pattern", () => {
    for (const p of antiPatterns()) expect(p.bytes.length).toBeGreaterThan(0);
  });

  it("parses the PE it builds", () => {
    expect(parsePe(buildPe(new Uint8Array(0x10))).sections[0].x).toBe(true);
  });
});
