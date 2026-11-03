import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { mapPeFile, parsePe } from "./pe";
import { listExceptionHandlers, parseUnwindInfo, resolveHandlerName, tlsCallbacks } from "./seh";
import { buildTestPe } from "./testpe";

const fixture = (n: string) => new Uint8Array(readFileSync(new URL(`./fixtures/${n}`, import.meta.url)));

describe("SEH on a clang/lld fixture with __try/__except/__finally", () => {
  const img = mapPeFile(fixture("fix-seh.exe"));
  const pe = parsePe(img);
  const r = listExceptionHandlers(img, pe);

  it("reads the unwind codes like llvm-objdump --unwind-info", () => {
    const u = parseUnwindInfo(img, 0x20d8)!;
    expect(u).toMatchObject({ version: 1, flags: 3, prologSize: 11, frameReg: 5, frameOffset: 2 });
    expect(u.codes.map((c) => [c.offset, c.name, c.text])).toEqual([
      [0x0b, "SET_FPREG", "frame register = rsp + 0x20"],
      [0x06, "ALLOC_SMALL", "sub rsp, 0x28"],
      [0x02, "PUSH_NONVOL", "push rsi"],
      [0x01, "PUSH_NONVOL", "push rbp"],
    ]);
  });

  it("finds the one guarded function, its handler through the import thunk and the scope table", () => {
    expect(r.functions).toBe(3);
    expect(r.handlers).toHaveLength(1);
    const h = r.handlers[0];
    expect(h).toMatchObject({ begin: 0x1010, end: 0x105c, handlerRva: 0x10c0, handlerName: "__C_specific_handler", kind: "c", flags: ["EHANDLER", "UHANDLER"] });
    // three __try blocks: __except(filter()), __finally, __except(1)
    expect(h.scopes!.map((s) => s.kind)).toEqual(["except", "finally", "except"]);
    expect(h.scopes![0]).toMatchObject({ filter: "rva", handler: 0x1080, target: 0x1055 });
    expect(h.scopes![1]).toMatchObject({ handler: 0x1060, target: 0 });
    expect(h.scopes![2]).toMatchObject({ filter: "EXCEPTION_EXECUTE_HANDLER", handler: 1, target: 0x104e });
    for (const s of h.scopes!) expect(s.begin >= h.begin && s.end <= h.end && s.begin < s.end).toBe(true);
    expect(r.routines).toEqual([{ rva: 0x10c0, name: "__C_specific_handler", kind: "c", count: 1 }]);
  });
});

describe("SEH on synthetic images", () => {
  // .text 0x1000, .pdata 0x2000, .xdata 0x3000
  const build = (xdata: Uint8Array, entries: [number, number, number][], text = new Uint8Array(0x200)) => {
    const pdata = new Uint8Array(entries.length * 12);
    const dv = new DataView(pdata.buffer);
    entries.forEach(([b, e, u], i) => { dv.setUint32(i * 12, b, true); dv.setUint32(i * 12 + 4, e, true); dv.setUint32(i * 12 + 8, u, true); });
    return buildTestPe(
      [{ name: ".text", rva: 0x1000, bytes: text }, { name: ".pdata", rva: 0x2000, bytes: pdata, chars: 0x40000040 }, { name: ".xdata", rva: 0x3000, bytes: xdata, chars: 0x40000040 }],
      { 3: { rva: 0x2000, size: pdata.length } },
    );
  };

  it("decodes large allocations, far saves and machine frames", () => {
    const x = new Uint8Array(0x40);
    const dv = new DataView(x.buffer);
    x.set([1, 20, 7, 0]);
    // ALLOC_LARGE info 1 (32-bit size), SAVE_NONVOL_FAR rbx, PUSH_MACHFRAME 1
    x.set([20, 0x11], 4); dv.setUint32(6, 0x12345, true);
    x.set([12, 0x35], 10); dv.setUint32(12, 0x80000, true);
    x.set([2, 0x1a], 16);
    const img = build(x, [[0x1000, 0x1100, 0x3000]]);
    const u = parseUnwindInfo(img, 0x3000)!;
    expect(u.codes.map((c) => c.text)).toEqual(["sub rsp, 0x12345", "mov [frame+0x80000], rbx", "machine frame (with error code)"]);
  });

  it("follows chained entries, finds handlers by heuristic and through user names", () => {
    const x = new Uint8Array(0x80);
    const dv = new DataView(x.buffer);
    // 0x3000: EHANDLER, no codes, handler 0x1180, scope table {1 entry in 0x1000..0x1100}
    x.set([1 | (1 << 3), 0, 0, 0]);
    dv.setUint32(4, 0x1180, true);
    dv.setUint32(8, 1, true);
    dv.setUint32(12, 0x1010, true); dv.setUint32(16, 0x1020, true); dv.setUint32(20, 1, true); dv.setUint32(24, 0x1030, true);
    // 0x3040: chained to 0x1000
    x[0x40] = 1 | (4 << 3);
    dv.setUint32(0x44, 0x1000, true); dv.setUint32(0x48, 0x1100, true); dv.setUint32(0x4c, 0x3000, true);
    const img = build(x, [[0x1000, 0x1100, 0x3000], [0x1100, 0x1140, 0x3040]]);
    const r = listExceptionHandlers(img);
    expect(r.chained).toBe(1);
    expect(r.handlers).toHaveLength(1);
    expect(r.handlers[0]).toMatchObject({ kind: "unknown", scopesHeuristic: true });
    expect(r.handlers[0].scopes).toEqual([{ begin: 0x1010, end: 0x1020, handler: 1, target: 0x1030, kind: "except", filter: "EXCEPTION_EXECUTE_HANDLER" }]);
    const named = listExceptionHandlers(img, undefined, { nameOf: (rva) => (rva === 0x1180 ? "__CxxFrameHandler4" : undefined) });
    expect(named.handlers[0]).toMatchObject({ kind: "cxx4", handlerName: "__CxxFrameHandler4" });
    expect(named.handlers[0].scopes).toBeUndefined();
  });

  it("resolves a REX-prefixed import thunk", () => {
    const text = new Uint8Array(0x200);
    // 0x1100: 48 ff 25 <disp> → slot 0x1100 + 7 + disp
    text.set([0x48, 0xff, 0x25], 0x100);
    new DataView(text.buffer).setInt32(0x103, 0x2000 - (0x1100 + 7), true);
    const img = build(new Uint8Array(0x10), [], text);
    const pe = parsePe(img);
    pe.imports.push({ dll: "ntdll.dll", funcs: [{ name: "__C_specific_handler", iatRva: 0x2000 }] });
    expect(resolveHandlerName(img, pe, 0x1100)).toBe("__C_specific_handler");
  });
});

describe("TLS callbacks", () => {
  it("lists the fixture's callback inside .text", () => {
    const img = mapPeFile(fixture("fix.exe"));
    const pe = parsePe(img);
    const t = tlsCallbacks(img, pe.imageBase, pe);
    expect(t.callbacks).toEqual([{ address: 0x140001000n, rva: 0x1000, section: ".text", executable: true }]);
    expect(t.directory?.callbacksAddress).toBeGreaterThan(0n);
  });
  it("flags callbacks outside the image", () => {
    const tls = new Uint8Array(0x40);
    const dv = new DataView(tls.buffer);
    dv.setBigUint64(24, 0x140002020n, true); // callbacks array
    dv.setBigUint64(0x20, 0x7ff000001000n, true);
    const img = buildTestPe([{ name: ".text", rva: 0x1000, bytes: new Uint8Array(16) }, { name: ".tls", rva: 0x2000, bytes: tls, chars: 0x40000040 }], { 9: { rva: 0x2000, size: 40 } });
    expect(tlsCallbacks(img, 0x140000000n).callbacks).toEqual([{ address: 0x7ff000001000n, rva: null, section: undefined, executable: false }]);
  });
});
