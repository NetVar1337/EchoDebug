import { describe, expect, it } from "vitest";
import { openMetadata, parseDotnet } from "./dotnet";
import { disassembleIl, formatIl, userStringRefs } from "./cil";
import { buildManagedImage, kCliRva, kMetaRva } from "./testdotnet";

/* ------------------------------------------------------------------ */
/* tests                                                               */
/* ------------------------------------------------------------------ */

describe("dotnet", () => {
  it("parses types, methods, fields and attributes", () => {
    const info = parseDotnet(buildManagedImage());
    expect(info).not.toBeNull();
    if (!info) return;

    expect(info.runtimeVersion).toBe("v4.0.30319");
    expect(info.metadataVersion).toBe("v4.0.30319");
    expect(info.entryPointToken).toBe(0x06000001);

    expect(info.types.map((t) => t.fullName)).toEqual(["Sample.Widget", "Sample.Widget+Nested"]);

    const widget = info.types[0];
    expect(widget.namespace).toBe("Sample");
    expect(widget.name).toBe("Widget");
    expect(widget.flags).toBe(1);
    expect(widget.baseType).toBe("System.Object");

    expect(widget.methods.map((m) => m.name)).toEqual([".ctor", "Compute"]);
    expect(widget.methods[0]).toMatchObject({ name: ".ctor", rva: 0x2200, flags: 0x1886 });
    expect(widget.methods[1]).toMatchObject({ name: "Compute", rva: 0x2250, flags: 0x0006 });
    expect(widget.methods[1].attributes).toEqual(["ObsoleteAttribute"]);
    expect(widget.methods[0].attributes).toEqual([]);

    expect(widget.fields.map((f) => f.name)).toEqual(["m_value", "m_count"]);
    expect(widget.fields[0]).toMatchObject({ name: "m_value", flags: 0x0011 });
    expect(widget.fields[0].attributes).toEqual(["ObsoleteAttribute"]);
    expect(widget.fields[1]).toMatchObject({ name: "m_count", flags: 0x0002 });
    expect(widget.fields[1].attributes).toEqual([]);

    const nested = info.types[1];
    expect(nested.namespace).toBe("Sample");
    expect(nested.name).toBe("Widget+Nested");
    expect(nested.flags).toBe(2);
    expect(nested.baseType).toBe("Sample.Widget");
    expect(nested.methods.map((m) => m.name)).toEqual(["Helper"]);
    expect(nested.methods[0]).toMatchObject({ rva: 0x2300, flags: 0x0006 });
    expect(nested.fields).toEqual([]);
  });

  it("decodes the same metadata with 4 byte heap indexes", () => {
    const narrow = parseDotnet(buildManagedImage(false));
    const wide = parseDotnet(buildManagedImage(true));
    expect(wide).toEqual(narrow);
    expect(wide?.types.map((t) => t.fullName)).toEqual(["Sample.Widget", "Sample.Widget+Nested"]);
  });

  it("returns null without a CLR data directory", () => {
    const img = buildManagedImage();
    const dv = new DataView(img.buffer);
    const oh = 0x84 + 20;
    dv.setUint32(oh + 108, 14, true); // only 14 directories -> no "CLR" entry
    expect(parseDotnet(img)).toBeNull();

    const img2 = buildManagedImage();
    const dv2 = new DataView(img2.buffer);
    dv2.setUint32(oh + 112 + 14 * 8, 0, true); // directory present but empty
    expect(parseDotnet(img2)).toBeNull();
  });

  it("returns null for garbage and for a broken metadata root", () => {
    expect(parseDotnet(new Uint8Array(0x100))).toBeNull();
    expect(parseDotnet(new Uint8Array(0))).toBeNull();

    const rnd = new Uint8Array(0x400);
    for (let i = 0; i < rnd.length; i++) rnd[i] = (i * 37 + 11) & 0xff;
    expect(parseDotnet(rnd)).toBeNull();

    const broken = buildManagedImage();
    new DataView(broken.buffer).setUint32(kMetaRva, 0x12345678, true); // not "BSJB"
    expect(parseDotnet(broken)).toBeNull();

    const broken2 = buildManagedImage();
    new DataView(broken2.buffer).setUint32(kMetaRva + 12, 0xfffffff0, true); // bogus version length
    expect(parseDotnet(broken2)).toBeNull();

    const broken3 = buildManagedImage();
    new DataView(broken3.buffer).setUint32(kCliRva + 8, 0xffffff00, true); // metadata rva out of range
    expect(parseDotnet(broken3)).toBeNull();
  });
});

describe("IL and user strings", () => {
  // #US heap: index 1 = "hello" (len 11 = 5 chars * 2 + flag byte), index 13 = "x"
  const us = [0, 11, ...Array.from("hello").flatMap((c) => [c.charCodeAt(0), 0]), 0, 3, 0x78, 0, 0];
  // Compute (MethodDef #2, rva 0x2250), tiny header: ldstr "hello"; callvirt ToString; pop;
  // ldarg.1; ldc.i4.s 5; add; brtrue.s +1; nop; ret
  const tinyCode = [0x72, 0x01, 0, 0, 0x70, 0x6f, 0x01, 0, 0, 0x0a, 0x26, 0x03, 0x1f, 0x05, 0x58, 0x2d, 0x01, 0x00, 0x2a];
  const tiny = [(tinyCode.length << 2) | 2, ...tinyCode];
  // Helper (#3, rva 0x2300), fat header with a try/finally: switch(2 targets); leave.s; endfinally; ret
  const fatCode = [0x45, 0x02, 0, 0, 0, 0x00, 0, 0, 0, 0x01, 0, 0, 0, 0xde, 0x00, 0xdc, 0x2a];
  const fatHeader = [0x1b, 0x30, 0x02, 0x00, ...[fatCode.length, 0, 0, 0], 0, 0, 0, 0];
  const pad = Array((4 - ((12 + fatCode.length) % 4)) % 4).fill(0);
  // small EH section: kind=1 (EHTable), size 16, one clause: finally, try 0..15, handler 15..16
  const eh = [0x01, 16, 0, 0, 0x02, 0x00, 0x00, 0x00, 15, 0x0f, 0x00, 1, 0, 0, 0, 0];
  const img = buildManagedImage(false, { us, bodies: [{ rva: 0x2250, bytes: tiny }, { rva: 0x2300, bytes: [...fatHeader, ...fatCode, ...pad, ...eh] }] });

  it("resolves tokens and reads the #US heap", () => {
    const md = openMetadata(img)!;
    expect(md).not.toBeNull();
    expect(md.userStrings.map((u) => u.text)).toEqual(["hello", "x"]);
    expect(md.userString(0x70000001)).toBe("hello");
    expect(md.tokenName(0x06000002)).toBe("Sample.Widget::Compute");
    expect(md.tokenName(0x06000003)).toBe("Sample.Widget/Nested::Helper");
    expect(md.tokenName(0x0a000001)).toBe("System.Object::ToString");
    expect(md.tokenName(0x01000002)).toBe("System.ObsoleteAttribute");
    expect(md.tokenName(0x04000002)).toBe("Sample.Widget::m_count");
    expect(md.methods.map((m) => m.name)).toEqual([".ctor", "Compute", "Helper"]);
  });

  it("disassembles tiny and fat bodies", () => {
    const md = openMetadata(img)!;
    const t = disassembleIl(img, 0x2250, md.tokenName);
    expect(t.headerSize).toBe(1);
    expect(formatIl(t)).toEqual([
      'IL_0000: ldstr "hello"',
      "IL_0005: callvirt System.Object::ToString",
      "IL_000a: pop",
      "IL_000b: ldarg.1",
      "IL_000c: ldc.i4.s 5",
      "IL_000e: add",
      "IL_000f: brtrue.s IL_0012",
      "IL_0011: nop",
      "IL_0012: ret",
    ]);
    const f = disassembleIl(img, 0x2300, md.tokenName);
    expect(f.headerSize).toBe(12);
    expect(f.maxStack).toBe(2);
    expect(f.code[0].opcode).toBe("switch");
    expect(f.code[0].targets).toEqual([13, 14]);
    expect(f.clauses).toEqual([{ kind: "finally", tryStart: 0, tryEnd: 15, handlerStart: 15, handlerEnd: 16 }]);
    expect(() => disassembleIl(img, 0, md.tokenName)).toThrow(/no body/);
  });

  it("finds where each user string is loaded", () => {
    const md = openMetadata(img)!;
    const refs = userStringRefs(img, md.methods);
    expect(refs.get(0x70000001)).toEqual([{ token: 0x70000001, method: "Sample.Widget::Compute", methodToken: 0x06000002, offset: 0 }]);
    expect(refs.has(0x7000000d)).toBe(false);
  });
});
