import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { changedFields, fromOffsets, guessFields, placeField, pointerTargets, proposeFields, type PtrKind, type ProposeContext } from "./structguess";
import { layout } from "./struct";
import { crc32, toBinja, toC, toGhidra, toIdaPython, toReclassProject, toReclassXml } from "./typeexport";

describe("struct guessing", () => {
  it("recognises vtables, pointers, strings, vectors, floats and ints", () => {
    const b = new Uint8Array(0x58);
    const dv = new DataView(b.buffer);
    dv.setBigUint64(0x00, 0x140005000n, true); // vtable (rdata)
    dv.setBigUint64(0x08, 0x20001230n, true); // heap pointer
    dv.setFloat32(0x10, 1.5, true); dv.setFloat32(0x14, -20.25, true); dv.setFloat32(0x18, 300, true); // vec3
    dv.setInt32(0x1c, 100, true); // hp
    dv.setBigUint64(0x20, 0x140001000n, true); // callback
    b.set(new TextEncoder().encode("PlayerOne\0"), 0x28); // name
    // 0x48..0x58 zero
    const kind = (v: bigint) => (v >= 0x140001000n && v < 0x140005000n ? "code" : v >= 0x140005000n && v < 0x140006000n ? "rdata" : v >= 0x20000000n && v < 0x30000000n ? "heap" : null);
    const f = guessFields(b, { kindOf: kind });
    expect(f.map((x) => x.type)).toEqual(["ptr", "ptr", "vec3", "i32", "ptr", "ascii", "hex64", "hex64"]);
    expect(f[0].name).toBe("vftable");
    expect(f[4].name).toBe("fn_20");
    const lay = layout(f);
    expect(lay[lay.length - 1].offset + lay[lay.length - 1].size).toBe(0x58);
  });

  it("flags the fields whose bytes changed", () => {
    const lay = [{ offset: 0, size: 4 }, { offset: 4, size: 4 }];
    expect(changedFields(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), new Uint8Array([1, 2, 3, 4, 5, 9, 7, 8]), lay)).toEqual([false, true]);
  });
});

describe("type export", () => {
  const fields = [{ type: "ptr" as const, name: "vftable" }, { type: "vec3" as const, name: "pos" }, { type: "i32" as const, name: "hp" }, { type: "ascii" as const, name: "name" }];
  it("writes C that a C compiler accepts with the right layout", () => {
    const c = toC("Player", fields);
    expect(c).toContain("float pos[3]; /* 0x8 */");
    const dir = mkdtempSync(join(tmpdir(), "echodebug-c-"));
    writeFileSync(join(dir, "t.c"), `${c}\n_Static_assert(sizeof(struct Player) == 0x38, "size");\n_Static_assert(__builtin_offsetof(struct Player, hp) == 0x14, "hp");\nint main(void){return 0;}\n`);
    try {
      execFileSync("cc", ["-c", "-o", join(dir, "t.o"), join(dir, "t.c")], { stdio: "pipe" });
    } catch (e) {
      const msg = String((e as { stderr?: Buffer }).stderr ?? e);
      if (/ENOENT|not found/.test(msg)) return; // no C compiler on this machine
      throw new Error(msg);
    }
  });
  it("wraps it for IDA, Ghidra and Binary Ninja", () => {
    expect(toIdaPython("Player", fields)).toContain("idc.parse_decls(decl, 0)");
    expect(toGhidra("Player", fields)).toContain('s.add(ArrayDataType(FloatDataType.dataType, 3, 4), 12, "pos", None)');
    expect(toBinja("Player", fields)).toContain("bv.define_user_type(n, t)");
  });
  it("writes a ReClass.NET project zip that unzip can read", () => {
    expect(crc32(new TextEncoder().encode("123456789"))).toBe(0xcbf43926);
    const xmlText = toReclassXml([{ name: "Player", fields }]);
    expect(xmlText).toContain('<node type="Vector3Node" name="pos"');
    const zip = toReclassProject([{ name: "Player", fields }]);
    const dir = mkdtempSync(join(tmpdir(), "echodebug-zip-"));
    writeFileSync(join(dir, "p.rcnet"), zip);
    // validate with whatever Python is installed: "python3" on unix, "python" on Windows
    // (where python3 is often the Microsoft Store stub that exits non-zero without ENOENT)
    const script = "import zipfile,sys;z=zipfile.ZipFile(sys.argv[1]);assert z.testzip() is None;sys.stdout.buffer.write(z.read('Data.xml'))";
    let listed: string | null = null;
    for (const py of ["python3", "python"]) {
      try {
        listed = execFileSync(py, ["-c", script, join(dir, "p.rcnet")]).toString();
        break;
      } catch (e) {
        if (py === "python" && !/ENOENT/.test(String(e))) throw e;
      }
    }
    if (listed !== null) expect(listed).toBe(xmlText);
  });
});

describe("per-slot proposals", () => {
  const modules = [{ name: "game.exe", base: "0x140000000", size: 0x100000 }];
  // what lib/ptrkind derives from the module's sections and the region map (first match wins)
  const ranges: [bigint, bigint, PtrKind][] = [
    [0x140001000n, 0x140080000n, "code"], // .text
    [0x140080000n, 0x1400c0000n, "rdata"], // .rdata
    [0x1400c0000n, 0x140100000n, "data"], // .data
    [0x140000000n, 0x140100000n, "rdata"], // headers / whole image
    [0x20000000n, 0x20100000n, "heap"],
  ];
  const kindOf = (v: bigint) => ranges.find(([lo, hi]) => v >= lo && v < hi)?.[2] ?? null;

  function obj(slots: (bigint | number[])[]): Uint8Array {
    const b = new Uint8Array(slots.length * 8);
    const dv = new DataView(b.buffer);
    slots.forEach((s, i) => (typeof s === "bigint" ? dv.setBigUint64(i * 8, s, true) : b.set(s, i * 8)));
    return b;
  }
  const qw = (...v: bigint[]) => { const b = new Uint8Array(v.length * 8); v.forEach((x, i) => new DataView(b.buffer).setBigUint64(i * 8, x, true)); return b; };
  const f32pair = (a: number, b: number) => { const x = new Uint8Array(8); const dv = new DataView(x.buffer); dv.setFloat32(0, a, true); dv.setFloat32(4, b, true); return [...x]; };
  const f64 = (d: number) => { const x = new Uint8Array(8); new DataView(x.buffer).setFloat64(0, d, true); return [...x]; };
  const ascii = (s: string) => [...new TextEncoder().encode(s)];

  const buf = obj([
    0x140080100n, // vtable in .rdata
    0x20000010n, // heap object
    0x20000100n, // heap char*
    0x1400c0010n, // module global
    0x140001234n, // function pointer
    0n,
    f32pair(1.5, -2.25),
    f64(1234.5),
    [1, 0, 0, 0, 7, 0, 0, 0],
    [0xff, 0xff, 0xff, 0xff, 0x10, 0x27, 0, 0], // -1, 10000
    ascii("PlayerNa"), ascii("me_Long"), [0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0],
    0xff800001ff800001n, // NaN halves
  ]);
  const deref = new Map<string, Uint8Array>([
    ["0x140080100", qw(0x140001000n, 0x140001010n, 0x140001020n)],
    ["0x20000010", qw(0x140080100n, 5n)],
    ["0x20000100", new Uint8Array([...ascii("hello world"), 0])],
  ]);
  const ctx: ProposeContext = { kindOf, modules, deref, rtti: new Map([[0, "class Player"]]) };

  it("lists pointer targets for the deref pass", () => {
    expect(pointerTargets(buf, ctx).sort()).toEqual(["0x140001234", "0x140080100", "0x1400c0010", "0x20000010", "0x20000100"].sort());
  });

  it("classifies every slot", () => {
    const g = proposeFields(buf, ctx);
    const by = (o: number) => g.find((x) => x.offset === o)!;
    expect(by(0)).toMatchObject({ kind: "vtable", type: "ptr", name: "vtable" });
    expect(by(0).label).toContain("game.exe+0x80100");
    expect(by(0).label).toContain("class Player");
    expect(by(8)).toMatchObject({ kind: "heap-ptr", type: "ptr" });
    expect(by(0x10)).toMatchObject({ kind: "string-ptr" });
    expect(by(0x10).label).toContain("hello world");
    expect(by(0x18)).toMatchObject({ kind: "module-ptr", label: "→ game.exe+0xc0010" });
    expect(by(0x20)).toMatchObject({ kind: "code-ptr" });
    expect(by(0x28)).toMatchObject({ kind: "zero", type: "hex64" });
    expect(by(0x30)).toMatchObject({ kind: "f32", type: "f32" });
    expect(by(0x34)).toMatchObject({ kind: "f32", label: "float -2.25" });
    expect(by(0x38)).toMatchObject({ kind: "f64", label: "double 1234.5" });
    expect(by(0x40)).toMatchObject({ kind: "bool" });
    expect(by(0x44)).toMatchObject({ kind: "small-int" });
    expect(by(0x48)).toMatchObject({ kind: "int", type: "i32", label: "int (-1)" });
    expect(by(0x4c)).toMatchObject({ kind: "int", label: "int (10000)" });
    expect(by(0x50)).toMatchObject({ kind: "ascii", type: "ascii" });
    // the inline string swallowed 0x58..0x6f
    expect(g.some((x) => x.offset > 0x50 && x.offset < 0x70)).toBe(false);
    expect(by(0x70)).toMatchObject({ kind: "unknown", type: "hex64" });
  });

  it("does not call an rdata pointer a vtable when its slots are not code", () => {
    const g = proposeFields(obj([0x140080200n]), { kindOf, modules, deref: new Map([["0x140080200", qw(5n, 6n)]]) });
    expect(g[0].kind).toBe("module-ptr");
  });

  it("treats values the classifier does not know as data", () => {
    const modOnly = (v: bigint): PtrKind | null => (v >= 0x140000000n && v < 0x140100000n ? "rdata" : null);
    const g = proposeFields(obj([0x140080100n, 0x20000010n]), { kindOf: modOnly, modules });
    expect(g[0].kind).toBe("module-ptr");
    expect(g[1].kind).not.toContain("ptr");
  });

  it("detects UTF-16 inline strings and wchar_t* targets", () => {
    const w = [...new Uint8Array([...ascii("Hello!")].flatMap((c) => [c, 0]))];
    const g = proposeFields(new Uint8Array([...w, ...new Array(64 - w.length).fill(0)]), { kindOf, modules });
    expect(g[0]).toMatchObject({ kind: "utf16", type: "utf16" });
    const p = proposeFields(obj([0x20000200n]), { kindOf, modules, deref: new Map([["0x20000200", new Uint8Array([...w, 0, 0])]]) });
    expect(p[0]).toMatchObject({ kind: "wstring-ptr" });
  });

  it("places fields without shifting the rest", () => {
    const base = fromOffsets(0x20, []);
    expect(base).toHaveLength(4);
    const f = placeField(base, 0x0c, { type: "f32", name: "hp" });
    const lay = layout(f);
    expect(lay[f.findIndex((x) => x.name === "hp")].offset).toBe(0x0c);
    expect(lay.at(-1)!.offset + lay.at(-1)!.size).toBe(0x20);
    // wider than what it replaces, and past the end
    const g = placeField(f, 0x08, { type: "hex64", name: "" });
    expect(layout(g).at(-1)!.offset + layout(g).at(-1)!.size).toBe(0x20);
    const h = placeField(g, 0x30, { type: "ptr", name: "far" });
    expect(layout(h)[h.length - 1]).toEqual({ offset: 0x30, size: 8 });
    // same range keeps the user's name
    const k = placeField([{ type: "hex64", name: "mine" }], 0, { type: "ptr", name: "" });
    expect(k).toEqual([{ type: "ptr", name: "mine" }]);
  });

  it("builds sparse layouts", () => {
    const f = fromOffsets(0x28, [[0, "ptr", "vtable"], [0x0c, "i32", "InternalIndex"], [0x20, "ptr", "Outer"]]);
    const lay = layout(f);
    const at = (n: string) => lay[f.findIndex((x) => x.name === n)].offset;
    expect([at("vtable"), at("InternalIndex"), at("Outer")]).toEqual([0, 0x0c, 0x20]);
    expect(lay.at(-1)!.offset + lay.at(-1)!.size).toBe(0x28);
  });
});
