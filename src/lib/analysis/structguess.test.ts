import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { changedFields, guessFields } from "./structguess";
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
    try {
      const listed = execFileSync("python3", ["-c", "import zipfile,sys;z=zipfile.ZipFile(sys.argv[1]);assert z.testzip() is None;sys.stdout.write(z.read('Data.xml').decode())", join(dir, "p.rcnet")]).toString();
      expect(listed).toBe(xmlText);
    } catch (e) {
      if (/ENOENT/.test(String(e))) return; // no python
      throw e;
    }
  });
});
