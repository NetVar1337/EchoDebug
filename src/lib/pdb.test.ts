import { beforeEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { mapPeFile } from "./analysis/pe";
import { readCodeView } from "./analysis/peextra";
import { protoAt, protoText, symAddr } from "./pdb";
import { entryId, pdbFunctionAt, pdbFunctions, pdbSymbolAt, useSymbols, type PdbSym } from "@/store/symbols";
import { useNames } from "@/store/names";

const fixture = (p: string) => new Uint8Array(readFileSync(new URL(`../../src-tauri/relay/tests/fixtures/${p}`, import.meta.url)));

describe("CodeView (RSDS) from a live image, read piecemeal", () => {
  it("reads only the headers, the debug directory and the record", async () => {
    const img = mapPeFile(fixture("pdbtypes/types.exe"));
    const reads: [number, number][] = [];
    const cv = await readCodeView(async (rva, size) => {
      reads.push([rva, size]);
      return img.subarray(rva, rva + size);
    });
    // llvm-pdbutil: GUID {3204B8A9-E641-4405-4C4C-44205044422E}, age 1
    expect(cv).toEqual({ format: "RSDS", guid: "3204B8A9-E641-4405-4C4C-44205044422E", age: 1, path: "types.pdb", symbolKey: "3204B8A9E64144054C4C44205044422E1" });
    expect(reads.length).toBe(3);
    expect(await readCodeView(async () => new Uint8Array(0x400))).toBeNull();
  });
});

describe("symbol lookups over a loaded PDB", () => {
  const m = { name: "types.exe", base: "0x140000000", size: 0x5000 };
  const syms: PdbSym[] = [
    { rva: 0x1000, name: "entity_score", kind: "function", size: 28, ret: "int", params: [{ name: "e", type: "Entity*", size: 8 }, { name: "bonus", type: "int", size: 4 }] },
    { rva: 0x1020, name: "entity_init", kind: "function", size: 35, ret: "void", params: [{ name: "e", type: "Entity*", size: 8 }, { name: "id", type: "unsigned __int64", size: 8 }] },
    { rva: 0x1060, name: "mainCRTStartup", kind: "function", size: 0, ret: "int", params: [] },
    { rva: 0x3010, name: "g_entities", kind: "data", size: 256, type: "Entity[2]" },
  ];
  beforeEach(() => {
    useSymbols.getState().clear();
    useNames.setState({ names: [] });
    useSymbols.getState().upsert(entryId(m), { module: m.name, base: m.base, size: m.size, status: "loaded", symbols: syms });
  });

  it("finds the containing function, sizeless publics up to the next start", () => {
    expect(pdbFunctionAt(0x140001010n)).toMatchObject({ sym: { name: "entity_score" }, offset: 0x10 });
    expect(pdbFunctionAt(0x14000101cn)).toBeNull(); // past entity_score's 28 bytes, before entity_init
    expect(pdbFunctionAt(0x140001070n)?.sym.name).toBe("mainCRTStartup");
    expect(pdbFunctionAt(0x150000000n)).toBeNull();
    expect(pdbSymbolAt(0x140003010n)?.sym.name).toBe("g_entities");
    expect(pdbFunctions(m).map((f) => f.size)).toEqual([28, 35, 0]);
  });

  it("symbolizes addresses and feeds the name lookup and the pseudocode", () => {
    expect(symAddr(0x140001024n, [m])).toBe("types.exe!entity_init+0x4");
    expect(symAddr(0x140001000n, [m])).toBe("types.exe!entity_score");
    expect(symAddr(0x140003010n, [m])).toBe("types.exe!g_entities");
    expect(symAddr(0x140004000n, [m])).toBe("types.exe+0x4000");
    // the existing name lookup falls back to the PDB; a user name wins
    expect(useNames.getState().nameOf("0x140001020")).toBe("entity_init");
    useNames.getState().rename("0x140001020", "my_init");
    expect(useNames.getState().nameOf("0x140001020")).toBe("my_init");
    expect(useNames.getState().userNameOf("0x140001000")).toBe("");
    expect(protoAt("0x140001000")).toEqual({ name: "entity_score", ret: "int", params: [{ name: "e", type: "Entity*" }, { name: "bonus", type: "int" }] });
    expect(protoText(syms[1])).toBe("void entity_init(Entity* e, unsigned __int64 id)");
    expect(protoText(syms[2])).toBe("int mainCRTStartup(void)");
  });

  it("copies names in bulk as one step without replacing the user's", () => {
    useNames.getState().rename("0x140001000", "mine");
    const n = useNames.getState().bulkRename(syms.map((s) => ({ address: "0x" + (0x140000000 + s.rva).toString(16), name: s.name })));
    expect(n).toBe(3);
    expect(useNames.getState().userNameOf("0x140001000")).toBe("mine");
    expect(useNames.getState().userNameOf("0x140003010")).toBe("g_entities");
  });
});
