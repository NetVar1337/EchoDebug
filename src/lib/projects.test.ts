import { describe, expect, it } from "vitest";
import { fmtAddr } from "./hex";
import {
  classify, countRelocation, fromItem, fromRva, migrateAnchored, peTimestamp, syncEntry, syncList, toItem, toRva, type Anchored,
} from "./projects";

const run1 = [{ name: "game.exe", base: "0x140000000", size: 0x10000 }];
const run2 = [{ name: "game.exe", base: "0x7ff600000000", size: 0x10000 }];
type E = Anchored & { name: string };

describe("rva conversion", () => {
  it("converts both ways", () => {
    expect(toRva(0x140001234n, run1)).toEqual({ module: "game.exe", rva: 0x1234n, base: "0x140000000" });
    expect(toRva(0x5n, run1)).toBeNull();
    expect(fromRva("GAME.EXE", 0x1234n, run2)).toBe(0x7ff600001234n);
    expect(fromRva("other.dll", 1n, run2)).toBeNull();
  });

  it("anchors a fresh entry, then follows an ASLR rebase", () => {
    const e: E = { address: "0x140001234", name: "f" };
    const a = syncEntry(e, run1, fmtAddr);
    expect(a.anchor).toEqual({ module: "game.exe", rva: "0x1234", base: "0x140000000", sig: undefined });
    expect(syncEntry(a, run1, fmtAddr)).toBe(a); // stable
    const b = syncEntry({ ...a, anchor: { ...a.anchor!, sig: "48 8B" } }, run2, fmtAddr);
    expect(b.address).toBe("0x7ff600001234");
    expect(b.anchor).toMatchObject({ rva: "0x1234", base: "0x7ff600000000", sig: "48 8B" });
  });

  it("keeps the last address while the module is not loaded", () => {
    const a = syncEntry({ address: "0x140001234", name: "f" } as E, run1, fmtAddr);
    expect(syncEntry(a, [], fmtAddr)).toBe(a);
  });

  it("re-anchors an address the user changed and drops a stale signature", () => {
    const a = syncEntry({ address: "0x140001234", name: "f" } as E, run1, fmtAddr);
    const b = syncEntry({ ...a, address: "0x140002000", anchor: { ...a.anchor!, sig: "90" } }, run1, fmtAddr);
    expect(b.anchor).toEqual({ module: "game.exe", rva: "0x2000", base: "0x140000000", sig: undefined });
    expect(syncEntry({ ...b, address: "0x10" }, run1, fmtAddr).anchor).toBeUndefined();
  });

  it("syncList returns the same array when nothing changed", () => {
    const l = syncList([{ address: "0x140000010", name: "x" } as E], run1, fmtAddr);
    expect(syncList(l, run1, fmtAddr)).toBe(l);
  });

  it("round trips through a project file, rebasing once the module loads", () => {
    const a = syncEntry({ address: "0x140001234", name: "f", anchor: undefined } as E, run1, fmtAddr);
    const item = toItem({ ...a, anchor: { ...a.anchor!, sig: "E8 ? ? ? ?" } })!;
    expect(item).toEqual({ name: "f", rva: "0x1234", sig: "E8 ? ? ? ?" });
    expect(toItem({ address: "0x5" })).toBeNull();
    const offline = fromItem<E>("game.exe", item, [], fmtAddr);
    expect(offline.address).toBe("0x1234");
    expect(syncEntry(offline, run2, fmtAddr).address).toBe("0x7ff600001234");
    expect(fromItem<E>("game.exe", item, run2, fmtAddr)).toMatchObject({ name: "f", address: "0x7ff600001234", anchor: { sig: "E8 ? ? ? ?" } });
  });
});

describe("persist migration", () => {
  it("keeps v0 entries and other fields, drops malformed ones", () => {
    const v0 = { names: [{ address: "0000000140001000", name: "a", comment: "" }, null, { name: "no address" }], other: 1 };
    expect(migrateAnchored("names")(v0, 0)).toEqual({ names: [{ address: "0000000140001000", name: "a", comment: "" }], other: 1 });
    expect(migrateAnchored("bookmarks")(undefined, 0)).toEqual({ bookmarks: [] });
    const v1 = { names: [{ junk: true }] };
    expect(migrateAnchored("names")(v1, 1)).toEqual(v1);
  });
});

describe("relocation / health classification", () => {
  it("classifies scan results", () => {
    expect(classify(0x10n, [0x10n])).toEqual({ status: "same", newRva: 0x10n });
    expect(classify(0x10n, [0x20n])).toEqual({ status: "moved", newRva: 0x20n });
    expect(classify(null, [0x20n])).toEqual({ status: "moved", newRva: 0x20n });
    expect(classify(0x10n, [0x10n, 0x20n])).toEqual({ status: "multiple" });
    expect(classify(0x10n, [])).toEqual({ status: "broken" });
  });

  it("counts matched / moved / lost", () => {
    expect(countRelocation(["same", "moved", "moved", "multiple", "broken", "nosig"])).toEqual({ matched: 1, moved: 2, lost: 3 });
  });

  it("reads the PE timestamp", () => {
    const head = new Uint8Array(0x200);
    const v = new DataView(head.buffer);
    head.set([0x4d, 0x5a]);
    v.setUint32(0x3c, 0x80, true);
    v.setUint32(0x80, 0x4550, true);
    v.setUint32(0x88, 0x65432100, true);
    expect(peTimestamp(head)).toBe(0x65432100);
    expect(peTimestamp(new Uint8Array(0x200))).toBe(0); // ELF / not mapped
  });
});
