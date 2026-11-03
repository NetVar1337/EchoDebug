import { describe, expect, it } from "vitest";
import { buildCallGraph } from "./graph";

const kBase = 0x7ff600000000n;

function abs(rva: number): string {
  return `0x${(kBase + BigInt(rva)).toString(16)}`;
}

function writeInt32LE(img: Uint8Array, off: number, value: number): void {
  const u = value >>> 0;
  img[off] = u & 0xff;
  img[off + 1] = (u >>> 8) & 0xff;
  img[off + 2] = (u >>> 16) & 0xff;
  img[off + 3] = (u >>> 24) & 0xff;
}

/**
 * Mapped image with two functions:
 *   0x100: E8 rel32            -> call  0x200 (known function)
 *   0x110: 0F 84 rel32         -> jcc   0x180 (unknown)
 *   0x120: 48 8B 05 disp32     -> mov rax, [rip+disp] -> 0x150 (unknown)
 */
function fakeImage(): Uint8Array {
  const img = new Uint8Array(0x2000);

  // call 0x200
  img[0x100] = 0xe8;
  writeInt32LE(img, 0x101, 0x200 - (0x100 + 5));

  // jz 0x180
  img[0x110] = 0x0f;
  img[0x111] = 0x84;
  writeInt32LE(img, 0x112, 0x180 - (0x110 + 6));

  // mov rax, [rip+0x29] -> 0x150
  img[0x120] = 0x48;
  img[0x121] = 0x8b;
  img[0x122] = 0x05;
  writeInt32LE(img, 0x123, 0x150 - 0x127);

  return img;
}

const kFns = [
  { address: abs(0x100), size: 0x80 },
  { address: abs(0x200), size: 0x40 },
];

describe("graph", () => {
  it("resolves direct call and jcc targets", () => {
    const g = buildCallGraph(fakeImage(), kFns, kBase);

    const call = g.edges.find((e) => e.kind === "call");
    expect(call).toBeDefined();
    expect(call?.from).toBe(abs(0x100));
    expect(call?.to).toBe(abs(0x200));
    expect(call?.fromRva).toBe(0x100);
    expect(call?.toRva).toBe(0x200);

    const jcc = g.edges.find((e) => e.kind === "jcc");
    expect(jcc).toBeDefined();
    expect(jcc?.from).toBe(abs(0x100));
    expect(jcc?.to).toBe(abs(0x180));
    expect(jcc?.toRva).toBe(0x180);
  });

  it("resolves RIP-relative memory operands", () => {
    const g = buildCallGraph(fakeImage(), kFns, kBase);
    const rip = g.edges.find((e) => e.kind === "rip");
    expect(rip).toBeDefined();
    expect(rip?.from).toBe(abs(0x100));
    expect(rip?.to).toBe(abs(0x150));
    expect(rip?.toRva).toBe(0x150);
  });

  it("marks known function targets as functions and the rest as unknown", () => {
    const g = buildCallGraph(fakeImage(), kFns, kBase);
    const fn200 = g.nodes.find((n) => n.rva === 0x200);
    const fn180 = g.nodes.find((n) => n.rva === 0x180);
    const fn150 = g.nodes.find((n) => n.rva === 0x150);

    expect(fn200?.kind).toBe("function");
    expect(fn180?.kind).toBe("unknown");
    expect(fn150?.kind).toBe("unknown");

    expect(fn200?.label).toBe("sub_200");
    expect(fn200?.address).toBe(abs(0x200));
  });

  it("sorts nodes by rva and edges by source then target", () => {
    const g = buildCallGraph(fakeImage(), kFns, kBase);
    const rvas = g.nodes.map((n) => n.rva);
    expect([...rvas].sort((a, b) => a - b)).toEqual(rvas);

    const keys = g.edges.map((e) => [e.fromRva, e.toRva] as const);
    const sorted = [...keys].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    expect(keys).toEqual(sorted);
  });

  it("deduplicates nodes by address and edges by (from,to,kind)", () => {
    const g = buildCallGraph(fakeImage(), kFns, kBase);
    const addresses = g.nodes.map((n) => n.address);
    expect(new Set(addresses).size).toBe(addresses.length);

    const edgeKeys = g.edges.map((e) => `${e.from}|${e.to}|${e.kind}`);
    expect(new Set(edgeKeys).size).toBe(edgeKeys.length);
  });

  it("honors maxDepth and maxNodes", () => {
    expect(buildCallGraph(fakeImage(), kFns, kBase, { maxDepth: 0 })).toEqual({ nodes: [], edges: [] });
    expect(buildCallGraph(fakeImage(), [], kBase)).toEqual({ nodes: [], edges: [] });

    const capped = buildCallGraph(fakeImage(), kFns, kBase, { maxNodes: 1 });
    expect(capped.nodes.length).toBeLessThanOrEqual(1);
  });

  it("ignores functions that fall outside the image", () => {
    const g = buildCallGraph(fakeImage(), [{ address: abs(0x9000), size: 0x10 }], kBase);
    expect(g.nodes).toEqual([]);
    expect(g.edges).toEqual([]);
  });
});
