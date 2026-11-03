import { describe, expect, it } from "vitest";
import { buildCfg, flowOf, layoutCfg, type CfgLine } from "./cfg";
import { resolveSwitch, toIntel } from "./jumptables";

const L = (address: number, length: number, text: string): CfgLine => ({ address: "0x" + address.toString(16), length, bytes: "", text });

function decoder(lines: CfgLine[]) {
  return async (a: bigint) => {
    const i = lines.findIndex((l) => BigInt(l.address) === a);
    return i < 0 ? [] : lines.slice(i, i + 4); // short runs force re-decoding
  };
}

describe("control-flow graph", () => {
  it("classifies control flow in Intel and AT&T text", () => {
    expect(flowOf("je 0x1010")).toEqual({ kind: "jcc", target: 0x1010n });
    expect(flowOf("jmp 0x1010")).toEqual({ kind: "jmp", target: 0x1010n });
    expect(flowOf("jmp rax").kind).toBe("indirect-jmp");
    expect(flowOf("jmpq *%rax").kind).toBe("indirect-jmp");
    expect(flowOf("call 0x2000")).toEqual({ kind: "call", target: 0x2000n });
    expect(flowOf("ret").kind).toBe("ret");
    expect(flowOf("retq").kind).toBe("ret");
    expect(flowOf("mov eax, 1").kind).toBe("none");
  });

  it("splits an if/else diamond with a loop into blocks and edges", async () => {
    const code = [
      L(0x1000, 3, "test ecx, ecx"),
      L(0x1003, 2, "je 0x100a"),
      L(0x1005, 5, "mov eax, 1"),
      L(0x100a, 5, "call 0x9000"),
      L(0x100f, 2, "dec ecx"),
      L(0x1011, 2, "jne 0x100a"),
      L(0x1013, 1, "ret"),
    ];
    const cfg = await buildCfg(0x1000n, decoder(code));
    expect(cfg.blocks.map((b) => b.start)).toEqual([0x1000n, 0x1005n, 0x100an, 0x1013n]);
    const e = cfg.edges.map((x) => `${x.from.toString(16)}>${x.to.toString(16)}:${x.kind}`).sort();
    expect(e).toEqual(["1000>1005:fallthrough", "1000>100a:taken", "1005>100a:fallthrough", "100a>100a:taken", "100a>1013:fallthrough"].sort());
    const pos = layoutCfg(cfg, (b) => b.lines.length * 16);
    expect(pos.get(0x1000n)!.y).toBe(0);
    expect(pos.get(0x1013n)!.y).toBeGreaterThan(pos.get(0x100an)!.y);
  });

  it("adds one edge per switch case", async () => {
    const code = [L(0x1000, 2, "jmp rax"), L(0x1100, 1, "ret"), L(0x1200, 1, "ret")];
    const cfg = await buildCfg(0x1000n, decoder(code), { switchTargets: () => [0x1100n, 0x1200n] });
    expect(cfg.edges.filter((x) => x.kind === "case").map((x) => x.to)).toEqual([0x1100n, 0x1200n]);
  });
});

describe("jump tables", () => {
  const base = 0x140000000n;
  const img = new Uint8Array(0x3000);
  const dv = new DataView(img.buffer);

  it("normalises AT&T operands", () => {
    expect(toIntel("movslq (%rdx,%rax,4),%rax")).toBe("movsxd rax, [rdx+rax*4]");
    expect(toIntel("jmpq *%rax")).toBe("jmp rax");
    expect(toIntel("lea 0x10(%rip),%rdx")).toBe("lea rdx, [rip+0x10]");
  });

  it("recovers an MSVC x64 rva table", () => {
    // table at rva 0x2000 with 3 entries
    [0x1100, 0x1200, 0x1300].forEach((v, i) => dv.setUint32(0x2000 + i * 4, v, true));
    const lines = [
      L(0x140001000, 3, "cmp ecx, 2"),
      L(0x140001003, 6, "ja 0x140001400"),
      L(0x140001009, 7, "lea rdx, [0x140000000]"),
      L(0x140001010, 7, "mov ecx, dword ptr [rdx+rcx*4+0x2000]"),
      L(0x140001017, 3, "add rcx, rdx"),
      L(0x14000101a, 2, "jmp rcx"),
    ];
    const t = resolveSwitch(lines, 5, img, base)!;
    expect(t.kind).toBe("msvc-rva");
    expect(t.bounded).toBe(true);
    expect(t.targets).toEqual([base + 0x1100n, base + 0x1200n, base + 0x1300n]);
  });

  it("recovers a GCC self-relative table", () => {
    // table at rva 0x2800; entries relative to the table
    [0x10, -0x20].forEach((v, i) => dv.setInt32(0x2800 + i * 4, v, true));
    const lines = [
      L(0x140001000, 3, "cmp eax, 1"),
      L(0x140001003, 2, "ja 0x140001100"),
      L(0x140001005, 7, "lea rdx, [rip+0x17f4]"), // next = 0x14000100c, +0x17f4 = 0x140002800
      L(0x14000100c, 4, "movsxd rax, dword ptr [rdx+rax*4]"),
      L(0x140001010, 3, "add rax, rdx"),
      L(0x140001013, 2, "jmp rax"),
    ];
    const t = resolveSwitch(lines, 5, img, base)!;
    expect(t.kind).toBe("relative");
    expect(t.table).toBe(base + 0x2800n);
    expect(t.targets).toEqual([base + 0x2810n, base + 0x27e0n]);
  });

  it("recovers the table from real GCC/iced AT&T output (notrack, resolved lea, movslq)", () => {
    // gcc -O1 switch as printed by the local backend (iced-x86 GAS formatter)
    const t0 = 0x2004;
    [0x10, 0x20, 0x30].forEach((v, i) => dv.setInt32(t0 + i * 4, v - t0, true)); // entries relative to the table
    const lines = [
      L(0x14000116f, 3, "and $7,%eax"),
      L(0x140001172, 3, "cmp $2,%eax"),
      L(0x140001175, 2, "ja 0x00000001400011AF"),
      L(0x140001177, 2, "mov %eax,%eax"),
      L(0x140001179, 7, "lea 0x140002004,%rdx ; 0x140002004"),
      L(0x140001180, 4, "movslq (%rdx,%rax,4),%rax"),
      L(0x140001184, 3, "add %rdx,%rax"),
      L(0x140001187, 3, "notrack jmp *%rax"),
    ];
    expect(flowOf("notrack jmp *%rax").kind).toBe("indirect-jmp");
    const t = resolveSwitch(lines, 7, img, base)!;
    expect(t).not.toBeNull();
    expect(t.kind).toBe("relative");
    expect(t.count).toBe(3);
    expect(t.targets).toEqual([base + 0x10n, base + 0x20n, base + 0x30n]);
  });

  it("returns null for a plain indirect jump", () => {
    expect(resolveSwitch([L(0x1000, 2, "jmp rax")], 0, img, base)).toBeNull();
  });
});
