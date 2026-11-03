import { describe, expect, it } from "vitest";
import { detectDecryptRoutine, decryptScore, planDecryptionCampaign } from "./strdec";
import type { ListingLine } from "./analysis/listing";

const decryptor: ListingLine[] = [
  { address: "0x5000", bytes: "", text: "mov al, [rcx]" },
  { address: "0x5003", bytes: "", text: "xor al, 0x5a" },
  { address: "0x5006", bytes: "", text: "rol al, 3" },
  { address: "0x5009", bytes: "", text: "mov [rcx], al" },
  { address: "0x500c", bytes: "", text: "inc rcx" },
  { address: "0x5010", bytes: "", text: "ret" },
];
const plain: ListingLine[] = [
  { address: "0x6000", bytes: "", text: "mov eax, 1" },
  { address: "0x6005", bytes: "", text: "ret" },
];

const func: ListingLine[] = [
  { address: "0x1000", bytes: "", text: "call 0x5000" },
  { address: "0x1005", bytes: "", text: "call 0x6000" },
  { address: "0x100a", bytes: "", text: "call rax" },
  { address: "0x100f", bytes: "", text: "call 0x7000" }, // no body known
];

describe("decryption campaign", () => {
  it("scores xor/rotate loops with immediate keys above plain functions", () => {
    const d = decryptScore(decryptor);
    const p = decryptScore(plain);
    expect(d.score).toBeGreaterThan(p.score);
    expect(d.reasons.join(" ")).toMatch(/xor op/);
    expect(d.reasons.join(" ")).toMatch(/rotate/);
    expect(d.reasons.join(" ")).toMatch(/immediate key/);
  });

  it("plans emulation order: best candidate first, indirect calls noted", () => {
    const bodies = new Map([["0x5000", decryptor], ["0x6000", plain]]);
    const c = planDecryptionCampaign(func, bodies);
    expect(c.candidates[0].target).toBe("0x5000");
    expect(c.candidates[0].callSite).toBe("0x1000");
    expect(c.plan[0]).toBe("0x5000");
    expect(c.candidates.find((x) => x.target === "0x7000")?.reasons).toEqual(["external/unknown body"]);
  });
});

describe("detectDecryptRoutine (#16)", () => {
  const disasmOf = async (addr: string, _size: number): Promise<ListingLine[]> => {
    if (addr === "0x5000") return decryptor;
    if (addr === "0x6000") return plain;
    return [];
  };

  it("picks the high-scoring decryptor among the function's calls", async () => {
    const top = await detectDecryptRoutine(func, disasmOf);
    expect(top?.target).toBe("0x5000");
    expect(top!.score).toBeGreaterThanOrEqual(5);
  });

  it("returns null when nothing scores like a decryptor", async () => {
    const boring: ListingLine[] = [
      { address: "0x1000", bytes: "", text: "call 0x6000" },
      { address: "0x1005", bytes: "", text: "ret" },
    ];
    expect(await detectDecryptRoutine(boring, disasmOf)).toBeNull();
  });

  it("bounds the number of target bodies fetched", async () => {
    let fetched = 0;
    const many: ListingLine[] = Array.from({ length: 50 }, (_, i) => ({ address: `0x${(0x8000 + i * 5).toString(16)}`, bytes: "", text: `call 0x${(0x9000 + i * 0x100).toString(16)}` }));
    const counting = async (addr: string, size: number) => {
      fetched++;
      return disasmOf(addr, size);
    };
    await detectDecryptRoutine(many, counting, { maxTargets: 10 });
    expect(fetched).toBe(10);
  });
});
