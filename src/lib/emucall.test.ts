import { describe, expect, it, vi } from "vitest";

vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => undefined, removeItem: () => undefined });

const emulate = vi.fn(async (_t: string, f: { start: string; end: string; read?: { address: string; size: number }[] }) => ({
  error_name: "ok",
  reached_end: true,
  instructions: 42,
  regs: { rax: "0x7ff81234", rsp: "0x8000" },
  api_calls: [{ address: "0x7ff80000", name: "VirtualAlloc", ret: "0x90000" }],
  read: (f.read ?? []).map((r) => ({ address: r.address, data: "4d5a" })),
}));
const disasm = vi.fn(async (_t: string, _f: unknown) => ({ results: [{ length: 3 }] }));
vi.mock("./client", () => ({
  client: { send: () => undefined },
  request: (t: string, f: unknown) => (t === "emulate" ? emulate(t, f as never) : disasm(t, f)),
}));

const { emulateCall, resolveCallTarget } = await import("./emucall");

describe("emulateCall (#3)", () => {
  it("disassembles the call site to find the end when none is given", async () => {
    const r = await emulateCall(0x1000n, 0x1050n);
    expect(disasm).toHaveBeenCalled();
    expect(emulate.mock.calls[0][1]).toMatchObject({ start: "0x1000", end: "0x1053" }); // 0x1050 + 3
    expect(r).toMatchObject({ reachedEnd: true, instructions: 42, stop: "returned" });
    expect(r.regs.rax).toBe("0x7ff81234");
    expect(r.apiCalls?.[0].name).toBe("VirtualAlloc");
  });

  it("passes args, writes and reads through, and returns read buffers", async () => {
    const r = await emulateCall(0x1000n, 0x1050n, {
      end: 0x1053n,
      regs: { rcx: "0x1", rdx: "0x2" },
      write: [{ address: "0x9000", data: "4d5a" }],
      read: [{ address: "0x9000", size: 2 }],
      stubs: true,
    });
    const sent = emulate.mock.calls.at(-1)![1] as Record<string, unknown>;
    expect(sent.regs).toEqual({ rcx: "0x1", rdx: "0x2" });
    expect(sent.write).toEqual([{ address: "0x9000", data: "4d5a" }]);
    expect(sent.stubs).toBe(true);
    expect(r.reads).toEqual([{ address: "0x9000", bytes: "4d5a" }]);
  });

  it("resolveCallTarget reads the register after an indirect call", async () => {
    const t = await resolveCallTarget(0x1000n, 0x1050n);
    expect(t).toBe(0x7ff81234n);
  });
});
