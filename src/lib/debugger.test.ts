import { describe, expect, it, vi } from "vitest";

const sent: { type: string; fields: unknown }[] = [];
vi.mock("./client", () => ({
  request: async (type: string, fields: unknown) => {
    sent.push({ type, fields });
    return { slot: 3, watch: { address: "0x1000", len: 4 }, auto: true };
  },
}));

const { callsToCsv, filterCalls, formatArgs, importSpecs, parseFunctionList, sortHits, startTrace, watchSize } = await import("./debugger");
type Call = Parameters<typeof callsToCsv>[0][number];

const call = (over: Partial<Call>): Call => ({
  seq: 1, t: 0, tid: 7, function: "kernel32.dll!CreateFileW", address: "0x7ff0", caller: "0x140001234",
  args: [{ name: "lpFileName", value: "0x10", text: 'L"C:\\a,b.txt"' }, { name: "dwDesiredAccess", value: "0x80000000", text: "0x80000000" }],
  ret: "0x1c4", ret_text: "0x1c4", returned: true, ...over,
});

describe("debugger helpers", () => {
  it("clamps the watch size to what a debug register covers", () => {
    expect(watchSize(4)).toBe(4);
    expect(watchSize(16)).toBe(8);
    expect(watchSize(0)).toBe(4);
    expect(watchSize(1)).toBe(1);
  });

  it("starts a trace through dbg_trace_start", async () => {
    const r = await startTrace("0x1000", 2, "access");
    expect(r.slot).toBe(3);
    expect(sent.at(-1)).toEqual({ type: "dbg_trace_start", fields: { address: "0x1000", size: 2, kind: "access" } });
  });

  it("sorts hits by count, then address", () => {
    const h = (address: string, count: number) => ({ address, count, length: 3, text: "mov", tid: 1, regs: {}, first: 0, last: 0 });
    expect(sortHits([h("0x20", 1), h("0x10", 1), h("0x30", 9)]).map((x) => x.address)).toEqual(["0x30", "0x10", "0x20"]);
  });

  it("filters calls with all terms and exclusions", () => {
    const calls = [call({ seq: 1 }), call({ seq: 2, function: "ws2_32.dll!send", args: [], ret_text: "-1" }), call({ seq: 3, tid: 42, function: "kernel32.dll!ReadFile", args: [] })];
    expect(filterCalls(calls, "").length).toBe(3);
    expect(filterCalls(calls, "kernel32").map((c) => c.seq)).toEqual([1, 3]);
    expect(filterCalls(calls, "kernel32 !readfile").map((c) => c.seq)).toEqual([1]);
    expect(filterCalls(calls, "a,b.txt").map((c) => c.seq)).toEqual([1]);
    expect(filterCalls(calls, "42").map((c) => c.seq)).toEqual([3]);
  });

  it("exports CSV with quoting", () => {
    const csv = callsToCsv([call({ t: Date.UTC(2026, 0, 2, 3, 4, 5) }), call({ seq: 2, ret: null, ret_text: "", returned: false })]);
    const lines = csv.trim().split("\n");
    expect(lines[0]).toBe("seq,time,tid,function,address,caller,arguments,return,return_text");
    expect(lines[1]).toBe('1,2026-01-02T03:04:05.000Z,7,kernel32.dll!CreateFileW,0x7ff0,0x140001234,"lpFileName=L""C:\\a,b.txt"", dwDesiredAccess=0x80000000",0x1c4,0x1c4');
    expect(lines[2].endsWith(",,")).toBe(true);
    expect(formatArgs(call({}))).toContain("dwDesiredAccess=0x80000000");
  });

  it("parses function picks and import specs", () => {
    expect(parseFunctionList("kernel32.dll!CreateFileW\n libc.so.6!open, kernel32.dll!createfilew,\n\n")).toEqual(["kernel32.dll!CreateFileW", "libc.so.6!open"]);
    expect(importSpecs([{ dll: "KERNEL32.dll", name: "CreateFileW" }, { dll: "KERNEL32.dll", name: "CreateFileW" }, { dll: "WS2_32.dll", name: "#23" }, { dll: "ADVAPI32.dll", name: "RegOpenKeyExW" }]))
      .toEqual(["advapi32.dll!RegOpenKeyExW", "kernel32.dll!CreateFileW"]);
  });
});
