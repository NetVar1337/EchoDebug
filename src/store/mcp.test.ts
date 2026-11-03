import { describe, expect, it } from "vitest";
import { parseList, useMcp } from "./mcp";

describe("mcp policy store", () => {
  it("parses tool lists", () => {
    expect(parseList("read_memory, disassemble\nwrite_memory  read_memory")).toEqual(["read_memory", "disassemble", "write_memory"]);
    expect(parseList("  ")).toEqual([]);
  });
  it("queues approvals and resolves them once", () => {
    const got: boolean[] = [];
    useMcp.getState().enqueue({ tool: "write_memory", verb: "write", args: {}, resolve: (ok) => got.push(ok) });
    const [a] = useMcp.getState().queue;
    useMcp.getState().answer(a.id, true);
    useMcp.getState().answer(a.id, false);
    expect(got).toEqual([true]);
    expect(useMcp.getState().queue).toHaveLength(0);
  });
});
