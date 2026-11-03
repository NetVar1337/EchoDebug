import { describe, expect, it } from "vitest";
import { Acl, AuditLog, classifyVerb, globMatch, shrinkArgs } from "./audit";

describe("audit log", () => {
  it("classifies verbs from the MCP annotation lists", () => {
    expect(classifyVerb("read")).toBe("read");
    expect(classifyVerb("disassemble")).toBe("read");
    expect(classifyVerb("write")).toBe("write");
    expect(classifyVerb("freeze")).toBe("write");
    expect(classifyVerb("scan_new")).toBe("stateful");
    expect(classifyVerb("dbg_step")).toBe("stateful");
    expect(classifyVerb("ui_set_name")).toBe("annotate");
  });

  it("keeps a bounded ring buffer with increasing seq and since()", () => {
    const log = new AuditLog(3);
    for (let i = 0; i < 5; i++) log.record({ client: "ui", verb: "read", ok: true, ms: 1, ts: i });
    expect(log.list().map((e) => e.seq)).toEqual([3, 4, 5]);
    expect(log.since(3).map((e) => e.seq)).toEqual([4, 5]);
  });

  it("shrinks hex payloads in args", () => {
    const args = shrinkArgs({ data: "ab".repeat(100), address: "0x1000", nested: { blob: "cd".repeat(50) } });
    expect(String(args.data)).toMatch(/\+\d+ hex chars/);
    expect(args.address).toBe("0x1000");
    expect(String((args.nested as Record<string, unknown>).blob)).toMatch(/hex chars/);
  });
});

describe("globMatch", () => {
  it("matches * wildcards only", () => {
    expect(globMatch("dbg_*", "dbg_step")).toBe(true);
    expect(globMatch("dbg_*", "read")).toBe(false);
    expect(globMatch("read", "read")).toBe(true);
    expect(globMatch("*", "anything")).toBe(true);
    expect(globMatch("a.b", "a.b")).toBe(true);
    expect(globMatch("a.b", "axb")).toBe(false);
  });
});

describe("Acl", () => {
  const acl = new Acl([
    { client: "plugin:*", deny: ["write", "freeze*"] },
    { client: "plugin:acme.*", allow: ["read*", "disassemble"] },
    { client: "mcp:ci-bot", allow: ["read", "scan_*", "sig_scan"] },
  ]);

  it("deny wins, allow restricts, more specific rule first", () => {
    expect(acl.allowed("plugin:acme.tools", "read")).toBe(true);
    expect(acl.allowed("plugin:acme.tools", "scan_new")).toBe(false); // allow list of acme.* applies
    expect(acl.allowed("plugin:other", "read")).toBe(true);
    expect(acl.allowed("plugin:other", "write")).toBe(false); // deny from plugin:*
    expect(acl.allowed("mcp:ci-bot", "sig_scan")).toBe(true);
    expect(acl.allowed("mcp:ci-bot", "write")).toBe(false);
    expect(acl.allowed("ui", "write")).toBe(true); // no rule matches the UI
  });

  it("explains a denial", () => {
    expect(acl.denyReason("mcp:ci-bot", "write")).toMatch(/allowed: read, scan_\*, sig_scan/);
    expect(acl.denyReason("ui", "write")).toBeNull();
  });
});
