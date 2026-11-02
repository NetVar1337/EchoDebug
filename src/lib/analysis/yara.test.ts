import { describe, expect, it } from "vitest";
import { hexToRegex, parseYara, scanYara, YaraError } from "./yara";

const enc = (s: string) => new TextEncoder().encode(s);
const cat = (...parts: (Uint8Array | number[])[]) => {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const wide = (s: string) => new Uint8Array(Array.from(s).flatMap((c) => [c.charCodeAt(0), 0]));

const buf = cat(
  [0x4d, 0x5a, 0x90, 0x00],
  enc("xxIsDebuggerPresentyy"),
  wide("Global\\Mutex"),
  [0x48, 0x8b, 0x05, 0x11, 0x22, 0x33, 0x44, 0xe8, 0xaa, 0xbb],
  enc(" password: Secret "),
  Array.from(enc("XORME"), (c) => c ^ 0x5a),
);

describe("YARA", () => {
  it("compiles hex strings", () => {
    expect(hexToRegex("4D 5A")).toBe("\\x4d\\x5a");
    expect(hexToRegex("4D ?? ?A B?")).toContain("[\\s\\S]");
    expect(hexToRegex("AA [2-4] BB")).toBe("\\xaa[\\s\\S]{2,4}?\\xbb");
    expect(hexToRegex("(AA | BB CC)")).toBe("(?:\\xaa|\\xbb\\xcc)");
    expect(() => hexToRegex("AA (BB")).toThrow(YaraError);
  });

  it("matches text, wide, nocase, fullword, xor, hex and regex strings", () => {
    const rules = parseYara(`
      rule mz_header : file pe {
        meta: author = "echo" version = 2 ok = true
        strings: $mz = { 4D 5A }
        condition: $mz at 0 and uint16(0) == 0x5A4D and filesize < 1MB
      }
      rule anti_debug {
        strings:
          $a = "isdebuggerpresent" nocase
          $w = "Global\\\\Mutex" wide
          $notword = "Debugger" fullword
        condition: $a and $w and not $notword
      }
      rule code {
        strings: $c = { 48 8B 05 ?? ?? ?? ?? E8 [1-3] BB }
        condition: #c == 1 and @c[1] > 4
      }
      rule secrets {
        strings:
          $re = /password:\\s+[a-z]+/i
          $x = "XORME" xor(0x50-0x5f)
        condition: all of them
      }
      rule none_here { strings: $z = "zzzz" condition: $z }
    `);
    expect(rules.map((r) => r.name)).toEqual(["mz_header", "anti_debug", "code", "secrets", "none_here"]);
    expect(rules[0].tags).toEqual(["file", "pe"]);
    expect(rules[0].meta).toEqual({ author: "echo", version: 2, ok: true });
    const hits = scanYara(rules, buf);
    expect(hits.map((h) => h.rule)).toEqual(["mz_header", "anti_debug", "code", "secrets"]);
    const code = hits.find((h) => h.rule === "code")!;
    expect(code.strings[0].data.startsWith("488b05")).toBe(true);
    expect(code.strings[0].offset).toBe(4 + 21 + 24);
  });

  it("supports of-sets, offsets, ranges, rule references, private and global rules", () => {
    const rules = parseYara(`
      private rule has_mz { condition: uint8(0) == 0x4D }
      rule two_of {
        strings: $s1 = "IsDebugger" $s2 = "Mutex" wide $s3 = "nothing"
        condition: has_mz and 2 of ($s*) and $s1 in (0..10) and !s1[1] == 10
      }
      global rule always { condition: true }
    `);
    const hits = scanYara(rules, buf);
    expect(hits.map((h) => h.rule)).toEqual(["two_of", "always"]);
  });

  it("encodes non-latin1 text as UTF-8", () => {
    const hits = scanYara(parseYara(`rule u { strings: $u = "héllo→" condition: $u }`), new TextEncoder().encode("..héllo→.."));
    expect(hits.length).toBe(1);
    expect(hits[0].strings[0].length).toBe(new TextEncoder().encode("héllo→").length);
  });

  it("rejects what it cannot do, with a reason", () => {
    expect(() => parseYara(`import "pe" rule a { condition: true }`)).toThrow(/not supported/);
    expect(() => parseYara(`rule a { condition: for any i in (1..2): (true) }`)).toThrow(/for/);
    expect(() => parseYara(`rule a { condition: pe.is_dll() }`)).toThrow(/modules/);
    expect(() => parseYara(`rule a { strings: $a = "x" }`)).toThrow(/no condition/);
    expect(() => scanYara(parseYara(`rule a { condition: $b }`), buf)).toThrow(/undefined string/);
  });
});
