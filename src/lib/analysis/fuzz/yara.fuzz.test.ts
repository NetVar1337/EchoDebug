// Fuzz / property tests for the YARA rule parser and the matcher.
import { describe, expect, it } from "vitest";
import { clean, fc, kCases, kTimeout, params, randomBytes } from "./harness";
import { hexMatches, parseYara, scanYara, YaraError } from "../yara";

const kRules = String.raw`
rule text_mods : tag1 tag2 {
  meta: author = "fuzz" score = 7 neg = -1 ok = true
  strings:
    $a = "MZ" ascii wide
    $b = "kernel32" nocase fullword
    $c = "\x90\x90" xor(1-3)
  condition: $a at 0 or #b > 1 or $c
}
rule hex_shapes {
  strings:
    $h1 = { 4D 5A ?? ?? [2-4] 50 45 }
    $h2 = { E8 ?? ?? ?? ?? ( 48 | 49 8B ) [0-] C3 }
    $h3 = { 4? ?5 [-] 00 00 }
  condition: any of ($h*) and filesize < 10MB
}
rule regexes {
  strings:
    $r1 = /https?:\/\/[a-z0-9.]{3,32}/i
    $r2 = /ab+c/s wide ascii
  condition: 1 of them
}
private rule helper { condition: uint16(0) == 0x5a4d }
rule arithmetic {
  condition: helper and (uint32(@a_missing[1]) | 0) >= 0 or (filesize % 3 == 1 and int8(1) < 0x7f) or uint32be(filesize - 4) ^ 5 == 9
}
`.replace("@a_missing[1]", "0");

describe("YARA under random and mutated input", () => {
  it("the rule corpus compiles", () => {
    expect(parseYara(kRules).map((r) => r.name)).toEqual(["text_mods", "hex_shapes", "regexes", "helper", "arithmetic"]);
  });

  it("parseYara on random text", () => {
    fc.assert(fc.property(fc.string({ maxLength: 300 }), (src) => { clean(() => parseYara(src)); }), params());
  }, kTimeout);

  it("parseYara on spliced rule sources", () => {
    const tokens = ["{", "}", "(", ")", "[", "]", "|", "??", "?", "-", "..", "/", "\\", '"', "$", "#", "@", "!", "=", "rule", "condition:", "strings:", "of", "them", "at", "in", "xor", "(0-255)", "(300-1)", "[5-2]", "[-]", "[999999999]", "and", "or", "not", "0x", "KB", "\n"];
    const junk = fc.array(fc.oneof(fc.constantFrom(...tokens), fc.string({ maxLength: 4 })), { maxLength: 12 }).map((a) => a.join(" "));
    fc.assert(
      fc.property(fc.nat({ max: kRules.length }), fc.nat({ max: 40 }), junk, (at, cut, ins) => {
        const src = kRules.slice(0, at) + ins + kRules.slice(Math.min(kRules.length, at + cut));
        const rules = clean(() => parseYara(src));
        if (rules) clean(() => scanYara(rules, new Uint8Array(256)));
      }),
      params(),
    );
  }, kTimeout);

  it("scanYara of the corpus over random buffers", () => {
    const rules = parseYara(kRules);
    fc.assert(fc.property(randomBytes(4096), (b) => { clean(() => scanYara(rules, b, { entrypoint: 0 })); }), params());
  }, kTimeout);

  it("scanYara of the corpus over repetitive buffers (backtracking bait)", () => {
    const rules = parseYara(kRules);
    const unit = fc.uint8Array({ minLength: 1, maxLength: 6 });
    fc.assert(
      fc.property(unit, fc.integer({ min: 1, max: 8192 }), (u, n) => {
        const b = new Uint8Array(u.length * n);
        for (let i = 0; i < n; i++) b.set(u, i * u.length);
        clean(() => scanYara(rules, b));
      }),
      params(),
    );
  }, kTimeout);

  it("the chained hex matcher reports exactly what the regex reports", () => {
    const atom = fc.constantFrom("AA", "BB", "??", "A?", "?B", "(AA | BB)", "(AA BB | ?? CC)", "(AA | BB CC)", "[2]");
    const jump = fc.constantFrom("[0-1]", "[0-]", "[1-3]", "[1-]", "[0-0]", "[3-]");
    const pattern = fc
      .tuple(fc.constantFrom("", "[0-2] "), fc.array(fc.tuple(atom, fc.option(jump, { nil: undefined })), { minLength: 1, maxLength: 5 }))
      .map(([lead, parts]) => lead + parts.map(([a, j]) => (j ? `${a} ${j}` : a)).join(" ") + " CC");
    const buf = fc.array(fc.constantFrom(0xaa, 0xbb, 0xab, 0xcc, 0x00), { maxLength: 96 }).map((a) => new Uint8Array(a));
    fc.assert(
      fc.property(pattern, buf, fc.integer({ min: 1, max: 6 }), (hex, b, limit) => {
        expect(hexMatches(hex, b, "auto", limit)).toEqual(hexMatches(hex, b, "regex", limit));
      }),
      params({ numRuns: kCases * 10 }),
    );
  }, kTimeout);
});

describe("YARA regressions", () => {
  // Each was found by the properties above or by review; the failing input is inlined.
  const mz = (n: number) => {
    const b = new Uint8Array(n);
    for (let i = 0; i + 1 < n; i += 2) { b[i] = 0x4d; b[i + 1] = 0x5a; }
    return b;
  };

  it("an unbounded jump over a buffer of near-misses is linear (was 1.6 s per 128 KiB, quadratic)", () => {
    const rules = parseYara("rule pe { strings: $a = { 4D 5A [0-] 50 45 } $b = { 4D [0-] 5A [0-] 4D [0-] 50 } $c = { 4D 5A [0-60000] 50 } condition: any of them }");
    expect(clean(() => scanYara(rules, mz(1 << 20)), 2000)).toEqual([]);
    const hit = mz(1 << 16);
    hit.set([0x50, 0x45], 0x8000);
    const m = scanYara(rules, hit)[0].strings.filter((s) => s.id === "$a");
    expect(m.length).toBe(1000); // limitPerString
    expect(m[0]).toMatchObject({ offset: 0, length: 0x8002 });
  });

  it("an invalid regex is a YaraError, not a SyntaxError", () => {
    expect(() => parseYara("rule r { strings: $r = /[z-a]/ condition: $r }")).toThrow(YaraError);
    expect(() => parseYara("rule r { strings: $r = /(/ condition: $r }")).toThrow(YaraError);
  });

  it("a reversed or out-of-range jump is a YaraError", () => {
    expect(() => parseYara("rule r { strings: $h = { AA [5-2] BB } condition: $h }")).toThrow(YaraError);
    expect(() => parseYara("rule r { strings: $h = { AA [99999999999] BB } condition: $h }")).toThrow(YaraError);
  });

  it("xor ranges are 0-255 (xor(0-1000000) used to build a million regexes)", () => {
    expect(() => parseYara('rule r { strings: $x = "abc" xor(0-1000000) condition: $x }')).toThrow(YaraError);
    expect(() => parseYara('rule r { strings: $x = "abc" xor(9-3) condition: $x }')).toThrow(YaraError);
    expect(parseYara('rule r { strings: $x = "abc" xor(1-3) condition: $x }')[0].strings[0].res.length).toBe(3);
  });

  it("deep nesting is a YaraError, not a stack overflow", () => {
    const deep = "(".repeat(20000) + "true" + ")".repeat(20000);
    expect(() => parseYara(`rule r { condition: ${deep} }`)).toThrow(YaraError);
    expect(() => parseYara(`rule r { condition: ${"not ".repeat(20000)} true }`)).toThrow(YaraError);
    expect(() => parseYara(`rule r { condition: ${"- ".repeat(20000)} 1 }`)).toThrow(YaraError);
    expect(() => parseYara(`rule r { strings: $h = { ${"(".repeat(5000)}AA${")".repeat(5000)} } condition: $h }`)).toThrow(YaraError);
    const long = Array.from({ length: 50000 }, () => "true").join(" and ");
    expect(() => parseYara(`rule r { condition: ${long} }`)).toThrow(YaraError);
    // a long but reasonable chain still works
    const ok = parseYara(`rule r { condition: ${Array.from({ length: 500 }, () => "true").join(" or ")} }`);
    expect(scanYara(ok, new Uint8Array(4)).length).toBe(1);
  });
});
