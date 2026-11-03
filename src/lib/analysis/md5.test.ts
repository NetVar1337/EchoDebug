import { describe, expect, it } from "vitest";
import { md5 } from "./md5";

describe("md5", () => {
  it("matches the RFC 1321 test suite", () => {
    expect(md5("")).toBe("d41d8cd98f00b204e9800998ecf8427e");
    expect(md5("abc")).toBe("900150983cd24fb0d6963f7d28e17f72");
    expect(md5("message digest")).toBe("f96b697d7cb7938d525a2f31aaf161d0");
    expect(md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890")).toBe("57edf4a22be3c955ac49da2e2107b67a");
    expect(md5(new Uint8Array(1000).fill(0x61))).toBe("cabe45dcc9ae5b66ba86600cca6b8ba8");
  });
});
