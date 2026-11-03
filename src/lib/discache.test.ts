import { describe, expect, it } from "vitest";
import { disasmCacheKey, hashBytes, patchsetHash } from "./discache";

describe("disassembly cache keys", () => {
  it("hashes bytes deterministically (FNV-1a)", () => {
    expect(hashBytes(new Uint8Array([1, 2, 3]))).toBe(hashBytes(new Uint8Array([1, 2, 3])));
    expect(hashBytes(new Uint8Array([1, 2, 3]))).not.toBe(hashBytes(new Uint8Array([1, 2, 4])));
    expect(hashBytes(new Uint8Array([]))).toMatch(/^[0-9a-f]{16}$/);
  });

  it("changes the key when the patch set changes, independent of order", () => {
    const p1 = { address: "0x1000", bytes: "9090" };
    const p2 = { address: "0x2000", bytes: "cc" };
    expect(patchsetHash([p1, p2])).toBe(patchsetHash([p2, p1]));
    expect(patchsetHash([p1])).not.toBe(patchsetHash([p1, p2]));
    expect(patchsetHash([])).not.toBe(patchsetHash([p1]));
  });

  it("keys include module identity and patches", () => {
    const mod = { base: "0x7ff60000", size: 0x1000, hash: "abc" };
    const k1 = disasmCacheKey(mod, []);
    expect(k1).toMatch(/^dis:abc:/);
    expect(disasmCacheKey(mod, [{ address: "0x1000", bytes: "90" }])).not.toBe(k1);
    expect(disasmCacheKey({ ...mod, hash: "def" }, [])).not.toBe(k1);
  });
});
