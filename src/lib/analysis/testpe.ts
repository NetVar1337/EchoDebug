// Test helper: a minimal mapped PE32+ image (indexed by RVA) with one section per entry and
// optional data directories. Used by the analysis tests only.

export type TestSection = { name: string; rva: number; bytes: Uint8Array; chars?: number };

export function buildTestPe(sections: TestSection[], dirs: Record<number, { rva: number; size: number }> = {}, opts: { headerBytes?: (img: Uint8Array) => void } = {}): Uint8Array {
  const end = Math.max(0x1000, ...sections.map((s) => s.rva + Math.max(s.bytes.length, 0x10)));
  const img = new Uint8Array((end + 0xfff) & ~0xfff);
  const dv = new DataView(img.buffer);
  img[0] = 0x4d;
  img[1] = 0x5a;
  dv.setUint32(0x3c, 0x80, true);
  dv.setUint32(0x80, 0x4550, true);
  const fh = 0x84;
  dv.setUint16(fh, 0x8664, true);
  dv.setUint16(fh + 2, sections.length, true);
  dv.setUint32(fh + 4, 0x5f000000, true);
  dv.setUint16(fh + 16, 0xf0, true);
  const oh = fh + 20;
  dv.setUint16(oh, 0x20b, true);
  dv.setUint32(oh + 16, sections[0]?.rva ?? 0x1000, true);
  dv.setBigUint64(oh + 24, 0x140000000n, true);
  dv.setUint32(oh + 56, img.length, true);
  dv.setUint16(oh + 68, 3, true);
  dv.setUint32(oh + 108, 16, true);
  for (const [i, d] of Object.entries(dirs)) {
    dv.setUint32(oh + 112 + Number(i) * 8, d.rva, true);
    dv.setUint32(oh + 112 + Number(i) * 8 + 4, d.size, true);
  }
  const st = oh + 0xf0;
  sections.forEach((s, i) => {
    const o = st + i * 40;
    img.set(new TextEncoder().encode(s.name.slice(0, 8)), o);
    dv.setUint32(o + 8, s.bytes.length, true);
    dv.setUint32(o + 12, s.rva, true);
    dv.setUint32(o + 16, s.bytes.length, true);
    dv.setUint32(o + 36, s.chars ?? 0x60000020, true);
    img.set(s.bytes, s.rva);
  });
  opts.headerBytes?.(img);
  return img;
}
