// PE resources from a mapped image: the type/name/language tree, version info, string tables,
// manifests, dialogs (header + controls) and icons (re-assembled into .ico files).
import { parsePe, scanBudget, type PeInfo } from "./pe";

export type ResId = number | string;
export type ResLeaf = { type: ResId; typeName: string; name: ResId; lang: number; rva: number; size: number; codePage: number };

const kTypes: Record<number, string> = {
  1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
  10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY",
  20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
};

/** Directory entries resourceTree reads at most (real images hold a few thousand). */
const kMaxEntries = 200_000;

export function resourceTree(img: Uint8Array, pe?: PeInfo): ResLeaf[] {
  const info = pe ?? parsePe(img);
  const dir = info.dirs.find((d) => d.name === "Resource");
  if (!dir?.rva || dir.rva + 16 > img.length) return [];
  const dv = new DataView(img.buffer, img.byteOffset, img.byteLength);
  const root = dir.rva;
  const out: ResLeaf[] = [];
  const name = (v: number): ResId => {
    if (!(v & 0x80000000)) return v & 0xffff;
    const o = root + (v & 0x7fffffff);
    if (o + 2 > img.length) return "?";
    const n = dv.getUint16(o, true);
    let s = "";
    for (let i = 0; i < n && o + 2 + i * 2 + 1 < img.length; i++) s += String.fromCharCode(dv.getUint16(o + 2 + i * 2, true));
    return s;
  };
  // A directory is walked once: subdirectory offsets are attacker-controlled and may point back
  // at the root or at each other, which would otherwise re-walk the tree 4096^depth times.
  const visited = new Set<number>();
  let entries = kMaxEntries;
  const walk = (off: number, path: ResId[], depth: number) => {
    if (depth > 3 || off + 16 > img.length || visited.has(off)) return;
    visited.add(off);
    const count = dv.getUint16(off + 12, true) + dv.getUint16(off + 14, true);
    for (let i = 0; i < count && i < 4096 && entries > 0; i++, entries--) {
      const e = off + 16 + i * 8;
      if (e + 8 > img.length) break;
      const id = name(dv.getUint32(e, true));
      const target = dv.getUint32(e + 4, true);
      if (target & 0x80000000) walk(root + (target & 0x7fffffff), [...path, id], depth + 1);
      else {
        const d = root + target;
        if (d + 16 > img.length) continue;
        const [type, nm] = path;
        out.push({ type, typeName: typeof type === "number" ? kTypes[type] ?? String(type) : type, name: nm ?? 0, lang: typeof id === "number" ? id : 0, rva: dv.getUint32(d, true), size: dv.getUint32(d + 4, true), codePage: dv.getUint32(d + 8, true) });
      }
    }
  };
  walk(root, [], 0);
  return out;
}

export function resourceBytes(img: Uint8Array, r: ResLeaf): Uint8Array {
  return img.subarray(r.rva, Math.min(img.length, r.rva + r.size));
}

// ---- version info ---------------------------------------------------------------------------

type VBlock = { key: string; value: Uint8Array; isText: boolean; children: VBlock[] };

function utf16z(b: Uint8Array, o: number, end: number): [string, number] {
  let s = "";
  while (o + 1 < end) {
    const c = b[o] | (b[o + 1] << 8);
    o += 2;
    if (!c) break;
    s += String.fromCharCode(c);
  }
  return [s, o];
}

function versionBlock(b: Uint8Array, o: number, end: number, depth = 0): VBlock | null {
  if (o + 6 > end || depth > 8) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const len = dv.getUint16(o, true);
  const valueLen = dv.getUint16(o + 2, true);
  const isText = dv.getUint16(o + 4, true) === 1;
  const stop = Math.min(end, o + len);
  if (len < 6) return null;
  let [key, p] = utf16z(b, o + 6, stop);
  p = (p + 3) & ~3;
  const vbytes = isText ? valueLen * 2 : valueLen;
  const value = b.subarray(p, Math.min(stop, p + vbytes));
  p = (p + vbytes + 3) & ~3;
  const children: VBlock[] = [];
  while (p < stop) {
    const c = versionBlock(b, p, stop, depth + 1);
    if (!c) break;
    children.push(c);
    p = (p + new DataView(b.buffer, b.byteOffset + p, 2).getUint16(0, true) + 3) & ~3;
  }
  return { key, value, isText, children };
}

export type VersionInfo = { fileVersion: string; productVersion: string; fileOS: number; fileType: number; strings: Record<string, Record<string, string>>; translations: string[] };

export function parseVersionInfo(data: Uint8Array): VersionInfo | null {
  const root = versionBlock(data, 0, data.length);
  if (!root || root.key !== "VS_VERSION_INFO") return null;
  const info: VersionInfo = { fileVersion: "", productVersion: "", fileOS: 0, fileType: 0, strings: {}, translations: [] };
  if (root.value.length >= 52) {
    const dv = new DataView(root.value.buffer, root.value.byteOffset, 52);
    if (dv.getUint32(0, true) === 0xfeef04bd) {
      const v = (ms: number, ls: number) => `${ms >>> 16}.${ms & 0xffff}.${ls >>> 16}.${ls & 0xffff}`;
      info.fileVersion = v(dv.getUint32(8, true), dv.getUint32(12, true));
      info.productVersion = v(dv.getUint32(16, true), dv.getUint32(20, true));
      info.fileOS = dv.getUint32(32, true);
      info.fileType = dv.getUint32(36, true);
    }
  }
  for (const c of root.children) {
    if (c.key === "StringFileInfo") {
      for (const table of c.children) {
        const m: Record<string, string> = {};
        for (const s of table.children) {
          let t = "";
          for (let i = 0; i + 1 < s.value.length; i += 2) {
            const ch = s.value[i] | (s.value[i + 1] << 8);
            if (!ch) break;
            t += String.fromCharCode(ch);
          }
          m[s.key] = t;
        }
        info.strings[table.key] = m;
      }
    } else if (c.key === "VarFileInfo") {
      for (const v of c.children) for (let i = 0; i + 3 < v.value.length; i += 4) {
        const dv = new DataView(v.value.buffer, v.value.byteOffset + i, 4);
        info.translations.push(`${dv.getUint16(0, true).toString(16).padStart(4, "0")}${dv.getUint16(2, true).toString(16).padStart(4, "0")}`);
      }
    }
  }
  return info;
}

// ---- string tables --------------------------------------------------------------------------

/** A STRING resource block holds 16 strings; block n covers ids (n-1)*16 … n*16-1. */
export function parseStringTable(blockId: number, data: Uint8Array): { id: number; text: string }[] {
  const out: { id: number; text: string }[] = [];
  let o = 0;
  for (let i = 0; i < 16 && o + 2 <= data.length; i++) {
    const n = data[o] | (data[o + 1] << 8);
    o += 2;
    let s = "";
    for (let k = 0; k < n && o + 1 < data.length; k++, o += 2) s += String.fromCharCode(data[o] | (data[o + 1] << 8));
    if (n) out.push({ id: (blockId - 1) * 16 + i, text: s });
  }
  return out;
}

// ---- dialogs --------------------------------------------------------------------------------

export type DialogInfo = { extended: boolean; title: string; font: string; x: number; y: number; cx: number; cy: number; controls: { id: number; cls: string; text: string; x: number; y: number; cx: number; cy: number }[] };

export function parseDialog(data: Uint8Array): DialogInfo | null {
  if (data.length < 18) return null;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const ex = dv.getUint16(0, true) === 1 && dv.getUint16(2, true) === 0xffff;
  if (ex && data.length < 26) return null;
  let o = 0;
  const sz = (): string => {
    if (o + 2 > data.length) return "";
    const first = dv.getUint16(o, true);
    if (first === 0xffff) { const ord = o + 4 <= data.length ? dv.getUint16(o + 2, true) : 0; o += 4; return `#${ord}`; }
    const [s, p] = utf16z(data, o, data.length);
    o = p;
    return s;
  };
  let style: number, count: number, x: number, y: number, cx: number, cy: number;
  if (ex) {
    style = dv.getUint32(12, true);
    count = dv.getUint16(16, true);
    [x, y, cx, cy] = [18, 20, 22, 24].map((k) => dv.getInt16(k, true));
    o = 26;
  } else {
    style = dv.getUint32(0, true);
    count = dv.getUint16(8, true);
    [x, y, cx, cy] = [10, 12, 14, 16].map((k) => dv.getInt16(k, true));
    o = 18;
  }
  sz(); // menu
  sz(); // class
  const title = sz();
  let font = "";
  if (style & 0x40) { // DS_SETFONT
    o += ex ? 6 : 2;
    font = sz();
  }
  const controls: DialogInfo["controls"] = [];
  for (let i = 0; i < count && i < 512; i++) {
    o = (o + 3) & ~3;
    if (o + (ex ? 24 : 18) > data.length) break;
    let id: number, c: number[];
    if (ex) {
      c = [12, 14, 16, 18].map((k) => dv.getInt16(o + k, true));
      id = dv.getUint32(o + 20, true);
      o += 24;
    } else {
      c = [8, 10, 12, 14].map((k) => dv.getInt16(o + k, true));
      id = dv.getUint16(o + 16, true);
      o += 18;
    }
    let cls = sz();
    const kCls: Record<string, string> = { "#128": "Button", "#129": "Edit", "#130": "Static", "#131": "ListBox", "#132": "ScrollBar", "#133": "ComboBox" };
    cls = kCls[cls] ?? cls;
    const text = sz();
    const extra = o + 2 <= data.length ? dv.getUint16(o, true) : 0;
    o += 2 + extra;
    controls.push({ id, cls, text, x: c[0], y: c[1], cx: c[2], cy: c[3] });
  }
  return { extended: ex, title, font, x, y, cx, cy, controls };
}

// ---- icons ----------------------------------------------------------------------------------

/** Largest .ico buildIco assembles. */
const kMaxIco = 16 << 20;

/** Rebuilds a .ico from a GROUP_ICON directory and the ICON resources it names. */
export function buildIco(group: Uint8Array, icons: Map<number, Uint8Array>, maxBytes = kMaxIco): Uint8Array | null {
  if (group.length < 6) return null;
  const dv = new DataView(group.buffer, group.byteOffset, group.byteLength);
  const count = dv.getUint16(4, true);
  const entries: { e: Uint8Array; data: Uint8Array }[] = [];
  // A group names each icon once; a hostile one names the same big icon 65535 times.
  const used = new Set<number>();
  let total = 0;
  for (let i = 0; i < count && 6 + i * 14 + 14 <= group.length; i++) {
    const id = dv.getUint16(6 + i * 14 + 12, true);
    const data = icons.get(id);
    if (!data || used.has(id) || total + data.length > maxBytes) continue;
    used.add(id);
    total += data.length;
    entries.push({ e: group.subarray(6 + i * 14, 6 + i * 14 + 12), data });
  }
  if (!entries.length) return null;
  const size = 6 + entries.length * 16 + total;
  const out = new Uint8Array(size);
  const ov = new DataView(out.buffer);
  ov.setUint16(2, 1, true);
  ov.setUint16(4, entries.length, true);
  let off = 6 + entries.length * 16;
  entries.forEach((x, i) => {
    out.set(x.e.subarray(0, 8), 6 + i * 16); // w h colors reserved planes bitcount
    ov.setUint32(6 + i * 16 + 8, x.data.length, true);
    ov.setUint32(6 + i * 16 + 12, off, true);
    out.set(x.data, off);
    off += x.data.length;
  });
  return out;
}

export type ResourceSummary = {
  leaves: ResLeaf[];
  version: VersionInfo | null;
  manifest: string;
  strings: { id: number; text: string }[];
  dialogs: { name: ResId; dialog: DialogInfo }[];
  icons: { name: ResId; ico: Uint8Array }[];
};

export function summarizeResources(img: Uint8Array, pe?: PeInfo): ResourceSummary {
  const leaves = resourceTree(img, pe);
  const of = (t: number) => leaves.filter((l) => l.type === t);
  const v = of(16)[0];
  const m = of(24)[0];
  const iconData = new Map<number, Uint8Array>();
  for (const l of of(3)) if (typeof l.name === "number") iconData.set(l.name, resourceBytes(img, l));
  // Leaves of a valid image do not overlap; hostile ones all point at the same image-sized blob,
  // so the bytes the decoders below read are budgeted (scanBudget is twice the image).
  const take = scanBudget(img.length);
  let iconBytes = 2 * img.length + 0x10000;
  const bytes = (l: ResLeaf): Uint8Array | null => {
    const b = resourceBytes(img, l);
    return take(0, b.length) ? b : null;
  };
  return {
    leaves,
    version: v ? parseVersionInfo(resourceBytes(img, v)) : null,
    manifest: m ? new TextDecoder().decode(resourceBytes(img, m)) : "",
    strings: of(6).flatMap((l) => {
      const b = typeof l.name === "number" ? bytes(l) : null;
      return b && typeof l.name === "number" ? parseStringTable(l.name, b) : [];
    }),
    dialogs: of(5).flatMap((l) => {
      const b = bytes(l);
      const d = b ? parseDialog(b) : null;
      return d ? [{ name: l.name, dialog: d }] : [];
    }),
    icons: of(14).flatMap((l) => {
      const b = bytes(l);
      const ico = b ? buildIco(b, iconData, Math.min(kMaxIco, iconBytes)) : null;
      if (ico) iconBytes -= ico.length;
      return ico ? [{ name: l.name, ico }] : [];
    }),
  };
}
