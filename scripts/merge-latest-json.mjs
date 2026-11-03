#!/usr/bin/env node
// Merges the Linux updater entries into a release's latest.json (Tauri updater format).
// The updater looks up `linux-x86_64-<bundle>` first (bundle = how the running app was installed),
// then `linux-x86_64`, and refuses a payload that does not match the install: a .deb install
// must get a .deb, an AppImage an AppImage.
// usage: node scripts/merge-latest-json.mjs <latest.json> <version> <bundle-file>... (each with a <bundle-file>.sig)
import { readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";

const kKinds = { ".AppImage": "appimage", ".deb": "deb" };

export function bundleKind(name) {
  const ext = Object.keys(kKinds).find((e) => name.endsWith(e));
  return ext ? kKinds[ext] : null;
}

/** bundles: [{ name, signature }] with name an .AppImage or .deb file name. */
export function mergeLatestJson(doc, version, bundles) {
  doc.platforms = doc.platforms ?? {};
  for (const { name, signature } of bundles) {
    const kind = bundleKind(name);
    if (!kind) throw new Error(`not an updater bundle: ${name}`);
    const entry = { signature, url: `https://github.com/NetVar1337/EchoDebug/releases/download/v${version}/${name}` };
    doc.platforms[`linux-x86_64-${kind}`] = entry;
    // fallback for installs the updater cannot classify; AppImage replaces itself without root
    if (kind === "appimage") doc.platforms["linux-x86_64"] = entry;
  }
  doc.version = doc.version ?? `v${version}`;
  return doc;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [file, version, ...files] = process.argv.slice(2);
  if (!file || !version || files.length === 0) {
    console.error("usage: merge-latest-json.mjs <latest.json> <version> <bundle-file>...");
    process.exit(2);
  }
  const bundles = files.map((f) => ({ name: basename(f), signature: readFileSync(`${f}.sig`, "utf8").trim() }));
  const doc = mergeLatestJson(JSON.parse(readFileSync(file, "utf8")), version, bundles);
  writeFileSync(file, JSON.stringify(doc, null, 2) + "\n");
  for (const b of bundles) console.log(`latest.json: linux-x86_64-${bundleKind(b.name)} -> ${b.name} (v${version})`);
}
