#!/usr/bin/env node
// Merges the Linux AppImage updater entry into a release's latest.json (Tauri updater format).
// usage: node scripts/merge-latest-json.mjs <latest.json> <sig-file> <version> <tarball-name> [out]
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function mergeLatestJson(doc, signature, version, tarball) {
  doc.platforms = doc.platforms ?? {};
  doc.platforms["linux-x86_64"] = {
    signature,
    url: `https://github.com/NetVar1337/EchoDebug/releases/download/v${version}/${tarball}`,
  };
  doc.version = doc.version ?? `v${version}`;
  return doc;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [file, sigFile, version, tarball, out = file] = process.argv.slice(2);
  if (!file || !sigFile || !version || !tarball) {
    console.error("usage: merge-latest-json.mjs <latest.json> <sig-file> <version> <tarball-name> [out]");
    process.exit(2);
  }
  const doc = mergeLatestJson(
    JSON.parse(readFileSync(file, "utf8")),
    readFileSync(sigFile, "utf8").trim(),
    version,
    tarball,
  );
  writeFileSync(out, JSON.stringify(doc, null, 2) + "\n");
  console.log(`latest.json: linux-x86_64 -> ${tarball} (v${version})`);
}
