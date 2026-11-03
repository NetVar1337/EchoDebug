import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeLatestJson } from "./merge-latest-json.mjs";

const base = () => ({
  version: "v0.5.0",
  notes: "x",
  pub_date: "2026-01-01T00:00:00Z",
  platforms: { "windows-x86_64": { signature: "abc", url: "https://example/setup.exe" } },
});
const url = (name) => `https://github.com/NetVar1337/EchoDebug/releases/download/v0.5.0/${name}`;

test("mergeLatestJson adds per-bundle linux entries and keeps others", () => {
  const doc = mergeLatestJson(base(), "0.5.0", [
    { name: "EchoDebug_0.5.0_amd64.AppImage", signature: "SIG_APPIMAGE" },
    { name: "EchoDebug_0.5.0_amd64.deb", signature: "SIG_DEB" },
  ]);
  assert.equal(doc.platforms["windows-x86_64"].url, "https://example/setup.exe");
  assert.deepEqual(doc.platforms["linux-x86_64-appimage"], { signature: "SIG_APPIMAGE", url: url("EchoDebug_0.5.0_amd64.AppImage") });
  assert.deepEqual(doc.platforms["linux-x86_64-deb"], { signature: "SIG_DEB", url: url("EchoDebug_0.5.0_amd64.deb") });
  // the bare fallback must be the AppImage, never the .deb
  assert.deepEqual(doc.platforms["linux-x86_64"], doc.platforms["linux-x86_64-appimage"]);
});

test("mergeLatestJson rejects files the updater cannot install", () => {
  assert.throws(() => mergeLatestJson(base(), "0.5.0", [{ name: "EchoDebug.tar.gz", signature: "x" }]));
});
