import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeLatestJson } from "./merge-latest-json.mjs";

test("mergeLatestJson adds the linux platform entry and keeps others", () => {
  const doc = mergeLatestJson(
    {
      version: "v0.5.0",
      notes: "x",
      pub_date: "2026-01-01T00:00:00Z",
      platforms: { "windows-x86_64": { signature: "abc", url: "https://example/setup.exe" } },
    },
    "SIGNATURE",
    "0.5.0",
    "EchoDebug.AppImage.tar.gz",
  );
  assert.equal(doc.platforms["windows-x86_64"].url, "https://example/setup.exe");
  assert.equal(doc.platforms["linux-x86_64"].signature, "SIGNATURE");
  assert.equal(
    doc.platforms["linux-x86_64"].url,
    "https://github.com/NetVar1337/EchoDebug/releases/download/v0.5.0/EchoDebug.AppImage.tar.gz",
  );
});
