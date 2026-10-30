// Writes one version into every place that carries it.
// Usage: node scripts/set-version.mjs 1.2.3
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const v = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(v ?? "")) {
  console.error("usage: set-version.mjs X.Y.Z");
  process.exit(1);
}

function edit(path, re, replacement) {
  if (!existsSync(path)) return;
  const before = readFileSync(path, "utf8");
  const after = before.replace(re, replacement);
  if (after === before && !before.includes(v)) throw new Error(`no version found in ${path}`);
  writeFileSync(path, after);
}

edit("package.json", /("version":\s*")[^"]+(")/, `$1${v}$2`);
edit("package-lock.json", /("name":\s*"echodebug",\s*"version":\s*")[^"]+(")/g, `$1${v}$2`);
edit("src-tauri/Cargo.toml", /^(version\s*=\s*")[^"]+(")/m, `$1${v}$2`);
edit("src-tauri/Cargo.lock", /(name = "echo-debug"\nversion = ")[^"]+(")/, `$1${v}$2`);
edit("agent/echo_debug.as", /^(const string AGENT_VERSION = ")[^"]+(";)/m, `$1${v}$2`);
console.log(`version set to ${v}`);
