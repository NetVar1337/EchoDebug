// Decides the next semver from conventional commits since the last v* tag.
// Usage: node scripts/next-version.mjs [--bump patch|minor|major] [--notes FILE]
// Prints the next version, or nothing when no releasable commit landed.
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const RELEASE_TYPES = { feat: "minor", fix: "patch", perf: "patch", refactor: "patch", revert: "patch" };
const RANK = { none: 0, patch: 1, minor: 2, major: 3 };

/** @param {{subject: string, body: string}[]} commits */
export function bumpFor(commits) {
  let bump = "none";
  for (const { subject, body } of commits) {
    const m = /^(\w+)(\([^)]*\))?(!)?:/.exec(subject);
    let b = "none";
    if ((m && m[3]) || /^BREAKING[ -]CHANGE:/m.test(body)) b = "major";
    else if (m && RELEASE_TYPES[m[1]]) b = RELEASE_TYPES[m[1]];
    if (RANK[b] > RANK[bump]) bump = b;
  }
  return bump;
}

export function applyBump(version, bump) {
  let [maj, min, pat] = version.split(".").map(Number);
  // pre-1.0: breaking changes bump minor, as semver allows anything below 1.0
  if (bump === "major" && maj === 0) bump = "minor";
  if (bump === "major") return `${maj + 1}.0.0`;
  if (bump === "minor") return `${maj}.${min + 1}.0`;
  if (bump === "patch") return `${maj}.${min}.${pat + 1}`;
  return null;
}

export function releaseNotes(commits) {
  const groups = { "Breaking changes": [], Features: [], Fixes: [], Other: [] };
  for (const { subject, body, sha } of commits) {
    const m = /^(\w+)(\([^)]*\))?(!)?:\s*(.*)$/.exec(subject);
    if (!m) continue;
    const line = `- ${m[2] ? `**${m[2].slice(1, -1)}:** ` : ""}${m[4]} (${sha.slice(0, 7)})`;
    if (m[3] || /^BREAKING[ -]CHANGE:/m.test(body)) groups["Breaking changes"].push(line);
    else if (m[1] === "feat") groups.Features.push(line);
    else if (m[1] === "fix") groups.Fixes.push(line);
    else if (RELEASE_TYPES[m[1]]) groups.Other.push(line);
  }
  return Object.entries(groups)
    .filter(([, l]) => l.length)
    .map(([h, l]) => `### ${h}\n${l.join("\n")}`)
    .join("\n\n");
}

function git(cmd) {
  return execSync(`git ${cmd}`, { encoding: "utf8" }).trim();
}

function commitsSince(tag) {
  const range = tag ? `${tag}..HEAD` : "HEAD";
  const raw = git(`log ${range} --format=%H%x1f%s%x1f%b%x1e`);
  return raw
    .split("\x1e")
    .map((r) => r.trim())
    .filter(Boolean)
    .map((r) => {
      const [sha, subject, body = ""] = r.split("\x1f");
      return { sha, subject, body };
    })
    .filter((c) => !c.subject.startsWith("chore(release)"));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const forced = args.includes("--bump") ? args[args.indexOf("--bump") + 1] : "";
  const notesFile = args.includes("--notes") ? args[args.indexOf("--notes") + 1] : "";
  let tag = "";
  try {
    tag = git("describe --tags --abbrev=0 --match 'v*'");
  } catch {
    // no release yet: every commit counts
  }
  const commits = commitsSince(tag);
  const current = JSON.parse(readFileSync("package.json", "utf8")).version;
  const bump = forced || bumpFor(commits);
  // First release ships the version already in package.json
  const next = !tag && bump !== "none" ? current : applyBump(current, bump);
  if (notesFile) writeFileSync(notesFile, releaseNotes(commits) || "Maintenance release.");
  if (next) console.log(next);
}
