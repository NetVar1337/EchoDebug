import { test } from "node:test";
import assert from "node:assert/strict";
import { applyBump, bumpFor, releaseNotes } from "./next-version.mjs";

const c = (subject, body = "") => ({ subject, body, sha: "abcdef1234" });

test("bump type from conventional commits", () => {
  assert.equal(bumpFor([c("docs: readme"), c("chore: deps")]), "none");
  assert.equal(bumpFor([c("fix(ui): crash")]), "patch");
  assert.equal(bumpFor([c("fix: a"), c("feat(scanner): b")]), "minor");
  assert.equal(bumpFor([c("feat!: new protocol")]), "major");
  assert.equal(bumpFor([c("fix: x", "BREAKING CHANGE: y")]), "major");
});

test("apply bump, pre-1.0 breaking is minor", () => {
  assert.equal(applyBump("0.3.4", "patch"), "0.3.5");
  assert.equal(applyBump("0.3.4", "minor"), "0.4.0");
  assert.equal(applyBump("0.3.4", "major"), "0.4.0");
  assert.equal(applyBump("1.3.4", "major"), "2.0.0");
  assert.equal(applyBump("1.3.4", "none"), null);
});

test("release notes group commits", () => {
  const notes = releaseNotes([c("feat(ai): chat"), c("fix: crash"), c("docs: x")]);
  assert.match(notes, /### Features\n- \*\*ai:\*\* chat \(abcdef1\)/);
  assert.match(notes, /### Fixes\n- crash/);
  assert.doesNotMatch(notes, /docs/);
});
