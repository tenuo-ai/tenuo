import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertDistTag,
  assertPeerRange,
  assertReleaseTag,
  checkWorkspace,
  distTagForVersion,
  parseVersion,
} from "./npm-release-policy.mjs";

test("stable versions publish on latest", () => {
  assert.equal(distTagForVersion("1.2.3"), "latest");
});

test("beta versions publish on beta", () => {
  assert.equal(distTagForVersion("1.2.3-beta.4"), "beta");
});

test("release candidates publish on next", () => {
  assert.equal(distTagForVersion("1.2.3-rc.2"), "next");
});

test("a prerelease cannot target latest", () => {
  assert.throws(
    () => assertDistTag("1.2.3-beta.4", "latest"),
    /must publish on beta, not latest/,
  );
});

test("unknown prerelease channels fail closed", () => {
  assert.throws(() => distTagForVersion("1.2.3-alpha.1"), /unsupported prerelease channel/);
  assert.throws(() => distTagForVersion("1.2.3-beta"), /unsupported prerelease channel/);
  assert.throws(() => distTagForVersion("1.2.3-rc.preview"), /unsupported prerelease channel/);
});

test("invalid semantic versions are rejected", () => {
  assert.throws(() => parseVersion("1.2"), /invalid semantic version/);
});

test("a coordinated repository tag may name the package version or its stable base", () => {
  assert.doesNotThrow(() => assertReleaseTag("0.3.3-beta.0", "v0.3.3"));
  assert.doesNotThrow(() => assertReleaseTag("0.3.3-beta.0", "v0.3.3-beta.0"));
  assert.throws(() => assertReleaseTag("0.3.3-beta.0", "v0.3.4"), /does not match/);
});

test("peer validation uses semantic range membership", () => {
  const range = ">=0.3.3-beta.0 <0.3.4";
  assert.doesNotThrow(() => assertPeerRange("0.3.3-beta.1", range));
  assert.throws(() => assertPeerRange("0.3.4-beta.0", range), /does not accept release/);
  assert.throws(() => assertPeerRange("0.3.4", range), /does not accept release/);
  assert.throws(() => assertPeerRange("0.3.3-beta.1", "not a range"), /invalid.*peer range/);
});

test("the workspace packages have one valid release channel", () => {
  const result = checkWorkspace();
  assert.equal(result.distTag, distTagForVersion(result.version));
});
