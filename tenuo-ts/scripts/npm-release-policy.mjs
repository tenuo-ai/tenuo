#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const WORKSPACE_DIR = resolve(SCRIPT_DIR, "..");

export function parseVersion(version) {
  const match = SEMVER.exec(version);
  if (!match) throw new Error(`invalid semantic version: ${version}`);
  if (match[5]) {
    throw new Error(`build metadata is not supported in npm release versions: ${version}`);
  }
  return {
    version,
    baseVersion: `${match[1]}.${match[2]}.${match[3]}`,
    prerelease: match[4] ?? null,
  };
}

export function distTagForVersion(version) {
  const parsed = parseVersion(version);
  if (parsed.prerelease === null) return "latest";

  if (/^beta\.(0|[1-9]\d*)$/.test(parsed.prerelease)) return "beta";
  if (/^rc\.(0|[1-9]\d*)$/.test(parsed.prerelease)) return "next";
  throw new Error(
    `unsupported prerelease channel in ${version}; use -beta.N for beta or -rc.N for next`,
  );
}

export function assertDistTag(version, distTag) {
  const expected = distTagForVersion(version);
  if (distTag !== expected) {
    throw new Error(`${version} must publish on ${expected}, not ${distTag}`);
  }
  return expected;
}

export function assertReleaseTag(version, releaseTag) {
  const { baseVersion } = parseVersion(version);
  const normalized = releaseTag.startsWith("v") ? releaseTag.slice(1) : releaseTag;
  if (normalized !== baseVersion && normalized !== version) {
    throw new Error(
      `release tag ${releaseTag} does not match package version ${version} or its base ${baseVersion}`,
    );
  }
}

export function assertPeerRange(version, peerRange) {
  if (!semver.validRange(peerRange)) {
    throw new Error(`invalid @tenuo/core peer range: ${peerRange}`);
  }
  if (!semver.satisfies(version, peerRange)) {
    throw new Error(`@tenuo/core peer range ${peerRange} does not accept release ${version}`);
  }
}

function readPackage(packageDirectory) {
  const packagePath = resolve(packageDirectory, "package.json");
  return JSON.parse(readFileSync(packagePath, "utf8"));
}

export function checkWorkspace({ releaseTag } = {}) {
  const core = readPackage(resolve(WORKSPACE_DIR, "packages/core"));
  const mcp = readPackage(resolve(WORKSPACE_DIR, "packages/mcp"));

  if (core.name !== "@tenuo/core" || mcp.name !== "@tenuo/mcp") {
    throw new Error("release policy expected @tenuo/core and @tenuo/mcp package manifests");
  }
  if (core.version !== mcp.version) {
    throw new Error(`package versions must stay in lockstep: core=${core.version}, mcp=${mcp.version}`);
  }

  const distTag = distTagForVersion(core.version);
  if (releaseTag) assertReleaseTag(core.version, releaseTag);

  const corePeer = mcp.peerDependencies?.["@tenuo/core"];
  if (typeof corePeer !== "string") {
    throw new Error("@tenuo/mcp must declare an @tenuo/core peer range");
  }
  assertPeerRange(core.version, corePeer);

  return { version: core.version, distTag };
}

function publishPackage(packageDirectory) {
  const absoluteDirectory = resolve(process.cwd(), packageDirectory);
  const pkg = readPackage(absoluteDirectory);
  const distTag = distTagForVersion(pkg.version);
  process.stdout.write(`Publishing ${pkg.name}@${pkg.version} on npm dist-tag ${distTag}\n`);
  const result = spawnSync(
    "npm",
    ["publish", "--access", "public", "--provenance", "--tag", distTag],
    { cwd: absoluteDirectory, stdio: "inherit", shell: process.platform === "win32" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

function usage() {
  process.stderr.write(
    "usage: npm-release-policy.mjs tag VERSION | assert VERSION TAG | check-workspace [RELEASE_TAG] | publish PACKAGE_DIR\n",
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  try {
    if (command === "tag" && args.length === 1) {
      process.stdout.write(`${distTagForVersion(args[0])}\n`);
    } else if (command === "assert" && args.length === 2) {
      assertDistTag(args[0], args[1]);
    } else if (command === "check-workspace" && args.length <= 1) {
      const result = checkWorkspace({ releaseTag: args[0] });
      process.stdout.write(`${result.version} ${result.distTag}\n`);
    } else if (command === "publish" && args.length === 1) {
      publishPackage(args[0]);
    } else {
      usage();
      process.exitCode = 2;
    }
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
