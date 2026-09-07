import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

const coreDir = join(dirname(fileURLToPath(import.meta.url)), "..");
copyFileSync(join(coreDir, "..", "..", "..", "LICENSE"), join(coreDir, "LICENSE"));
const packDir = mkdtempSync(join(tmpdir(), "tenuo-core-pack-"));
const installDir = mkdtempSync(join(tmpdir(), "tenuo-core-smoke-"));

try {
  const tarball = packPackage(coreDir, packDir);
  assertPacked(tarball, [
    "package/dist/index.js",
    "package/dist/generated/tenuo_wasm_bg.wasm",
    "package/dist/generated/tenuo_wasm.js",
    "package/LICENSE",
    "package/README.md",
  ]);

  writeFileSync(join(installDir, "package.json"), JSON.stringify({ private: true, type: "module" }));
  run("npm", ["install", "--omit=dev", tarball], { cwd: installDir, stdio: "inherit" });
  copyFileSync(join(coreDir, "scripts", "pack-smoke-consumer.mjs"), join(installDir, "smoke.mjs"));
  execFileSync(process.execPath, [join(installDir, "smoke.mjs")], {
    cwd: installDir,
    stdio: "inherit",
    env: { ...process.env, NODE_ENV: "test" },
  });
} finally {
  rmSync(packDir, { recursive: true, force: true });
  rmSync(installDir, { recursive: true, force: true });
}

function run(command, args, options) {
  return execFileSync(resolveBin(command), args, options);
}

function resolveBin(command) {
  if (process.platform !== "win32") {
    return command;
  }
  if (command.endsWith(".cmd") || command.endsWith(".exe")) {
    return command;
  }
  return `${command}.cmd`;
}

function packPackage(cwd, destination) {
  const packed = run("pnpm", ["pack", "--pack-destination", destination], {
    cwd,
    encoding: "utf8",
  })
    .trim()
    .split(/\r?\n/)
    .at(-1);
  if (packed === undefined || packed.length === 0) {
    throw new Error("pnpm pack did not print a tarball path");
  }
  return isAbsolute(packed) ? packed : join(destination, packed);
}

function assertPacked(tarball, required) {
  const listing = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" });
  const entries = listing.split(/\r?\n/);
  for (const path of required) {
    if (!entries.includes(path)) {
      throw new Error(`packed tarball is missing ${path}`);
    }
  }
}
